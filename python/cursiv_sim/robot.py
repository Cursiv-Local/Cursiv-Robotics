"""A simulated research robot's evidence side: it signs every record it writes, keeps a
durable local log (its outbox), and synchronizes with the bridge when the link is up.

This is the part a real robot would run. Navigation, motion and safety are not here,
and nothing the bridge sends can command the robot: the only replies it reads are
acceptance results and the bridge's record count/head.
"""
from __future__ import annotations

import json
import math
import os
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .client import BridgeClient, LinkDown
from .identity import CHECKPOINT_TYPE, RECORD_TYPE, Identity, body_json, merkle_root, payload_hash

SOFTWARE = "cursiv-sim"
VERSION = "0.1.0"


def utc(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class RobotAgent:
    def __init__(self, robot_id: str, state_dir: Path, client: BridgeClient, *, mission_id: str):
        self.robot_id = robot_id
        self.mission_id = mission_id
        self.dir = Path(state_dir) / robot_id
        self.dir.mkdir(parents=True, exist_ok=True)
        self.identity = Identity.load_or_create(self.dir / "robot.key")
        self.client = client
        self.link_up = True
        self.clock_drift_s_per_obs = 0.0     # fault injection: sensor clock running fast
        self._drift = 0.0
        self.log_path = self.dir / "outbox.jsonl"
        self.envelopes: list[dict] = []
        self.hashes: list[str] = []
        self.acked = 0
        self._load()

    # --- durable local log -------------------------------------------------
    def _load(self) -> None:
        """Reload after a restart. A torn last line (power cut mid-write) is dropped."""
        if not self.log_path.exists():
            return
        lines = self.log_path.read_text(encoding="utf-8").splitlines(keepends=True)
        good = []
        for i, line in enumerate(lines):
            try:
                env = json.loads(line)
                if not line.endswith("\n"):
                    raise ValueError("torn")
                good.append(env)
            except ValueError:
                if i != len(lines) - 1:
                    raise RuntimeError(f"{self.log_path}: corrupt line {i + 1}") from None
                with self.log_path.open("w", encoding="utf-8") as f:
                    f.writelines(json.dumps(e) + "\n" for e in good)
        self.envelopes = good
        self.hashes = [payload_hash(e) for e in good]
        ack = self.dir / "acked"
        self.acked = int(ack.read_text()) if ack.exists() else 0

    def _persist(self, env: dict) -> None:
        with self.log_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(env) + "\n")
            f.flush()
            os.fsync(f.fileno())

    def _save_ack(self) -> None:
        tmp = self.dir / "acked.tmp"
        tmp.write_text(str(self.acked))
        os.replace(tmp, self.dir / "acked")

    # --- observations ------------------------------------------------------
    def sensor_now(self) -> str:
        """Sensor clock: wall time plus any injected drift (the simulated clock fault)."""
        self._drift += self.clock_drift_s_per_obs
        return utc(datetime.now(timezone.utc) + timedelta(seconds=self._drift))

    def observation(self, observation_type: str, *, sensor: dict, value=None, unit: str = "", uncertainty=None,
                    lat=None, lon=None, attachments=None, sensor_time: str | None = "now", correction=None,
                    processing=None, derived_from=None, text=None) -> dict:
        location = None if lat is None else {"lat": lat, "lon": lon, "alt_m": None, "crs": "EPSG:4326",
                                             "horizontal_accuracy_m": 1.5, "source": "simulated"}
        measurement = None
        if value is not None or unit:
            measurement = {"value": value, "text": text, "unit": unit,
                           "uncertainty": None if uncertainty is None else {"kind": "standard", "value": uncertainty, "coverage_k": None}}
        return {
            "schema": "cursiv-observation-1",
            "observation_id": f"{self.robot_id}-{uuid.uuid4().hex[:16]}",
            "robot_id": self.robot_id,
            "mission_id": self.mission_id,
            "observation_type": observation_type,
            "synthetic": True,
            "sensor": sensor,
            "sensor_time": self.sensor_now() if sensor_time == "now" else sensor_time,
            "time_source": "simulated",
            "clock": None,
            "location": location,
            "measurement": measurement,
            "attachments": attachments or [],
            "provenance": {"source": "simulated", "software": SOFTWARE, "software_version": VERSION,
                           "derived_from": derived_from or []},
            "processing": processing or [],
            "quality": {"flag": "unassessed", "basis": "simulated sensor; no field quality control"},
            "correction": correction,
        }

    # --- derived results and findings (checked by the verifier's `reasoning` module) ----------
    def derive(self, op: str, inputs: list[dict], *, params: dict | None = None, observation_type: str | None = None) -> dict:
        """Record a derived result. The verifier re-computes it from the cited inputs, so it must be
        computed exactly as `crates/cursiv-evidence/src/reasoning.rs::recompute` does."""
        obs = [body_json(e)["observation"] for e in inputs]
        values = [(o["measurement"]["value"], o["measurement"]["unit"]) for o in obs]
        value, unit = recompute(op, params or {}, values)
        u = propagate(op, params or {}, [v[1] for v in values], [standard_u(o.get("measurement")) for o in obs])
        same_place = len({(o["location"] or {}).get("lat") for o in obs}) == 1 and obs[0]["location"]
        o = self.observation(observation_type or f"{obs[0]['observation_type']}_{op}",
                             sensor={"sensor_id": f"{self.robot_id}-compute", "sensor_type": "computation", "model": None, "calibration": None},
                             value=value, unit=unit, uncertainty=u,
                             sensor_time=max(x["sensor_time"] for x in obs if x["sensor_time"]),
                             derived_from=[f"{x['robot_id']}/{x['observation_id']}" for x in obs],
                             processing=[{"step": "cursiv.derive", "software": SOFTWARE, "version": VERSION,
                                          "parameters": {"op": op, "params": params or {},
                                                         "uncertainty": "GUM first-order propagation, inputs assumed uncorrelated" if u is not None else None}}])
        if same_place:
            o["location"] = obs[0]["location"]
        o["provenance"]["source"] = "derived"
        o["synthetic"] = any(x["synthetic"] for x in obs)
        o["quality"] = {"flag": "unassessed", "basis": "derived value; reproducibility is checked by the verifier, plausibility is not implied"}
        return self.record(o)

    def finding(self, statement: str, *, epistemic: str, author_kind: str = "human", model: str | None = None,
                supports: list[dict] = (), contradicts: list[dict] = (), assumptions: list[str] = ()) -> dict:
        """Record an interpretation citing signed observations. It is evidence about reasoning, not proof."""
        cite = lambda envs: [f"{body_json(e)['observation']['robot_id']}/{body_json(e)['observation']['observation_id']}" for e in envs]
        cited = [body_json(e)["observation"] for e in [*supports, *contradicts]]
        o = self.observation("finding", sensor={"sensor_id": f"{self.robot_id}-analysis", "sensor_type": "analysis", "model": None, "calibration": None})
        o.update(measurement=None, synthetic=any(c["synthetic"] for c in cited), quality=None,
                 claim={"statement": statement, "epistemic": epistemic, "author_kind": author_kind, "model": model,
                        "supports": cite(supports), "contradicts": cite(contradicts), "assumptions": list(assumptions)})
        o["provenance"]["source"] = "interpretation"
        return self.record(o)

    def record(self, observation: dict, written_time: str | None = None) -> dict:
        """Sign and persist a record. `written_time` defaults to this computer's clock; simulations
        pass their mission clock so runs are reproducible."""
        rec = {"schema": "cursiv-record-1", "robot_id": self.robot_id, "seq": len(self.envelopes) + 1,
               "prev": self.hashes[-1] if self.hashes else "genesis", "written_time": written_time or utc(datetime.now(timezone.utc)),
               "observation": observation}
        env = self.identity.sign(rec, RECORD_TYPE)
        self._persist(env)
        self.envelopes.append(env)
        self.hashes.append(payload_hash(env))
        return env

    def checkpoint(self) -> dict:
        return self.identity.sign({"schema": "cursiv-checkpoint-1", "robot_id": self.robot_id, "count": len(self.hashes),
                                   "head": self.hashes[-1] if self.hashes else "genesis",
                                   "merkle_root": merkle_root(self.hashes), "signed_time": utc(datetime.now(timezone.utc))},
                                  CHECKPOINT_TYPE)

    def upload(self, data: bytes, sha: str) -> None:
        if not self.link_up:
            raise LinkDown("link down")
        status, body = self.client.put_attachment(data, sha)
        if status not in (200, 201):
            raise RuntimeError(f"attachment rejected: {body}")

    # --- synchronization ---------------------------------------------------
    def sync(self, batch: int = 200, fail_after: int | None = None) -> dict:
        """Send everything the bridge has not got, from the head it reports. Safe to repeat.
        `fail_after` simulates the link dropping after that many records were sent."""
        if not self.link_up:
            return {"sent": 0, "link": "down", "pending": len(self.envelopes) - self.acked}
        try:
            status, head, _ = self.client.get(f"/v1/robots/{self.robot_id}/head")
            have = head.get("count", 0)
            if have > len(self.hashes):
                raise RuntimeError(f"bridge has {have} records for {self.robot_id}, this robot only {len(self.hashes)}: "
                                   "local state was lost; do not reuse this identity without operator review")
            if have and head.get("head") != self.hashes[have - 1]:
                raise RuntimeError("bridge's head differs from this robot's record: history fork")
            sent, i, results = 0, have, {}
            while i < len(self.envelopes):
                chunk = self.envelopes[i:i + batch]
                if fail_after is not None and sent + len(chunk) > fail_after:
                    chunk = chunk[:max(0, fail_after - sent)]
                    if chunk:
                        self.client.submit(chunk)
                        sent += len(chunk)
                    self.link_up = False
                    raise LinkDown("link dropped during transfer")
                status, data, _ = self.client.submit(chunk)
                if status == 507:
                    # the station is full: nothing from this chunk was stored; keep it and retry later
                    return {"sent": sent, "link": "station_full", "pending": len(self.envelopes) - i}
                for r in data.get("results", [data]):
                    results[r.get("status") or r.get("code", "?")] = results.get(r.get("status") or r.get("code", "?"), 0) + 1
                    if r.get("status") == "rejected":
                        raise RuntimeError(f"{self.robot_id}: record rejected: {r}")
                i += len(chunk)
                sent += len(chunk)
            self.acked = len(self.envelopes)
            self._save_ack()
            cp = self.checkpoint()
            self.client.post("/v1/checkpoints", cp)
            return {"sent": sent, "link": "up", "results": results, "pending": 0}
        except LinkDown:
            self.link_up = False
            return {"sent": 0, "link": "lost", "pending": len(self.envelopes) - self.acked}


# Mirror of crates/cursiv-evidence/src/units.rs: (from, to, a, b) with to = a * from + b.
UNIT_TABLE = [("degC", "K", 1.0, 273.15), ("degC", "degF", 9.0 / 5.0, 32.0), ("hPa", "Pa", 100.0, 0.0), ("hPa", "kPa", 0.1, 0.0),
              ("%", "1", 0.01, 0.0), ("m", "cm", 100.0, 0.0), ("m", "km", 0.001, 0.0), ("m", "ft", 1.0 / 0.3048, 0.0),
              ("m/s", "km/h", 3.6, 0.0), ("mS/cm", "uS/cm", 1000.0, 0.0), ("mg/L", "ppm", 1.0, 0.0), ("dbar", "Pa", 10_000.0, 0.0)]


def _direct(f, t):
    for a_, b_, a, b in UNIT_TABLE:
        if a_ == f and b_ == t:
            return a, b
        if b_ == f and a_ == t:
            return 1.0 / a, -b / a
    return None


def affine(f: str, t: str):
    if f == t:
        return 1.0, 0.0
    d = _direct(f, t)
    if d:
        return d
    for a_, b_, _, _ in UNIT_TABLE:
        for mid in (a_, b_):
            if mid not in (f, t):
                x, y = _direct(f, mid), _direct(mid, t)
                if x and y:
                    return y[0] * x[0], y[0] * x[1] + y[1]
    return None


def standard_u(m: dict | None):
    """Mirror of science.rs::standard_u."""
    u = (m or {}).get("uncertainty")
    if not u:
        return None
    if u["kind"] == "standard":
        return u["value"]
    if u["kind"] == "expanded":
        k = u.get("coverage_k") or 2.0
        return u["value"] / (k if k > 0 else 2.0)
    return u["value"] / math.sqrt(3.0)


def propagate(op: str, params: dict, units: list[str], us: list) -> float | None:
    """Mirror of reasoning.rs::propagate (GUM, uncorrelated inputs). None = not propagated."""
    if op not in ("mean", "sum", "linear", "convert") or not us or any(u is None for u in us):
        return None
    rss = 0.0
    for u in us:
        rss += u * u
    rss = math.sqrt(rss)
    if op == "mean":
        return rss / len(us)
    if op == "sum":
        return rss
    if op == "linear":
        return abs(params["a"]) * us[0]
    a = affine(units[0], params["to"])
    return abs(a[0]) * us[0] if a else None


def recompute(op: str, params: dict, inputs: list[tuple[float, str]]) -> tuple[float, str]:
    """Mirror of reasoning.rs::recompute (same operation order, IEEE 754 doubles)."""
    unit = inputs[0][1]
    xs = [v for v, _ in inputs]
    if op not in ("count", "linear", "convert") and any(u != unit for _, u in inputs):
        raise ValueError("inputs have different units")
    n = float(len(xs))
    total = 0.0
    for x in xs:
        total += x
    if op == "mean":
        return total / n, unit
    if op == "sum":
        return total, unit
    if op == "count":
        return n, "1"
    if op == "min":
        return min(xs), unit
    if op == "max":
        return max(xs), unit
    if op == "median":
        s, k = sorted(xs), len(xs) // 2
        return (s[k] if len(s) % 2 else (s[k - 1] + s[k]) / 2.0), unit
    if op == "stddev":
        m = total / n
        ss = 0.0
        for x in xs:
            ss += (x - m) * (x - m)
        return math.sqrt(ss / (n - 1.0)), unit
    if op == "linear":
        return params["a"] * xs[0] + params["b"], params.get("unit", unit)
    if op == "convert":
        a = affine(unit, params["to"])
        if a is None:
            raise ValueError(f"no conversion from {unit} to {params['to']}")
        return a[0] * xs[0] + a[1], params["to"]
    raise ValueError(f"unknown operation {op}")
