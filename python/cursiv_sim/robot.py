"""A simulated research robot's evidence side: it signs every record it writes, keeps a
durable local log (its outbox), and synchronizes with the bridge when the link is up.

This is the part a real robot would run. Navigation, motion and safety are not here,
and nothing the bridge sends can command the robot: the only replies it reads are
acceptance results and the bridge's record count/head.
"""
from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .client import BridgeClient, LinkDown
from .identity import CHECKPOINT_TYPE, RECORD_TYPE, Identity, merkle_root, payload_hash

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

    def record(self, observation: dict) -> dict:
        rec = {"schema": "cursiv-record-1", "robot_id": self.robot_id, "seq": len(self.envelopes) + 1,
               "prev": self.hashes[-1] if self.hashes else "genesis", "written_time": utc(datetime.now(timezone.utc)),
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
