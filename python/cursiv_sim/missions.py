"""Deterministic virtual research missions: buoys, underwater vehicles, aerial drones, ground
rovers, alone or together, with seeded fault injection. EVERY measurement is SYNTHETIC.

    py -m cursiv_sim.missions run ../missions/coastal-survey.json [--out ../runs/missions] [--check]

Reproducible by construction: one seed drives every random choice, time comes from a simulated
mission clock (not the wall clock), observation ids are sequential and simulation keys are
derived from the seed. The same mission file therefore produces the same signed records, down to
each robot's chain head, and `--check` compares a run with the mission's expected results.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import random
import shutil
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .identity import Identity, body_json, sha256_hex
from .lab import Lab, binary
from .robot import RobotAgent
from .world import png

SOFTWARE = "cursiv-sim-missions"
PROFILE = {
    "name": "virtual-lab-1",
    "types": {
        "water_temperature": {"unit": "degC", "min": -2, "max": 35, "requires_attachment": False, "compare_radius_m": 1500, "compare_window_s": 300, "expected_interval_s": 60, "compare_vertical_m": 1.0},
        "conductivity": {"unit": "mS/cm", "min": 0, "max": 70, "requires_attachment": False, "compare_radius_m": None, "compare_window_s": None, "expected_interval_s": None},
        "salinity": {"unit": "PSU", "min": 0, "max": 42, "requires_attachment": False, "compare_radius_m": None, "compare_window_s": None, "expected_interval_s": None},
        "dissolved_oxygen": {"unit": "mg/L", "min": 0, "max": 20, "requires_attachment": False, "compare_radius_m": None, "compare_window_s": None, "expected_interval_s": None},
        "depth": {"unit": "m", "min": -1, "max": 6000, "requires_attachment": False, "compare_radius_m": None, "compare_window_s": None, "expected_interval_s": None},
        "air_temperature": {"unit": "degC", "min": -90, "max": 60, "requires_attachment": False, "compare_radius_m": None, "compare_window_s": None, "expected_interval_s": None},
        "relative_humidity": {"unit": "%", "min": 0, "max": 100, "requires_attachment": False, "compare_radius_m": None, "compare_window_s": None, "expected_interval_s": None},
        "air_pressure": {"unit": "hPa", "min": 300, "max": 1100, "requires_attachment": False, "compare_radius_m": None, "compare_window_s": None, "expected_interval_s": None},
        "altitude": {"unit": "m", "min": -10, "max": 500, "requires_attachment": False, "compare_radius_m": None, "compare_window_s": None, "expected_interval_s": None},
        "soil_moisture": {"unit": "%", "min": 0, "max": 100, "requires_attachment": False, "compare_radius_m": None, "compare_window_s": None, "expected_interval_s": None},
        "image": {"unit": "", "min": None, "max": None, "requires_attachment": True, "compare_radius_m": None, "compare_window_s": None, "expected_interval_s": None},
    },
    "region": None,
    "max_clock_offset_s": 120.0,
    "contradiction_sigma": 3.0,
    "check_clock_against_receipts": False,   # simulated mission clock, delivered later
}
# sensor specifications: (unit, standard uncertainty, sensor type)
SPECS = {
    "water_temperature": ("degC", 0.05, "thermistor"), "conductivity": ("mS/cm", 0.1, "conductivity_cell"),
    "salinity": ("PSU", 0.05, "derived_ctd"), "dissolved_oxygen": ("mg/L", 0.15, "optode"), "depth": ("m", 0.2, "pressure_transducer"),
    "air_temperature": ("degC", 0.2, "rtd"), "relative_humidity": ("%", 2.0, "capacitive_rh"), "air_pressure": ("hPa", 0.1, "barometer"),
    "altitude": ("m", 1.5, "barometric_altimeter"), "soil_moisture": ("%", 1.0, "tdr_probe"),
}


def utc(t: datetime) -> str:
    return t.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def parse(s: str) -> datetime:
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def move(lat, lon, heading_deg, metres):
    d = metres / 6_371_000.0
    h = math.radians(heading_deg)
    return (lat + math.degrees(d * math.cos(h)), lon + math.degrees(d * math.sin(h) / math.cos(math.radians(lat))))


class Platform:
    """One simulated vehicle or station. `sample(t)` returns [(type, value, location, attachment)]."""

    def __init__(self, spec: dict, mission: dict, rng: random.Random):
        self.spec, self.mission, self.rng = spec, mission, rng
        self.id, self.kind = spec["robot_id"], spec["kind"]
        self.lat, self.lon = spec["start"]
        self.last_fix_s = 0.0
        self.calibration = {s: {"calibrated_utc": "2026-01-15T00:00:00Z", "valid_until_utc": "2027-01-15T00:00:00Z",
                                "reference": "simulated bench calibration", "certificate_sha256": None} for s in spec["sensors"]}

    def sensors(self):
        return self.spec["sensors"]

    def link_up(self, t: float) -> bool:
        return True

    def location(self, t: float):
        return {"lat": round(self.lat, 7), "lon": round(self.lon, 7), "alt_m": None, "crs": "EPSG:4326",
                "horizontal_accuracy_m": 2.5, "source": "simulated"}

    def step(self, t: float, dt: float):
        pass

    def truth(self, sensor: str, t: float) -> float:
        h = (self.mission["_start"] + timedelta(seconds=t)).hour + t / 3600.0 % 1
        return {"water_temperature": 14.0 + 1.2 * math.sin(2 * math.pi * (h - 9) / 24), "conductivity": 44.5, "salinity": 33.2,
                "dissolved_oxygen": 8.1 - 0.02 * t / 60, "air_temperature": 16.5 + 2.0 * math.sin(2 * math.pi * (h - 9) / 24),
                "relative_humidity": 72.0, "air_pressure": 1013.2 - 0.0002 * t, "soil_moisture": 23.0, "depth": 0.0, "altitude": 0.0}[sensor]


class Stationary(Platform):
    """A moored buoy or weather mast: fixed position, regular cadence, always connected."""

    def location(self, t):
        loc = super().location(t)
        loc["alt_m"] = 0.0
        return loc


class Ground(Platform):
    def step(self, t, dt):
        self.lat, self.lon = move(self.lat, self.lon, self.spec.get("heading_deg", 45), self.spec.get("speed_mps", 0.5) * dt)


class Underwater(Platform):
    """An AUV: dives and surfaces on a cycle. No GNSS or radio under water: position is dead
    reckoning with growing uncertainty, and it can only deliver records while surfaced."""

    def surfaced(self, t):
        cycle = self.spec.get("surface_every_s", 900)
        return (t % cycle) < self.spec.get("surface_for_s", 120)

    def depth(self, t):
        return 0.0 if self.surfaced(t) else self.spec.get("max_depth_m", 40) * abs(math.sin(math.pi * (t % 900) / 900))

    def step(self, t, dt):
        self.lat, self.lon = move(self.lat, self.lon, self.spec.get("heading_deg", 90), self.spec.get("speed_mps", 1.2) * dt)
        if self.surfaced(t):
            self.last_fix_s = t

    def link_up(self, t):
        return self.surfaced(t)

    def location(self, t):
        loc = super().location(t)
        loc["alt_m"] = round(-self.depth(t), 2)       # below the surface
        if not self.surfaced(t):
            loc.update(source="dead_reckoning", horizontal_accuracy_m=round(2.5 + 0.03 * (t - self.last_fix_s), 2))
        return loc

    def truth(self, sensor, t):
        d = self.depth(t)
        if sensor == "depth":
            return d
        if sensor == "water_temperature":
            return super().truth(sensor, t) - 0.12 * d    # same water as the buoy at the surface; thermocline below
        if sensor == "salinity":
            return 33.0 + 0.01 * d
        return super().truth(sensor, t)


class Aerial(Platform):
    """A survey drone: climbs, flies a line, lands; air temperature follows the lapse rate."""

    def altitude(self, t):
        flight, alt = self.spec.get("flight_s", 1200), self.spec.get("altitude_m", 80)
        if t > flight:
            return 0.0
        return alt * min(1.0, t / 60.0, (flight - t) / 60.0)

    def step(self, t, dt):
        if t <= self.spec.get("flight_s", 1200):
            self.lat, self.lon = move(self.lat, self.lon, self.spec.get("heading_deg", 0), self.spec.get("speed_mps", 8.0) * dt)

    def location(self, t):
        loc = super().location(t)
        loc["alt_m"] = round(self.altitude(t), 2)
        return loc

    def truth(self, sensor, t):
        if sensor == "altitude":
            return self.altitude(t)
        if sensor == "air_temperature":
            return super().truth(sensor, t) - 0.0065 * self.altitude(t)
        return super().truth(sensor, t)


KINDS = {"stationary": Stationary, "ground": Ground, "underwater": Underwater, "aerial": Aerial}


class Mission:
    def __init__(self, cfg: dict, out: Path):
        self.cfg, self.out = cfg, out
        cfg["_start"] = parse(cfg["start_utc"])
        self.rng = random.Random(cfg["seed"])
        self.events: list[str] = []
        self.counters = {"duplicate_sends": 0, "duplicates_acknowledged": 0, "corrupt_uploads_rejected": 0, "packet_losses": 0,
                         "station_full_refusals": 0, "robot_restarts": 0, "station_crashes": 0}

    def fault(self, kind, robot=None):
        return [f for f in self.cfg.get("faults", []) if f["kind"] == kind and (robot is None or f.get("robot") in (None, robot))]

    def run(self) -> dict:
        cfg = self.cfg
        if self.out.exists():
            shutil.rmtree(self.out)
        ids = [p["robot_id"] for p in cfg["platforms"]] + ["analysis-01"]
        lab = Lab(self.out, ids, station_id="virtual-station")
        for rid in ids:   # SIMULATION keys derived from the seed, so the mission is reproducible
            Identity.from_seed(f"{cfg['seed']}:{cfg['mission_id']}:{rid}".encode()).save(lab.robot_state / rid / "robot.key")
        lab.enrol()
        lab.start()
        plats = {p["robot_id"]: KINDS[p["kind"]](p, cfg, random.Random(f"{cfg['seed']}:{p['robot_id']}")) for p in cfg["platforms"]}
        agents = {rid: RobotAgent(rid, lab.robot_state, lab.client, mission_id=cfg["mission_id"]) for rid in plats}
        for f in self.fault("expired_calibration"):
            plats[f["robot"]].calibration[f["sensor"]]["valid_until_utc"] = "2026-03-01T00:00:00Z"
        seq = {rid: 0 for rid in plats}
        clock_offset = {rid: 0.0 for rid in plats}
        recorded = {rid: [] for rid in plats}
        duration, tick = cfg["duration_s"], cfg.get("tick_s", 10)
        quota_on = False
        try:
            t = 0.0
            while t <= duration:
                for f in self.fault("storage_exhaustion"):
                    if not quota_on and t >= f["at_s"] and t < f["until_s"]:
                        used = sum(x.stat().st_size for x in (self.out / "store").rglob("*") if x.is_file())
                        lab.stop()
                        lab.extra_args = ["--max-store-bytes", str(used + f["headroom_bytes"])]
                        lab.start()
                        quota_on = True
                        self.events.append(f"t={t:.0f}s station storage limited to {f['headroom_bytes']} more bytes")
                    elif quota_on and t >= f["until_s"]:
                        lab.stop()
                        lab.extra_args = []
                        lab.start()
                        quota_on = False
                        self.events.append(f"t={t:.0f}s station storage freed")
                for f in self.fault("station_crash"):
                    if abs(t - f["at_s"]) < tick / 2:
                        lab.kill()
                        lab.start()
                        self.counters["station_crashes"] += 1
                        self.events.append(f"t={t:.0f}s station killed and restarted")
                for rid, plat in plats.items():
                    g = agents[rid]
                    plat.step(t, tick)
                    for f in self.fault("clock_step", rid):
                        if abs(t - f["at_s"]) < tick / 2:
                            clock_offset[rid] += f["offset_s"]
                            self.events.append(f"t={t:.0f}s {rid} clock jumps {f['offset_s']:+.0f} s")
                    for f in self.fault("shutdown", rid):
                        if abs(t - f["at_s"]) < tick / 2:
                            agents[rid] = g = RobotAgent(rid, lab.robot_state, lab.client, mission_id=cfg["mission_id"])
                            self.counters["robot_restarts"] += 1
                            self.events.append(f"t={t:.0f}s {rid} restarted unexpectedly (state reloaded from its log)")
                    if t % plat.spec.get("interval_s", 60) < tick / 2:
                        self.sample(plat, g, t, clock_offset[rid], seq, recorded)
                    if t % plat.spec.get("sync_every_s", 60) < tick / 2 or t + tick > duration:
                        self.deliver(plat, g, t, rid)
                t += tick
            for rid, g in agents.items():      # end of mission: everyone surfaces / lands / reconnects
                for _ in range(20):
                    r = g.sync(batch=200)
                    if r.get("link") == "up":
                        break
                    g.link_up = True
            stats = self.summarize(agents, lab)
            name = f"{cfg['mission_id']}-package"
            pkg = lab.export(name)
            profile = self.out / "profile.json"
            profile.write_text(json.dumps(PROFILE, indent=2))
            import subprocess
            outp = subprocess.run([str(binary("cursiv-verify")), "package", str(pkg), "--trust", str(lab.trust_path), "--json", "--science",
                                   "--profile", str(profile)], capture_output=True, text=True)
            verification = json.loads(outp.stdout)
            result = self.result(agents, verification, outp.returncode, stats)
            (self.out / "result.json").write_text(json.dumps(result, indent=2))
            report = write_report(self.out, cfg, pkg, verification, stats, self.events, result)
            result["report"] = str(report)
            result["package"], result["trust"] = str(pkg), str(lab.trust_path)
            return result
        finally:
            lab.stop()

    def sample(self, plat, g, t, offset, seq, recorded):
        rid = plat.id
        if any(f["from_s"] <= t < f["until_s"] for f in self.fault("sensor_dropout", rid)):
            return        # the sensors produce nothing in this window (cable fault, brown-out)
        when = self.cfg["_start"] + timedelta(seconds=t + offset)
        for s in plat.sensors():
            if s == "image":
                img = png(32, 24, seed=int(t) + int(hashlib.sha256(rid.encode()).hexdigest()[:6], 16))
                sha = sha256_hex(img)
                if self.upload(g, plat, img, sha, t):
                    o = g.observation("image", sensor=self.sensor(rid, s, plat), sensor_time=utc(when), attachments=[
                        {"sha256": sha, "size": len(img), "media_type": "image/png", "role": "raw"}])
                    self.record(g, o, plat, t, seq, recorded)
                continue
            unit, u, _ = SPECS[s]
            v = plat.truth(s, t) + plat.rng.gauss(0, u)
            for f in self.fault("sensor_drift", rid):
                if f["sensor"] == s and t >= f["from_s"]:
                    v += f["rate_per_h"] * (t - f["from_s"]) / 3600.0
            o = g.observation(s, sensor=self.sensor(rid, s, plat), value=round(v, 4), unit=unit, uncertainty=u, sensor_time=utc(when))
            self.record(g, o, plat, t, seq, recorded)
            for f in self.fault("duplicate_reading", rid):
                if seq[rid] % f["every"] == 0:      # the same reading recorded twice under different ids (firmware bug)
                    dup = dict(o)
                    self.record(g, dup, plat, t, seq, recorded)

    def sensor(self, rid, s, plat):
        unit, u, typ = SPECS.get(s, ("", None, "rgb_camera"))
        return {"sensor_id": f"{rid}-{s.replace('_', '-')}", "sensor_type": typ, "model": "sim-1",
                "calibration": dict(plat.calibration[s]) if s in plat.calibration else None}

    def record(self, g, o, plat, t, seq, recorded):
        seq[plat.id] += 1
        o = dict(o, observation_id=f"{plat.id}-{seq[plat.id]:06d}", location=plat.location(t))
        o["quality"] = {"flag": "unassessed", "basis": "simulated sensor"}
        rec_env = g.record(o, written_time=o["sensor_time"])   # the robot's (simulated) clock
        recorded[plat.id].append(rec_env)

    def upload(self, g, plat, data, sha, t) -> bool:
        if not plat.link_up(t):
            return False        # images are only taken while the link can carry them
        for f in self.fault("corrupt_upload", plat.id):
            if plat.rng.random() < f["probability"]:
                bad = bytearray(data)
                bad[len(bad) // 2] ^= 0xFF
                st, _ = g.client.put_attachment(bytes(bad), sha)
                if st == 400:
                    self.counters["corrupt_uploads_rejected"] += 1
        st, _ = g.client.put_attachment(data, sha)
        return st in (200, 201)

    def deliver(self, plat, g, t, rid):
        if not plat.link_up(t):
            g.link_up = False
            return
        lost = any(plat.rng.random() < f["probability"] for f in self.fault("packet_loss", rid))
        if lost:
            self.counters["packet_losses"] += 1
            g.link_up = False
            return
        g.link_up = True
        for f in self.fault("duplicate_send", rid):
            if g.acked and len(g.envelopes) % f["every"] == 0:   # resend something already delivered
                self.counters["duplicate_sends"] += 1
                st, data, _ = g.client.submit([g.envelopes[g.acked - 1]])
                if st == 200:
                    self.counters["duplicates_acknowledged"] += 1
        r = g.sync(batch=200)
        if r.get("link") == "station_full":
            self.counters["station_full_refusals"] += 1

    def summarize(self, agents, lab):
        analyst = RobotAgent("analysis-01", lab.robot_state, lab.client, mission_id=self.cfg["mission_id"])
        stats = {}
        for rid, g in agents.items():
            groups = {}
            for e in g.envelopes:
                o = body_json(e)["observation"]
                if (o.get("measurement") or {}).get("value") is not None:
                    groups.setdefault(o["observation_type"], []).append(e)
            for ty, envs in sorted(groups.items()):
                d = analyst.derive("mean", envs, observation_type=f"{ty}_mean")
                o = body_json(d)["observation"]
                stats[f"{rid} {ty}"] = {"n": len(envs), "mean": o["measurement"]["value"], "unit": o["measurement"]["unit"],
                                        "u": (o["measurement"]["uncertainty"] or {}).get("value"), "id": f"analysis-01/{o['observation_id']}",
                                        "inputs": [f"{rid}/{body_json(e)['observation']['observation_id']}" for e in envs[:3]]}
        analyst.sync(batch=100)
        return stats

    def result(self, agents, v, code, stats):
        ver = v["verification"]
        return {"mission_id": self.cfg["mission_id"], "seed": self.cfg["seed"], "synthetic": True,
                "verify_exit": code, "verdicts": {k: x.split(":")[0] for k, x in ver["verdicts"].items()},
                "records": {rid: x["records"] for rid, x in ver["robots"].items()},
                "heads": {rid: x["head"] for rid, x in ver["robots"].items() if rid != "analysis-01"},
                "science_counts": v["science"]["counts"], "derivations": v["reasoning"]["derivations"], "counters": self.counters}


def write_report(out: Path, cfg: dict, pkg: Path, v: dict, stats: dict, events: list[str], result: dict) -> Path:
    """Research summary with a citation for every number; anomalies listed with their evidence."""
    from cursiv_field.dossier import to_html, to_pdf
    sci, rsn, ver = v["science"], v["reasoning"], v["verification"]
    md = [f"# Mission report: {cfg['mission_id']}", "",
          f"> **SYNTHETIC DATA.** Every measurement in this report was produced by the Cursiv virtual lab (seed {cfg['seed']}). It is not real-world evidence and shows nothing about physical hardware.", "",
          f"{cfg.get('description', '')}", "", "## Verification", "", "| Question | Result |", "|---|---|"]
    md += [f"| {k} | {x.split(':')[0]} |" for k, x in ver["verdicts"].items()]
    d = rsn["derivations"]
    md += ["", f"Derived results recomputed independently: {d['verified']} match, {d['mismatch']} mismatch; propagated uncertainties confirmed: {d.get('uncertainty_verified', 0)}.", "",
           "## Platforms", "", "| Platform | Kind | Records | Sensors |", "|---|---|---|---|"]
    for p in cfg["platforms"]:
        md.append(f"| {p['robot_id']} | {p['kind']} | {ver['robots'].get(p['robot_id'], {}).get('records', 0)} | {', '.join(p['sensors'])} |")
    md += ["", "## Results (each value cites its signed record)", "",
           "Each mean uses every reading in its series, including readings flagged under Anomalies (for example, an expired calibration). "
           "The uncertainty is the GUM first-order propagation of the stated per-reading uncertainties, assuming uncorrelated inputs; "
           "it does not include calibration bias or drift.", "", "| Series | n | Mean | Std. uncertainty of mean | Citation | Example inputs |", "|---|---|---|---|---|---|"]
    for k, s in stats.items():
        md.append(f"| {k} | {s['n']} | {s['mean']:.4g} {s['unit']} | {('%.2g ' % s['u']) + s['unit'] if s['u'] is not None else 'unknown'} | `{s['id']}` | {', '.join('`' + i + '`' for i in s['inputs'])} |")
    md += ["", "## Anomalies and uncertainties", ""]
    labels = {"out_of_order_time": "time went backwards (Known)", "calibration_expired": "calibration expired (Known)",
              "duplicate_content": "same reading under two ids (Known)", "contradiction": "sensors disagree (Known)",
              "clock_drift": "clock drift (Inferred)", "sampling_gap": "readings missing (Known)", "out_of_range": "outside range (Known)",
              "location_unknown": "no position (Unknown)", "sensor_time_after_write": "inconsistent clocks (Known)"}
    shown, per = 0, {}
    for f in sci["flags"]:            # up to 3 examples of each kind, each citing its records
        if f["code"] in labels and per.get(f["code"], 0) < 3:
            per[f["code"]] = per.get(f["code"], 0) + 1
            md.append(f"- **{labels[f['code']]}** `{f['code']}` ({f['robot_id']}; cites {', '.join('`' + i + '`' for i in f['observation_ids'][:2])}): {f['message']}")
            shown += 1
    if not shown:
        md.append("None flagged.")
    md += ["", "Counts: " + ", ".join(f"`{k}` {n}" for k, n in sorted(sci["counts"].items())), "",
           "## Operational events (simulated faults)", ""] + [f"- {e}" for e in events] + [
           "", "Fault counters: " + ", ".join(f"{k} {n}" for k, n in result["counters"].items()), "",
           "## Reproduce", "", f"`py -m cursiv_sim.missions run <mission file> --check` with seed {cfg['seed']} reproduces every record; chain heads:", ""]
    md += [f"- {rid}: `{h}`" for rid, h in result["heads"].items()]
    path = out / "mission-report.md"
    text = "\n".join(md) + "\n"
    path.write_text(text, encoding="utf-8")
    (out / "mission-report.html").write_text(to_html(text, f"Mission report: {cfg['mission_id']}"), encoding="utf-8")
    to_pdf(out / "mission-report.html", out / "mission-report.pdf")
    return path


def check(result: dict, expected: dict) -> list[str]:
    """Differences between a run and the mission's documented expected results."""
    problems = []
    for key in ("verdicts", "records", "heads", "derivations", "counters"):
        if key in expected and expected[key] != result[key]:
            problems.append(f"{key}: expected {expected[key]}, got {result[key]}")
    for code, n in expected.get("science_at_least", {}).items():
        if result["science_counts"].get(code, 0) < n:
            problems.append(f"science {code}: expected at least {n}, got {result['science_counts'].get(code, 0)}")
    for code in expected.get("science_absent", []):
        if result["science_counts"].get(code, 0):
            problems.append(f"science {code}: expected none, got {result['science_counts'][code]}")
    return problems


def main(argv=None) -> int:
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    ap = argparse.ArgumentParser(prog="cursiv_sim.missions")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("mission")
    r.add_argument("--out", default="../runs/missions")
    r.add_argument("--check", action="store_true", help="compare with the mission's expected results")
    r.add_argument("--update-expected", action="store_true", help="write this run's exact results into the mission's expected file")
    a = ap.parse_args(argv)
    cfg = json.loads(Path(a.mission).read_text())
    t0 = time.perf_counter()
    res = Mission(cfg, Path(a.out) / cfg["mission_id"]).run()
    print(json.dumps({k: res[k] for k in ("verdicts", "records", "derivations", "counters")}, indent=1))
    print("science:", res["science_counts"])
    print(f"report: {res['report']}  ({time.perf_counter() - t0:.1f} s)")
    exp_path = Path(a.mission).with_suffix(".expected.json")
    if a.update_expected:
        exp = json.loads(exp_path.read_text()) if exp_path.exists() else {}
        exp.update({k: res[k] for k in ("verdicts", "records", "heads", "derivations", "counters")})
        exp_path.write_text(json.dumps(exp, indent=2) + "\n")
        print("expected results written:", exp_path)
    if a.check:
        problems = check(res, json.loads(exp_path.read_text()))
        print("CHECK", "PASSED" if not problems else "FAILED")
        for p in problems:
            print("  -", p)
        return 1 if problems else 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
