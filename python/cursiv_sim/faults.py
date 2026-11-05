"""The 15 required fault scenarios, end to end against the real bridge binary and the
independent verifier CLI. Writes a machine-readable result file.

    python -m cursiv_sim.faults [--out runs/faults]

Integrity faults must be DETECTED; scientific faults must be FLAGGED (never "fixed");
operational faults must be RECOVERED from without losing or duplicating records.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import threading
import time
from pathlib import Path

from .identity import Identity, sha256_hex
from .lab import Lab
from .robot import RobotAgent
from .rovers import ROVERS
from .world import Site, png

RESULTS: list[dict] = []


def scenario(n: int, name: str, kind: str):
    def wrap(fn):
        def run(*a):
            t0 = time.perf_counter()
            try:
                observed, passed = fn(*a)
            except Exception as e:  # a scenario crashing is a failure, recorded as such
                observed, passed = f"{type(e).__name__}: {e}", False
            RESULTS.append({"id": n, "scenario": name, "kind": kind, "passed": passed, "observed": observed,
                            "seconds": round(time.perf_counter() - t0, 3)})
            print(f"  {'PASS' if passed else 'FAIL'}  {n:>2}. {name}: {observed}", flush=True)
        return run
    return wrap


def errors(rep: dict) -> set[str]:
    return {f["code"] for f in rep["verification"]["findings"] if f["severity"] == "error"}


def first(d: dict) -> dict:
    """The outcome of a single-record submission ({"accepted", "results": [outcome]})."""
    return (d.get("results") or [d])[0]


def v(rep: dict, key: str) -> str:
    return rep["verification"]["verdicts"][key].split(":")[0]


def edit_record(pkg: Path, robot: str, index: int, mutate) -> None:
    f = pkg / f"robots/{robot}/records.jsonl"
    lines = f.read_text().splitlines()
    env = json.loads(lines[index])
    rec = json.loads(env["payload"])
    mutate(rec)
    env["payload"] = json.dumps(rec, separators=(",", ":"), sort_keys=True)
    lines[index] = json.dumps(env)
    f.write_text("\n".join(lines) + "\n")


class Fleet:
    def __init__(self, lab: Lab, mission="fault-suite"):
        self.site = Site(seed=11)
        self.rovers = {rid: cls(RobotAgent(rid, lab.robot_state, lab.client, mission_id=mission), self.site) for rid, cls in ROVERS.items()}

    def run(self, steps: int, start: int = 0, total: int = 40, sync_every: int = 5):
        for i in range(start, start + steps):
            for r in self.rovers.values():
                r.step(i, total)
            if i % sync_every == sync_every - 1:
                for r in self.rovers.values():
                    r.agent.sync()
        for r in self.rovers.values():
            r.agent.sync()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="runs/faults")
    a = ap.parse_args(argv)
    out = Path(a.out)
    if out.exists():
        shutil.rmtree(out)
    lab = Lab(out / "main", list(ROVERS))
    lab.enrol()
    lab.start()
    fleet = Fleet(lab)
    fleet.run(12)
    base = lab.export("baseline")
    code, rep = lab.verify(base)
    print(f"baseline package: exit {code}; " + ", ".join(f"{k}={v(rep, k)}" for k in rep["verification"]["verdicts"]))
    assert code == 0, rep["verification"]["findings"][:5]

    @scenario(1, "Altered measurement", "integrity")
    def s1():
        p = lab.copy_package(base, "s1")
        edit_record(p, "rover-01", 5, lambda r: r["observation"]["measurement"].__setitem__("value", 99.9))
        code, rep = lab.verify(p)
        return f"exit {code}; integrity={v(rep, 'integrity')}; {sorted(errors(rep) & {'record_signature', 'chain', 'file_changed'})}", \
            code == 1 and "record_signature" in errors(rep)

    @scenario(2, "Modified evidence attachment", "integrity")
    def s2():
        p = lab.copy_package(base, "s2")
        blob = sorted((p / "blobs/sha256").iterdir())[0]
        data = bytearray(blob.read_bytes())
        data[-20] ^= 0xFF
        blob.write_bytes(bytes(data))
        code, rep = lab.verify(p)
        return f"exit {code}; attachments={v(rep, 'attachments')}; {sorted(errors(rep) & {'attachment_changed'})}", \
            code == 1 and "attachment_changed" in errors(rep)

    @scenario(3, "Missing observation", "integrity")
    def s3():
        p = lab.copy_package(base, "s3")
        f = p / "robots/rover-02/records.jsonl"
        lines = f.read_text().splitlines()
        f.write_text("\n".join(lines[:-1]) + "\n")          # drop the LAST record: chain still links
        code, rep = lab.verify(p)
        return f"exit {code}; completeness={v(rep, 'completeness')}; {sorted(errors(rep) & {'records_missing', 'station_count_mismatch'})}", \
            code == 1 and "records_missing" in errors(rep)

    @scenario(4, "Duplicate observation", "operational")
    def s4():
        g = fleet.rovers["rover-02"].agent
        st1, d1, _ = lab.client.submit([g.envelopes[3]]); d1 = first(d1)
        obs = json.loads(g.envelopes[3]["payload"])["observation"]
        clone = dict(obs, sensor_time=g.sensor_now())
        st2, d2, _ = lab.client.submit([g.record(clone)])     # new record reusing an observation_id
        d2 = first(d2)
        g.envelopes.pop(); g.hashes.pop()
        g.log_path.write_text("".join(json.dumps(e) + "\n" for e in g.envelopes))
        return f"resend -> {st1} {d1.get('status')}; reused observation_id -> {st2} {d2.get('code')}", \
            st1 == 200 and d1.get("status") == "duplicate" and st2 == 409 and d2.get("code") == "duplicate_observation_id"

    # A second lab for the science and operational scenarios, so the baseline stays clean.
    lab2 = Lab(out / "ops", list(ROVERS))
    lab2.enrol()
    lab2.start()
    f2 = Fleet(lab2, "fault-suite-ops")
    f2.rovers["rover-02"].agent.clock_drift_s_per_obs = 7.0        # 6: fast sensor clock
    f2.rovers["rover-03"].bias["air_temperature"] = 3.5             # 8: biased thermometer
    f2.run(8)
    r1 = f2.rovers["rover-01"]
    lat, lon = f2.site.point(3, 40, 0)
    late = r1.agent.observation("soil_temperature", sensor={"sensor_id": "rover-01-thermistor", "sensor_type": "thermistor", "model": "sim-1",
                                "calibration": None}, value=11.9, unit="degC", uncertainty=0.1, lat=lat, lon=lon,
                                sensor_time="2026-01-01T00:00:00.000Z")                  # 5: time goes backwards
    r1.agent.record(late)
    f2.run(6, start=8)

    @scenario(7, "Robot communication failure", "operational")
    def s7():
        g = f2.rovers["rover-01"].agent
        before = lab2.client.get("/v1/robots/rover-01/head")[1]["count"]
        g.link_up = False
        for i in range(14, 20):
            f2.rovers["rover-01"].step(i, 40)
        off = g.sync()
        during = lab2.client.get("/v1/robots/rover-01/head")[1]["count"]
        g.link_up = True
        g.sync()
        after = lab2.client.get("/v1/robots/rover-01/head")[1]["count"]
        return f"bridge {before} -> {during} while offline ({off['pending']} queued on robot) -> {after} after reconnect", \
            during == before and after == len(g.envelopes) and off["pending"] == 18

    @scenario(9, "Interrupted evidence transfer", "operational")
    def s9():
        img = png(64, 64, seed=999)
        sha = sha256_hex(img)
        s = socket.create_connection(("127.0.0.1", lab2.port))
        s.sendall(f"PUT /v1/attachments/{sha} HTTP/1.1\r\nHost: 127.0.0.1:{lab2.port}\r\nContent-Length: {len(img)}\r\n\r\n".encode() + img[: len(img) // 2])
        s.shutdown(socket.SHUT_WR)
        reply = s.recv(4096).decode(errors="replace").split("\r\n")[0]
        s.close()
        present = lab2.client.get(f"/v1/attachments/{sha}")[0]
        st, _ = lab2.client.put_attachment(img, sha)
        return f"cut-off upload -> '{reply}', blob present: {present == 200}; full retry -> {st}", \
            present == 404 and st == 201

    @scenario(12, "Invalid or untrusted signing key", "authenticity")
    def s12():
        impostor = Identity.generate()
        g = f2.rovers["rover-02"].agent
        rec = json.loads(g.envelopes[-1]["payload"])
        rec = dict(rec, seq=len(g.envelopes) + 1, prev=g.hashes[-1])
        st, d, _ = lab2.client.submit([impostor.sign(rec)]); d = first(d)
        bad = dict(g.envelopes[-1], signature=g.envelopes[-2]["signature"])
        st2, d2, _ = lab2.client.submit([bad]); d2 = first(d2)
        incidents = (lab2.dir / "store/incidents.jsonl").read_text()
        return f"impostor key -> {st} {d.get('code')}; forged signature -> {st2} {d2.get('code')}; logged: {'untrusted_key' in incidents}", \
            st == 403 and d.get("code") == "untrusted_key" and st2 == 400 and "untrusted_key" in incidents

    @scenario(13, "Partial synchronization", "operational")
    def s13():
        g = f2.rovers["rover-02"].agent
        g.link_up = False
        for i in range(14, 30):
            f2.rovers["rover-02"].step(i, 40)
        g.link_up = True
        r = g.sync(batch=7, fail_after=20)
        mid = lab2.client.get("/v1/robots/rover-02/head")[1]["count"]
        g.link_up = True
        g.sync(batch=7)
        end = lab2.client.get("/v1/robots/rover-02/head")[1]["count"]
        return f"transfer dropped after 20 -> bridge {mid}/{len(g.envelopes)}; resumed -> {end}/{len(g.envelopes)}", \
            r["link"] == "lost" and mid < len(g.envelopes) and end == len(g.envelopes)

    @scenario(14, "Unexpected robot restart (and station power cut)", "operational")
    def s14():
        rid = "rover-03"
        old = f2.rovers[rid].agent
        n_before = len(old.envelopes)
        fresh = RobotAgent(rid, lab2.robot_state, lab2.client, mission_id="fault-suite-ops")   # process restarted from disk
        f2.rovers[rid].agent = fresh
        for i in range(14, 18):
            f2.rovers[rid].step(i, 40)
        fresh.sync()
        resumed = lab2.client.get(f"/v1/robots/{rid}/head")[1]["count"]
        # lost state: same key, empty log -> a second history
        amnesia_dir = lab2.dir / "amnesia"
        (amnesia_dir / rid).mkdir(parents=True)
        shutil.copy(lab2.robot_state / rid / "robot.key", amnesia_dir / rid / "robot.key")
        amnesiac = RobotAgent(rid, amnesia_dir, lab2.client, mission_id="fault-suite-ops")
        amnesiac.record(amnesiac.observation("air_temperature", sensor={"sensor_id": "rover-03-thermo", "sensor_type": "thermistor", "model": "sim-1", "calibration": None},
                                             value=16.0, unit="degC", uncertainty=0.2, lat=45.1, lon=-122.2))
        try:
            amnesiac.sync()
            refused_by_robot = False
        except RuntimeError:
            refused_by_robot = True
        st, d, _ = lab2.client.submit(amnesiac.envelopes); d = first(d)
        # station power cut during a burst, then restart
        g = f2.rovers["rover-01"].agent
        for i in range(20, 60):
            f2.rovers["rover-01"].step(i, 60)
        t = threading.Thread(target=lambda: g.sync(batch=5))
        t.start()
        time.sleep(0.05)
        lab2.kill()
        t.join()
        lab2.start()
        g.link_up = True
        g.sync()
        count = lab2.client.get("/v1/robots/rover-01/head")[1]["count"]
        return (f"restarted robot resumed at {n_before + 1} -> bridge {resumed}; lost-state fork refused by robot: {refused_by_robot}, "
                f"by bridge: {st} {d.get('code')}; after station kill -9 + restart rover-01 {count}/{len(g.envelopes)}"), \
            resumed == len(fresh.envelopes) and refused_by_robot and d.get("code") == "equivocation" and count == len(g.envelopes)

    @scenario(15, "High-volume data burst", "operational")
    def s15():
        lab3 = Lab(out / "burst", [f"burst-{i:02d}" for i in range(10)], queue=4, workers=8)
        lab3.enrol()
        lab3.start()
        agents = [RobotAgent(rid, lab3.robot_state, lab3.client, mission_id="burst") for rid in lab3.robot_ids]
        sensor = {"sensor_id": "s1", "sensor_type": "rtd", "model": "sim-1", "calibration": None}
        per = 2000
        for g in agents:
            sensor["sensor_id"] = f"{g.robot_id}-s1"
            for k in range(per):
                g.record(g.observation("air_temperature", sensor=dict(sensor), value=15 + k * 1e-3, unit="degC", uncertainty=0.2, lat=45.1, lon=-122.2))
        retries = []
        def push(g):
            for i in range(0, per, 250):
                _, _, attempt = lab3.client.submit(g.envelopes[i:i + 250])
                retries.append(attempt)
        t0 = time.perf_counter()
        ts = [threading.Thread(target=push, args=(g,)) for g in agents]
        [t.start() for t in ts]
        [t.join() for t in ts]
        dt = time.perf_counter() - t0
        counts = [lab3.client.get(f"/v1/robots/{g.robot_id}/head")[1]["count"] for g in agents]
        lab3.stop()
        return f"{len(agents)} robots x {per} records in {dt:.2f}s ({len(agents) * per / dt:.0f} records/s); 503 retries: {sum(retries)}; stored {sum(counts)}", \
            all(c == per for c in counts)

    for fn in (s1, s2, s3, s4, s7, s9, s12, s13, s14, s15):
        fn()

    # Package-level checks on the operations lab after everything above.
    ops_pkg = lab2.export("ops-final")
    code, rep = lab2.verify(ops_pkg)
    sci = rep["science"]["counts"]

    @scenario(5, "Out-of-order timestamp", "science")
    def s5():
        return f"out_of_order_time flags: {sci.get('out_of_order_time', 0)} (integrity={v(rep, 'integrity')})", \
            sci.get("out_of_order_time", 0) >= 1 and v(rep, "integrity") == "pass"

    @scenario(6, "Sensor clock drift", "science")
    def s6():
        f = [x for x in rep["science"]["flags"] if x["code"] == "clock_drift"]
        return f"clock_drift flags: {[x['robot_id'] for x in f]}", any(x["robot_id"] == "rover-02" for x in f)

    @scenario(8, "Contradictory measurements", "science")
    def s8():
        groups = sorted({x["group"] for x in rep["science"]["flags"] if x["code"] == "contradiction"})
        return f"contradiction groups: {groups}", any("rover-03-thermo" in g for g in groups)

    @scenario(10, "Corrupted export", "integrity")
    def s10():
        p = lab.copy_package(base, "s10")
        f = p / "receipts.jsonl"
        f.write_bytes(f.read_bytes()[:-57])
        code, r = lab.verify(p)
        return f"exit {code}; integrity={v(r, 'integrity')}; {sorted(errors(r) & {'truncated_file', 'file_changed', 'receipts_mismatch'})}", \
            code == 1 and v(r, "integrity") == "fail"

    @scenario(11, "Rebuilt hash chain", "authenticity")
    def s11():
        p = lab.copy_package(base, "s11")
        attacker = Identity.generate()
        f = p / "robots/rover-01/records.jsonl"
        prev, out_lines = "genesis", []
        for line in f.read_text().splitlines():
            rec = json.loads(json.loads(line)["payload"])
            rec["prev"] = prev
            if rec["seq"] == 3:
                rec["observation"]["measurement"]["value"] = 55.5
            env = attacker.sign(rec)
            prev = sha256_hex(env["payload"].encode())
            out_lines.append(json.dumps(env))
        f.write_text("\n".join(out_lines) + "\n")
        (p / "robots/rover-01/checkpoints.jsonl").unlink()
        m = json.loads((p / "manifest.json").read_text())
        body = json.loads(m["payload"])
        body["files"].pop("robots/rover-01/checkpoints.jsonl", None)
        for name in body["files"]:
            b = (p / name).read_bytes()
            body["files"][name] = {"sha256": sha256_hex(b), "size": len(b)}
        (p / "manifest.json").write_text(json.dumps(attacker.sign(body)))
        code, r = lab.verify(p)
        code_nt, r_nt = lab.verify(p, trust=False)
        return (f"with trust store: exit {code}, authenticity={v(r, 'authenticity')}; without: exit {code_nt}, "
                f"authenticity={v(r_nt, 'authenticity')}, integrity={v(r_nt, 'integrity')}"), \
            code == 1 and v(r, "authenticity") == "fail" and code_nt == 1 and v(r_nt, "authenticity") == "not_assessed"

    for fn in (s5, s6, s8, s10, s11):
        fn()
    lab.stop()
    lab2.stop()
    RESULTS.sort(key=lambda r: r["id"])
    passed = sum(r["passed"] for r in RESULTS)
    (out / "fault-results.json").write_text(json.dumps({"synthetic": True, "passed": passed, "total": len(RESULTS),
                                                        "results": RESULTS}, indent=2))
    print(f"\n{passed}/{len(RESULTS)} scenarios passed. Results: {out / 'fault-results.json'}")
    return 0 if passed == len(RESULTS) else 1


if __name__ == "__main__":
    raise SystemExit(main())
