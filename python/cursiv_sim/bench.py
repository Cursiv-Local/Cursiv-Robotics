"""Repeatable benchmarks. Records hardware, versions, configuration and measured results.

    python -m cursiv_sim.bench [--out bench/out] [--scales 1,3,10,100,1000]

Simulated agent counts are processes' worth of signing threads on ONE computer;
they say nothing about real robot hardware or radio links.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import statistics
import subprocess
import threading
import time
from pathlib import Path

from .identity import sha256_hex
from .lab import Lab, binary
from .robot import RobotAgent

SENSOR = {"sensor_id": "x", "sensor_type": "rtd", "model": "sim-1", "calibration": None}
PER_AGENT = {1: 5000, 3: 3000, 10: 1000, 100: 200, 1000: 20}


def proc_stats(pid: int) -> dict:
    """Peak RSS and CPU seconds of the bridge process (Linux /proc; elsewhere not measured)."""
    try:
        status = Path(f"/proc/{pid}/status").read_text()
        hwm = next(int(l.split()[1]) for l in status.splitlines() if l.startswith("VmHWM"))
        fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
        tick = os.sysconf("SC_CLK_TCK")
        return {"peak_rss_mib": round(hwm / 1024, 1), "cpu_s": round((int(fields[11]) + int(fields[12])) / tick, 2)}
    except (OSError, StopIteration, ValueError):
        return {"peak_rss_mib": None, "cpu_s": None, "note": "not measured on this platform"}


def du(p: Path) -> int:
    return sum(f.stat().st_size for f in p.rglob("*") if f.is_file())


def hardware() -> dict:
    cpu = platform.processor()
    try:
        cpu = next(l.split(":", 1)[1].strip() for l in Path("/proc/cpuinfo").read_text().splitlines() if l.startswith("model name"))
    except (OSError, StopIteration):
        pass
    mem = None
    try:
        mem = round(int(next(l.split()[1] for l in Path("/proc/meminfo").read_text().splitlines() if l.startswith("MemTotal"))) / 1024 / 1024, 1)
    except (OSError, StopIteration):
        pass
    rustc = subprocess.run(["rustc", "--version"], capture_output=True, text=True).stdout.strip()
    return {"cpu": cpu, "logical_cpus": os.cpu_count(), "memory_gib": mem, "os": platform.platform(),
            "python": platform.python_version(), "rustc": rustc, "build": "cargo --release"}


def run_scale(out: Path, n_agents: int, per: int) -> dict:
    lab = Lab(out / f"scale-{n_agents}", [f"agent-{i:04d}" for i in range(n_agents)], queue=256, workers=8)
    lab.enrol()
    lab.start()
    agents = [RobotAgent(rid, lab.robot_state, lab.client, mission_id="bench") for rid in lab.robot_ids]
    t0 = time.perf_counter()
    for g in agents:
        s = dict(SENSOR, sensor_id=f"{g.robot_id}-t")
        for k in range(per):
            g.record(g.observation("air_temperature", sensor=s, value=15 + k * 1e-3, unit="degC", uncertainty=0.2, lat=45.1, lon=-122.2))
    gen_s = time.perf_counter() - t0
    total = n_agents * per
    latencies, lock = [], threading.Lock()
    batch = 100
    queue = list(agents)

    def worker():
        while True:
            with lock:
                if not queue:
                    return
                g = queue.pop()
            for i in range(0, per, batch):
                t = time.perf_counter()
                lab.client.submit(g.envelopes[i:i + batch])
                with lock:
                    latencies.append(time.perf_counter() - t)

    threads = [threading.Thread(target=worker) for _ in range(min(32, n_agents))]
    t0 = time.perf_counter()
    [t.start() for t in threads]
    [t.join() for t in threads]
    ingest_s = time.perf_counter() - t0
    stored = sum(lab.client.get(f"/v1/robots/{g.robot_id}/head")[1]["count"] for g in agents)
    stats = proc_stats(lab.proc.pid)
    store_bytes = du(lab.dir / "store")
    payload_bytes = sum(len(e["payload"]) for g in agents for e in g.envelopes)
    t0 = time.perf_counter()
    pkg = lab.export("bench")
    export_s = time.perf_counter() - t0
    t0 = time.perf_counter()
    code, rep = lab.verify(pkg)
    verify_s = time.perf_counter() - t0
    # recovery: hard stop and reopen (rebuilds indexes, checks chains)
    lab.kill()
    t0 = time.perf_counter()
    lab.start()
    restart_s = time.perf_counter() - t0
    lab.stop()
    shutil.rmtree(lab.dir / "robots", ignore_errors=True)
    lat = sorted(latencies)
    return {"agents": n_agents, "records_per_agent": per, "records": total, "stored": stored, "verify_exit": code,
            "client_sign_records_per_s": round(total / gen_s),
            "ingest_records_per_s": round(total / ingest_s), "ingest_s": round(ingest_s, 3),
            "batch_latency_ms": {"batch_size": batch, "p50": round(lat[len(lat) // 2] * 1000, 2), "p95": round(lat[int(len(lat) * 0.95)] * 1000, 2), "max": round(lat[-1] * 1000, 2)},
            "export_s": round(export_s, 3), "verify_s_including_science": round(verify_s, 3), "verify_records_per_s": round(total / verify_s),
            "store_bytes_per_record": round(store_bytes / total), "payload_bytes_per_record": round(payload_bytes / total),
            "overhead_ratio": round(store_bytes / payload_bytes, 2), "restart_after_kill_s": round(restart_s, 3), "bridge": stats}


def attachments(out: Path, n: int = 50, size: int = 1 << 20) -> dict:
    lab = Lab(out / "attachments", ["rover-01"])
    lab.enrol()
    lab.start()
    blobs = [os.urandom(size) for _ in range(n)]
    t0 = time.perf_counter()
    for b in blobs:
        st, _ = lab.client.put_attachment(b, sha256_hex(b))
        assert st == 201
    dt = time.perf_counter() - t0
    lab.stop()
    return {"uploads": n, "bytes_each": size, "mib_per_s": round(n * size / dt / (1 << 20), 1), "seconds": round(dt, 3)}


def sync_after_outage(out: Path, records: int = 5000) -> dict:
    lab = Lab(out / "sync", ["rover-01"])
    lab.enrol()
    lab.start()
    g = RobotAgent("rover-01", lab.robot_state, lab.client, mission_id="bench")
    g.link_up = False
    s = dict(SENSOR, sensor_id="rover-01-t")
    for k in range(records):
        g.record(g.observation("air_temperature", sensor=s, value=15.0, unit="degC", uncertainty=0.2, lat=45.1, lon=-122.2))
    g.link_up = True
    t0 = time.perf_counter()
    r = g.sync(batch=500)
    dt = time.perf_counter() - t0
    lab.stop()
    return {"records_buffered_offline": records, "sync_s": round(dt, 3), "sent": r["sent"]}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="bench/out")
    ap.add_argument("--scales", default="1,3,10,100,1000")
    a = ap.parse_args(argv)
    out = Path(a.out)
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    result = {"schema": "cursiv-bench-1", "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "hardware": hardware(),
              "bridge_binary": str(binary("cursiv-bridge").relative_to(binary("cursiv-bridge").parents[2])),
              "config": {"queue": 256, "workers": 8, "client_threads": "min(32, agents)", "batch": 100, "fsync": "per coalesced batch"},
              "note": "One computer; simulated agents are threads signing records, not robots.", "scales": []}
    for n in [int(x) for x in a.scales.split(",")]:
        r = run_scale(out, n, PER_AGENT.get(n, 100))
        print(json.dumps(r), flush=True)
        result["scales"].append(r)
    result["attachments"] = attachments(out)
    print(json.dumps(result["attachments"]))
    result["sync_after_outage"] = sync_after_outage(out)
    print(json.dumps(result["sync_after_outage"]))
    (out / "bench-results.json").write_text(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
