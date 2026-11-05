"""Reproducible multi-gigabyte verification benchmark.

    python -m cursiv_sim.bench_scale --sizes-gb 0.1 1 2 5 [--dir D:\\bench] [--out results.json]

For each target size the Rust benchmark (`examples/bench.rs`) generates, signs, ingests and
exports a format-2 package of synthetic records (3 robots, about 2 KB per record). Then
`cursiv-verify` runs as a separate process:
- in streaming mode, always (bounded memory)
- in collecting mode (`--science`), up to --collect-max-gb, because it holds every record and
  shows the memory the format-1 era verifier needed

Wall time and peak resident memory of each verifier run are recorded. Peak memory comes from
`resource` on Linux and macOS; on Windows it is measured only when psutil is installed, and
reported as null otherwise.

Everything is deterministic except timing. Needs about 2.2 x the largest size of free disk.
This measures software on the computer it runs on. It says nothing about robot hardware.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

from .lab import REPO, binary

BYTES_PER_RECORD = 1992  # measured: package bytes / records for the benchmark's records


def run_measured(cmd: list[str], env=None) -> tuple[int, float, float | None, str]:
    """(exit code, wall seconds, peak RSS MiB or None, stdout)."""
    t = time.perf_counter()
    if os.name == "nt":
        try:
            import psutil  # optional
        except ImportError:
            psutil = None
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        peak = [0]
        if psutil:
            def watch():
                try:
                    pp = psutil.Process(p.pid)
                    while p.poll() is None:
                        peak[0] = max(peak[0], pp.memory_info().peak_wset)
                        time.sleep(0.05)
                except Exception:
                    pass
            threading.Thread(target=watch, daemon=True).start()
        out, _ = p.communicate()
        return p.returncode, time.perf_counter() - t, (peak[0] / 2**20 if psutil and peak[0] else None), out.decode()
    # os.wait4 returns the resource usage of exactly this child (Linux and macOS)
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env)
    chunks = []
    reader = threading.Thread(target=lambda: chunks.append(p.stdout.read()), daemon=True)
    reader.start()
    _, status, usage = os.wait4(p.pid, 0)
    reader.join()
    wall = time.perf_counter() - t
    kib = usage.ru_maxrss / (1024 if sys.platform == "darwin" else 1)
    code = os.waitstatus_to_exitcode(status)
    return code, wall, kib / 1024, b"".join(chunks).decode()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="cursiv_sim.bench_scale", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sizes-gb", type=float, nargs="+", default=[0.1, 1.0, 2.0])
    ap.add_argument("--dir", default=None, help="working folder (default: system temp)")
    ap.add_argument("--collect-max-gb", type=float, default=1.0, help="largest size also verified in collecting (--science) mode")
    ap.add_argument("--out", default=None)
    a = ap.parse_args(argv)
    bench = REPO / "target" / "release" / "examples" / ("bench.exe" if os.name == "nt" else "bench")
    if not bench.exists():
        subprocess.run(["cargo", "build", "--release", "--example", "bench"], cwd=REPO, check=True)
    verify = binary("cursiv-verify")
    base = Path(a.dir) if a.dir else Path(os.environ.get("TMPDIR", "/tmp" if os.name != "nt" else os.environ.get("TEMP", ".")))
    base.mkdir(parents=True, exist_ok=True)
    # private copies, so rebuilding the project during a long run cannot change the binaries mid-run
    bindir = base / "cursiv-scale-bin"
    bindir.mkdir(exist_ok=True)
    bench, verify = Path(shutil.copy2(bench, bindir)), Path(shutil.copy2(verify, bindir))
    results = []
    for gb in sorted(a.sizes_gb):
        per = max(1000, int(gb * 1e9 / BYTES_PER_RECORD / 3))
        work = base / f"cursiv-scale-{gb}gb"
        if work.exists():
            shutil.rmtree(work)
        work.mkdir()
        env = {**os.environ, "CURSIV_BENCH_DIR": str(work), "CURSIV_BENCH_KEEP": "1", "CURSIV_BENCH_SCIENCE_MAX": "0"}
        print(f"[{gb} GB] generating {per * 3:,} records ...", flush=True)
        t = time.perf_counter()
        g = subprocess.run([str(bench), str(per), "3"], capture_output=True, env=env, text=True)
        if g.returncode != 0:
            print(g.stdout[-2000:], g.stderr[-2000:])
            return 1
        gen = json.loads(g.stdout)
        gen_s = time.perf_counter() - t
        pkg = Path(g.stderr.strip().splitlines()[-1].replace("package kept at ", ""))
        trust = pkg.parent / "trust.json"  # written by the benchmark: simulation keys only
        code, wall, peak, out = run_measured([str(verify), "package", str(pkg), "--trust", str(trust), "--json"])
        status = json.loads(out)["verification"]["status"] if out.strip() else None
        row = {"target_gb": gb, "records": gen["records"], "package_bytes": gen["package_bytes"], "segment_records": gen["segment_records"],
               "generate_s": round(gen_s, 1), "ingest_records_per_s": gen["ingest_records_per_s"], "export_s": round(gen["export_s"], 2),
               "reopen_s": round(gen["reopen_s"], 2),
               "verify_streaming": {"exit": code, "status": status, "wall_s": round(wall, 2), "records_per_s": round(gen["records"] / wall),
                                    "mb_per_s": round(gen["package_bytes"] / 1e6 / wall, 1), "peak_rss_mib": peak and round(peak, 1)}}
        if gb <= a.collect_max_gb:
            code, wall, peak, out = run_measured([str(verify), "package", str(pkg), "--trust", str(trust), "--json", "--science", "--max-records", "100000000"])
            row["verify_collecting_with_science"] = {"exit": code, "wall_s": round(wall, 2), "peak_rss_mib": peak and round(peak, 1)}
        print(json.dumps(row), flush=True)
        results.append(row)
        shutil.rmtree(work)
    doc = {"schema": "cursiv-bench-scale-1", "measured_on": f"{platform.system()} {platform.machine()}, {os.cpu_count()} logical CPUs (software benchmark, not robot hardware)",
           "python": platform.python_version(), "results": results}
    if a.out:
        Path(a.out).write_text(json.dumps(doc, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
