"""One-command demonstration of the whole workflow, on simulated data.

    python python/cursiv_demo [--mission missions/coastal-survey.json] [--out runs/demo-full]

 1 build the Rust tools if they are missing (needs cargo)
 2 run a seeded virtual mission: AUV, buoy, drone and rover, with failures injected
 3 check the run against the mission's documented expected results
 4 package and sign the evidence (station key) and verify it independently
 5 tamper with a copy and show the verifier catching it
 6 discover packages on a "drive" folder and import them into a research workspace,
   refusing the tampered one and leaving the source untouched
 7 point to the research report: citations, anomalies, uncertainties

Everything produced is SYNTHETIC and says so. It demonstrates software, not hardware.
"""
from __future__ import annotations

import argparse
import base64
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve()
REPO = HERE.parents[2]
sys.path.insert(0, str(REPO / "python"))

from cursiv_integration import importer, layout  # noqa: E402
from cursiv_sim import missions  # noqa: E402
from cursiv_sim.lab import binary  # noqa: E402


def say(n: int, text: str) -> None:
    print(f"\n[{n}] {text}", flush=True)


def ensure_built() -> None:
    try:
        binary("cursiv-bridge"), binary("cursiv-verify")
        return
    except FileNotFoundError:
        pass
    if not shutil.which("cargo"):
        raise SystemExit("Rust is not installed. Install it from https://rustup.rs (free), then run this again.")
    print("    building the Rust tools (first run only, a few minutes)...", flush=True)
    subprocess.run(["cargo", "build", "--release"], cwd=REPO, check=True)


def tamper(pkg: Path, dest: Path) -> Path:
    """Copy the package and change one measured value inside a signed record."""
    bad = dest / pkg.name
    shutil.copytree(pkg, bad)
    buoy = next(r for r in layout.robots(bad) if r.startswith("buoy-"))
    f = layout.record_files(bad, buoy)[0]
    lines = f.read_text().splitlines()
    env = json.loads(lines[5])
    body = json.loads(base64.b64decode(env["payload"]))
    m = body["observation"].get("measurement") or {}
    old = m.get("value")
    m["value"] = (old or 0) + 0.5
    env["payload"] = base64.b64encode(json.dumps(body, separators=(",", ":")).encode()).decode()
    lines[5] = json.dumps(env)
    f.write_text("\n".join(lines) + "\n")
    print(f"    changed {body['observation']['observation_id']} from {old} to {m['value']} (signature left as it was)")
    return bad


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="cursiv_demo", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--mission", default=str(REPO / "missions/coastal-survey.json"))
    ap.add_argument("--out", default=str(REPO / "runs/demo-full"))
    a = ap.parse_args(argv)
    out = Path(a.out).resolve()
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    t0 = time.perf_counter()
    ok = True

    say(1, "Rust tools")
    ensure_built()
    print(f"    {binary('cursiv-verify')}")

    cfg = json.loads(Path(a.mission).read_text())
    say(2, f"Virtual mission {cfg['mission_id']} (seed {cfg['seed']}, {cfg['duration_s'] // 60} simulated minutes): "
           f"{', '.join(f"{p['robot_id']} ({p['kind']})" for p in cfg['platforms'])}")
    res = missions.Mission(cfg, out / "mission").run()
    print(f"    records: {res['records']}")
    print(f"    injected failures handled: {res['counters']}")

    say(3, "Compare with the documented expected results")
    exp_path = Path(a.mission).with_suffix(".expected.json")
    problems = missions.check(res, json.loads(exp_path.read_text())) if exp_path.exists() else ["no expected results file"]
    print("    PASSED: identical to", exp_path.name if not problems else "")
    for p in problems:
        ok = False
        print("    DIFFERENCE:", p)

    pkg, trust = Path(res["package"]), Path(res["trust"])
    say(4, "Signed package, verified independently")
    print(f"    package: {pkg}")
    print("    verdicts:", ", ".join(f"{k}={v}" for k, v in res["verdicts"].items()))
    print("    scientific flags:", res["science_counts"])
    ok &= all(v == "pass" for v in res["verdicts"].values())

    say(5, "Tamper with a copy")
    drive = out / "usb-drive"
    shutil.copytree(pkg, drive / "good" / pkg.name)
    bad = tamper(pkg, drive / "tampered")
    r = subprocess.run([str(binary("cursiv-verify")), "package", str(bad), "--trust", str(trust), "--json"], capture_output=True, text=True)
    rep = json.loads(r.stdout)["verification"]
    caught = r.returncode == 1 and rep["verdicts"]["integrity"].startswith("fail")
    why = sorted({f["code"] for f in rep["findings"] if f["severity"] == "error"})
    print(f"    cursiv-verify exit code {r.returncode}, integrity {rep['verdicts']['integrity'].split(':')[0]} ({', '.join(why)}): "
          + ("tampering DETECTED" if caught else "NOT DETECTED"))
    ok &= caught

    say(6, f"Discover and import from the drive folder {drive}")
    ws = out / "research-workspace"
    found = importer.discover(drive)
    print(f"    found {len(found)} packages")
    imported = None
    for p in found:
        before = importer.fingerprint(p)
        s = importer.import_package(p, ws, trust)
        print(f"    {p.parent.name}/{p.name}: " + ("IMPORTED" if s["imported"] else f"REFUSED ({s['reason']})")
              + f"; source unchanged: {importer.fingerprint(p) == before}")
        if s["imported"]:
            imported = s
    ok &= imported is not None

    say(7, "Research outputs")
    print(f"    mission report (md/html/pdf): {res['report']}")
    if imported:
        print(f"    research summary for Cursiv:  {imported['summary']}")
        print(f"    observations table:           {Path(imported['summary']).parent / 'observations.csv'}")
    print(f"    every value is SYNTHETIC; this demonstrates software, not hardware. ({time.perf_counter() - t0:.0f} s)")
    print("\nDEMO", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
