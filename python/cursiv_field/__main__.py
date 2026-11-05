"""One command from phone recordings to a verified research dossier.

    py -m cursiv_field run recording.zip [more.zip ...] --mission my-walk [--title "..."] [--notes "..."]

Keeps a persistent station folder (default: ~/CursivField) with the evidence store, keys and
trust store, and writes reports/<mission>/dossier.md (+ .html, .pdf when Edge/Chrome is
installed, and data.csv). Give dossier.md or dossier.pdf to Cursiv with `add document <path>`.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cursiv_sim.identity import body_json  # noqa: E402
from cursiv_sim.lab import Lab, binary  # noqa: E402
from cursiv_sim.robot import RobotAgent  # noqa: E402

from . import dossier, phyphox  # noqa: E402

ANALYSIS = "analysis-01"
PROFILE = {
    "name": "phone-field-1",
    "types": {
        "air_pressure": {"unit": "hPa", "min": 300, "max": 1100, "requires_attachment": False, "compare_radius_m": None, "compare_window_s": None},
        "illuminance": {"unit": "lx", "min": 0, "max": 200000, "requires_attachment": False, "compare_radius_m": None, "compare_window_s": None},
        "ambient_temperature": {"unit": "degC", "min": -40, "max": 85, "requires_attachment": False, "compare_radius_m": None, "compare_window_s": None},
        "relative_humidity": {"unit": "%", "min": 0, "max": 100, "requires_attachment": False, "compare_radius_m": None, "compare_window_s": None},
        "gps_height": {"unit": "m", "min": -500, "max": 9000, "requires_attachment": False, "compare_radius_m": None, "compare_window_s": None},
        "gps_speed": {"unit": "m/s", "min": 0, "max": 100, "requires_attachment": False, "compare_radius_m": None, "compare_window_s": None},
    },
    "region": None,
    "max_clock_offset_s": 120.0,
    "contradiction_sigma": 3.0,
    "check_clock_against_receipts": False,   # recordings are imported after the fact
}


def summarize(analyst: RobotAgent, envelopes: list[dict]) -> dict:
    """Per series, record count/mean/min/max/stddev as derived observations the verifier re-computes."""
    groups: dict[tuple, list[dict]] = {}
    for e in envelopes:
        o = body_json(e)["observation"]
        m = o.get("measurement") or {}
        if m.get("value") is not None and o["provenance"]["source"] == "sensor":
            groups.setdefault((o["observation_type"], m["unit"], o["sensor"]["sensor_id"]), []).append(e)
    stats = {}
    for (ty, unit, sensor), envs in sorted(groups.items()):
        s = {"unit": unit, "ids": {}}
        for op in dossier.STATS:
            if op == "stddev" and len(envs) < 2:
                continue
            d = analyst.derive(op, envs, observation_type=f"{ty}_{op}")
            o = body_json(d)["observation"]
            s[op] = o["measurement"]["value"]
            s["ids"][op] = f"{o['robot_id']}/{o['observation_id']}"
        stats[f"{ty} [{sensor}]"] = s
    return stats


def run(a) -> int:
    station = Path(a.station).expanduser()
    if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,40}", a.mission):
        print("--mission must be lowercase letters, digits, '.', '_' or '-' (up to 41)")
        return 2
    lab = Lab(station, [a.device, ANALYSIS], station_id="field-station")
    lab.enrol()
    lab.start()
    try:
        phone = RobotAgent(a.device, lab.robot_state, lab.client, mission_id=a.mission)
        before = len(phone.envelopes)
        summary = phyphox.import_exports([Path(p) for p in a.recordings], phone, max_rate_hz=a.max_rate)
        new = phone.envelopes[before:]
        print(f"imported {summary['observations']} observations: {summary['series']}")
        for n in summary["notes"]:
            print("note:", n)
        if not new:
            print("nothing new to import")
            return 1
        r = phone.sync(batch=500)
        if r.get("link") != "up":
            print("could not deliver to the evidence service:", r)
            return 1
        analyst = RobotAgent(ANALYSIS, lab.robot_state, lab.client, mission_id=a.mission)
        stats = summarize(analyst, new)
        analyst.sync(batch=100)
        name = f"{a.mission}-{time.strftime('%Y%m%d-%H%M%S')}"
        package = lab.export(name)
        profile = station / "profile-phone-field.json"
        profile.write_text(json.dumps(PROFILE, indent=2))
        out = subprocess.run([str(binary("cursiv-verify")), "package", str(package), "--trust", str(lab.trust_path), "--json",
                              "--science", "--profile", str(profile)], capture_output=True, text=True)
        verification = json.loads(out.stdout)
        qartod = None
        try:
            from cursiv_sim import qartod as q
            qartod = q.run(package, lab.trust_path)
        except ImportError:
            pass
        report_dir = station / "reports" / name
        (report_dir).mkdir(parents=True, exist_ok=True)
        (report_dir / "verification.json").write_text(json.dumps(verification, indent=2))
        paths = dossier.write(report_dir, title=a.title or f"Field recording: {a.mission}", mission=a.mission, package=package,
                              verification=verification, import_summary=summary, stats=stats, notes=a.notes or "",
                              qartod=qartod, pdf=not a.no_pdf, trust=lab.trust_path)
        v = verification["verification"]["verdicts"]
        print("verification:", ", ".join(f"{k}={v[k].split(':')[0]}" for k in v), "| exit", out.returncode)
        print("derived statistics recomputed:", verification["reasoning"]["derivations"])
        for k, p in paths.items():
            print(f"{k:>8}: {p}")
        if "pdf" not in paths and not a.no_pdf:
            print("     pdf: no Edge/Chrome found; open dossier.html and print to PDF")
        print("Give dossier.md (or dossier.pdf) to Cursiv:  add document", paths.get("pdf", paths["markdown"]))
        return 0 if out.returncode == 0 else out.returncode
    finally:
        lab.stop()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="cursiv_field")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="import phone recordings, verify, write a research dossier")
    r.add_argument("recordings", nargs="+", help="phyphox export .zip (or minimal .csv) files")
    r.add_argument("--mission", required=True)
    r.add_argument("--title")
    r.add_argument("--notes", help="your own notes about the recording (marked unverified in the dossier)")
    r.add_argument("--station", default=str(Path.home() / "CursivField"))
    r.add_argument("--device", default="phone-01", help="an id for your phone, e.g. phone-01")
    r.add_argument("--max-rate", type=float, default=2.0, help="keep at most this many samples per second per series (default 2)")
    r.add_argument("--no-pdf", action="store_true")
    a = ap.parse_args(argv)
    return run(a)


if __name__ == "__main__":
    raise SystemExit(main())
