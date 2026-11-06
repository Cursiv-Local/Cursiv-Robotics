"""Scientific quality control with IOOS QARTOD, using the reference implementation `ioos_qc`
(U.S. Integrated Ocean Observing System, Apache License 2.0) rather than reimplementing it.

QC runs only on records that the independent verifier has accepted (integrity and
authenticity pass), so flags are never computed for forged or unattributable data.
QARTOD flags: 1 GOOD (pass), 2 UNKNOWN (not evaluated), 3 SUSPECT, 4 FAIL, 9 MISSING.
A flag describes plausibility under the stated thresholds; it never establishes that a value is correct.

    python -m cursiv_sim.qartod <package> --trust trust.json [--config qc.json] [--out qc-report.json]

Optional dependency: python -m pip install ioos_qc   (pulls numpy, pandas and xarray)
"""
from __future__ import annotations

import argparse
import json
import subprocess
from collections import defaultdict
from pathlib import Path

from cursiv_integration.layout import record_lines, robots

from .identity import body_json
from .lab import binary

# Illustrative thresholds for the SIMULATION profile only. Real deployments must take them from the
# instrument specification and the relevant QARTOD manual (e.g. temperature/salinity, dissolved oxygen).
DEFAULT_CONFIG = {
    "air_temperature": {"gross_range": {"fail_span": [-90, 60], "suspect_span": [-20, 45]},
                        "spike": {"suspect_threshold": 1.5, "fail_threshold": 4.0},
                        "rate_of_change": {"threshold": 0.05},
                        "flat_line": {"suspect_threshold": 1800, "fail_threshold": 3600, "tolerance": 0.0005}},
    "relative_humidity": {"gross_range": {"fail_span": [0, 100], "suspect_span": [5, 99]},
                          "spike": {"suspect_threshold": 8, "fail_threshold": 20}},
    "air_pressure": {"gross_range": {"fail_span": [300, 1100], "suspect_span": [900, 1060]},
                     "spike": {"suspect_threshold": 2, "fail_threshold": 6}},
    "soil_moisture": {"gross_range": {"fail_span": [0, 100], "suspect_span": [2, 60]},
                      "spike": {"suspect_threshold": 6, "fail_threshold": 15}},
    "soil_ph": {"gross_range": {"fail_span": [0, 14], "suspect_span": [3.5, 10]}},
    "soil_temperature": {"gross_range": {"fail_span": [-50, 80], "suspect_span": [-20, 45]},
                         "spike": {"suspect_threshold": 1.0, "fail_threshold": 3.0}},
    "_location": {"range_max_m": 5000},
}
FLAG_NAMES = {1: "GOOD", 2: "UNKNOWN", 3: "SUSPECT", 4: "FAIL", 9: "MISSING"}


def verified_records(pkg: Path, trust: Path) -> tuple[list[dict], dict]:
    """Run the independent verifier; return current (uncorrected) records only if it accepts the package."""
    out = subprocess.run([str(binary("cursiv-verify")), "package", str(pkg), "--trust", str(trust), "--json"],
                         capture_output=True, text=True)
    report = json.loads(out.stdout)["verification"]
    v = report["verdicts"]
    if v["integrity"] != "pass" or v["authenticity"] != "pass":
        return [], report
    records = []
    for r in robots(Path(pkg)):
        records += [body_json(json.loads(line)) for line in record_lines(Path(pkg), r)]
    corrected = {(r["robot_id"], r["observation"]["correction"]["corrects_observation_id"]) for r in records if r["observation"]["correction"]}
    return [r for r in records if (r["robot_id"], r["observation"]["observation_id"]) not in corrected], report


def run(pkg: Path, trust: Path, config: dict | None = None) -> dict:
    import numpy as np
    from ioos_qc import qartod
    from importlib.metadata import version

    config = config or DEFAULT_CONFIG
    records, ver = verified_records(pkg, trust)
    result = {"schema": "cursiv-qartod-report-1", "package": str(pkg), "qc_software": f"ioos_qc {version('ioos_qc')} (IOOS QARTOD, Apache-2.0)",
              "verification": ver["verdicts"], "flag_meaning": FLAG_NAMES,
              "statement": "QARTOD flags describe plausibility under the configured thresholds. They do not establish that a value is correct.",
              "series": [], "observations": {}}
    if not records:
        result["refused"] = "the package did not pass integrity and authenticity verification; QC is not run on unverified data"
        return result
    series = defaultdict(list)
    for r in records:
        o = r["observation"]
        m = o.get("measurement") or {}
        if m.get("value") is not None and o.get("sensor_time"):
            series[(o["robot_id"], o["sensor"]["sensor_id"], o["observation_type"])].append(o)
    for (robot, sensor, ty), obs in sorted(series.items()):
        obs.sort(key=lambda o: o["sensor_time"])
        x = np.array([o["measurement"]["value"] for o in obs], dtype=float)
        t = np.array([o["sensor_time"].rstrip("Z") for o in obs], dtype="datetime64[ns]")
        cfg = config.get(ty)
        tests, not_run = {}, {}

        def attempt(name, fn, *args, **kw):
            # A test that cannot run on this series (e.g. too few points for its time window) is
            # recorded as not evaluated (QARTOD 2), with the reason; it is never guessed.
            try:
                tests[name] = np.asarray(fn(*args, **kw))
            except (ValueError, IndexError, ZeroDivisionError) as e:
                not_run[name] = f"{type(e).__name__}: {e}"

        if cfg:
            if "gross_range" in cfg:
                attempt("gross_range", qartod.gross_range_test, x, **cfg["gross_range"])
            if "spike" in cfg:
                attempt("spike", qartod.spike_test, x, **cfg["spike"])
            if "rate_of_change" in cfg:
                attempt("rate_of_change", qartod.rate_of_change_test, x, t, **cfg["rate_of_change"])
            if "flat_line" in cfg:
                attempt("flat_line", qartod.flat_line_test, x, t, **cfg["flat_line"])
        locs = [o.get("location") for o in obs]
        if all(locs) and "_location" in config:
            attempt("location", qartod.location_test, lon=np.array([l["lon"] for l in locs]), lat=np.array([l["lat"] for l in locs]),
                    range_max=config["_location"]["range_max_m"], range_method="wgs84")
        agg = qartod.qartod_compare(list(tests.values())) if tests else np.full(len(obs), 2)
        counts = {FLAG_NAMES[int(k)]: int(v) for k, v in zip(*np.unique(np.asarray(agg), return_counts=True))}
        result["series"].append({"robot_id": robot, "sensor_id": sensor, "observation_type": ty, "n": len(obs),
                                 "tests": sorted(tests), "not_evaluated": not_run, "aggregate_counts": counts,
                                 "note": None if cfg else "no QARTOD thresholds configured for this type: not evaluated (UNKNOWN)"})
        for i, o in enumerate(obs):
            result["observations"][o["observation_id"]] = {"aggregate": int(agg[i]), **{k: int(v[i]) for k, v in tests.items()}}
    return result


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("package")
    ap.add_argument("--trust", required=True)
    ap.add_argument("--config")
    ap.add_argument("--out")
    a = ap.parse_args(argv)
    cfg = json.loads(Path(a.config).read_text()) if a.config else None
    r = run(Path(a.package), Path(a.trust), cfg)
    text = json.dumps(r, indent=2)
    if a.out:
        Path(a.out).write_text(text)
    for s in r["series"]:
        print(f"{s['robot_id']:<10} {s['sensor_id']:<22} {s['observation_type']:<18} n={s['n']:<4} {s['aggregate_counts']}")
    if "refused" in r:
        print("REFUSED:", r["refused"])
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
