"""Phone recordings (phyphox exports) to verified evidence and a research dossier.

The exports here are FORMAT FIXTURES generated to match phyphox-android's DataExport.java
(quoted labels, "0.000000000E0" numbers, meta/time.csv and meta/device.csv). They are not real
recordings; real exports should be added under tests/fixtures/phyphox once available.
"""
from __future__ import annotations

import json
import math
import re
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))

from cursiv_field import __main__ as field  # noqa: E402
from cursiv_field import phyphox  # noqa: E402


def java_sci(v: float) -> str:
    """phyphox writes DecimalFormat("0.000000000E0"): 1.013250000E3, 5.000000000E-1."""
    if v == 0:
        return "0.000000000E0"
    e = math.floor(math.log10(abs(v)))
    m = v / 10**e
    if round(abs(m), 9) >= 10:
        m, e = m / 10, e + 1
    return f"{m:.9f}E{e}"


def export(path: Path, sets: dict[str, tuple[list[str], list[list[float]]]], *, start_unix: float, sep=",", dec=".",
           device=None, with_time=True) -> Path:
    def num(v):
        return "NaN" if v is None else java_sci(v).replace(".", dec)
    with zipfile.ZipFile(path, "w") as z:
        for name, (labels, rows) in sets.items():
            text = sep.join(f'"{l}"' for l in labels) + "\n" + "".join(sep.join(num(c) for c in r) + "\n" for r in rows)
            z.writestr(f"{name}.csv", text)
        dev = device or {"deviceModel": "Pixel 7", "deviceBrand": "Google", "phyphoxVersion": "1.2.0",
                         "PRESSURE Name": "BMP390 Barometer", "PRESSURE Vendor": "Bosch"}
        z.writestr("meta/device.csv", f'"property"{sep}"value"\n' + "".join(f'"{k}"{sep}"{v}"\n' for k, v in dev.items()))
        if with_time:
            z.writestr("meta/time.csv", f'"event"{sep}"experiment time"{sep}"system time"{sep}"system time text"\n'
                       f'"START"{sep}{num(0.0)}{sep}{f"{start_unix:.3f}".replace(".", dec)}{sep}"2026-11-05 10:00:00.000 UTC+00:00"\n')
    return path


T0 = 1793872800.0   # 2026-11-05T10:00:00Z


def walk(tmp: Path, sep=",", dec="."):
    gps_rows = [[float(t), 45.1 + t * 1e-5, -122.2 + t * 1e-5, 120.0 + t * 0.1, 1.3, 90.0, 4.0 + (t % 3), 6.0] for t in range(0, 120)]
    gps = export(tmp / "gps.zip", {"Raw Data": (["Time (s)", "Latitude (°)", "Longitude (°)", "Height (m)", "Velocity (m/s)",
                                                 "Direction (°)", "Horizontal Accuracy (m)", "Vertical Accuracy (m)"], gps_rows)},
                 start_unix=T0, sep=sep, dec=dec)
    p_rows = [[t / 25.0, 1009.5 - (t / 25.0) * 0.001 + (0.02 if t % 7 == 0 else 0.0)] for t in range(0, 25 * 120)]   # 25 Hz barometer
    p_rows[100][1] = None                                                                                        # a gap (NaN)
    pressure = export(tmp / "pressure.zip", {"Raw Data": (["Time (s)", "Pressure (hPa)"], p_rows)}, start_unix=T0 + 0.5, sep=sep, dec=dec)
    return gps, pressure


@pytest.mark.parametrize("sep,dec", [(",", "."), (";", ","), ("\t", ",")])
def test_phyphox_variants_parse_with_absolute_time(tmp_path, sep, dec):
    gps, pressure = walk(tmp_path, sep, dec)
    ex = phyphox.read(pressure)
    ds = ex.sets[0]
    assert ds.labels == ["Time (s)", "Pressure (hPa)"]
    assert ds.rows[0][1] == pytest.approx(1009.52) and ds.rows[100][1] is None
    assert ex.absolute(2.0) == pytest.approx(T0 + 2.5)
    fx = phyphox.fixes([phyphox.read(gps)])
    assert len(fx) == 120 and fx[0]["hacc"] == 4.0


def test_minimal_csv_has_unknown_times(tmp_path):
    f = tmp_path / "m.csv"
    f.write_text('"Time (s)","Pressure (hPa)"\n0.000000000E0,1.009500000E3\n')
    ex = phyphox.read(f)
    assert ex.absolute(0.0) is None and "unknown" in ex.notes[0]


def test_phone_walk_to_verified_dossier(tmp_path):
    gps, pressure = walk(tmp_path)
    station = tmp_path / "station"
    code = field.main(["run", str(gps), str(pressure), "--mission", "walk-1", "--station", str(station),
                       "--notes", "Walked along the creek path.", "--title", "Creek walk test"])
    assert code == 0
    report = next((station / "reports").iterdir())
    md = (report / "dossier.md").read_text()
    v = json.loads((report / "verification.json").read_text())
    assert all(x == "pass" for x in v["verification"]["verdicts"].values()), v["verification"]["verdicts"]
    d = v["reasoning"]["derivations"]
    assert d["verified"] >= 10 and d["mismatch"] == 0, d
    assert "REAL SENSOR DATA" in md and "Instructions for anyone writing" in md and "Walked along the creek path." in md
    assert "air_pressure" in md and "BMP390" in md and "Unknown:* sensor calibration" in md
    assert "from 2026-11-05T10:00:00.000Z" in md, "absolute time comes from meta/time.csv"
    heads = [int(h) for h in re.findall(r"^## (\d+)\.", md, re.M)]
    assert heads == list(range(1, len(heads) + 1)), heads
    rows = (report / "data.csv").read_text().splitlines()
    pressure_rows = [r for r in rows if ",air_pressure," in r]
    assert 230 <= len(pressure_rows) <= 241, "25 Hz reduced to 2 Hz, minus the NaN gap"
    located = [r for r in pressure_rows if r.split(",")[6]]
    assert len(located) == len(pressure_rows), "every pressure reading is within 10 s of a GPS fix"
    # re-running the same files does not duplicate anything
    assert field.main(["run", str(gps), str(pressure), "--mission", "walk-1", "--station", str(station), "--no-pdf"]) == 1
    # the PDF exists when a browser is installed (Edge/Chrome on Windows; Chromium here)
    if (report / "dossier.pdf").exists():
        assert (report / "dossier.pdf").read_bytes()[:5] == b"%PDF-"


def test_tampered_recording_attachment_is_caught(tmp_path):
    gps, pressure = walk(tmp_path)
    station = tmp_path / "station"
    assert field.main(["run", str(pressure), "--mission", "walk-2", "--station", str(station), "--no-pdf"]) == 0
    pkg = next((station / "store/exports").iterdir())
    blob = pkg / "data/blobs/sha256" / phyphox.read(pressure).sha256
    blob.write_bytes(blob.read_bytes() + b"x")
    import subprocess
    from cursiv_sim.lab import binary
    out = subprocess.run([str(binary("cursiv-verify")), "package", str(pkg), "--trust", str(station / "trust.json"), "--json"],
                         capture_output=True, text=True)
    assert out.returncode == 1 and json.loads(out.stdout)["verification"]["verdicts"]["attachments"] == "fail"


def test_iphone_export_format(tmp_path):
    """phyphox-ios: same layout, but clock times in 16-digit scientific notation, no trailing newline,
    device.csv with "version"/"deviceModel" and no sensor names (ExperimentExport.swift)."""
    rows = [[t / 10.0, 1012.0 + t * 0.001] for t in range(50)]
    data = '"Time (s)","Pressure (hPa)"' + "".join("\n" + ",".join(java_sci(c) for c in r) for r in rows)   # no final newline
    f = tmp_path / "iphone.zip"
    with zipfile.ZipFile(f, "w") as z:
        z.writestr("Raw Data.csv", data)
        z.writestr("meta/device.csv", '"property","value"\n"version","1.2.1"\n"build","10211"\n"deviceModel","iPhone14,5"\n"deviceBrand","Apple"\n')
        z.writestr("meta/time.csv", '"event","experiment time","system time","system time text"\n'
                   f'"START",0.000000000000000E0,{T0 / 1e9:.15f}E9,"2026-11-05 10:00:00.000 UTC+00:00"\n')
    ex = phyphox.read(f)
    assert len(ex.sets[0].rows) == 50 and ex.sets[0].rows[-1][1] == pytest.approx(1012.049)
    assert ex.absolute(1.0) == pytest.approx(T0 + 1.0, abs=1e-3)
    station = tmp_path / "station"
    assert field.main(["run", str(f), "--mission", "iphone-1", "--station", str(station), "--no-pdf"]) == 0
    md = next((station / "reports").iterdir()).joinpath("dossier.md").read_text()
    assert "Apple iPhone14,5" in md and "phyphox 1.2.1" in md and "2026-11-05T10:00:00.000Z" in md
