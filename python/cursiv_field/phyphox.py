"""Import phyphox recordings (https://phyphox.org, RWTH Aachen) as real, signed observations.

phyphox exports a ZIP with one CSV per data set plus ``meta/device.csv`` (phone and sensor
names) and ``meta/time.csv`` (experiment time ↔ phone clock at each START/PAUSE). The format
handled here follows phyphox-android's ``DataExport.java`` and phyphox-ios's
``ExperimentExport.swift``/``ExperimentExportSet.swift`` (iOS: 16-digit scientific clock times,
no trailing newline, no sensor names in device.csv, and phyphox's unique device id is never written): quoted header labels such as
``"Pressure (hPa)"``, values like ``1.013250000E3``, five separator/decimal variants, and
``NaN`` for empty cells. A minimal single CSV (no ZIP) is accepted too, but it has no clock
mapping, so every sensor time is recorded as unknown.

Nothing is invented:
- times come from ``meta/time.csv``; without it they are unknown;
- a location is attached only from a GPS fix within ``max_fix_age_s`` of the reading;
- calibration and uncertainty are unknown (phones do not report them);
- the phone's clock synchronization cannot be verified, so ``time_source`` is "unknown".

Custody (stated in every record and the dossier): the phone does not sign anything. The
recording is signed when this computer imports it, and the original export file is attached
by SHA-256, so the chain is "phone file with this hash → signed at import".
"""
from __future__ import annotations

import csv
import io
import json
import math
import re
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from cursiv_sim.identity import sha256_hex

SOFTWARE, VERSION = "cursiv-field", "0.1.0"
LABEL = re.compile(r"^\s*(.*?)\s*\(([^()]*)\)\s*$")
UNITS = {"°C": "degC", "℃": "degC", "m/s²": "m/s2", "m/s^2": "m/s2", "µT": "uT", "μT": "uT", "°": "deg", "rad/s": "rad/s",
         "hPa": "hPa", "lx": "lx", "%": "%", "m": "m", "m/s": "m/s", "dB": "dB", "Hz": "Hz", "s": "s", "Pa": "Pa"}
TYPES = {"pressure": "air_pressure", "illuminance": "illuminance", "light": "illuminance",
         "temperature": "ambient_temperature", "relative humidity": "relative_humidity", "humidity": "relative_humidity"}
# phyphox sensor metadata prefixes in meta/device.csv, by quantity name
SENSORS = {"pressure": "PRESSURE", "illuminance": "LIGHT", "light": "LIGHT", "temperature": "TEMPERATURE",
           "humidity": "HUMIDITY", "relative humidity": "HUMIDITY", "acceleration": "ACCELEROMETER",
           "linear acceleration": "LINEAR_ACCELERATION", "magnetic field": "MAGNETIC_FIELD", "gyroscope": "GYROSCOPE",
           "angular velocity": "GYROSCOPE", "proximity": "PROXIMITY"}
GPS = {"latitude": "lat", "longitude": "lon", "height": "alt", "altitude": "alt", "horizontal accuracy": "hacc",
       "vertical accuracy": "vacc", "velocity": "speed", "speed": "speed", "direction": "heading", "satellites": "sats"}


MAX_UNPACKED = 1024**3        # 1 GiB in total
MAX_MEMBER = 256 * 1024**2    # 256 MiB per file (phyphox CSVs are usually kilobytes to megabytes)
MAX_MEMBERS = 1000

def slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", s.lower()).strip("_")[:60] or "value"


@dataclass
class DataSet:
    name: str
    labels: list[str]
    rows: list[list[float | None]]


@dataclass
class Export:
    path: Path
    sha256: str
    size: int
    sets: list[DataSet]
    device: dict[str, str] = field(default_factory=dict)
    time_events: list[tuple[str, float, float]] = field(default_factory=list)   # (event, experiment s, unix s)
    notes: list[str] = field(default_factory=list)

    def absolute(self, t: float) -> float | None:
        """Phone-clock time of experiment time t, from the latest START at or before t."""
        starts = [(e, s) for ev, e, s in self.time_events if ev.upper() == "START" and e <= t + 1e-9]
        if not starts:
            return None
        e, s = max(starts)
        return s + (t - e)


def _number(cell: str, decimal_comma: bool) -> float | None:
    c = cell.strip().strip('"')
    if not c or c.lower() == "nan":
        return None
    if decimal_comma:
        c = c.replace(",", ".")
    try:
        v = float(c)
    except ValueError:
        return None
    return v if math.isfinite(v) else None


def _parse_csv(text: str) -> tuple[list[str], list[list[float | None]]]:
    first = text.split("\n", 1)[0]
    m = re.match(r'^"(?:[^"]|"")*"(.)', first)
    sep = m.group(1) if m else ","
    reader = csv.reader(io.StringIO(text), delimiter=sep, quotechar='"')
    header = next(reader, [])
    rows = [r for r in reader if any(c.strip() for c in r)]
    decimal_comma = sep in (";", "\t") and any("," in c for r in rows[:20] for c in r)
    return [h.lstrip("'") for h in header], [[_number(c, decimal_comma) for c in r] for r in rows]


def _meta_rows(text: str) -> list[list[str]]:
    first = text.split("\n", 1)[0]
    m = re.match(r'^"(?:[^"]|"")*"(.)', first)
    return list(csv.reader(io.StringIO(text), delimiter=m.group(1) if m else ",", quotechar='"'))[1:]


def read(path: Path) -> Export:
    path = Path(path)
    data = path.read_bytes()
    exp = Export(path=path, sha256=sha256_hex(data), size=len(data), sets=[])
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as z:
            # Decompression limits. zipfile never reads past a member's declared size (and checks its
            # CRC), so bounding the declared sizes bounds what is actually decompressed.
            total = sum(i.file_size for i in z.infolist())
            biggest = max((i.file_size for i in z.infolist()), default=0)
            if total > MAX_UNPACKED or biggest > MAX_MEMBER or len(z.infolist()) > MAX_MEMBERS:
                raise ValueError(f"{path.name}: refusing an export that unpacks to {total} bytes / {len(z.infolist())} files "
                                 f"(largest {biggest}); limits {MAX_UNPACKED} / {MAX_MEMBERS} / {MAX_MEMBER} per file")
            for info in z.infolist():
                name = info.filename
                if info.is_dir() or not name.lower().endswith(".csv") or ".." in Path(name).parts or name.startswith("/"):
                    continue
                text = z.read(info).decode("utf-8-sig", errors="replace")
                if name == "meta/device.csv":
                    exp.device = {r[0]: r[1] for r in _meta_rows(text) if len(r) >= 2}
                elif name == "meta/time.csv":
                    dec = ";" in text.split("\n", 1)[0] or "\t" in text.split("\n", 1)[0]
                    for r in _meta_rows(text):
                        if len(r) >= 3:
                            e, s = _number(r[1], dec), _number(r[2], dec)
                            if e is not None and s is not None:
                                exp.time_events.append((r[0], e, s))
                elif not name.startswith("meta/"):
                    labels, rows = _parse_csv(text)
                    exp.sets.append(DataSet(Path(name).stem, labels, rows))
    else:
        labels, rows = _parse_csv(data.decode("utf-8-sig", errors="replace"))
        exp.sets.append(DataSet(path.stem, labels, rows))
        exp.notes.append("minimal CSV export: no meta/time.csv, so sensor times are unknown")
    if not exp.time_events and zipfile.is_zipfile(path):
        exp.notes.append("no meta/time.csv in the export: sensor times are unknown")
    return exp


def _columns(ds: DataSet):
    """(time index, gps {key: index}, [(index, quantity name, unit)])."""
    t_idx, gps, values = None, {}, []
    for i, lab in enumerate(ds.labels):
        m = LABEL.match(lab)
        name, unit = (m.group(1), m.group(2)) if m else (lab.strip(), "")
        low = name.lower()
        if low in ("time", "t") and unit == "s" and t_idx is None:
            t_idx = i
        elif low in GPS and (low not in ("height", "altitude") or any(k.lower().startswith("latitude") for k in ds.labels)):
            gps[GPS[low]] = i
        else:
            values.append((i, name, UNITS.get(unit, unit)))
    return t_idx, gps, values


def fixes(exports: list[Export]) -> list[dict]:
    """Every GPS fix in the exports, with phone-clock time."""
    out = []
    for ex in exports:
        for ds in ex.sets:
            t_idx, gps, _ = _columns(ds)
            if t_idx is None or "lat" not in gps or "lon" not in gps:
                continue
            for r in ds.rows:
                t = r[t_idx]
                lat, lon = r[gps["lat"]], r[gps["lon"]]
                if t is None or lat is None or lon is None or not (-90 <= lat <= 90 and -180 <= lon <= 180):
                    continue
                at = ex.absolute(t)
                if at is not None:
                    out.append({"t": at, "lat": lat, "lon": lon, "alt": r[gps["alt"]] if "alt" in gps else None,
                                "hacc": r[gps["hacc"]] if "hacc" in gps else None})
    return sorted(out, key=lambda f: f["t"])


def _nearest(fx: list[dict], t: float, max_age: float):
    if not fx:
        return None
    lo, hi = 0, len(fx)
    while lo < hi:
        mid = (lo + hi) // 2
        if fx[mid]["t"] < t:
            lo = mid + 1
        else:
            hi = mid
    best = min((fx[i] for i in (lo - 1, lo) if 0 <= i < len(fx)), key=lambda f: abs(f["t"] - t))
    return best if abs(best["t"] - t) <= max_age else None


def utc(unix: float) -> str:
    return datetime.fromtimestamp(unix, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def import_exports(paths: list[Path], agent, *, max_rate_hz: float = 2.0, max_fix_age_s: float = 10.0) -> dict:
    """Record every value column of every export as observations from `agent`. Returns a summary."""
    exports = [read(p) for p in paths]
    registry = agent.dir / "imported.json"
    done = json.loads(registry.read_text()) if registry.exists() else {}
    fx = fixes(exports)
    summary = {"files": [], "observations": 0, "series": {}, "fixes": len(fx), "notes": []}
    for ex in exports:
        if ex.sha256 in done:
            summary["notes"].append(f"{ex.path.name} was already imported on {done[ex.sha256]}: skipped (no duplicates)")
            continue
        agent.upload(ex.path.read_bytes(), ex.sha256)
        source = {"sha256": ex.sha256, "size": ex.size, "media_type": "application/zip" if zipfile.is_zipfile(ex.path) else "text/csv",
                  "role": "source_recording"}
        model = " ".join(v for v in (ex.device.get("deviceBrand") or ex.device.get("deviceManufacturer"), ex.device.get("deviceModel")) if v) or None
        # phyphox writes its version under "version" (and "build"); iOS and Android share these identifiers
        app = ex.device.get("version") or ex.device.get("phyphoxVersion") or ex.device.get("build") or "unknown version"
        summary["files"].append({"file": ex.path.name, "sha256": ex.sha256, "device": model, "phyphox": app, "sets": [d.name for d in ex.sets],
                                 "time_reference": bool(ex.time_events), "notes": ex.notes})
        summary["notes"] += [f"{ex.path.name}: {n}" for n in ex.notes]
        for ds in ex.sets:
            t_idx, gps, values = _columns(ds)
            is_gps = "lat" in gps and "lon" in gps
            if is_gps:     # GPS rows: height and speed become observations at their own fix
                values = [(gps[k], name, unit) for k, name, unit in (("alt", "gps_height", "m"), ("speed", "gps_speed", "m/s")) if k in gps]
            times = [r[t_idx] for r in ds.rows] if t_idx is not None else [None] * len(ds.rows)
            dts = sorted(b - a for a, b in zip(times, times[1:]) if a is not None and b is not None and b > a)
            rate = 1 / dts[len(dts) // 2] if dts else None
            keep = list(range(len(ds.rows)))
            if rate and rate > max_rate_hz:
                window, last, keep = 1.0 / max_rate_hz, None, []
                for i, t in enumerate(times):
                    if t is not None and (last is None or t - last >= window - 1e-9):
                        keep.append(i)
                        last = t
            for col, name, unit in values:
                low = name.lower()
                ty = name if is_gps else TYPES.get(low, slug(name))
                prefix = next((v for k, v in SENSORS.items() if low.startswith(k)), None)
                sname = " ".join(x for x in (ex.device.get(f"{prefix} Vendor"), ex.device.get(f"{prefix} Name")) if x) if prefix else ""
                sensor = {"sensor_id": f"{agent.robot_id}-{slug(prefix or ty)}"[:64], "sensor_type": (prefix or ("gnss" if is_gps else "phone_sensor")).lower(),
                          "model": " · ".join(x for x in (model, sname) if x) or None, "calibration": None}
                n = 0
                for i in keep:
                    row = ds.rows[i]
                    if col >= len(row) or row[col] is None:
                        continue
                    t = times[i]
                    at = ex.absolute(t) if t is not None else None
                    lat = lon = None
                    loc = None
                    if is_gps:
                        loc = {"t": at, "lat": row[gps["lat"]], "lon": row[gps["lon"]], "alt": row[gps["alt"]] if "alt" in gps else None,
                               "hacc": row[gps["hacc"]] if "hacc" in gps else None}
                    elif at is not None:
                        loc = _nearest(fx, at, max_fix_age_s)
                    if loc and loc["lat"] is not None:
                        lat, lon = loc["lat"], loc["lon"]
                    processing = [{"step": "phyphox_import", "software": SOFTWARE, "version": VERSION,
                                   "parameters": {"export_sha256": ex.sha256, "set": ds.name, "column": ds.labels[col], "row": i + 1,
                                                  "experiment_time_s": t, "phyphox": app,
                                                  "location_from": None if not loc or is_gps else f"nearest GPS fix, {abs(loc['t'] - at):.1f} s away"}}]
                    if len(keep) != len(ds.rows):
                        processing.append({"step": "resample", "software": SOFTWARE, "version": VERSION,
                                           "parameters": {"method": "first sample in each window, no averaging", "window_s": round(1.0 / max_rate_hz, 6),
                                                          "original_rows": len(ds.rows), "kept_rows": len(keep), "original_rate_hz": round(rate, 3)}})
                    o = agent.observation(ty, sensor=sensor, value=row[col], unit=unit, uncertainty=None, lat=lat, lon=lon,
                                          sensor_time=utc(at) if at is not None else None, attachments=[source], processing=processing)
                    o["observation_id"] = f"{agent.robot_id}-{ex.sha256[:10]}-{slug(ds.name)[:16]}-{col}-{i + 1}"[:64]
                    o["synthetic"] = False
                    o["time_source"] = "unknown"
                    o["provenance"].update(source="sensor", software=f"phyphox {app}", software_version=str(app))
                    o["quality"] = {"flag": "unassessed", "basis": "phone sensor; no calibration or uncertainty reported by the device"}
                    if o["location"] is not None:
                        o["location"].update(source="phone_gps", horizontal_accuracy_m=loc.get("hacc"),
                                             alt_m=loc.get("alt") if is_gps else None)
                    agent.record(o)
                    n += 1
                if n:
                    key = f"{ty} ({unit})"
                    summary["series"][key] = summary["series"].get(key, 0) + n
                    summary["observations"] += n
        done[ex.sha256] = utc(datetime.now(timezone.utc).timestamp())
    registry.write_text(json.dumps(done, indent=2))
    return summary
