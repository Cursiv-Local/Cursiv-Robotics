"""Semantic adapters for common ROS 2 message types (pure functions over decoded dicts, no ROS).

Each adapter turns a decoded message (the dict `rosidl_runtime_py.message_to_ordereddict`
produces, or `mcap-ros2-support` decodes) into a measurement. Every captured message is also
kept byte for byte as an opaque CDR attachment, so an adapter can only add an interpretation,
never lose information.

Rules (unknown stays unknown):
- `variance` 0 means "unknown" in sensor_msgs, so the uncertainty is null, not zero.
- Unit conversions are recorded as processing steps (Pa -> hPa, fraction -> %).
- A NavSatFix gives a location only with a fix (status >= 0); covariance type 0 means unknown accuracy.
- Range readings outside [min_range, max_range] are marked suspect, as REP 117 specifies.
- Messages with no scalar meaning (Imu, MagneticField, LaserScan, PointCloud2, Image, ...) are
  captured opaque and labelled with their type; no value is invented for them.
"""
from __future__ import annotations

import math

VERSION = "0.1.0"


def _sigma(variance) -> float | None:
    if not isinstance(variance, (int, float)) or variance <= 0 or not math.isfinite(variance):
        return None
    return math.sqrt(variance)


def _step(name: str, **params) -> dict:
    return {"step": name, "software": "cursiv-ros2", "version": VERSION, "parameters": params or None}


def stamp_ns(msg: dict | None) -> int | None:
    st = ((msg or {}).get("header") or {}).get("stamp") or {}
    sec, nsec = st.get("sec"), st.get("nanosec", 0)
    if not isinstance(sec, int) or sec <= 0:
        return None
    return sec * 1_000_000_000 + int(nsec or 0)


def location(fix: dict | None) -> dict | None:
    if not fix or (fix.get("status") or {}).get("status", -1) < 0:
        return None
    lat, lon = fix.get("latitude"), fix.get("longitude")
    if not all(isinstance(v, (int, float)) and math.isfinite(v) for v in (lat, lon)):
        return None
    acc = None
    if fix.get("position_covariance_type", 0) > 0:
        cov = fix.get("position_covariance") or []
        if len(cov) >= 5 and cov[0] > 0 and cov[4] > 0:
            acc = round(math.sqrt(max(cov[0], cov[4])), 3)
    alt = fix.get("altitude")
    return {"lat": lat, "lon": lon, "alt_m": alt if isinstance(alt, (int, float)) and math.isfinite(alt) else None,
            "crs": "EPSG:4326", "horizontal_accuracy_m": acc, "source": "gnss"}


def _scalar(value, unit, sigma=None, steps=(), quality=None):
    if not isinstance(value, (int, float)) or not math.isfinite(value):
        return {"measurement": None, "processing": list(steps) + [_step("not_a_finite_value")], "quality": {"flag": "bad", "basis": "the message value is not a finite number"}}
    out = {"measurement": {"value": float(value), "text": None, "unit": unit,
                           "uncertainty": None if sigma is None else {"kind": "standard", "value": sigma, "coverage_k": None}},
           "processing": list(steps)}
    if quality:
        out["quality"] = quality
    return out


def temperature(m):
    return "temperature", _scalar(m.get("temperature"), "degC", _sigma(m.get("variance")))


def relative_humidity(m):
    s = _sigma(m.get("variance"))
    v = m.get("relative_humidity")
    return "relative_humidity", _scalar(v * 100 if isinstance(v, (int, float)) else v, "%", None if s is None else s * 100,
                                        [_step("fraction_to_percent", factor=100)])


def fluid_pressure(m):
    s = _sigma(m.get("variance"))
    v = m.get("fluid_pressure")
    return "pressure", _scalar(v / 100 if isinstance(v, (int, float)) else v, "hPa", None if s is None else s / 100,
                               [_step("pa_to_hpa", factor=0.01)])


def illuminance(m):
    return "illuminance", _scalar(m.get("illuminance"), "lx", _sigma(m.get("variance")))


def range_(m):
    v, lo, hi = m.get("range"), m.get("min_range"), m.get("max_range")
    q = None
    if isinstance(v, (int, float)) and isinstance(lo, (int, float)) and isinstance(hi, (int, float)) and not (lo <= v <= hi):
        q = {"flag": "suspect", "basis": f"range {v} outside the sensor's stated [{lo}, {hi}] m (REP 117: no valid detection)"}
    return "range", _scalar(v, "m", None, [_step("range_limits", min_range=lo, max_range=hi, field_of_view=m.get("field_of_view"))], q)


def battery(m):
    return "battery_voltage", _scalar(m.get("voltage"), "V")


def navsatfix(m):
    loc = location(m)
    return "gnss_fix", {"measurement": None, "location": loc,
                        "processing": [_step("navsatfix", status=(m.get("status") or {}).get("status"), covariance_type=m.get("position_covariance_type"))],
                        **({} if loc else {"quality": {"flag": "bad", "basis": "no GNSS fix (status < 0)"}})}


ADAPTERS = {
    "sensor_msgs/msg/Temperature": temperature,
    "sensor_msgs/msg/RelativeHumidity": relative_humidity,
    "sensor_msgs/msg/FluidPressure": fluid_pressure,
    "sensor_msgs/msg/Illuminance": illuminance,
    "sensor_msgs/msg/Range": range_,
    "sensor_msgs/msg/BatteryState": battery,
    "sensor_msgs/msg/NavSatFix": navsatfix,
}

# Types whose payload is itself a standard file format, attached in addition to the raw CDR.
MEDIA = {"sensor_msgs/msg/CompressedImage": lambda m: (bytes(m.get("data") or b""), f"image/{(m.get('format') or 'unknown').split(';')[0].strip() or 'unknown'}")}


def adapt(msg_type: str, msg: dict) -> tuple[str, dict] | None:
    """(observation_type, fields) for a known type, or None (capture opaque)."""
    f = ADAPTERS.get(msg_type)
    return f(msg) if f else None
