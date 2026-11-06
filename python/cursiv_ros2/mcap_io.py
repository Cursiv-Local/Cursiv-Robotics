"""MCAP import and export. EXPERIMENTAL. Optional dependency: `pip install mcap mcap-ros2-support` (MIT).

Import (`import_mcap`) records every message on the selected channels, whatever its encoding
(cdr, json, protobuf, ...):
- the exact message bytes become an opaque, type-labelled attachment
- the channel's schema is kept as an attachment
- log time, publish time, sequence and the MCAP file's SHA-256 go into each record's processing
- ROS 2 CDR channels with a ros2msg schema are also decoded, so the semantic adapters apply
- the file is read message by message, never loaded whole

Export (`export_mcap`) writes a package to MCAP for Foxglove-style tools. By default the package
must have verified first; the verification status is written into the file either way.
- Raw ROS 2 messages go back on their original topics: exact CDR bytes, with their ros2msg
  schema when the capture stored one.
- `/cursiv/<robot>/<observation_type>`: JSON observations (value, unit, uncertainty, record seq
  and hash, synthetic, quality), with a JSON schema.
- `/cursiv/<robot>/location`: `foxglove.LocationFix` JSON messages for map panels.
- `cursiv.package` metadata: verification status and verdicts.

What MCAP cannot carry is listed in docs/INTEROPERABILITY.md. In short: signatures, hash chains,
seals and checkpoints stay in the package; the MCAP file is a view, not evidence.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .capture import CaptureCore, Item

SOFTWARE, VERSION = "cursiv-ros2", "0.1.0"

LOCATION_FIX_SCHEMA = {  # shape of Foxglove's published foxglove.LocationFix JSON schema (not tested in Foxglove itself)
    "title": "foxglove.LocationFix", "type": "object",
    "properties": {
        "timestamp": {"type": "object", "properties": {"sec": {"type": "integer"}, "nsec": {"type": "integer"}}},
        "frame_id": {"type": "string"}, "latitude": {"type": "number"}, "longitude": {"type": "number"},
        "altitude": {"type": "number"}, "position_covariance": {"type": "array", "items": {"type": "number"}, "minItems": 9, "maxItems": 9},
        "position_covariance_type": {"type": "integer"}}}

OBSERVATION_SCHEMA = {
    "title": "cursiv.Observation", "type": "object",
    "properties": {
        "timestamp": {"type": "object", "properties": {"sec": {"type": "integer"}, "nsec": {"type": "integer"}}},
        "observation_id": {"type": "string"}, "robot_id": {"type": "string"}, "observation_type": {"type": "string"},
        "value": {"type": ["number", "null"]}, "unit": {"type": ["string", "null"]}, "standard_uncertainty": {"type": ["number", "null"]},
        "synthetic": {"type": "boolean"}, "quality": {"type": ["string", "null"]},
        "record_seq": {"type": "integer"}, "record_sha256": {"type": "string"}, "time_source": {"type": "string"}}}


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def import_mcap(path: Path, core: CaptureCore, *, topics: list[str] | None = None) -> dict:
    """Record the messages of an MCAP file. Returns counts per topic and the file's SHA-256."""
    from mcap.reader import make_reader
    try:
        from mcap_ros2.decoder import DecoderFactory
        ros2 = DecoderFactory()
    except ImportError:
        ros2 = None
    path = Path(path)
    sha = file_sha256(path)
    decoders: dict[int, object] = {}
    counts: dict[str, int] = {}
    with open(path, "rb") as f:
        for schema, channel, message in make_reader(f).iter_messages():
            if topics and channel.topic not in topics:
                continue
            msg_type = schema.name if schema and schema.name else f"unknown:{channel.topic}"
            decoded = None
            if ros2 and schema and channel.message_encoding == "cdr" and schema.encoding == "ros2msg":
                if schema.id not in decoders:
                    decoders[schema.id] = ros2.decoder_for(channel.message_encoding, schema)
                try:
                    decoded = _plain(decoders[schema.id](message.data))
                except Exception:
                    decoded = None   # kept opaque; the raw bytes are recorded either way
            step = {"step": "mcap_import", "software": SOFTWARE, "version": VERSION,
                    "parameters": {"mcap_sha256": sha, "mcap_file": path.name, "channel_id": channel.id, "log_time_ns": message.log_time,
                                   "publish_time_ns": message.publish_time, "sequence": message.sequence,
                                   "schema_encoding": schema.encoding if schema else None, "channel_metadata": dict(channel.metadata or {})}}
            it = Item(channel.topic, msg_type, bytes(message.data), message.log_time,
                      {"source_timestamp": message.publish_time or None, "received_timestamp": message.log_time,
                       "publication_sequence_number": message.sequence or None},
                      decoded=decoded, encoding=channel.message_encoding or "unknown",
                      schema=bytes(schema.data) if schema and schema.data else None, extra_steps=[step])
            core.record_item(it)
            counts[channel.topic] = counts.get(channel.topic, 0) + 1
    core.agent.flush()
    return {"mcap_sha256": sha, "recorded": counts}


def _plain(v):
    if isinstance(v, (bytes, bytearray, memoryview)):
        return bytes(v)
    if isinstance(v, (list, tuple)):
        return [_plain(x) for x in v]
    slots = getattr(v, "__slots__", None)
    if slots:
        return {k: _plain(getattr(v, k)) for k in slots}
    return v


def _ns(t: str | None) -> int | None:
    if not t:
        return None
    from datetime import datetime
    return int(datetime.strptime(t.replace("Z", "+0000"), "%Y-%m-%dT%H:%M:%S.%f%z" if "." in t else "%Y-%m-%dT%H:%M:%S%z").timestamp() * 1e9)


def export_mcap(pkg: Path, out: Path, *, verification: dict, allow_unverified: bool = False, raw: bool = True) -> dict:
    """Write a package to MCAP. `verification` is the verifier's JSON report ("verification" part)."""
    from mcap.writer import Writer

    from cursiv_integration.layout import envelopes
    from cursiv_sim.identity import body_json, payload_hash

    status = verification.get("status")
    if status != "verified" and not allow_unverified:
        raise ValueError(f"the package did not verify (status {status!r}); pass allow_unverified=True to export it anyway, labelled")
    pkg, out = Path(pkg), Path(out)
    blobs = pkg / "data" / "blobs" / "sha256"
    counts = {"raw": 0, "observations": 0, "locations": 0, "raw_without_schema": 0}
    with open(out, "wb") as f:
        w = Writer(f)
        w.start(profile="", library=f"{SOFTWARE} {VERSION}")
        w.add_metadata("cursiv.package", {"package": pkg.name, "status": str(status), "verdicts": json.dumps(verification.get("verdicts", {})),
                                          "note": "A view of the package for visualisation. Signatures, chains and seals are not carried; verify the package itself."})
        obs_schema = w.register_schema("cursiv.Observation", "jsonschema", json.dumps(OBSERVATION_SCHEMA).encode())
        loc_schema = w.register_schema("foxglove.LocationFix", "jsonschema", json.dumps(LOCATION_FIX_SCHEMA).encode())
        channels: dict[tuple, int] = {}
        raw_schemas: dict[str, int] = {}

        def channel(key, topic, schema_id, encoding):
            if key not in channels:
                channels[key] = w.register_channel(topic, encoding, schema_id)
            return channels[key]

        for robot, env in envelopes(pkg):
            rec = body_json(env)
            o = rec["observation"]
            t = _ns(o.get("sensor_time")) or _ns(rec.get("written_time")) or 0
            stamp = {"sec": t // 1_000_000_000, "nsec": t % 1_000_000_000}
            steps = {s["step"]: s.get("parameters") or {} for s in o.get("processing") or []}
            cap = steps.get("ros2_capture")
            if raw and cap:
                rawa = next((a for a in o["attachments"] if a["role"] == "raw_message"), None)
                sch = next((a for a in o["attachments"] if a["role"] == "schema"), None)
                if rawa and (blobs / rawa["sha256"]).is_file():
                    mtype = cap["type"]
                    if mtype not in raw_schemas:
                        data = (blobs / sch["sha256"]).read_bytes() if sch and (blobs / sch["sha256"]).is_file() else b""
                        raw_schemas[mtype] = w.register_schema(mtype, "ros2msg" if data else "", data)
                        if not data:
                            counts["raw_without_schema"] += 1
                    enc = cap.get("encoding", "cdr")
                    cid = channel(("raw", cap["topic"], mtype), cap["topic"], raw_schemas[mtype], enc)
                    log = cap.get("received_timestamp_ns") or cap.get("capture_received_ns") or t
                    w.add_message(cid, log_time=log, publish_time=cap.get("source_timestamp_ns") or log,
                                  data=(blobs / rawa["sha256"]).read_bytes(), sequence=cap.get("publication_sequence_number") or 0)
                    counts["raw"] += 1
            m = o.get("measurement") or {}
            u = (m.get("uncertainty") or {})
            msg = {"timestamp": stamp, "observation_id": o["observation_id"], "robot_id": robot, "observation_type": o["observation_type"],
                   "value": m.get("value"), "unit": m.get("unit"), "standard_uncertainty": u.get("value") if u.get("kind") == "standard" else None,
                   "synthetic": o["synthetic"], "quality": (o.get("quality") or {}).get("flag"),
                   "record_seq": rec["seq"], "record_sha256": payload_hash(env), "time_source": o["time_source"]}
            cid = channel(("obs", robot, o["observation_type"]), f"/cursiv/{robot}/{o['observation_type']}", obs_schema, "json")
            w.add_message(cid, log_time=t, publish_time=t, data=json.dumps(msg).encode())
            counts["observations"] += 1
            loc = o.get("location")
            if loc:
                acc = loc.get("horizontal_accuracy_m")
                cov = [acc * acc, 0, 0, 0, acc * acc, 0, 0, 0, 0] if acc else [0.0] * 9
                fix = {"timestamp": stamp, "frame_id": robot, "latitude": loc["lat"], "longitude": loc["lon"],
                       "altitude": loc.get("alt_m") or 0.0, "position_covariance": cov, "position_covariance_type": 2 if acc else 0}
                cid = channel(("loc", robot), f"/cursiv/{robot}/location", loc_schema, "json")
                w.add_message(cid, log_time=t, publish_time=t, data=json.dumps(fix).encode())
                counts["locations"] += 1
        w.finish()
    return {"path": str(out), "status": status, **counts}
