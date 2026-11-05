"""Import ROS 2 recordings (MCAP, the rosbag2 default since ROS 2 Iron) as signed observations.

Uses the MCAP project's readers (`mcap`, `mcap-ros2-support`, MIT License, Foxglove), which
decode ROS 2 CDR messages without a ROS installation. The MCAP file itself is uploaded as a
content-addressed attachment and every observation cites it (sha256, topic, log time,
sequence), so each value can be traced back to the exact recorded message.

Library use: ``import_mcap(path, agent, {topic: sensor_dict}, synthetic=...)``, then ``agent.sync()``.

Optional dependency: python -m pip install mcap mcap-ros2-support
"""
from __future__ import annotations

from pathlib import Path

from .identity import sha256_hex
from .ros2_adapter import observation_from_ros

SUPPORTED = {"sensor_msgs/msg/Temperature", "sensor_msgs/msg/RelativeHumidity", "sensor_msgs/msg/FluidPressure", "sensor_msgs/msg/Image"}
FIX = "sensor_msgs/msg/NavSatFix"


def to_dict(msg):
    """mcap-ros2-support decodes messages to objects with __slots__; turn them into plain dicts."""
    if isinstance(msg, (bytes, bytearray, memoryview)):
        return bytes(msg)
    if isinstance(msg, (list, tuple)):
        return [to_dict(x) for x in msg]
    slots = getattr(msg, "__slots__", None)
    if slots:
        return {k: to_dict(getattr(msg, k)) for k in slots}
    return msg


def import_mcap(path: Path, agent, sensors: dict[str, dict], *, synthetic: bool, time_source: str = "unknown",
                upload: bool = True) -> dict:
    """Record one observation per supported message on a mapped topic.

    `sensors` maps topic -> sensor dict. NavSatFix messages on any topic update the current
    location (never invented: before the first fix, location stays unknown)."""
    from mcap_ros2.reader import read_ros2_messages
    from importlib.metadata import version

    path = Path(path)
    data = path.read_bytes()
    mcap_sha = sha256_hex(data)
    if upload:
        agent.upload(data, mcap_sha)
    source = {"sha256": mcap_sha, "size": len(data), "media_type": "application/x-mcap", "role": "source_recording"}
    sw = {"step": "mcap_import", "software": "mcap-ros2-support", "version": version("mcap-ros2-support")}
    fix, counts, skipped = None, {}, {}

    def sink(blob: bytes) -> str:
        sha = sha256_hex(blob)
        if upload:
            agent.upload(blob, sha)
        return sha

    for m in read_ros2_messages(str(path)):
        kind, topic = m.schema.name, m.channel.topic
        msg = to_dict(m.ros_msg)
        if kind == FIX:
            fix = msg
            continue
        if kind not in SUPPORTED or topic not in sensors:
            skipped[f"{topic} ({kind})"] = skipped.get(f"{topic} ({kind})", 0) + 1
            continue
        obs = observation_from_ros(kind, msg, agent, sensor=sensors[topic], fix=fix, time_source=time_source,
                                   synthetic=synthetic, blob_sink=sink)
        obs["attachments"].append(source)
        obs["processing"].insert(0, dict(sw, parameters={"mcap_sha256": mcap_sha, "topic": topic, "log_time_ns": m.log_time_ns,
                                                         "publish_time_ns": m.publish_time_ns, "sequence": m.sequence_count if hasattr(m, "sequence_count") else None}))
        agent.record(obs)
        counts[kind] = counts.get(kind, 0) + 1
    return {"mcap_sha256": mcap_sha, "recorded": counts, "skipped": skipped}
