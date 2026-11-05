"""ROS 2 adapter boundary.

`observation_from_ros()` maps standard ROS 2 message contents (as plain dicts, the
shape `rosidl_runtime_py.message_to_ordereddict` produces) to Cursiv observations.
It is pure and tested without ROS.

`Ros2Forwarder` subscribes to topics and records observations through a RobotAgent.
It is only defined when `rclpy` is importable. LIVE ROS 2 INTEGRATION IS UNVERIFIED:
no ROS 2 installation was available when this was written.

Mapping rules (unknown stays unknown):
- header.stamp -> sensor_time. ROS time may be simulation time or an unsynced clock,
  so time_source is "unknown" unless the caller states it.
- variance 0 means "unknown" in sensor_msgs: uncertainty becomes null, not zero.
- sensor_msgs/RelativeHumidity is a 0..1 fraction: converted to % (recorded in processing).
- sensor_msgs/FluidPressure is Pa: converted to hPa (recorded in processing).
- NavSatFix supplies location only when status.status >= 0 (a fix); covariance type 0 = unknown accuracy.
- The adapter only reads messages. It publishes nothing and cannot command actuators.
"""
from __future__ import annotations

import math
from datetime import datetime, timezone

from .identity import sha256_hex

ADAPTER = {"step": "ros2_adapter", "software": "cursiv-sim", "version": "0.1.0", "parameters": None}


def _stamp(header: dict | None) -> str | None:
    st = (header or {}).get("stamp") or {}
    sec, nsec = st.get("sec"), st.get("nanosec", 0)
    if not isinstance(sec, int) or sec <= 0:
        return None
    dt = datetime.fromtimestamp(sec + nsec / 1e9, timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _sigma(variance) -> float | None:
    if not isinstance(variance, (int, float)) or variance <= 0 or not math.isfinite(variance):
        return None
    return math.sqrt(variance)


def location_from_navsatfix(fix: dict | None) -> dict | None:
    if not fix or (fix.get("status") or {}).get("status", -1) < 0:
        return None
    acc = None
    if fix.get("position_covariance_type", 0) > 0:
        cov = fix.get("position_covariance") or []
        if len(cov) >= 5 and cov[0] > 0 and cov[4] > 0:
            acc = round(math.sqrt(max(cov[0], cov[4])), 3)
    alt = fix.get("altitude")
    return {"lat": fix["latitude"], "lon": fix["longitude"], "alt_m": alt if isinstance(alt, (int, float)) and math.isfinite(alt) else None,
            "crs": "EPSG:4326", "horizontal_accuracy_m": acc, "source": "gnss"}


def observation_from_ros(msg_type: str, msg: dict, agent, *, sensor: dict, fix: dict | None = None,
                         time_source: str = "unknown", synthetic: bool = True, blob_sink=None) -> dict:
    """Build an observation from one ROS message. `blob_sink(bytes) -> sha` stores Image data."""
    t = _stamp(msg.get("header"))
    loc = location_from_navsatfix(fix)
    kw = dict(sensor=sensor, sensor_time=t, lat=loc["lat"] if loc else None, lon=loc["lon"] if loc else None)
    processing = [dict(ADAPTER, parameters={"msg_type": msg_type, "frame_id": (msg.get("header") or {}).get("frame_id")})]
    if msg_type == "sensor_msgs/msg/Temperature":
        o = agent.observation("air_temperature", value=msg["temperature"], unit="degC", uncertainty=_sigma(msg.get("variance")), processing=processing, **kw)
    elif msg_type == "sensor_msgs/msg/RelativeHumidity":
        s = _sigma(msg.get("variance"))
        processing.append({"step": "fraction_to_percent", "software": "cursiv-sim", "version": "0.1.0", "parameters": {"factor": 100}})
        o = agent.observation("relative_humidity", value=round(msg["relative_humidity"] * 100, 6), unit="%", uncertainty=None if s is None else s * 100, processing=processing, **kw)
    elif msg_type == "sensor_msgs/msg/FluidPressure":
        s = _sigma(msg.get("variance"))
        processing.append({"step": "pa_to_hpa", "software": "cursiv-sim", "version": "0.1.0", "parameters": {"factor": 0.01}})
        o = agent.observation("air_pressure", value=round(msg["fluid_pressure"] / 100, 6), unit="hPa", uncertainty=None if s is None else s / 100, processing=processing, **kw)
    elif msg_type == "sensor_msgs/msg/Image":
        if blob_sink is None:
            raise ValueError("Image messages need a blob_sink to store the pixel data")
        data = bytes(msg["data"])
        sha = blob_sink(data)
        processing[0]["parameters"].update(width=msg.get("width"), height=msg.get("height"), encoding=msg.get("encoding"))
        o = agent.observation("image", attachments=[{"sha256": sha, "size": len(data), "media_type": f"application/x-ros-image;encoding={msg.get('encoding', 'unknown')}", "role": "raw"}],
                              processing=processing, **kw)
    else:
        raise ValueError(f"no mapping for {msg_type}; add one rather than guessing")
    if loc:
        o["location"] = loc
    o["time_source"] = time_source
    if not synthetic:
        o["synthetic"] = False
        o["provenance"]["source"] = "sensor"
        o["quality"] = {"flag": "unassessed", "basis": "forwarded from ROS 2 without field quality control"}
    return o


try:  # pragma: no cover - requires a ROS 2 installation (unverified)
    import rclpy  # type: ignore
    from rclpy.node import Node  # type: ignore
    from rosidl_runtime_py.convert import message_to_ordereddict  # type: ignore

    class Ros2Forwarder(Node):
        """Subscribe to sensor topics and record observations. Read-only: no publishers."""

        def __init__(self, agent, topics: dict[str, tuple[type, str, dict]], fix_topic: str | None = None, synthetic: bool = False):
            super().__init__(f"cursiv_forwarder_{agent.robot_id.replace('-', '_')}")
            self.agent, self.synthetic, self.fix = agent, synthetic, None
            if fix_topic:
                from sensor_msgs.msg import NavSatFix  # type: ignore
                self.create_subscription(NavSatFix, fix_topic, lambda m: setattr(self, "fix", message_to_ordereddict(m)), 10)
            for topic, (msg_cls, msg_type, sensor) in topics.items():
                self.create_subscription(msg_cls, topic, lambda m, t=msg_type, s=sensor: self._on(t, m, s), 10)

        def _on(self, msg_type, msg, sensor):
            def sink(data: bytes) -> str:
                sha = sha256_hex(data)
                self.agent.upload(data, sha)
                return sha
            obs = observation_from_ros(msg_type, dict(message_to_ordereddict(msg)), self.agent, sensor=sensor, fix=self.fix,
                                       synthetic=self.synthetic, blob_sink=sink)
            self.agent.record(obs)
except ImportError:
    Ros2Forwarder = None
