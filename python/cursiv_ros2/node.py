"""ROS 2 evidence capture node (rclpy). EXPERIMENTAL.

Integration-tested against simulated publishers on ROS 2 Jazzy (tests/test_ros2.py). It has not
been run on a physical robot.

The node is read-only: it creates subscriptions and no publishers, services or actions. It
subscribes with `raw=True`, so the serialized CDR bytes are recorded exactly as received. Its
default QoS is best effort, which works with both reliable and best-effort publishers and never
makes a publisher wait for this node. The callback hands bytes and DDS metadata to
`CaptureCore.offer()`, which never blocks.
"""
from __future__ import annotations

import fnmatch
import threading
import time

import rclpy
from rclpy.node import Node
from rclpy.qos import HistoryPolicy, QoSProfile, ReliabilityPolicy
from rclpy.serialization import deserialize_message
from rosidl_runtime_py.convert import message_to_ordereddict
from rosidl_runtime_py.utilities import get_message

from .capture import CaptureCore


def _plain(v):
    """OrderedDicts, arrays and numpy types to plain JSON-able Python."""
    if isinstance(v, dict):
        return {k: _plain(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [_plain(x) for x in v]
    if hasattr(v, "tolist"):
        return v.tolist()
    if isinstance(v, (bytes, bytearray, memoryview)):
        return bytes(v)
    return v


PRIMITIVES = {"bool", "byte", "char", "float32", "float64", "int8", "uint8", "int16", "uint16", "int32", "uint32", "int64", "uint64",
              "string", "wstring"}


def message_definition(msg_type: str) -> str | None:
    """Full ROS 2 message definition text (the "ros2msg" format MCAP and rosbag2 use): the type's
    .msg file followed by every type it depends on. None when the type's .msg is not installed."""
    from rosidl_runtime_py import get_interface_path

    def read(t: str) -> str | None:
        pkg, _, name = t.partition("/msg/") if "/msg/" in t else (t.split("/")[0], "", t.split("/")[-1])
        try:
            return open(get_interface_path(f"{pkg}/msg/{name}")).read()
        except Exception:
            return None

    main = read(msg_type)
    if main is None:
        return None
    seen, out, todo = {msg_type.replace("/msg/", "/")}, [main], [(msg_type.split("/")[0], main)]
    while todo:
        pkg, text = todo.pop()
        for line in text.splitlines():
            parts = line.split("#", 1)[0].split()
            if len(parts) < 2 or "=" in "".join(parts[1:]):   # blank, comment, or a constant (NAME=value)
                continue
            t = parts[0].split("[")[0].split("<=")[0]
            if t in PRIMITIVES:
                continue
            full = t if "/" in t else f"{pkg}/{t}"
            if full in seen:
                continue
            seen.add(full)
            dep = read(full.replace("/", "/msg/", 1))
            if dep is None:
                return None
            out.append("=" * 80 + f"\nMSG: {full}\n" + dep)
            todo.append((full.split("/")[0], dep))
    return "\n".join(out)


class CaptureNode(Node):
    def __init__(self, core: CaptureCore, patterns: list[str], *, reliable: bool = False, discover_every_s: float = 2.0,
                 node_name: str = "cursiv_capture"):
        super().__init__(node_name)
        self.core, self.patterns = core, patterns
        self.qos = QoSProfile(depth=100, history=HistoryPolicy.KEEP_LAST,
                              reliability=ReliabilityPolicy.RELIABLE if reliable else ReliabilityPolicy.BEST_EFFORT)
        self.subs: dict[str, object] = {}
        self.unsubscribable: dict[str, str] = {}
        self.classes: dict[str, type] = {}
        self.publisher_counts: dict[str, int] = {}
        self.create_timer(discover_every_s, self.discover)
        self.discover()

    def wanted(self, topic: str) -> bool:
        return any(fnmatch.fnmatchcase(topic, p) for p in self.patterns)

    def discover(self) -> None:
        for topic in self.subs:
            self.publisher_counts[topic] = self.count_publishers(topic)
        for topic, types in self.get_topic_names_and_types():
            if topic in self.subs or topic in self.unsubscribable or not self.wanted(topic):
                continue
            if topic.startswith("/rosout") or topic.startswith("/parameter_events"):
                continue
            msg_type = types[0]
            try:
                cls = get_message(msg_type)
            except (AttributeError, ModuleNotFoundError, ValueError) as e:
                # the message package is not installed here: rclpy cannot subscribe without its type support
                self.unsubscribable[topic] = f"{msg_type}: {e}"
                self.get_logger().warning(f"cannot capture {topic}: type {msg_type} is not installed on this computer")
                continue
            self.classes[msg_type] = cls

            def cb(raw, info, topic=topic, msg_type=msg_type):
                # rclpy (Jazzy) gives no publisher GID; sequence numbers are per publisher, so gaps
                # can only be attributed when the topic has exactly one publisher.
                info = dict(info)
                info["single_publisher"] = self.publisher_counts.get(topic) == 1
                self.core.offer(topic, msg_type, raw, info)

            self.subs[topic] = self.create_subscription(cls, topic, cb, self.qos, raw=True)
            self.publisher_counts[topic] = self.count_publishers(topic)
            self.get_logger().info(f"capturing {topic} ({msg_type})")

    def schema(self, msg_type: str) -> bytes | None:
        text = message_definition(msg_type)
        return text.encode() if text else None

    def decoder(self, msg_type: str, raw: bytes) -> dict:
        cls = self.classes.get(msg_type) or get_message(msg_type)
        return _plain(message_to_ordereddict(deserialize_message(raw, cls)))


def list_topics(wait_s: float = 2.0) -> list[tuple[str, list[str]]]:
    """Topics and types visible on the ROS graph (discovery takes a moment)."""
    rclpy.init()
    node = Node("cursiv_discover")
    try:
        end = time.monotonic() + wait_s
        while time.monotonic() < end:
            rclpy.spin_once(node, timeout_sec=0.1)
        return sorted(node.get_topic_names_and_types())
    finally:
        node.destroy_node()
        rclpy.shutdown()


def run(core: CaptureCore, patterns: list[str], *, duration_s: float | None = None, sync_every_s: float = 5.0,
        reliable: bool = False, on_sync=None) -> dict:
    """Capture until `duration_s` elapses or Ctrl+C, syncing to the station periodically."""
    rclpy.init()
    node = CaptureNode(core, patterns, reliable=reliable)
    core.decoder = node.decoder
    core.schema_provider = node.schema
    core.start()
    stop = threading.Event()

    def syncer():
        while not stop.wait(sync_every_s):
            r = core.agent.sync()
            if on_sync:
                on_sync(r)

    t = threading.Thread(target=syncer, daemon=True)
    t.start()
    try:
        end = None if duration_s is None else time.monotonic() + duration_s
        while rclpy.ok() and (end is None or time.monotonic() < end):
            rclpy.spin_once(node, timeout_sec=0.05)
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        t.join()
        core.stop()
        final = core.agent.sync()
        node.destroy_node()
        if rclpy.ok():
            rclpy.shutdown()
    return {"sync": final, "accounting": core.accounting(), "subscribed": sorted(node.subs), "unsubscribable": node.unsubscribable,
            "errors": core.errors[:20]}
