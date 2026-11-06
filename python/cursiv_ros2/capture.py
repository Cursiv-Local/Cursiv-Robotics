"""Capture core: bounded queue, backpressure, drop accounting and record building.

No ROS dependency, so it is tested deterministically without a ROS graph. The ROS node
(`node.py`) only takes each serialized message plus its DDS metadata and calls `offer()`. That
call never blocks and never raises, so capture cannot slow the robot's own callbacks or control
loop. A worker thread decodes (when an adapter exists), signs and writes records in batches.

Every message is preserved as an opaque, type-labelled CDR attachment. Decoded values are added
alongside it, never instead of it.

Accounting is evidence too. Per topic the core counts:
- received
- recorded
- dropped because the queue was full
- dropped because the payload was too large
- decode failures
- messages lost before they reached the node, from gaps in each publisher's publication
  sequence numbers (only where a topic has a single publisher, since rclpy on Jazzy gives no
  publisher GID; otherwise loss is counted as not assessable)
- messages a publisher sent before capture began (its first sequence number seen, minus one)

The counts are written as signed `capture_accounting` records at an interval and at shutdown,
so a reader can see what the evidence is missing.
"""
from __future__ import annotations

import collections
import json
import re
import threading
import time
from dataclasses import dataclass, field

from .adapters import MEDIA, adapt, location, stamp_ns
from .agent import StreamingAgent, utc_from_ns

SOFTWARE, VERSION = "cursiv-ros2", "0.1.0"
TIME_SOURCES = {"gnss", "ntp", "ptp", "rtc_synced", "rtc_unsynced", "monotonic_only", "simulated", "unknown"}


@dataclass
class TopicConfig:
    name: str
    mode: str = "auto"                    # auto: adapter if one exists; opaque: never decode
    observation_type: str | None = None   # override, e.g. "water_temperature"
    sensor_id: str | None = None
    sensor_type: str | None = None
    calibration: dict | None = None
    location_source: bool = False         # a NavSatFix topic whose fix locates the other observations


@dataclass
class CaptureConfig:
    robot_id: str
    mission_id: str
    synthetic: bool                       # required: simulation (Gazebo, test publishers) or real sensors
    time_source: str = "unknown"          # how the publishing computers' clocks are disciplined
    queue_size: int = 1000
    drop_policy: str = "drop_newest"      # or drop_oldest
    max_payload_bytes: int = 8 * 1024 * 1024
    batch: int = 100                      # records per fsync
    accounting_interval_s: float = 10.0
    topics: list[TopicConfig] = field(default_factory=list)

    def __post_init__(self):
        if self.time_source not in TIME_SOURCES:
            raise ValueError(f"time_source must be one of {sorted(TIME_SOURCES)}")
        if self.drop_policy not in ("drop_newest", "drop_oldest"):
            raise ValueError("drop_policy must be drop_newest or drop_oldest")
        if self.queue_size < 1:
            raise ValueError("queue_size must be at least 1")

    @staticmethod
    def from_dict(d: dict) -> "CaptureConfig":
        topics = [TopicConfig(**t) if isinstance(t, dict) else TopicConfig(name=t) for t in d.get("topics", [])]
        return CaptureConfig(**{**{k: v for k, v in d.items() if k != "topics"}, "topics": topics})


def slug(topic: str) -> str:
    s = re.sub(r"[^a-z0-9._-]+", "-", topic.lower()).strip("-.") or "root"
    return s[:40]


@dataclass
class Item:
    topic: str
    msg_type: str
    raw: bytes
    received_ns: int
    info: dict                            # DDS message info (timestamps, sequence numbers, publisher gid)
    decoded: dict | None = None           # given (MCAP import) or filled by the decoder in the worker
    encoding: str = "cdr"                 # message encoding (MCAP channels may use json, protobuf, ...)
    schema: bytes | None = None           # message definition, when the source carries it
    extra_steps: list | None = None       # provenance from an importer


class Counters(dict):
    def bump(self, topic: str, key: str, n: int = 1):
        t = self.setdefault(topic, {"received": 0, "recorded": 0, "dropped_queue_full": 0, "dropped_too_large": 0,
                                    "decode_errors": 0, "record_errors": 0, "lost_upstream": 0, "loss_unassessable": 0, "before_capture": 0})
        t[key] += n


class CaptureCore:
    def __init__(self, cfg: CaptureConfig, agent: StreamingAgent, decoder=None):
        """`decoder(msg_type, raw) -> dict` (from rclpy, or None to capture everything opaque)."""
        self.cfg, self.agent, self.decoder = cfg, agent, decoder
        self.schema_provider = None       # msg_type -> definition bytes (from the ROS installation)
        self._schema_sha: dict[str, str | None] = {}
        self.topics = {t.name: t for t in cfg.topics}
        self.q: collections.deque[Item] = collections.deque()
        self.lock = threading.Lock()
        self.wake = threading.Condition(self.lock)
        self.counts = Counters()
        self.last_pub_seq: dict[tuple[str, str], int] = {}
        self.fix: dict | None = None
        self.stopping = False
        self.worker: threading.Thread | None = None
        self.started_ns = time.time_ns()
        self._last_accounting = time.monotonic()
        self.errors: list[str] = []

    # --- called from the ROS callback: never blocks, never raises ------------------
    def offer(self, topic: str, msg_type: str, raw: bytes, info: dict | None = None) -> bool:
        try:
            now = time.time_ns()
            info = info or {}
            with self.lock:
                self.counts.bump(topic, "received")
                gid, seq = info.get("publisher_gid"), info.get("publication_sequence_number")
                if gid is None and info.get("single_publisher"):
                    gid = "single-publisher"
                if gid is None and isinstance(seq, int):
                    self.counts.bump(topic, "loss_unassessable")   # several publishers, no GID: gaps cannot be attributed
                if gid is not None and isinstance(seq, int) and seq > 0:
                    key = (topic, str(gid))
                    prev = self.last_pub_seq.get(key)
                    if prev is None and seq > 1:
                        # published before this node subscribed: not a loss, but not captured either
                        self.counts.bump(topic, "before_capture", seq - 1)
                    if prev is not None and seq > prev + 1:
                        self.counts.bump(topic, "lost_upstream", seq - prev - 1)
                    if prev is None or seq > prev:
                        self.last_pub_seq[key] = seq
                if len(raw) > self.cfg.max_payload_bytes:
                    self.counts.bump(topic, "dropped_too_large")
                    return False
                if len(self.q) >= self.cfg.queue_size:
                    if self.cfg.drop_policy == "drop_newest":
                        self.counts.bump(topic, "dropped_queue_full")
                        return False
                    old = self.q.popleft()
                    self.counts.bump(old.topic, "dropped_queue_full")
                self.q.append(Item(topic, msg_type, bytes(raw), now, dict(info)))
                self.wake.notify()
            return True
        except Exception as e:  # pragma: no cover - defensive: the robot's callback must never fail
            self.errors.append(repr(e))
            return False

    # --- worker -------------------------------------------------------------------
    def start(self) -> None:
        self.worker = threading.Thread(target=self._run, name="cursiv-capture", daemon=True)
        self.worker.start()

    def stop(self) -> None:
        with self.lock:
            self.stopping = True
            self.wake.notify()
        if self.worker:
            self.worker.join()
        self.process_pending()
        self.write_accounting(final=True)
        self.agent.flush()

    def _run(self) -> None:
        while True:
            with self.lock:
                while not self.q and not self.stopping:
                    self.wake.wait(timeout=0.5)
                    if time.monotonic() - self._last_accounting >= self.cfg.accounting_interval_s:
                        break
                if self.stopping and not self.q:
                    return
            self.process_pending()
            if time.monotonic() - self._last_accounting >= self.cfg.accounting_interval_s:
                self.write_accounting()

    def process_pending(self, limit: int | None = None) -> int:
        """Drain the queue into signed records (up to `limit`), one fsync per batch."""
        done = 0
        while limit is None or done < limit:
            batch = []
            with self.lock:
                while self.q and len(batch) < self.cfg.batch:
                    batch.append(self.q.popleft())
            if not batch:
                break
            for it in batch:
                try:
                    self.agent.record(self.observation(it))
                    with self.lock:
                        self.counts.bump(it.topic, "recorded")
                except Exception as e:  # keep capturing; the failure is counted and reported
                    with self.lock:
                        self.counts.bump(it.topic, "record_errors")
                    self.errors.append(f"{it.topic}: {type(e).__name__}: {e}"[:300])
            self.agent.flush()
            done += len(batch)
        return done

    def observation(self, it: Item) -> dict:
        tc = self.topics.get(it.topic) or TopicConfig(name=it.topic)
        decoded = it.decoded if tc.mode != "opaque" else None
        if decoded is None and tc.mode != "opaque" and self.decoder is not None and it.encoding == "cdr":
            try:
                decoded = self.decoder(it.msg_type, it.raw)
            except Exception as e:
                with self.lock:
                    self.counts.bump(it.topic, "decode_errors")
                self.errors.append(f"{it.topic}: cannot decode {it.msg_type}: {e}"[:300])
        cdr_sha = self.agent.store_blob(it.raw)
        media = {"cdr": "application/x-ros2-cdr", "json": "application/json", "protobuf": "application/x-protobuf",
                 "ros1": "application/x-ros1", "cbor": "application/cbor", "flatbuffer": "application/x-flatbuffer"}.get(it.encoding, f"application/x-{it.encoding}")
        attachments = [{"sha256": cdr_sha, "size": len(it.raw), "media_type": f"{media}; type={it.msg_type}", "role": "raw_message"}]
        schema_sha = self._schema(it)
        if schema_sha:
            attachments.append({"sha256": schema_sha[0], "size": schema_sha[1], "media_type": f"text/x-ros2msg; type={it.msg_type}", "role": "schema"})
        header_ns = stamp_ns(decoded) if decoded else None
        source_ns = it.info.get("source_timestamp")
        sensor_ns = header_ns or (source_ns if isinstance(source_ns, int) and source_ns > 0 else None)
        params = {"topic": it.topic, "type": it.msg_type, "cdr_sha256": cdr_sha, "size": len(it.raw),
                  "source_timestamp_ns": source_ns, "received_timestamp_ns": it.info.get("received_timestamp"),
                  "capture_received_ns": it.received_ns,
                  "publication_sequence_number": it.info.get("publication_sequence_number"),
                  "reception_sequence_number": it.info.get("reception_sequence_number"),
                  "publisher_gid": _gid(it.info.get("publisher_gid")),
                  "header_stamp_ns": header_ns, "frame_id": ((decoded or {}).get("header") or {}).get("frame_id"),
                  "sensor_time_from": "header.stamp" if header_ns else ("dds_source_timestamp" if sensor_ns else None)}
        params["encoding"] = it.encoding
        processing = [*(it.extra_steps or []), {"step": "ros2_capture", "software": SOFTWARE, "version": VERSION, "parameters": params}]
        obs_type, fields = "ros2_message", {"measurement": None}
        if decoded is not None:
            if it.msg_type in MEDIA:
                data, media = MEDIA[it.msg_type](decoded)
                if data:
                    attachments.append({"sha256": self.agent.store_blob(data), "size": len(data), "media_type": media, "role": "raw"})
            a = adapt(it.msg_type, decoded)
            if a:
                obs_type, fields = a
                processing += fields.get("processing", [])
                if it.msg_type == "sensor_msgs/msg/NavSatFix" and tc.location_source:
                    self.fix = decoded
        n = self.agent.count + 1
        obs = {
            "schema": "cursiv-observation-1",
            "observation_id": f"{self.agent.robot_id}-{n:010d}"[:64],
            "robot_id": self.agent.robot_id,
            "mission_id": self.cfg.mission_id,
            "observation_type": tc.observation_type or obs_type,
            "synthetic": self.cfg.synthetic,
            "sensor": {"sensor_id": tc.sensor_id or f"{self.agent.robot_id}-{slug(it.topic)}"[:64], "sensor_type": tc.sensor_type or it.msg_type,
                       "model": None, "calibration": tc.calibration},
            "sensor_time": utc_from_ns(sensor_ns) if sensor_ns else None,
            "time_source": self.cfg.time_source,
            "clock": None,
            "location": fields.get("location") or location(self.fix),
            "measurement": fields.get("measurement"),
            "attachments": attachments,
            "provenance": {"source": "simulated" if self.cfg.synthetic else "sensor", "software": SOFTWARE, "software_version": VERSION, "derived_from": []},
            "processing": processing,
            "quality": fields.get("quality") or {"flag": "unassessed", "basis": "captured from ROS 2; no field quality control"},
            "correction": None,
        }
        return obs

    def _schema(self, it: Item):
        """(sha, size) of the message definition, stored once per type (content-addressed)."""
        if it.msg_type not in self._schema_sha:
            data = it.schema
            if data is None and self.schema_provider and it.encoding == "cdr":
                try:
                    data = self.schema_provider(it.msg_type)
                except Exception:
                    data = None
            self._schema_sha[it.msg_type] = (self.agent.store_blob(data), len(data)) if data else None
        return self._schema_sha[it.msg_type]

    def record_item(self, it: Item) -> None:
        """Record one message synchronously (importers), with the same accounting as live capture."""
        with self.lock:
            self.counts.bump(it.topic, "received")
        self.agent.record(self.observation(it))
        with self.lock:
            self.counts.bump(it.topic, "recorded")

    def accounting(self) -> dict:
        with self.lock:
            per_topic = json.loads(json.dumps(self.counts))
            queued = len(self.q)
        totals = {k: sum(t[k] for t in per_topic.values()) for k in ("received", "recorded", "dropped_queue_full", "dropped_too_large", "decode_errors", "record_errors", "lost_upstream", "loss_unassessable", "before_capture")}
        return {"since_ns": self.started_ns, "queued": queued, "queue_size": self.cfg.queue_size, "drop_policy": self.cfg.drop_policy,
                "totals": totals, "topics": per_topic}

    def write_accounting(self, final: bool = False) -> dict:
        self._last_accounting = time.monotonic()
        acc = self.accounting()
        acc["final"] = final
        obs = {
            "schema": "cursiv-observation-1", "observation_id": f"{self.agent.robot_id}-{self.agent.count + 1:010d}"[:64],
            "robot_id": self.agent.robot_id, "mission_id": self.cfg.mission_id, "observation_type": "capture_accounting",
            "synthetic": self.cfg.synthetic,
            "sensor": {"sensor_id": f"{self.agent.robot_id}-capture", "sensor_type": "cursiv-ros2", "model": None, "calibration": None},
            "sensor_time": utc_from_ns(time.time_ns()), "time_source": self.cfg.time_source, "clock": None, "location": None,
            "measurement": {"value": float(acc["totals"]["dropped_queue_full"] + acc["totals"]["dropped_too_large"] + acc["totals"]["lost_upstream"]),
                            "text": "messages not captured (queue full + too large + lost before reaching the node)", "unit": "1", "uncertainty": None},
            "attachments": [],
            "provenance": {"source": "simulated" if self.cfg.synthetic else "sensor", "software": SOFTWARE, "software_version": VERSION, "derived_from": []},
            "processing": [{"step": "capture_accounting", "software": SOFTWARE, "version": VERSION, "parameters": acc}],
            "quality": None, "correction": None,
        }
        self.agent.record(obs)
        self.agent.flush()
        return acc


def _gid(g):
    if g is None:
        return None
    if isinstance(g, (bytes, bytearray)):
        return bytes(g).hex()
    if isinstance(g, (list, tuple)):
        return bytes(int(x) & 0xFF for x in g).hex()
    return str(g)
