"""ROS 2 capture core without ROS: bounded queue, backpressure, drop accounting, opaque payloads,
adapters, the streaming agent's durability, and end-to-end verification of what it records.
(These are software tests with fabricated messages; see test_ros2.py for the live ROS 2 graph.)"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))

from cursiv_integration.layout import envelopes  # noqa: E402
from cursiv_ros2 import adapters  # noqa: E402
from cursiv_ros2.agent import Frontier, StreamingAgent  # noqa: E402
from cursiv_ros2.capture import CaptureConfig, CaptureCore  # noqa: E402
from cursiv_sim.identity import body_json, merkle_root, sha256_hex  # noqa: E402
from cursiv_sim.lab import Lab, binary  # noqa: E402


def test_python_frontier_matches_the_reference_tree():
    hs = [sha256_hex(str(i).encode()) for i in range(130)]
    f = Frontier()
    assert f.root() == merkle_root([])
    for n in range(1, len(hs) + 1):
        f.push(hs[n - 1])
        assert f.root() == merkle_root(hs[:n]), n


def test_adapters_map_units_uncertainty_and_refuse_to_invent():
    t, f = adapters.adapt("sensor_msgs/msg/Temperature", {"temperature": 21.5, "variance": 0.04})
    assert t == "temperature" and f["measurement"]["value"] == 21.5 and f["measurement"]["uncertainty"]["value"] == pytest.approx(0.2)
    _, f = adapters.adapt("sensor_msgs/msg/Temperature", {"temperature": 21.5, "variance": 0.0})
    assert f["measurement"]["uncertainty"] is None, "variance 0 means unknown, not exact"
    _, f = adapters.adapt("sensor_msgs/msg/FluidPressure", {"fluid_pressure": 101325.0, "variance": 0})
    assert f["measurement"]["value"] == pytest.approx(1013.25) and f["measurement"]["unit"] == "hPa"
    _, f = adapters.adapt("sensor_msgs/msg/RelativeHumidity", {"relative_humidity": 0.5, "variance": 0.0001})
    assert f["measurement"]["value"] == pytest.approx(50.0) and f["measurement"]["uncertainty"]["value"] == pytest.approx(1.0)
    _, f = adapters.adapt("sensor_msgs/msg/Range", {"range": 9.0, "min_range": 0.1, "max_range": 4.0})
    assert f["quality"]["flag"] == "suspect"
    _, f = adapters.adapt("sensor_msgs/msg/NavSatFix", {"status": {"status": -1}, "latitude": 1, "longitude": 2})
    assert f["location"] is None and f["quality"]["flag"] == "bad"
    _, f = adapters.adapt("sensor_msgs/msg/Temperature", {"temperature": float("nan")})
    assert f["measurement"] is None and f["quality"]["flag"] == "bad"
    assert adapters.adapt("sensor_msgs/msg/Imu", {}) is None, "no scalar meaning: captured opaque"


class FakeClient:
    def __getattr__(self, name):
        raise AssertionError("no network in this test")


def core(tmp_path, **kw) -> CaptureCore:
    cfg = CaptureConfig.from_dict({"robot_id": "bot-01", "mission_id": "t", "synthetic": True, "time_source": "simulated",
                                   "topics": [{"name": "/t"}, {"name": "/imu"}], **kw})
    return CaptureCore(cfg, StreamingAgent("bot-01", tmp_path, FakeClient(), mission_id="t"))


def test_backpressure_never_blocks_and_every_drop_is_counted(tmp_path):
    c = core(tmp_path, queue_size=5)
    accepted = [c.offer("/imu", "sensor_msgs/msg/Imu", bytes([i]) * 40, {"publisher_gid": b"g", "publication_sequence_number": i + 1}) for i in range(20)]
    assert accepted == [True] * 5 + [False] * 15
    assert not c.offer("/imu", "sensor_msgs/msg/Imu", b"x" * (9 * 1024 * 1024)), "too large"
    # a publisher sequence gap: messages 21..29 never reached the node
    c.offer("/t", "sensor_msgs/msg/Temperature", b"a", {"publisher_gid": b"h", "publication_sequence_number": 1})
    c.offer("/t", "sensor_msgs/msg/Temperature", b"b", {"publisher_gid": b"h", "publication_sequence_number": 11})
    acc = c.accounting()["topics"]
    assert acc["/imu"]["dropped_queue_full"] == 15 and acc["/imu"]["dropped_too_large"] == 1
    assert acc["/t"]["dropped_queue_full"] == 2, "the /t messages met a full queue"
    assert acc["/t"]["lost_upstream"] == 9
    c.process_pending()
    c.write_accounting(final=True)
    assert c.accounting()["totals"]["recorded"] == 5
    # drop_oldest keeps the newest messages
    c2 = core(tmp_path / "b", queue_size=3, drop_policy="drop_oldest")
    for i in range(6):
        c2.offer("/imu", "sensor_msgs/msg/Imu", bytes([i]), {})
    assert [it.raw for it in c2.q] == [b"\x03", b"\x04", b"\x05"]
    assert c2.accounting()["topics"]["/imu"]["dropped_queue_full"] == 3


def test_records_keep_the_raw_message_metadata_and_decoded_values(tmp_path):
    def decoder(t, raw):
        if raw == b"bad":
            raise ValueError("corrupt CDR")
        return {"header": {"stamp": {"sec": 1793000000, "nanosec": 5_000_000}, "frame_id": "probe"}, "temperature": 12.5, "variance": 0.01}
    c = core(tmp_path)
    c.decoder = decoder
    info = {"source_timestamp": 1793000000_010_000_000, "received_timestamp": 1793000000_011_000_000,
            "publication_sequence_number": 7, "reception_sequence_number": 7, "publisher_gid": bytes(range(16))}
    c.offer("/t", "sensor_msgs/msg/Temperature", b"\x00\x01cdr", info)
    c.offer("/t", "sensor_msgs/msg/Temperature", b"bad", info)
    c.offer("/imu", "sensor_msgs/msg/Imu", b"imu-cdr", {})
    c.process_pending()
    c.agent.flush()
    recs = [json.loads(l) for l in (tmp_path / "bot-01/outbox.jsonl").read_text().splitlines()]
    o = [body_json(r)["observation"] for r in recs]
    assert o[0]["observation_type"] == "temperature" and o[0]["measurement"]["value"] == 12.5
    from datetime import datetime, timezone
    expect = datetime.fromtimestamp(1793000000, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S") + ".005Z"
    assert o[0]["sensor_time"] == expect, "header.stamp, not the arrival time"
    p = o[0]["processing"][0]["parameters"]
    assert p["publication_sequence_number"] == 7 and p["publisher_gid"] == bytes(range(16)).hex() and p["frame_id"] == "probe"
    assert o[0]["attachments"][0]["media_type"] == "application/x-ros2-cdr; type=sensor_msgs/msg/Temperature"
    assert (tmp_path / "bot-01/blobs" / o[0]["attachments"][0]["sha256"]).read_bytes() == b"\x00\x01cdr"
    assert o[1]["observation_type"] == "ros2_message" and o[1]["measurement"] is None, "undecodable: kept opaque, not dropped"
    assert c.accounting()["topics"]["/t"]["decode_errors"] == 1
    assert o[2]["observation_type"] == "ros2_message" and o[2]["sensor"]["sensor_type"] == "sensor_msgs/msg/Imu"


def test_agent_recovers_from_a_torn_outbox_and_resumes(tmp_path):
    a = StreamingAgent("bot-01", tmp_path, FakeClient(), mission_id="t")
    c = CaptureCore(CaptureConfig(robot_id="bot-01", mission_id="t", synthetic=True), a)
    for i in range(5):
        c.offer("/x", "std_msgs/msg/String", bytes([i]), {})
    c.process_pending()
    a.close()
    with open(tmp_path / "bot-01/outbox.jsonl", "ab") as f:
        f.write(b'{"payload":"eyJzY2hl')          # power lost mid-write
    b = StreamingAgent("bot-01", tmp_path, FakeClient(), mission_id="t")
    assert b.count == 5 and b.head == a.head and b.frontier.root() == a.frontier.root()
    assert b.recovered and "incomplete final line" in b.recovered[0]


@pytest.fixture()
def lab(tmp_path):
    binary("cursiv-bridge")
    lab = Lab(tmp_path / "lab", ["bot-01"])
    lab.enrol()
    lab.start()
    yield lab
    lab.stop()


def test_captured_evidence_syncs_offline_first_and_verifies(lab, tmp_path):
    agent = StreamingAgent("bot-01", lab.robot_state, lab.client, mission_id="t")
    c = CaptureCore(CaptureConfig(robot_id="bot-01", mission_id="t", synthetic=True, time_source="simulated", queue_size=50), agent)
    c.decoder = lambda t, raw: {"temperature": raw[0] / 10, "variance": 0} if t.endswith("Temperature") else (_ for _ in ()).throw(ValueError("no type"))
    for i in range(120):
        c.offer("/t", "sensor_msgs/msg/Temperature", bytes([i % 250]), {"publisher_gid": b"p", "publication_sequence_number": i + 1})
        c.offer("/blob", "custom_msgs/msg/Unknown", b"opaque-%d" % i, {})
        if i % 20 == 19:
            c.process_pending()
    # the station goes away: capture continues locally, nothing is lost
    lab.stop()
    assert agent.sync()["link"] == "down"
    c.process_pending()
    lab.start()
    c.stop()
    r = agent.sync()
    assert r["link"] == "up", r
    pkg = lab.export("capture-1")
    code, rep = lab.verify(pkg)
    v = rep["verification"]
    assert code == 0 and v["status"] == "verified", v["verdicts"]
    acc = [body_json(e)["observation"] for _, e in envelopes(pkg) if body_json(e)["observation"]["observation_type"] == "capture_accounting"]
    totals = acc[-1]["processing"][0]["parameters"]["totals"]
    assert totals["received"] == 240 and totals["recorded"] + totals["dropped_queue_full"] == 240
    assert v["robots"]["bot-01"]["records"] == totals["recorded"] + len(acc)
