"""MCAP import (any encoding, opaque + decoded) and export (raw ROS 2 channels, Foxglove-style JSON
and LocationFix), round-tripped through a verified package. No ROS installation needed."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))
pytest.importorskip("mcap_ros2")

from cursiv_ros2.agent import StreamingAgent  # noqa: E402
from cursiv_ros2.capture import CaptureConfig, CaptureCore  # noqa: E402
from cursiv_ros2.mcap_io import export_mcap, import_mcap  # noqa: E402
from cursiv_sim.lab import Lab, binary  # noqa: E402

HEADER = """================================================================================
MSG: std_msgs/Header
builtin_interfaces/Time stamp
string frame_id
================================================================================
MSG: builtin_interfaces/Time
int32 sec
uint32 nanosec"""
TEMPERATURE = "std_msgs/Header header\nfloat64 temperature\nfloat64 variance\n" + HEADER
NAVSATFIX = ("std_msgs/Header header\nNavSatStatus status\nfloat64 latitude\nfloat64 longitude\nfloat64 altitude\n"
             "float64[9] position_covariance\nuint8 position_covariance_type\n" + HEADER +
             "\n================================================================================\nMSG: sensor_msgs/NavSatStatus\nint8 status\nuint16 service")


def make_mcap(path: Path) -> None:
    from mcap.writer import Writer as Raw
    from mcap_ros2.writer import Writer
    with open(path, "wb") as f:
        w = Writer(f)
        ts = w.register_msgdef("sensor_msgs/msg/Temperature", TEMPERATURE)
        fs = w.register_msgdef("sensor_msgs/msg/NavSatFix", NAVSATFIX)
        for i in range(30):
            t = 1_793_000_000_000_000_000 + i * 100_000_000
            stamp = {"sec": t // 10**9, "nanosec": t % 10**9}
            if i % 10 == 0:
                w.write_message("/gps/fix", fs, {"header": {"stamp": stamp, "frame_id": "gps"}, "status": {"status": 0, "service": 1},
                                                 "latitude": 45.5, "longitude": -122.6, "altitude": 30.0,
                                                 "position_covariance": [4.0, 0, 0, 0, 4.0, 0, 0, 0, 9.0], "position_covariance_type": 2},
                                log_time=t, publish_time=t, sequence=i // 10 + 1)
            w.write_message("/probe/temperature", ts, {"header": {"stamp": stamp, "frame_id": "probe"}, "temperature": 10 + i / 10, "variance": 0.04},
                            log_time=t + 1000, publish_time=t, sequence=i + 1)
        w.finish()
    # append a non-ROS channel (JSON) through a second file: MCAP writers cannot reopen, so build it separately
    with open(path.with_name("other.mcap"), "wb") as f:
        r = Raw(f)
        r.start()
        s = r.register_schema("acme.Status", "jsonschema", b'{"type":"object"}')
        c = r.register_channel("/acme/status", "json", s)
        for i in range(5):
            r.add_message(c, log_time=1_793_000_000_000_000_000 + i, publish_time=1_793_000_000_000_000_000 + i, data=json.dumps({"ok": i}).encode(), sequence=i + 1)
        r.finish()


@pytest.fixture()
def lab(tmp_path):
    binary("cursiv-bridge")
    lab = Lab(tmp_path / "lab", ["bag-robot"])
    lab.enrol()
    lab.start()
    yield lab
    lab.stop()


def test_mcap_import_verify_and_export_round_trip(lab, tmp_path):
    from mcap.reader import make_reader
    from mcap_ros2.decoder import DecoderFactory
    src = tmp_path / "recording.mcap"
    make_mcap(src)
    agent = StreamingAgent("bag-robot", lab.robot_state, lab.client, mission_id="bag-import")
    core = CaptureCore(CaptureConfig.from_dict({"robot_id": "bag-robot", "mission_id": "bag-import", "synthetic": True, "time_source": "unknown",
                                                "topics": [{"name": "/gps/fix", "location_source": True}]}), agent)
    r1 = import_mcap(src, core)
    r2 = import_mcap(src.with_name("other.mcap"), core)
    assert r1["recorded"] == {"/gps/fix": 3, "/probe/temperature": 30} and r2["recorded"] == {"/acme/status": 5}
    core.write_accounting(final=True)
    assert agent.sync()["link"] == "up"
    pkg = lab.export("bag-1")
    code, rep = lab.verify(pkg)
    assert code == 0 and rep["verification"]["status"] == "verified", rep["verification"]["verdicts"]

    out = tmp_path / "view.mcap"
    res = export_mcap(pkg, out, verification=rep["verification"])
    assert res["raw"] == 38 and res["raw_without_schema"] == 0 and res["locations"] > 0
    ros2 = DecoderFactory()
    temps, json_obs, fixes, acme = [], [], [], []
    with open(out, "rb") as f:
        reader = make_reader(f)
        meta = {m.name: m.metadata for m in reader.iter_metadata()}
        assert meta["cursiv.package"]["status"] == "verified"
    with open(out, "rb") as f:
        decoders = {}
        for schema, channel, message in make_reader(f).iter_messages():
            if channel.topic == "/probe/temperature":
                assert schema.encoding == "ros2msg"
                decoders.setdefault(schema.id, ros2.decoder_for("cdr", schema))
                temps.append((decoders[schema.id](message.data).temperature, message.sequence, message.log_time))
            elif channel.topic == "/acme/status":
                acme.append(json.loads(message.data))
            elif channel.topic == "/cursiv/bag-robot/temperature":
                json_obs.append(json.loads(message.data))
            elif channel.topic == "/cursiv/bag-robot/location":
                fixes.append(json.loads(message.data))
    # exact raw messages, original sequence numbers and log times survive the round trip
    assert [round(t, 10) for t, _, _ in temps] == [round(10 + i / 10, 10) for i in range(30)]
    assert [s for _, s, _ in temps] == list(range(1, 31))
    assert temps[0][2] == 1_793_000_000_000_000_000 + 1000
    assert acme == [{"ok": i} for i in range(5)], "non-ROS encodings are carried opaque, byte for byte"
    assert len(json_obs) == 30 and json_obs[3]["value"] == pytest.approx(10.3) and json_obs[3]["standard_uncertainty"] == pytest.approx(0.2)
    assert all(o["synthetic"] for o in json_obs) and len(json_obs[0]["record_sha256"]) == 64
    assert fixes[0]["latitude"] == 45.5 and fixes[0]["position_covariance_type"] == 2


def test_an_unverified_package_is_not_exported_unless_asked(tmp_path):
    with pytest.raises(ValueError, match="did not verify"):
        export_mcap(tmp_path, tmp_path / "x.mcap", verification={"status": "failed"})
