"""Interoperability with independent, established tools (optional dependencies; skipped if absent).

    python -m pip install bagit securesystemslib
    python -m pytest tests/test_interop.py -q

- bagit (bagit-python, public domain): our evidence packages are valid RFC 8493 bags, and
  a changed file is caught by BagIt fixity without any Cursiv software.
- securesystemslib (MIT): our records are standard DSSE envelopes it can verify.
"""
from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))

from cursiv_sim.lab import Lab  # noqa: E402
from cursiv_sim.robot import RobotAgent  # noqa: E402
from cursiv_sim.rovers import ROVERS  # noqa: E402
from cursiv_sim.world import Site  # noqa: E402


@pytest.fixture(scope="module")
def package(tmp_path_factory):
    d = tmp_path_factory.mktemp("interop")
    lab = Lab(d / "lab", list(ROVERS))
    lab.enrol()
    lab.start()
    site = Site(3)
    rovers = {rid: cls(RobotAgent(rid, lab.robot_state, lab.client, mission_id="interop"), site) for rid, cls in ROVERS.items()}
    for i in range(6):
        for r in rovers.values():
            r.step(i, 6)
    for r in rovers.values():
        r.agent.sync()
    pkg = lab.export("interop")
    yield lab, pkg
    lab.stop()


def test_package_is_a_valid_bagit_bag_and_tampering_breaks_fixity(package, tmp_path):
    bagit = pytest.importorskip("bagit")
    lab, pkg = package
    bag = bagit.Bag(str(pkg))
    bag.validate()                                  # raises BagValidationError if not valid
    assert bag.info["Bag-Software-Agent"].startswith("cursiv-evidence")
    import shutil
    copy = tmp_path / "bag"
    shutil.copytree(pkg, copy)
    f = copy / "data/robots/rover-01/records.jsonl"
    f.write_bytes(f.read_bytes().replace(b"A", b"B", 1))
    with pytest.raises(bagit.BagValidationError):
        bagit.Bag(str(copy)).validate()
    code, rep = lab.verify(copy)
    assert code == 1 and rep["verification"]["verdicts"]["integrity"] == "fail"


def test_records_are_standard_dsse_envelopes(package):
    pytest.importorskip("securesystemslib")
    from securesystemslib.dsse import Envelope
    from securesystemslib.signer import SSlibKey
    lab, pkg = package
    trust = json.loads(lab.trust_path.read_text())
    for rid in ROVERS:
        k = trust["robots"][rid][0]
        key = SSlibKey(keyid=k["key_id"], keytype="ed25519", scheme="ed25519",
                       keyval={"public": base64.b64decode(k["public_key"]).hex()})
        for line in (pkg / f"data/robots/{rid}/records.jsonl").read_text().splitlines():
            env = Envelope.from_dict(json.loads(line))
            assert list(env.verify([key], 1)) == [k["key_id"]]
    station = trust["stations"][lab.station_id][0]
    skey = SSlibKey(keyid=station["key_id"], keytype="ed25519", scheme="ed25519",
                    keyval={"public": base64.b64decode(station["public_key"]).hex()})
    Envelope.from_dict(json.loads((pkg / "manifest.json").read_text())).verify([skey], 1)


HEADER = """================================================================================
MSG: std_msgs/Header
builtin_interfaces/Time stamp
string frame_id
================================================================================
MSG: builtin_interfaces/Time
int32 sec
uint32 nanosec
"""
TEMPERATURE = "std_msgs/Header header\nfloat64 temperature\nfloat64 variance\n" + HEADER
NAVSATFIX = ("std_msgs/Header header\nNavSatStatus status\nfloat64 latitude\nfloat64 longitude\nfloat64 altitude\n"
             "float64[9] position_covariance\nuint8 position_covariance_type\n"
             "================================================================================\nMSG: sensor_msgs/NavSatStatus\n"
             "int8 status\nuint16 service\n" + HEADER)


def test_ros2_mcap_recording_is_imported_traceably_and_verifies(tmp_path):
    pytest.importorskip("mcap_ros2")
    from mcap_ros2.writer import Writer
    from cursiv_sim.mcap_import import import_mcap
    rec = tmp_path / "survey.mcap"
    t0 = 1_762_300_000
    with rec.open("wb") as f:                       # real ROS 2 CDR encoding, written without ROS
        w = Writer(f)
        ts = w.register_msgdef("sensor_msgs/msg/Temperature", TEMPERATURE)
        fs = w.register_msgdef("sensor_msgs/msg/NavSatFix", NAVSATFIX)
        w.write_message("/env/temperature", ts, {"header": {"stamp": {"sec": t0, "nanosec": 0}, "frame_id": "probe"},
                        "temperature": 15.5, "variance": 0.0}, log_time=t0 * 10**9, publish_time=t0 * 10**9)
        for i in range(1, 6):
            w.write_message("/gps/fix", fs, {"header": {"stamp": {"sec": t0 + i, "nanosec": 0}, "frame_id": "gps"}, "status": {"status": 0, "service": 1},
                            "latitude": 45.1 + i * 1e-5, "longitude": -122.2, "altitude": 120.0, "position_covariance": [4.0, 0, 0, 0, 4.0, 0, 0, 0, 9.0],
                            "position_covariance_type": 2}, log_time=(t0 + i) * 10**9, publish_time=(t0 + i) * 10**9)
            w.write_message("/env/temperature", ts, {"header": {"stamp": {"sec": t0 + i, "nanosec": 500_000_000}, "frame_id": "probe"},
                            "temperature": 15.5 + i * 0.1, "variance": 0.04}, log_time=(t0 + i) * 10**9 + 5, publish_time=(t0 + i) * 10**9)
        w.write_message("/cmd_vel", ts, {"header": {"stamp": {"sec": t0, "nanosec": 0}, "frame_id": ""}, "temperature": 0.0, "variance": 0.0},
                        log_time=t0 * 10**9, publish_time=t0 * 10**9)
        w.finish()
    lab = Lab(tmp_path / "lab", ["rover-04"])
    lab.enrol()
    lab.start()
    try:
        g = RobotAgent("rover-04", lab.robot_state, lab.client, mission_id="mcap-import")
        sensor = {"sensor_id": "rover-04-probe", "sensor_type": "thermistor", "model": None, "calibration": None}
        summary = import_mcap(rec, g, {"/env/temperature": sensor}, synthetic=True, time_source="simulated")
        assert summary["recorded"] == {"sensor_msgs/msg/Temperature": 6}
        assert summary["skipped"] == {"/cmd_vel (sensor_msgs/msg/Temperature)": 1}, "unmapped topics are never recorded"
        g.sync()
        pkg = lab.export("mcap")
        code, rep = lab.verify(pkg)
        assert code == 0, rep["verification"]["findings"][:3]
        from cursiv_sim.identity import body_json
        obs = [body_json(json.loads(l))["observation"] for l in (pkg / "data/robots/rover-04/records.jsonl").read_text().splitlines()]
        assert obs[0]["location"] is None and obs[0]["measurement"]["uncertainty"] is None, "no fix yet; ROS variance 0 = unknown"
        assert obs[1]["location"]["horizontal_accuracy_m"] == 2.0 and obs[1]["measurement"]["value"] == pytest.approx(15.6)
        src = [a for a in obs[1]["attachments"] if a["role"] == "source_recording"][0]
        assert src["sha256"] == summary["mcap_sha256"] and obs[1]["processing"][0]["parameters"]["topic"] == "/env/temperature"
        blob = pkg / "data/blobs/sha256" / src["sha256"]
        blob.write_bytes(blob.read_bytes()[:-1] + b"\x00")
        code, rep = lab.verify(pkg)
        assert rep["verification"]["verdicts"]["attachments"] == "fail"
    finally:
        lab.stop()


def test_qartod_flags_a_spike_on_verified_data_and_refuses_unverified(package, tmp_path):
    pytest.importorskip("ioos_qc")
    from cursiv_sim import qartod
    lab, _ = package
    g = RobotAgent("rover-02", lab.robot_state, lab.client, mission_id="interop")
    s = {"sensor_id": "rover-02-qc", "sensor_type": "rtd", "model": None, "calibration": None}
    ids = []
    for k, v in enumerate([15.0, 15.1, 15.2, 66.0, 15.3, 15.4, 15.4]):     # one physically implausible jump
        env = g.record(g.observation("air_temperature", sensor=s, value=v, unit="degC", uncertainty=0.1, lat=45.1, lon=-122.2))
        from cursiv_sim.identity import body_json
        ids.append(body_json(env)["observation"]["observation_id"])
    g.sync()
    pkg = lab.export("qartod")
    r = qartod.run(pkg, lab.trust_path)
    assert "refused" not in r and r["qc_software"].startswith("ioos_qc")
    spike = r["observations"][ids[3]]
    assert spike["gross_range"] == 4 and spike["aggregate"] == 4
    assert r["observations"][ids[1]]["gross_range"] == 1
    import shutil
    bad = tmp_path / "bad"
    shutil.copytree(pkg, bad)
    f = bad / "data/robots/rover-02/records.jsonl"
    f.write_text(f.read_text().replace("A", "B", 1))
    assert "refused" in qartod.run(bad, lab.trust_path)
