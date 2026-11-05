"""Python tests: identities and Merkle roots agree with Rust, the bridge's network and
input defences, the ROS 2 mapping, and the full demo and fault suite.

    cargo build --release && python -m pytest tests -q
"""
from __future__ import annotations

import json
import socket
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))

from cursiv_sim import demo, faults  # noqa: E402
from cursiv_sim.identity import Identity, body_json, merkle_root, pae, payload_hash  # noqa: E402
from cursiv_sim.lab import Lab, binary  # noqa: E402
from cursiv_sim.robot import RobotAgent  # noqa: E402
from cursiv_sim.ros2_adapter import location_from_navsatfix, observation_from_ros  # noqa: E402


@pytest.fixture
def lab(tmp_path):
    lab = Lab(tmp_path / "lab", ["rover-01"])
    lab.enrol()
    lab.start()
    yield lab
    lab.stop()


def raw(lab, request: bytes) -> str:
    with socket.create_connection(("127.0.0.1", lab.port)) as s:
        s.sendall(request)
        s.shutdown(socket.SHUT_WR)
        return s.recv(65536).decode(errors="replace")


def test_python_and_rust_merkle_roots_agree(tmp_path, lab):
    g = RobotAgent("rover-01", lab.robot_state, lab.client, mission_id="m")
    for _ in range(7):
        g.record(g.observation("air_temperature", sensor={"sensor_id": "rover-01-t", "sensor_type": "rtd", "model": None, "calibration": None},
                               value=1.0, unit="degC", uncertainty=0.1, lat=45.1, lon=-122.2))
    g.sync()                      # the bridge recomputes the root in Rust and rejects a mismatch
    cp_ok = [l for l in (lab.dir / "store/robots/rover-01/checkpoints.jsonl").read_text().splitlines()]
    assert len(cp_ok) == 1 and body_json(json.loads(cp_ok[0]))["merkle_root"] == merkle_root(g.hashes)


def test_pae_matches_the_dsse_spec_example():
    assert pae("application/example", b"hello world") == b"DSSEv1 19 application/example 11 hello world"


def test_key_file_round_trip_and_tamper(tmp_path):
    p = tmp_path / "k.key"
    a = Identity.load_or_create(p)
    assert Identity.load_or_create(p).key_id == a.key_id
    assert (p.stat().st_mode & 0o077) == 0 or sys.platform == "win32"
    data = json.loads(p.read_text())
    data["key_id"] = "0" * 16
    p.write_text(json.dumps(data))
    with pytest.raises(ValueError):
        Identity.load_or_create(p)


def test_host_origin_size_and_unknown_routes_are_refused(lab):
    assert " 421 " in raw(lab, f"GET /v1/status HTTP/1.1\r\nHost: evil.example:{lab.port}\r\n\r\n".encode())
    body = b'{"payload":"x","payloadType":"x","signatures":[]}'
    req = (f"POST /v1/observations HTTP/1.1\r\nHost: 127.0.0.1:{lab.port}\r\nOrigin: https://evil.example\r\n"
           f"Content-Type: application/json\r\nContent-Length: {len(body)}\r\n\r\n").encode() + body
    assert " 403 " in raw(lab, req)
    big = 9 * 1024 * 1024
    head = f"POST /v1/observations HTTP/1.1\r\nHost: 127.0.0.1:{lab.port}\r\nContent-Length: {big}\r\n\r\n".encode()
    assert " 413 " in raw(lab, head)
    assert lab.client.get("/v1/robots/..%2F..%2Fetc/head")[0] in (400, 404)
    assert lab.client.post("/v1/exports", {"name": "../../outside"})[0] == 400
    assert lab.client.post("/v1/verify", {"package": "/etc"})[0] == 400
    status, data, _ = lab.client.post("/v1/observations", {"records": []})
    assert status == 400
    assert lab.client._call("POST", "/v1/observations", b"{not json")[0] == 400


def test_non_loopback_bind_without_token_is_refused(tmp_path):
    lab = Lab(tmp_path / "x", ["rover-01"])
    lab.enrol()
    out = subprocess.run([str(binary("cursiv-bridge")), "serve", "--store", str(tmp_path / "s"), "--station-id", "s",
                          "--key", str(lab.station_key), "--trust", str(lab.trust_path), "--bind", "0.0.0.0:0"],
                         capture_output=True, text=True, timeout=10)
    assert out.returncode == 2 and "without --token-file" in out.stderr


def test_token_required_when_configured(tmp_path):
    lab = Lab(tmp_path / "t", ["rover-01"])
    lab.enrol()
    token = "t" * 40
    (tmp_path / "token").write_text(token)
    proc = subprocess.Popen([str(binary("cursiv-bridge")), "serve", "--store", str(tmp_path / "s"), "--station-id", "s",
                             "--key", str(lab.station_key), "--trust", str(lab.trust_path), "--bind", f"127.0.0.1:{lab.port}",
                             "--token-file", str(tmp_path / "token")], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        import time
        for _ in range(100):
            try:
                if lab.client.get("/v1/health")[0] == 200:
                    break
            except ConnectionError:
                time.sleep(0.05)
        assert lab.client.get("/v1/status")[0] == 401
        lab.client.token = "x" * 40
        assert lab.client.get("/v1/status")[0] == 401
        lab.client.token = token
        assert lab.client.get("/v1/status")[0] == 200
    finally:
        proc.terminate()
        proc.wait()


class _Agent(RobotAgent):
    def __init__(self):
        self.robot_id, self.mission_id, self.clock_drift_s_per_obs, self._drift = "rover-09", "m", 0.0, 0.0


def test_ros2_mapping_keeps_unknowns_unknown():
    a = _Agent()
    sensor = {"sensor_id": "t1", "sensor_type": "rtd", "model": None, "calibration": None}
    msg = {"header": {"stamp": {"sec": 1762300000, "nanosec": 500_000_000}, "frame_id": "base"}, "temperature": 18.25, "variance": 0.0}
    o = observation_from_ros("sensor_msgs/msg/Temperature", msg, a, sensor=sensor)
    assert o["measurement"]["uncertainty"] is None, "ROS variance 0 means unknown"
    assert o["time_source"] == "unknown" and o["sensor_time"].endswith(".500Z")
    assert o["location"] is None
    rh = observation_from_ros("sensor_msgs/msg/RelativeHumidity", {"header": {}, "relative_humidity": 0.61, "variance": 0.0001}, a, sensor=sensor)
    assert rh["measurement"]["value"] == 61.0 and rh["measurement"]["uncertainty"]["value"] == pytest.approx(1.0)
    assert rh["sensor_time"] is None
    p = observation_from_ros("sensor_msgs/msg/FluidPressure", {"header": {}, "fluid_pressure": 100950.0, "variance": 0}, a, sensor=sensor)
    assert p["measurement"]["value"] == 1009.5 and p["measurement"]["unit"] == "hPa"
    nofix = {"status": {"status": -1}, "latitude": 1.0, "longitude": 2.0}
    assert location_from_navsatfix(nofix) is None
    fix = {"status": {"status": 0}, "latitude": 45.1, "longitude": -122.2, "altitude": 120.0, "position_covariance_type": 2,
           "position_covariance": [4.0, 0, 0, 0, 9.0, 0, 0, 0, 16.0]}
    assert location_from_navsatfix(fix)["horizontal_accuracy_m"] == 3.0
    with pytest.raises(ValueError):
        observation_from_ros("sensor_msgs/msg/Imu", {}, a, sensor=sensor)


def test_demo_end_to_end(tmp_path):
    assert demo.main(["--steps", "20", "--out", str(tmp_path / "demo")]) == 0
    s = json.loads((tmp_path / "demo/demo-summary.json").read_text())
    assert s["altered_package"]["verdicts"]["integrity"] == "fail"
    assert s["resync"]["bridge_count"] == s["resync"]["robot_count"]
    report = (tmp_path / "demo/evidence-report.md").read_text()
    assert "SYNTHETIC DATA" in report and "not determined" in report


def test_all_seventeen_fault_scenarios(tmp_path):
    faults.RESULTS.clear()
    assert faults.main(["--out", str(tmp_path / "faults")]) == 0
    r = json.loads((tmp_path / "faults/fault-results.json").read_text())
    assert r["total"] == 17 and r["passed"] == 17


def test_bridge_storage_quota_and_live_trust_reload(tmp_path):
    lab = Lab(tmp_path / "q", ["rover-01"])
    lab.enrol()
    import time
    proc = subprocess.Popen([str(binary("cursiv-bridge")), "serve", "--store", str(lab.dir / "store"), "--station-id", lab.station_id,
                             "--key", str(lab.station_key), "--trust", str(lab.trust_path), "--bind", f"127.0.0.1:{lab.port}",
                             "--max-store-bytes", "40000"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        for _ in range(100):
            try:
                if lab.client.get("/v1/health")[0] == 200:
                    break
            except ConnectionError:
                time.sleep(0.05)
        g = RobotAgent("rover-01", lab.robot_state, lab.client, mission_id="m")
        s = {"sensor_id": "rover-01-t", "sensor_type": "rtd", "model": None, "calibration": None}
        for _ in range(60):
            g.record(g.observation("air_temperature", sensor=s, value=1.0, unit="degC", uncertainty=0.1, lat=45.1, lon=-122.2))
        seen = []
        for i in range(0, 60, 5):          # a batch is admitted whole or refused whole (nothing half-written)
            status, data, _ = lab.client.submit(g.envelopes[i:i + 5])
            seen.append((status, {r.get("code") or r["status"] for r in data["results"]}))
            if status == 507:
                break
        assert seen[0][1] == {"accepted"} and seen[-1] == (507, {"storage_full"}), seen
        stored = lab.client.get("/v1/robots/rover-01/head")[1]["count"]
        assert stored == 5 * (len(seen) - 1), "everything before the quota stored, nothing after it"
        # operator revokes the robot's key and reloads the trust store without restarting
        trust = json.loads(lab.trust_path.read_text())
        trust["robots"]["rover-01"][0]["status"] = "revoked"
        lab.trust_path.write_text(json.dumps(trust))
        assert lab.client.post("/v1/trust/reload", {})[0] == 200
        lab.trust_path.write_text("{not json")
        assert lab.client.post("/v1/trust/reload", {})[0] == 400, "a broken trust file is refused; the current one stays"
    finally:
        proc.terminate()
        proc.wait()
