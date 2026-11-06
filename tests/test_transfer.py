"""Faster record transfer: gzip request bodies (with bomb protection), raw-line submission,
and the client's compression policy. Runs the real bridge."""
from __future__ import annotations

import gzip
import json
import sys
import urllib.request
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))

from cursiv_sim.client import BridgeClient  # noqa: E402
from cursiv_sim.lab import Lab, binary  # noqa: E402
from cursiv_sim.robot import RobotAgent  # noqa: E402


@pytest.fixture()
def lab(tmp_path):
    binary("cursiv-bridge")
    lab = Lab(tmp_path / "lab", ["rover-01"])
    lab.enrol()
    lab.start()
    yield lab
    lab.stop()


def raw_post(lab, body: bytes, encoding: str | None):
    req = urllib.request.Request(f"http://127.0.0.1:{lab.port}/v1/observations", data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    if encoding:
        req.add_header("Content-Encoding", encoding)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(req, timeout=30) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def records(lab, n):
    agent = RobotAgent("rover-01", lab.robot_state, lab.client, mission_id="t")
    sensor = {"sensor_id": "rover-01-t", "sensor_type": "thermistor", "model": None, "calibration": None}
    return [agent.record(agent.observation("air_temperature", sensor=sensor, value=10 + i / 10, unit="degC", uncertainty=0.1)) for i in range(n)]


def test_gzip_batches_are_accepted_and_bombs_refused(lab):
    envs = records(lab, 50)
    body = json.dumps({"records": envs}).encode()
    status, data = raw_post(lab, gzip.compress(body), "gzip")
    assert status == 201 and data["accepted"] == 50
    # a 9 MB body of zeros compresses to a few KB: refused after decompression, nothing stored
    status, data = raw_post(lab, gzip.compress(b'{"records":[' + b" " * (9 * 1024 * 1024) + b"]}"), "gzip")
    assert status == 413 and data["error"] == "too_large"
    status, data = raw_post(lab, b"not gzip at all", "gzip")
    assert status == 400 and data["error"] == "bad_gzip"
    status, data = raw_post(lab, body, "br")
    assert status == 415 and data["error"] == "unsupported_encoding"
    status, data = raw_post(lab, b"{not json", None)
    assert status == 400 and data["error"] == "malformed_json"
    assert lab.client.get("/v1/robots/rover-01/head")[1]["count"] == 50


def test_client_compression_policy_and_raw_lines(lab):
    assert BridgeClient(f"http://127.0.0.1:{lab.port}").compress is False, "loopback: compression only costs CPU"
    assert BridgeClient("http://station.example:8750").compress is True, "a real link: compress"
    c = BridgeClient(f"http://127.0.0.1:{lab.port}", compress=True)
    envs = records(lab, 30)
    status, data, _ = c.submit_lines([json.dumps(e).encode() + b"\n" for e in envs])
    assert status == 201 and data["accepted"] == 30
    status, data, _ = c.submit_lines([json.dumps(e).encode() for e in envs[:5]])
    assert status == 200 and all(r["status"] == "duplicate" for r in data["results"]), "resending is harmless"


def test_station_status_page_is_read_only_html(lab):
    records(lab, 3)
    agent = RobotAgent("rover-01", lab.robot_state, lab.client, mission_id="t")
    assert agent.sync()["link"] == "up"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(f"http://127.0.0.1:{lab.port}/", timeout=30) as r:
        html, headers = r.read().decode(), r.headers
    assert headers["Content-Type"].startswith("text/html") and "default-src 'none'" in headers["Content-Security-Policy"]
    assert "<script" not in html.lower() and "rover-01" in html and "Accepting records." in html
    assert "<td class=n>3</td>" in html, html
    req = urllib.request.Request(f"http://127.0.0.1:{lab.port}/", method="POST", data=b"x")
    try:
        opener.open(req, timeout=30)
        raise AssertionError("POST / must not be accepted")
    except urllib.error.HTTPError as e:
        assert e.code == 404
