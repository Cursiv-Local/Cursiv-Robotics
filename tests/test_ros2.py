"""Live ROS 2 integration test with SIMULATED publishers (not physical robot validation).

Runs tests/ros2/graph_check.py under the ROS 2 Python (ROS must be installed, e.g. Jazzy in
/opt/ros/jazzy). Skipped when ROS 2 is not available, which includes Windows unless ROS 2 is
installed there.
"""
from __future__ import annotations

import glob
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SETUP = sorted(glob.glob("/opt/ros/*/setup.bash"))
PY = os.environ.get("CURSIV_ROS_PYTHON") or shutil.which("python3.12") or "/usr/bin/python3"


@pytest.mark.skipif(not SETUP or os.name == "nt", reason="ROS 2 is not installed here")
def test_capture_node_records_a_live_ros2_graph_as_verifiable_evidence():
    out = subprocess.run(["bash", "-c", f"source {SETUP[-1]} && {PY} {ROOT / 'tests/ros2/graph_check.py'}"],
                         capture_output=True, text=True, timeout=300)
    line = next((l for l in out.stdout.splitlines() if l.startswith("RESULT ")), None)
    assert line, out.stdout[-3000:] + out.stderr[-3000:]
    r = json.loads(line[len("RESULT "):])
    assert r["verify_exit"] == 0 and r["status"] == "verified", r["verdicts"]
    assert set(r["subscribed"]) == {"/sim/temperature", "/sim/imu", "/sim/fix", "/sim/note", "/sim/camera/compressed"}
    assert not r["errors"] and not r["unsubscribable"]
    for topic, a in r["per_topic_accounting"].items():
        assert a["received"] > 0 and a["recorded"] == a["received"], (topic, a)
        # every published message is either captured, published before capture began, or counted lost
        assert a["received"] + a["before_capture"] + a["lost_upstream"] == r["published"][topic], (topic, a, r["published"][topic])
    assert r["checks"]["temperature_mismatch"] == 0 and r["checks"]["temperature_values_match_raw"] > 0
    assert r["observations_with_location"] > 0, "the NavSatFix topic locates later observations"
    assert {"temperature", "gnss_fix", "ros2_message", "capture_accounting"} <= set(r["observation_types"])
    assert all(m["publication_sequence_number"] and m["source_timestamp_ns"] for m in r["metadata_sample"].values())

    # The captured message definitions let a tool without ROS decode the exact messages: export the
    # package to MCAP and decode it with mcap-ros2-support (no ROS installation involved).
    pytest.importorskip("mcap_ros2")
    import sys
    sys.path.insert(0, str(ROOT / "python"))
    from mcap.reader import make_reader
    from mcap_ros2.decoder import DecoderFactory

    from cursiv_ros2.mcap_io import export_mcap
    from cursiv_sim.lab import binary
    v = json.loads(subprocess.run([str(binary("cursiv-verify")), "package", r["package"], "--trust", r["trust"], "--json"],
                                  capture_output=True, text=True).stdout)["verification"]
    out_mcap = Path(r["package"]).with_suffix(".mcap")
    res = export_mcap(Path(r["package"]), out_mcap, verification=v)
    assert res["raw_without_schema"] == 0
    seen, f = {}, open(out_mcap, "rb")
    dec = DecoderFactory()
    for schema, channel, message in make_reader(f).iter_messages():
        if channel.topic.startswith("/sim/"):
            m = dec.decoder_for("cdr", schema)(message.data)
            seen[channel.topic] = m
    f.close()
    assert set(seen) == set(r["subscribed"])
    assert 20 <= seen["/sim/temperature"].temperature < 22 and seen["/sim/fix"].latitude == 45.5
    assert seen["/sim/note"].data.startswith("note ") and abs(seen["/sim/imu"].linear_acceleration.z - 9.81) < 1e-9
