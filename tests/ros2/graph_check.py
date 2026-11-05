"""Live ROS 2 graph check (run with ROS 2 sourced; invoked by tests/test_ros2.py).

Starts a station (cursiv-bridge), the simulated publishers in another process, and the capture
node subscribing to '/sim/*'. Then it exports and verifies the package and prints a JSON summary.
This is an integration test with simulated publishers. It is not validation on a robot.
"""
import base64
import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "python"))

from cursiv_integration.layout import envelopes  # noqa: E402
from cursiv_ros2.agent import StreamingAgent  # noqa: E402
from cursiv_ros2.capture import CaptureConfig, CaptureCore  # noqa: E402
from cursiv_ros2.node import run  # noqa: E402
from cursiv_sim.identity import body_json  # noqa: E402
from cursiv_sim.lab import Lab  # noqa: E402


def main():
    work = Path(tempfile.mkdtemp(prefix="cursiv-ros2-"))
    lab = Lab(work / "lab", ["sim-robot-01"])
    lab.enrol()
    lab.start()
    counts_file = work / "published.json"
    pub = subprocess.Popen([sys.executable, str(HERE / "publishers.py"), "6", str(counts_file)])
    try:
        agent = StreamingAgent("sim-robot-01", lab.robot_state, lab.client, mission_id="ros2-graph-check")
        cfg = CaptureConfig.from_dict({"robot_id": "sim-robot-01", "mission_id": "ros2-graph-check", "synthetic": True,
                                       "time_source": "unknown", "queue_size": 5000,
                                       "topics": [{"name": "/sim/*"}, {"name": "/sim/fix", "location_source": True}]})
        core = CaptureCore(cfg, agent)
        time.sleep(0.5)                                  # let the publishers come up
        out = run(core, ["/sim/*"], duration_s=7.0, sync_every_s=2.0)
    finally:
        pub.wait(timeout=30)
    published = json.loads(counts_file.read_text())
    pkg = lab.export("ros2-graph-check")
    code, rep = lab.verify(pkg)
    lab.stop()

    from rclpy.serialization import deserialize_message
    from sensor_msgs.msg import Temperature
    obs = [body_json(e)["observation"] for _, e in envelopes(pkg)]
    by_topic, checks = {}, {"temperature_values_match_raw": 0, "temperature_mismatch": 0}
    for o in obs:
        if o["observation_type"] == "capture_accounting":
            continue
        p = o["processing"][0]["parameters"]
        by_topic.setdefault(p["topic"], []).append(o)
        if p["type"] == "sensor_msgs/msg/Temperature":
            raw = (pkg / "data/blobs/sha256" / o["attachments"][0]["sha256"]).read_bytes()
            m = deserialize_message(raw, Temperature)
            ok = abs(m.temperature - o["measurement"]["value"]) < 1e-12
            checks["temperature_values_match_raw" if ok else "temperature_mismatch"] += 1
    sample = {t: {k: v for k, v in os_[0]["processing"][0]["parameters"].items() if k in ("type", "publication_sequence_number", "source_timestamp_ns", "publisher_gid", "sensor_time_from")}
              for t, os_ in by_topic.items()}
    located = sum(1 for os_ in by_topic.values() for o in os_ if o["location"])
    acc = [o for o in obs if o["observation_type"] == "capture_accounting"][-1]["processing"][0]["parameters"]
    per_topic_acc = acc["topics"]
    print("RESULT " + json.dumps({"package": str(pkg), "trust": str(lab.trust_path), "per_topic_accounting": per_topic_acc, "verify_exit": code, "status": rep["verification"]["status"], "verdicts": rep["verification"]["verdicts"],
                      "published": published, "recorded_per_topic": {t: len(v) for t, v in by_topic.items()},
                      "accounting": acc["totals"], "subscribed": out["subscribed"], "unsubscribable": out["unsubscribable"],
                      "errors": out["errors"], "checks": checks, "observations_with_location": located, "metadata_sample": sample,
                      "observation_types": sorted({o["observation_type"] for o in obs})}))


if __name__ == "__main__":
    main()
