"""Command line: discover topics, capture them as signed evidence. See docs/ROS2_QUICKSTART.md."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

try:
    import tomllib
except ImportError:  # Python 3.10
    tomllib = None


def load_config(a) -> dict:
    cfg: dict = {}
    if a.config:
        p = Path(a.config)
        cfg = tomllib.loads(p.read_text()) if p.suffix == ".toml" and tomllib else json.loads(p.read_text())
    for key, val in (("robot_id", a.robot), ("mission_id", a.mission), ("time_source", a.time_source), ("queue_size", a.queue),
                     ("drop_policy", a.drop_policy)):
        if val is not None:
            cfg[key] = val
    if a.real or a.synthetic:
        cfg["synthetic"] = bool(a.synthetic)
    if a.topics:
        cfg["topics"] = [*cfg.get("topics", []), *({"name": t} for t in a.topics)]
    if "synthetic" not in cfg:
        raise SystemExit("say what the data is: --real (sensors on a robot) or --synthetic (simulator, test publishers)")
    for need in ("robot_id", "mission_id"):
        if need not in cfg:
            raise SystemExit(f"missing {need} (--robot / --mission or the config file)")
    if not cfg.get("topics"):
        raise SystemExit("no topics: pass --topics '/a' '/sensors/*' (or '*' for all) or list them in the config file")
    return cfg


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="cursiv_ros2")
    sub = ap.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("discover", help="list topics and types on the ROS graph")
    d.add_argument("--wait", type=float, default=2.0)
    c = sub.add_parser("capture", help="capture topics as signed evidence records")
    c.add_argument("--config", help="JSON or TOML file (see docs/ROS2_QUICKSTART.md)")
    c.add_argument("--robot")
    c.add_argument("--mission")
    c.add_argument("--topics", nargs="*", help="topic names or patterns ('*' = all)")
    g = c.add_mutually_exclusive_group()
    g.add_argument("--real", action="store_true", help="data comes from real sensors")
    g.add_argument("--synthetic", action="store_true", help="data comes from a simulator or test publishers")
    c.add_argument("--time-source", help="gnss, ntp, ptp, rtc_synced, rtc_unsynced, monotonic_only, simulated, unknown (default)")
    c.add_argument("--queue", type=int)
    c.add_argument("--drop-policy", choices=["drop_newest", "drop_oldest"])
    c.add_argument("--reliable", action="store_true", help="subscribe with reliable QoS (default best effort)")
    c.add_argument("--station", default="http://127.0.0.1:8750")
    c.add_argument("--token-file")
    c.add_argument("--state", default="cursiv-capture-state", help="folder for the robot key and outbox")
    c.add_argument("--duration", type=float, help="seconds (default: until Ctrl+C)")
    a = ap.parse_args(argv)

    if a.cmd == "discover":
        from .node import list_topics
        for topic, types in list_topics(a.wait):
            print(f"{topic}\t{', '.join(types)}")
        return 0

    from cursiv_sim.client import BridgeClient

    from .agent import StreamingAgent
    from .capture import CaptureConfig, CaptureCore
    from .node import run
    cfg = CaptureConfig.from_dict(load_config(a))
    token = Path(a.token_file).read_text().strip() if a.token_file else None
    agent = StreamingAgent(cfg.robot_id, Path(a.state), BridgeClient(a.station, token=token), mission_id=cfg.mission_id)
    print(f"robot key {agent.identity.key_id[:16]}... (enrol it in the station's trust store before syncing)")
    print(f"public key: {agent.identity.trusted_entry('cursiv-ros2')['public_key']}")
    core = CaptureCore(cfg, agent)
    out = run(core, [t.name for t in cfg.topics], duration_s=a.duration, reliable=a.reliable,
              on_sync=lambda r: print("sync:", r, flush=True))
    print(json.dumps(out, indent=1, default=str))
    return 0 if out["sync"].get("link") == "up" else 1


if __name__ == "__main__":
    sys.exit(main())
