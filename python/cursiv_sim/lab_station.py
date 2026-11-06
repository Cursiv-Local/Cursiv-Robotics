"""Run a local station (cursiv-bridge) for development, with robot keys enrolled.

    python -m cursiv_sim.lab_station --dir ~/cursiv-station --robots ros-robot-01 [--port 8750]

Creates the station key, the robot keys (in <dir>/robots/<id>/robot.key) and the trust store
(<dir>/trust.json), starts the bridge on 127.0.0.1 and runs until Ctrl+C. Development only:
real deployments enrol keys deliberately (docs/ROBOTICS_THREAT_MODEL.md).
"""
from __future__ import annotations

import argparse
import signal
import time
from pathlib import Path

from .lab import Lab


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="cursiv_sim.lab_station")
    ap.add_argument("--dir", required=True)
    ap.add_argument("--robots", nargs="+", required=True)
    ap.add_argument("--port", type=int, default=8750)
    a = ap.parse_args(argv)
    lab = Lab(Path(a.dir).expanduser(), a.robots)
    lab.port = a.port
    from .client import BridgeClient
    lab.client = BridgeClient(f"http://127.0.0.1:{a.port}")
    lab.enrol()
    # stop the bridge on SIGTERM too (kill, service managers), not only on Ctrl+C
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    lab.start()
    print(f"station on http://127.0.0.1:{a.port}; trust store {lab.trust_path}; exports in {lab.dir / 'store' / 'exports'}", flush=True)
    try:
        while lab.proc and lab.proc.poll() is None:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        lab.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
