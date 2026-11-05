#!/usr/bin/env bash
# The ROS 2 quick start (docs/ROS2_QUICKSTART.md) as one script: station, simulated publishers,
# capture, export, verify, MCAP view. Needs ROS 2 (Jazzy tested) sourced or in /opt/ros.
# All data is SYNTHETIC. This is a demonstration, not robot validation.
set -euo pipefail
cd "$(dirname "$0")/.."
REPO=$PWD
if [ -z "${ROS_DISTRO:-}" ]; then set +u; source /opt/ros/jazzy/setup.bash; set -u; fi
PY=${CURSIV_ROS_PYTHON:-python3}
WORK=${1:-$(mktemp -d)}
PORT=${CURSIV_PORT:-8750}
cargo build --release -q
cd python
$PY -m cursiv_sim.lab_station --dir "$WORK/station" --robots ros-robot-01 --port "$PORT" & STATION=$!
trap 'kill $STATION 2>/dev/null || true' EXIT
for _ in $(seq 50); do curl -sf "http://127.0.0.1:$PORT/v1/health" >/dev/null && break; sleep 0.2; done
$PY "$REPO/tests/ros2/publishers.py" 20 "$WORK/published.json" & PUB=$!
sleep 2
$PY -m cursiv_ros2 discover | grep /sim/
$PY -m cursiv_ros2 capture --robot ros-robot-01 --mission quickstart --topics '/sim/*' --synthetic \
    --station "http://127.0.0.1:$PORT" --state "$WORK/station/robots" --duration 10 > "$WORK/capture.json"
wait $PUB
curl -sf -X POST "http://127.0.0.1:$PORT/v1/exports" -d '{"name": "quickstart"}' > /dev/null
PKG="$WORK/station/store/exports/quickstart"
"$REPO/target/release/cursiv-verify" package "$PKG" --trust "$WORK/station/trust.json"
if $PY -c "import mcap_ros2" 2>/dev/null; then
  $PY -m cursiv_ros2 mcap-export "$PKG" --trust "$WORK/station/trust.json" --out "$WORK/quickstart.mcap"
fi
echo "QUICKSTART PASSED: package $PKG"
