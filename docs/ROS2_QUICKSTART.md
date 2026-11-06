# ROS 2 quick start (experimental)

The capture node subscribes to the topics you choose and turns every message into a signed evidence record:
- the exact serialized bytes
- the message type and its full definition
- DDS timestamps and sequence numbers
- a decoded value where an adapter exists

It is read-only. It creates no publishers, services or actions. It subscribes with best-effort QoS by
default, so it never makes a publisher wait. Its callback never blocks: a bounded queue absorbs
bursts, and anything it cannot keep is counted in signed `capture_accounting` records.

**Tested:**
- ROS 2 Jazzy (Ubuntu 24.04) with simulated publishers in a separate process, in `tests/test_ros2.py`
- Temperature, Imu, NavSatFix, String and CompressedImage at 2–100 Hz

**Not tested:**
- on a physical robot
- with other ROS 2 distributions or DDS vendors
- at high bandwidth, such as point clouds or raw camera images at full rate

The steps below are `scripts/ros2_quickstart.sh`, which CI runs.

## 1. Install (Ubuntu 24.04 or WSL 2 on Windows 11)

```bash
sudo curl -sSL https://raw.githubusercontent.com/ros/rosdistro/master/ros.key -o /usr/share/keyrings/ros-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/ros-archive-keyring.gpg] http://packages.ros.org/ros2/ubuntu noble main" | sudo tee /etc/apt/sources.list.d/ros2.list
sudo apt-get update && sudo apt-get install -y ros-jazzy-ros-base ros-jazzy-sensor-msgs python3-cryptography
cargo build --release
```

On Windows 11, install ROS 2 inside WSL 2 (Ubuntu 24.04). Native Windows ROS 2 has not been tested with this node.

## 2. Start a station and the demo publishers

```bash
source /opt/ros/jazzy/setup.bash
cd python
python3 -m cursiv_sim.lab_station --dir ~/cursiv-station --robots ros-robot-01 &   # development station with keys enrolled
python3 ../tests/ros2/publishers.py 60 /tmp/published.json &                       # simulated sensors, 60 s
python3 -m cursiv_ros2 discover
```

## 3. Capture

```bash
python3 -m cursiv_ros2 capture --robot ros-robot-01 --mission lab-1 --topics '/sim/*' --synthetic \
    --station http://127.0.0.1:8750 --state ~/cursiv-station/robots --duration 30
```

- **Real or synthetic:** `--real` or `--synthetic` is required. The evidence must say whether it
  came from real sensors or a simulator.
- **Time source:** `--time-source ntp|ptp|gnss|...` states how the publishing computers' clocks are
  disciplined. The default is `unknown`.
- **Queue:** `--queue N` and `--drop-policy drop_newest|drop_oldest` control backpressure.
- **QoS:** `--reliable` subscribes with reliable QoS.
- **Config file:** a JSON or TOML file can set everything per topic, including observation type,
  sensor id, calibration and `location_source` for a NavSatFix topic:

```toml
robot_id = "ros-robot-01"
mission_id = "lab-1"
synthetic = false
time_source = "ntp"
queue_size = 5000
[[topics]]
name = "/ctd/temperature"
observation_type = "water_temperature"
sensor_id = "ros-robot-01-ctd"
calibration = { calibrated_utc = "2026-10-01T00:00:00Z", valid_until_utc = "2027-10-01T00:00:00Z", reference = "lab bath", certificate_sha256 = "" }
[[topics]]
name = "/gps/fix"
location_source = true
```

The robot key is created in `--state/<robot>/robot.key`. Enrol its public key in the station's trust store before
syncing; the node prints it. Capture continues while the station is offline. Records and payloads wait in the
outbox and are sent when the link returns.

## 4. Verify and view

```bash
curl -s -X POST http://127.0.0.1:8750/v1/exports -d '{"name": "lab-1"}'
../target/release/cursiv-verify package ~/cursiv-station/store/exports/lab-1 --trust ~/cursiv-station/trust.json
python3 -m cursiv_ros2 mcap-export ~/cursiv-station/store/exports/lab-1 --trust ~/cursiv-station/trust.json --out lab-1.mcap
```

`lab-1.mcap` holds the original ROS 2 messages on their topics, JSON observations and `foxglove.LocationFix`.
See [INTEROPERABILITY.md](INTEROPERABILITY.md) for what an MCAP view cannot carry.

## What the accounting tells you

Per topic, the `capture_accounting` records report:

| Counter | Meaning |
|---|---|
| `received` | Messages that reached the node |
| `recorded` | Messages that became signed records |
| `dropped_queue_full` | Lost to backpressure (queue full) |
| `dropped_too_large` | Above `max_payload_bytes` (default 8 MiB) |
| `decode_errors` | Recorded opaque because decoding failed |
| `record_errors` | Could not be recorded at all (error text in the capture result) |
| `lost_upstream` | Gaps in the publisher's sequence numbers (single-publisher topics only) |
| `before_capture` | Sent before capture began |
| `loss_unassessable` | Several publishers on one topic: rclpy on Jazzy exposes no publisher GID, so gaps cannot be attributed |
