# Roadmap

Documented, not implemented. The order reflects what real deployments need first.

## Next milestone (recommended)

**One real sensor, end to end, on Windows and a Raspberry Pi.** For example a USB or I²C temperature or
humidity sensor read by a small Python agent with `synthetic: false`, a stated real time source (NTP or
GNSS), and a calibration record from an actual reference check. Run it for 72 hours with a deliberately
flaky link. Success means:
- every reading is verifiable with `cursiv-verify` by someone else, using only the package and a trust store;
- the clock-drift and calibration flags behave on real data;
- the Windows build and tests pass.

Alongside it:
- CI: `cargo test`, `cargo clippy`, `cargo audit`/`cargo deny`, pytest, on Windows, Linux and macOS.
- Live ROS 2 (Jazzy) test of `Ros2Forwarder` against `sensor_msgs` publishers in a container.
- Segment files (rotate `records.jsonl` per N records, each sealed by a checkpoint), so very long missions do not need whole-log reads at start.

## Integrity and trust

- External anchoring of station checkpoints: an RFC 3161 timestamp authority, or a transparency log witnessed by another station. This closes the "station rewrites everything with its own key" gap.
- Hardware-backed keys: TPM 2.0 on PCs, secure elements on embedded boards, Windows DPAPI as Cursiv uses.
- Signed key-rotation statements (old key authorises new key) instead of trust-store edits alone.
- At-rest encryption of the store (reuse Cursiv's vault design).

## Interfaces (standards first)

| Target | Approach |
|---|---|
| ROS 2 | `rclpy` forwarder (exists, unverified); rosbag2 (MCAP) import with per-message provenance |
| MAVLink (drones) | read-only telemetry adapter via pymavlink; no command messages |
| Underwater vehicles | adapters for vendor telemetry (e.g. Blue Robotics/ArduSub via MAVLink); sonar and imagery as attachments |
| MQTT sensor networks | subscriber adapter; each sensor node holds its own key where possible |
| Research stations | Cursiv Field Station (`cursiv_engine/station`) as the bridge host once it has been validated on hardware |
| Metadata standards | map the observation model to OGC SensorThings / Observations & Measurements, W3C PROV for provenance, CF conventions for units and variables |
| Space data | review CCSDS (Space Packet Protocol, Bundle Protocol for delay-tolerant networking, CCSDS 650 OAIS for archives) before designing anything new; packages are already store-and-forward friendly |

## Scale and operations

- Multi-station federation: stations exchange packages and verify each other's checkpoints; per-robot histories merge without reordering, as now.
- Delay-tolerant links: bundle-based transfer of segments, with resumable attachment upload by byte range.
- Fleet dashboards (a research interface): read-only views of packages, verification and science reports. Never a control surface.
- Long-duration field stations: power-loss testing on real storage, wear-aware write batching.

## Science

- Profiles per mission and instrument (ranges, units, comparison radii) maintained by scientists, versioned and signed.
- Unit conversion via a shared library (reuse Cursiv's `fieldcalc` logic).
- AI-assisted interpretation, only as labelled annotations citing observation ids and never as validation. Imported metadata is treated as data (prompt-injection safe).

## Exploration (long term, no claims yet)

Lunar and Martian operations need radiation-tolerant hardware, CCSDS-aligned links, hours-to-days of
delay and autonomous operation without a station. The evidence model (per-robot signed logs,
checkpoints, offline-first sync, independent verification) is designed so it would not need to
change, but nothing here has been tested beyond simulation on Earth.
