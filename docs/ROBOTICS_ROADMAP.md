# Roadmap

Documented, not implemented. The order reflects what real deployments need first.

## Done since the first milestone

- Real data without hardware: phone recordings (phyphox) to signed evidence and a research dossier for Cursiv (`docs/PHONE_GUIDE.md`). Format fixtures follow phyphox's exporter; a real export from the owner's phone is the next validation.
- Pre-hardware hardening (2026-11-05, `docs/AUDIT_2026-11-05.md`): storage quota, fail-stop, atomic export, live trust reload, units and GUM uncertainty propagation, duplicate/gap/timestamp checks, deterministic virtual missions (stationary, ground, underwater, aerial, multi-robot), Cursiv package contract v1 with a reference importer, property and mutation fuzz tests, Rust benchmark, CI on Linux and Windows with `cargo audit` and Rust 1.82.

- Interoperability and scalability (2026-11-05): segmented logs with seals and streaming verification (5 GB at 194 MiB), store migration, ROS 2 capture node (Jazzy, simulated publishers), MCAP import/export, PROV-JSON and SensorThings converters, stable Rust and Python APIs v1.

## Next milestone (recommended)

**One real sensor, end to end, on Windows and a Raspberry Pi.** For example a USB or I²C temperature or
humidity sensor read by a small Python agent with `synthetic: false`, a stated real time source (NTP or
GNSS), and a calibration record from an actual reference check. Run it for 72 hours with a deliberately
flaky link. Success means:
- every reading is verifiable with `cursiv-verify` by someone else, using only the package and a trust store;
- the clock-drift and calibration flags behave on real data;
- the same build passes on a Windows 11 desktop (CI covers Windows Server only).

Alongside it:
- CI on macOS, and `cargo deny` for licences.
- Make the Cursiv-side integration changes (`docs/CURSIV_INTEGRATION.md`), with the owner's approval.
- Streaming verification (memory independent of package size) and a read timeout or reverse proxy for off-host use.
- Live ROS 2 (Jazzy) test of `Ros2Forwarder` against `sensor_msgs` publishers in a container.
- Segment files (rotate `records.jsonl` per N records, each sealed by a checkpoint), so very long missions do not need whole-log reads at start.

## Integrity and trust

- External anchoring of station checkpoints in the **C2SP tlog-checkpoint** signed-note format, so independent **transparency-dev witnesses** (or a Tessera log) can cosign them; RFC 3161 timestamps as an alternative. This closes the "station rewrites everything with its own key" gap. Our Merkle tree is already RFC 6962-style; the leaf input must be fixed as the 32-byte record hash for tlog compatibility.
- Optional submission of DSSE records to Sigstore Rekor, for projects that accept an online public log.
- C2PA (Content Credentials) verification of camera images that carry manifests (c2pa-rs).
- Hardware-backed keys: TPM 2.0 on PCs, secure elements on embedded boards, Windows DPAPI as Cursiv uses.
- Signed key-rotation statements (old key authorises new key) instead of trust-store edits alone.
- At-rest encryption of the store (reuse Cursiv's vault design).

## Interfaces (standards first)

| Target | Approach |
|---|---|
| ROS 2 | MCAP import exists and is tested on real CDR messages; live `rclpy` forwarder exists, unverified |
| MAVLink (drones) | read-only telemetry adapter via pymavlink; no command messages |
| Underwater vehicles | adapters for vendor telemetry (e.g. Blue Robotics/ArduSub via MAVLink); sonar and imagery as attachments |
| MQTT sensor networks | subscriber adapter; each sensor node holds its own key where possible |
| Research stations | Cursiv Field Station (`cursiv_engine/station`) as the bridge host once it has been validated on hardware |
| Metadata standards | export to OGC SensorThings (FROST-Server) and W3C PROV-JSON (`prov` library, MIT); CF conventions/UDUNITS for units; QARTOD flags as `resultQuality` |
| Other black-box recorders | robot-black-box (MIT) shares the separate-verdict design; explore a shared DSSE-based exchange format |
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
