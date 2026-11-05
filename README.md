# Cursiv Robotics

Offline-first scientific evidence infrastructure for autonomous robots and sensor networks.
It is headless, hardware independent and free, with no cloud, accounts or API keys.

Robots sign every observation they record. A local station stores them in per-robot append-only
logs and exports signed packages. Anyone can then check a package with a standalone verifier,
without the station, a GUI or an AI model. The verifier reports integrity, authenticity,
completeness and scientific plausibility **separately**, because a valid signature never means a
measurement is correct. It also recomputes every derived result, uncertainty included, and checks
every conclusion against the records it cites.

> **Status: pre-hardware.** Everything has run in software only: unit, property, fuzz and fault
> tests, and a deterministic virtual lab with simulated robots. **Nothing has run on a physical
> robot, sensor or Raspberry Pi.** Passing simulations does not show the system is ready to deploy
> on hardware; see [what needs hardware](#what-needs-physical-hardware).

## Try it (Windows 11)

You need [Rust](https://rustup.rs) and [Python 3.10+](https://www.python.org/downloads/), both free.
Then in PowerShell, from this folder:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\demo.ps1
```

On Linux or macOS, run `sh scripts/demo.sh`. Once the tools are built, the demo takes a few seconds:

1. A seeded virtual mission runs: an underwater vehicle, a buoy, a drone and a ground rover, with
   packet loss, corrupt uploads, duplicate sends, sensor dropout and drift, an expired calibration,
   a clock step, a robot shutdown, a station crash and a full disk.
2. The run is compared with the mission's documented expected results, byte for byte down to the signed chain heads.
3. The evidence is packaged, signed and verified independently.
4. A copy is tampered with, and the verifier catches it.
5. Packages are discovered on a "drive" folder and imported into a research workspace. The tampered
   copy is refused and the source is never modified.
6. A report (Markdown, HTML and PDF) cites a signed record for every number and lists every anomaly and uncertainty.

Then open `runs\demo-full\mission\mission-report.html`. All data in it is labelled **SYNTHETIC**.

## Capabilities

**Implemented** means built and tested in software. **Simulated** means exercised only against
simulated robots. **Experimental** means it works but the interface may change. **Planned** means not built yet.

| Capability | Status | Where |
|---|---|---|
| Ed25519 / DSSE-signed records, per-robot hash chains, RFC 6962 Merkle checkpoints | Implemented | `crates/cursiv-evidence` |
| Operator trust store with rotation, validity windows, revocation and live reload; keys never trusted from packages | Implemented | `trust.rs`, `cursiv-bridge` |
| BagIt (RFC 8493) packages with a station-signed manifest; atomic export | Implemented | `package.rs` |
| Segmented logs with station-signed seals (package and store format 2); format 1 still written on request and verified; safe store migration | Implemented | `segment.rs`, `store.rs`, [formats](docs/FORMATS.md) |
| Streaming verification of multi-gigabyte packages (5 GB verified at 194 MiB peak; memory about 80 bytes per record, independent of record size) | Implemented | `verify.rs`, [formats](docs/FORMATS.md#verification-memory) |
| Standalone verifier with five separate verdicts, exit codes and JSON output | Implemented | `crates/cursiv-verify` |
| Loopback ingestion service: Host/Origin checks, token auth off-host, body and batch limits, storage quota, fail-stop on write errors, crash recovery | Implemented | `crates/cursiv-bridge` |
| Science checks: units with conversion, range, calibration validity, timestamps and clock drift, sampling gaps, duplicates, contradictions, missing uncertainty | Implemented | `science.rs`, `units.rs` |
| Derived results recomputed with GUM uncertainty propagation; findings checked against their citations; AI findings never "known" | Implemented | `reasoning.rs` |
| Cursiv package contract v1, reference importer, research workspace | Implemented (Robotics side) | `python/cursiv_integration`, [contract](docs/CURSIV_INTEGRATION.md) |
| Changes inside the Cursiv app (import command, USB discovery, Research panel) | Planned, specified | [contract §Required changes](docs/CURSIV_INTEGRATION.md#required-changes-in-the-cursiv-application-proposed-not-made) |
| Deterministic virtual lab: stationary, ground, underwater, aerial and multi-robot missions with seeded failures | Simulated | `python/cursiv_sim/missions.py`, `missions/` |
| Phone recordings (phyphox on iPhone and Android) to signed evidence and a research dossier | Implemented (real data) | `python/cursiv_field`, [phone guide](docs/PHONE_GUIDE.md) |
| ROS 2 evidence capture node: topic discovery, raw CDR + type + definition + DDS metadata per message, sensor_msgs adapters, bounded queue with signed drop accounting, offline-first | Experimental; integration-tested on ROS 2 Jazzy with simulated publishers, **not on a robot** | `python/cursiv_ros2`, [ROS 2 quick start](docs/ROS2_QUICKSTART.md) |
| MCAP import (any encoding) and export (raw ROS 2 channels, JSON observations, `foxglove.LocationFix`) | Experimental (needs `mcap`, `mcap-ros2-support`) | `cursiv_ros2/mcap_io.py` |
| Converters to W3C PROV-JSON and the OGC SensorThings data model, refusing unverified evidence | Experimental mappings, no conformance claimed | `convert.rs`, [interoperability](docs/INTEROPERABILITY.md) |
| Stable Rust (`cursiv_evidence::api`) and Python (`cursiv_robotics`) APIs, version 1.0.0 | Implemented | [API](docs/API.md) |
| IOOS QARTOD QC (`ioos_qc`) | Experimental (optional package) | `qartod.py` |
| Hardware-backed keys (TPM or secure element), real sensors and robots, field networks | Planned (needs hardware) | [roadmap](docs/ROBOTICS_ROADMAP.md) |

## Verify a package yourself

```powershell
cargo build --release
target\release\cursiv-verify package examples\sample-package\sample-buoy-1-package --trust examples\sample-package\trust.json --science
```

| Exit code | Meaning |
|---|---|
| 0 | status `verified`: every verdict passed and every derived result and finding checked out |
| 1 | status `failed` (a verdict failed) or `incomplete` (authenticity or completeness not established, e.g. no trust store) |
| 2 | usage error |
| 3 | records authentic and complete, but a derived result or finding is invalid |

## Security model, in short

- Signatures prove *who* wrote a record and that it has not changed since. They do not prove it is true.
- Who is trusted comes only from the operator's trust store, never from the package.
- Checkpoints prove completeness up to a count. The station's receipts add when each record arrived.
- Integrity failures are never repaired silently. Corrections are new records that point at the original.
- The station listens on loopback only unless it has a token of at least 32 characters. TLS is not built in.
- A segment seal is station-signed and chains to the previous seal; missing, reordered, duplicated, truncated or altered segments are detected ([formats](docs/FORMATS.md)).
- Converters and the Python API refuse evidence that did not verify; a converted file is a view, not evidence.
- Residual risks are listed in the [threat model](docs/ROBOTICS_THREAT_MODEL.md) and the [audit](docs/AUDIT_2026-11-05.md). They include plaintext key files, no read timeout on the HTTP server, and no external timestamping.

## Installation and compatibility

| | |
|---|---|
| Rust | 1.82 or newer (MSRV tested in CI), from [rustup.rs](https://rustup.rs); `cargo build --release` |
| Python | 3.10+ with `cryptography`. Optional: `mcap`, `mcap-ros2-support` (MCAP), `prov` (PROV tests), `bagit`, `securesystemslib`, `ioos_qc` (interop tests) |
| Operating systems | Linux and Windows (CI: ubuntu-latest, windows-latest). Windows 11 desktop: not tested directly. macOS: not tested |
| ROS 2 | Jazzy on Ubuntu 24.04 (CI and local). Other distributions, DDS vendors and native Windows ROS 2: not tested. On Windows 11 use WSL 2 |
| Network | None needed: offline-first, no cloud, accounts or API keys |

## Supported formats

| Format | Read | Write |
|---|---|---|
| Cursiv package format 2 (segmented, sealed) / format 1 | yes / yes | yes (default) / on request |
| BagIt 1.0, DSSE envelopes, Ed25519 | yes | yes |
| MCAP (ROS 2 CDR decoded; other encodings opaque) | yes (experimental) | yes (experimental) |
| ROS 2 topics (live) | yes (experimental) | no (read-only node) |
| phyphox phone exports | yes | no |
| Cursiv notebook exports (legacy) | verify only | no |
| W3C PROV-JSON, OGC SensorThings data model JSON | no | yes (experimental) |

## Tests (2026-11-05)

| Suite | Result |
|---|---|
| Rust unit, fault, segment, API, property and mutation-fuzz tests (`cargo test --release`) | 55 passed, 0 failed (Linux, Rust 1.97 and 1.82) |
| Clippy, `-D warnings`, all targets | 0 warnings |
| Python (`pytest tests`): bridge, faults, virtual missions, phone importer, Cursiv import, demo, ROS 2 capture core, **live ROS 2 Jazzy graph**, MCAP round trip, API and converters | 44 passed, 1 skipped (`ioos_qc` not installed) |
| ROS 2 quick start (`scripts/ros2_quickstart.sh`) | passed (1,066 records, all verdicts pass) |
| `cargo audit` | 0 vulnerabilities |
| CI (Linux, Windows, Rust 1.82, ROS 2 Jazzy, cargo audit) | see the pull request checks and [test results](docs/ROBOTICS_TEST_RESULTS.md) |

Benchmarks measure software on the test computer, not robot hardware. Results are in
[test results](docs/ROBOTICS_TEST_RESULTS.md), [formats](docs/FORMATS.md#verification-memory) and `bench/results/`. To run them:

```powershell
cargo run --release -p cursiv-evidence --example bench -- 10000 3
cd python; py -m cursiv_sim.bench_scale --sizes-gb 0.1 1 2 --dir D:\bench   # multi-GB; needs 2.2x the size free
```

## Known limitations

- Nothing has run on a physical robot, sensor or single-board computer.
- Station ingest on Windows is slow: 249 records/s on the CI runner (two fsyncs per batch), against about 15,000 records/s on Linux.
- Verification memory grows by about 80 bytes per record (indexes for receipts and duplicate checks), so
  a 50-million-record package would need about 4 GB. Science checks need the records in memory and report
  `not_assessed` above `--max-records`.
- ROS 2 capture: Jazzy rclpy exposes no publisher GID, so upstream loss is attributed only on single-publisher topics.
  Message types not installed on the capturing computer cannot be subscribed (reported, not silently skipped).
  High-bandwidth topics (point clouds, raw images at full rate) are untested.
- PROV, SensorThings and MCAP views cannot carry signatures or seals; the package stays the evidence.
- The HTTP server has no read timeout (use a reverse proxy off-host); key files are plaintext; no external timestamping.

## What needs physical hardware

The following have to be measured or tested on real hardware:

- real sensor accuracy, drift and calibration
- timing and clock behaviour on a robot computer
- throughput, power and storage endurance on a Raspberry Pi-class board
- radio and acoustic links
- underwater surfacing schedules
- GNSS loss
- key protection in a TPM or secure element
- ROS 2 capture on a real robot's graph (rates, DDS vendors, network partitions)
- behaviour under vibration, temperature and power loss

The [roadmap](docs/ROBOTICS_ROADMAP.md) lists the hardware milestones.

## Documents

| | |
|---|---|
| [Audit 2026-11-05](docs/AUDIT_2026-11-05.md) | Prioritised findings, fixes and residual risks |
| [Developer APIs](docs/API.md) | Stable Rust and Python APIs, status and errors, stability labels |
| [Formats](docs/FORMATS.md) | Package and store formats 1 and 2, segment seals, migration, verification memory |
| [Interoperability](docs/INTEROPERABILITY.md) | ROS 2, MCAP, Foxglove, PROV, SensorThings mappings and what each loses |
| [ROS 2 quick start](docs/ROS2_QUICKSTART.md) | Capture topics as verifiable evidence |
| [Cursiv integration](docs/CURSIV_INTEGRATION.md) | Workspace contract v1 (package formats 1 and 2), import rules, exact Cursiv changes |
| [Simulation guide](docs/ROBOTICS_SIMULATION_GUIDE.md) | Virtual lab, missions, faults, expected results |
| [Phone guide](docs/PHONE_GUIDE.md) | Real recordings from an iPhone or Android phone |
| [Architecture](docs/ROBOTICS_ARCHITECTURE.md) · [API](docs/ROBOTICS_API.md) · [OpenAPI](docs/openapi.json) | Components, data model, interfaces |
| [Threat model](docs/ROBOTICS_THREAT_MODEL.md) | Trust boundaries, controls, residual risks |
| [Test results](docs/ROBOTICS_TEST_RESULTS.md) | Measured results and benchmarks |
| [Prior art](docs/ROBOTICS_PRIOR_ART.md) · [Code audit of Cursiv](docs/ROBOTICS_CODE_AUDIT.md) | What exists elsewhere and what was reused |
| [Roadmap](docs/ROBOTICS_ROADMAP.md) | Next milestones |

## Contributing and testing

```powershell
cargo test --release
cargo clippy --release --all-targets -- -D warnings
py -m pip install pytest cryptography mcap mcap-ros2-support prov
py -m pytest tests -q
$env:CURSIV_FUZZ_CASES = 5000; cargo test --release --test properties   # longer mutation fuzzing
```

Every new check needs a test that fails without it. Every simulated value must carry `synthetic: true`.
Do not commit keys: `*.key` files are ignored, and the sample trust store holds simulation keys only.

MIT License. Attribution: [NOTICE.md](NOTICE.md).
