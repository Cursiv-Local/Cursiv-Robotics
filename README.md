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
| Standalone verifier with five separate verdicts, exit codes and JSON output | Implemented | `crates/cursiv-verify` |
| Loopback ingestion service: Host/Origin checks, token auth off-host, body and batch limits, storage quota, fail-stop on write errors, crash recovery | Implemented | `crates/cursiv-bridge` |
| Science checks: units with conversion, range, calibration validity, timestamps and clock drift, sampling gaps, duplicates, contradictions, missing uncertainty | Implemented | `science.rs`, `units.rs` |
| Derived results recomputed with GUM uncertainty propagation; findings checked against their citations; AI findings never "known" | Implemented | `reasoning.rs` |
| Cursiv package contract v1, reference importer, research workspace | Implemented (Robotics side) | `python/cursiv_integration`, [contract](docs/CURSIV_INTEGRATION.md) |
| Changes inside the Cursiv app (import command, USB discovery, Research panel) | Planned, specified | [contract §Required changes](docs/CURSIV_INTEGRATION.md#required-changes-in-the-cursiv-application-proposed-not-made) |
| Deterministic virtual lab: stationary, ground, underwater, aerial and multi-robot missions with seeded failures | Simulated | `python/cursiv_sim/missions.py`, `missions/` |
| Phone recordings (phyphox on iPhone and Android) to signed evidence and a research dossier | Implemented (real data) | `python/cursiv_field`, [phone guide](docs/PHONE_GUIDE.md) |
| IOOS QARTOD QC (`ioos_qc`), MCAP / ROS 2 recording import | Experimental (optional packages) | `qartod.py`, `mcap_import.py` |
| Live ROS 2 (DDS) node | Planned | `ros2_adapter.py` is a boundary only, untested with ROS 2 |
| Hardware-backed keys (TPM or secure element), real sensors and robots, field networks | Planned (needs hardware) | [roadmap](docs/ROBOTICS_ROADMAP.md) |

## Verify a package yourself

```powershell
cargo build --release
target\release\cursiv-verify package examples\sample-package\sample-buoy-1-package --trust examples\sample-package\trust.json --science
```

| Exit code | Meaning |
|---|---|
| 0 | every verdict passed and every derived result and finding checked out |
| 1 | a verdict failed, or authenticity could not be assessed because no trust store was given |
| 2 | usage error |
| 3 | records authentic and complete, but a derived result or finding is invalid |

## Security model, in short

- Signatures prove *who* wrote a record and that it has not changed since. They do not prove it is true.
- Who is trusted comes only from the operator's trust store, never from the package.
- Checkpoints prove completeness up to a count. The station's receipts add when each record arrived.
- Integrity failures are never repaired silently. Corrections are new records that point at the original.
- The station listens on loopback only unless it has a token of at least 32 characters. TLS is not built in.
- Residual risks are listed in the [threat model](docs/ROBOTICS_THREAT_MODEL.md) and the [audit](docs/AUDIT_2026-11-05.md). They include plaintext key files, no read timeout on the HTTP server, and no external timestamping.

## Tests (2026-11-05)

| Suite | Result |
|---|---|
| Rust unit, fault, property and mutation-fuzz tests (`cargo test --release`) | 43 passed, 0 failed (Linux, Rust 1.97 and 1.82) |
| Clippy, `-D warnings`, all targets | 0 warnings |
| Python (`pytest tests`): bridge, faults, three virtual missions vs expected results, phone importer, Cursiv import, demo | 27 passed, 4 skipped (optional interop packages not installed) |
| `cargo audit` | 0 vulnerabilities, 0 warnings |
| Windows 11 / Windows Server CI | see [test results](docs/ROBOTICS_TEST_RESULTS.md) |

Benchmarks measure software on the test computer, not robot hardware. Results are in
[test results](docs/ROBOTICS_TEST_RESULTS.md) and `bench/results/`. To run them:

```powershell
cargo run --release -p cursiv-evidence --example bench -- 10000 3
```

## What needs physical hardware

The following have to be measured or tested on real hardware:

- real sensor accuracy, drift and calibration
- timing and clock behaviour on a robot computer
- throughput, power and storage endurance on a Raspberry Pi-class board
- radio and acoustic links
- underwater surfacing schedules
- GNSS loss
- key protection in a TPM or secure element
- live ROS 2
- behaviour under vibration, temperature and power loss

The [roadmap](docs/ROBOTICS_ROADMAP.md) lists the hardware milestones.

## Documents

| | |
|---|---|
| [Audit 2026-11-05](docs/AUDIT_2026-11-05.md) | Prioritised findings, fixes and residual risks |
| [Cursiv integration](docs/CURSIV_INTEGRATION.md) | Package contract v1, import rules, exact Cursiv changes |
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
py -m pip install pytest cryptography
py -m pytest tests -q
$env:CURSIV_FUZZ_CASES = 5000; cargo test --release --test properties   # longer mutation fuzzing
```

Every new check needs a test that fails without it. Every simulated value must carry `synthetic: true`.
Do not commit keys: `*.key` files are ignored, and the sample trust store holds simulation keys only.

MIT License. Attribution: [NOTICE.md](NOTICE.md).
