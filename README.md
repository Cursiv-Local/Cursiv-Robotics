# Cursiv Robotics

Offline-first scientific evidence infrastructure for autonomous robots and sensor networks.
It is headless and hardware independent, and it is built from Cursiv's notebook integrity design.

Robots sign every observation they record. A loopback service stores them in per-robot
append-only logs. Anyone can later check an exported evidence package with a standalone verifier,
without the service, a GUI or an AI model. Integrity, authenticity, completeness and scientific
plausibility are reported **separately**. A valid signature never means a measurement is correct.

Cursiv Robotics does not move, steer or command robots. It sits beside the manufacturer's
navigation and safety systems and only records what they report.

**Status: first milestone.** Three simulated research robots submit independently verifiable
observations. Deliberately corrupted evidence is detected (15/15 fault scenarios). Nothing has run on
physical robots yet. Live ROS 2 integration is unverified, and Windows has not been tested yet.

```bash
cargo build --release
python3 -m pip install cryptography pytest
cd python && python3 -m cursiv_sim.demo        # 11-step demonstration, all data SYNTHETIC
```

| Document | |
|---|---|
| [Code audit](docs/ROBOTICS_CODE_AUDIT.md) | What Cursiv has, what was reused, what was missing |
| [Architecture](docs/ROBOTICS_ARCHITECTURE.md) | Components, data model, trade-offs |
| [Threat model](docs/ROBOTICS_THREAT_MODEL.md) | Trust boundaries, controls, residual risks |
| [API](docs/ROBOTICS_API.md) · [OpenAPI](docs/openapi.json) | Ingestion API and CLIs |
| [Simulation guide](docs/ROBOTICS_SIMULATION_GUIDE.md) | Demo, faults, writing an agent |
| [Test results](docs/ROBOTICS_TEST_RESULTS.md) | Measured results and benchmarks |
| [Roadmap](docs/ROBOTICS_ROADMAP.md) | Next milestones and standards |

| Path | |
|---|---|
| `crates/cursiv-evidence` | Rust core: model, Ed25519, store, packages, verifier, science, Cursiv-export verification |
| `crates/cursiv-bridge` | Loopback HTTP ingestion service |
| `crates/cursiv-verify` | Standalone verifier CLI |
| `python/cursiv_sim` | Simulation lab, robot agent, ROS 2 adapter boundary, faults, benchmarks |

MIT License. Attribution: [NOTICE.md](NOTICE.md).
