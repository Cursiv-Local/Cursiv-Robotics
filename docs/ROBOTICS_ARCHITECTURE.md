# Architecture

Cursiv Robotics is an evidence layer. It records what robots and sensors observed,
proves later that the records were not changed and who signed them, and checks them
for scientific plausibility. It does **not** navigate, move, perceive or make safety
decisions, and no component can command an actuator.

```
 robot / sensor side                      station side                         anyone, later
 ┌──────────────────────────┐   HTTP    ┌──────────────────────────────┐   files   ┌─────────────────────┐
 │ sensors / ROS 2 topics   │ loopback  │ cursiv-bridge (Rust)         │  package  │ cursiv-verify (Rust)│
 │   ↓ adapter (Python)     │ ───────▶  │  verify signature + trust    │ ───────▶  │  structure          │
 │ RobotAgent               │  signed   │  chain / gap / fork checks   │  signed   │  integrity          │
 │  signs every record      │  records  │  bounded queue → 1 writer    │  manifest │  authenticity       │
 │  durable outbox          │           │  per-robot logs + receipts   │           │  completeness       │
 │  resumable sync          │ ◀───────  │  content-addressed blobs     │           │  attachments        │
 │  signed checkpoints      │  head /   │  station checkpoint, export  │           │ + science (separate)│
 └──────────────────────────┘  results  └──────────────────────────────┘           └─────────────────────┘
```

## Components

| Component | Language | Location | Role |
|---|---|---|---|
| Evidence core | Rust | `crates/cursiv-evidence` | Model, crypto, store, packages, verifier, science, legacy Cursiv export verification |
| Robotics bridge | Rust | `crates/cursiv-bridge` | Headless loopback HTTP service (`docs/openapi.json`) |
| Verification | Rust | `crates/cursiv-verify` | Standalone CLI; no service, GUI or AI |
| Simulation lab | Python | `python/cursiv_sim` | Robot agents, three rovers, faults, demo, benchmarks, ROS 2 boundary |
| Research interface | — | not built | Roadmap: a read-only viewer over packages and reports |

Why Rust for the core: the verifier must be a small, dependency-light, memory-safe
binary that third parties can run anywhere (Windows, Linux, macOS, ARM), and ingestion
must be fast enough for sensor streams. Why Python for robots: the robot side
interoperates with ROS 2 (rclpy) and Cursiv's existing Python ecosystem. Cursiv itself
is not migrated or modified.

## Data model (summary; `crates/cursiv-evidence/src/model.rs`)

- **Observation** (`cursiv-observation-1`): ids, mission, type, `synthetic` (required), sensor + calibration (null = unknown), `sensor_time` + `time_source` + clock quality, location with CRS (EPSG:4326) and accuracy, measurement (value, as-reported text, unit, uncertainty with kind), attachments (sha256, size, media type, role), provenance (source, software, derived_from), processing steps, quality flag with stated basis, optional correction (target + reason).
- **Record** (`cursiv-record-1`): `{robot_id, seq, prev, written_time, observation}`. Signed by the robot.
- **Checkpoint** (`cursiv-checkpoint-1`): `{robot_id, count, head, merkle_root}`. Signed by the robot.
- **Receipt** (`cursiv-receipt-1`): the station's chained note of when each record arrived.
- **Envelope**: `{payload, key_id, public_key, signature}`. The signature covers the exact payload bytes, so no component re-serialises JSON to verify.

## Integrity, authenticity, accuracy, reliability

| Question | Mechanism | Strength |
|---|---|---|
| Record integrity | SHA-256 of payload, `prev` chain, Merkle root in checkpoints, manifest hashes | Any change, removal, insertion or reordering is detected once a signed checkpoint exists |
| Record authenticity | Ed25519 per record and checkpoint, judged against the operator's trust store | Only as strong as key custody; trust store is out of band |
| Completeness | Robot checkpoints and station checkpoint (`count`, Merkle root) | Removal of trailing records is detected only by a trusted checkpoint |
| Scientific plausibility | `science.rs`: ranges, units, calibration, time, region, cross-sensor agreement | Can show inconsistency; **cannot** show correctness |
| Sensor reliability | Not assessed | Calibration metadata is reported, never assumed |

## Ordering and synchronization

- No global clock order is assumed. Order is **per robot** (`seq`, `prev`). The station's receipt chain adds an arrival order that is the station's own claim.
- Ingestion is contiguous per robot. `seq <= count` with the same hash is a **duplicate** (idempotent retry). With a different hash it is **equivocation**: two histories under one key. That happens after a restart with lost state, or a forgery; it is rejected and logged in `incidents.jsonl`. `seq > count + 1` is a **gap**, answered with the expected seq, and the robot resumes from `GET /v1/robots/{id}/head`.
- Offline operation: the robot signs and fsyncs every record to its outbox before sending. Sync is safe to repeat and resumes after partial transfers.
- Corrections are new records referencing the original; originals are never altered.

## Storage and throughput

- One log per robot (no single serialized chain), JSONL, append + `fdatasync` per coalesced batch.
- Bounded queue (`--queue`) to one writer thread; when it is full, writers get `503 Retry-After` (backpressure). Attachments stream to a temp file outside the lock and are renamed in only if length and hash match.
- Recovery on start: a torn final line is cut (and reported); any other corruption stops the service; records missing receipts get late receipts, marked by their time.
- Measured numbers: `docs/ROBOTICS_TEST_RESULTS.md`.

## Trade-offs and decisions

- **Signature per record** costs about 1 KiB of envelope per record (store about 1.7 KiB/record against a 1.0 KiB payload) but lets any subset be checked and pins authorship at the source, not at the station.
- **JSONL instead of a database**: inspectable, appendable, trivially exportable; indexes are rebuilt in memory at start (0.2 s for 20,000 records measured). Very large stores will need segment files and on-disk indexes (roadmap).
- **Trust store as a file**, reloaded at restart: simple and auditable; no enrollment over the network in this version.
- **Science checks are deterministic and profile-driven**: transparent and reproducible, but only as good as the stated profile. Work is bounded (2 million comparisons, 50 listed flags per sensor pair) because the benchmark showed an unbounded check could be driven out of memory.
- **Not reused as code**: Cursiv's Python notebook (one chain per device, full reread per append). Its semantics (append-only, reasoned corrections, signed heads, per-device logs, pinned keys) were kept.
