# Test results

Recorded 2026-11-05. Every figure below was measured; nothing is estimated. Local runs used a Linux cloud
container; Windows results come from GitHub Actions (`windows-latest`, Windows Server) running
`.github/workflows/ci.yml`. **No test ran on a robot, sensor or single-board computer.** Windows 11 on a
desktop has not been tested directly; Windows Server CI is the closest check available here.

## Environment

| | |
|---|---|
| CPU | Intel Xeon Processor @ 2.10 GHz, 4 logical CPUs |
| Memory | 15.7 GiB |
| OS | Linux 6.18 x86_64, glibc 2.39 (Ubuntu 24.04) |
| Rust | rustc 1.97.0 and 1.82.0 (minimum supported), `cargo --release` |
| Python | 3.13.18, cryptography; optional: bagit 1.9.0, securesystemslib 1.6.0, mcap 1.6.0, mcap-ros2-support 0.6.0, ioos_qc 3.0.0 |
| ROS 2 | not installed |

## Automated tests (pre-hardware hardening, local)

| Suite | Command | Result |
|---|---|---|
| Rust unit tests | `cargo test --release` | 7 passed |
| Rust evidence and fault tests (`tests/faults.rs`): tampering, forks, keys, quota, fail-stop, concurrent blobs, atomic export, trust reload, units, duplicates, gaps, uncertainty propagation | `cargo test --release` | 25 passed |
| Rust property and mutation fuzz tests (`tests/properties.rs`): 7 proptest properties × 256 cases, 150 seeded byte mutations (1,500 also run: all detected), every file deleted, neighbouring files swapped | `cargo test --release` | 11 passed |
| Same suites on the minimum supported Rust | `cargo +1.82 test --locked --workspace` | 43 passed |
| Clippy | `cargo clippy --release --all-targets -- -D warnings` | 0 warnings |
| Dependency advisories | `cargo audit` (0.22.2, 1,409 advisories, 67 crates) | 0 vulnerabilities, 0 warnings |
| Python (`pytest tests`): bridge defences, quota and trust reload, all faults, demo, three virtual missions against their expected results, phone importer incl. zip bombs, Cursiv integration (incl. ingestion by Cursiv's `documents.py`), one-command demo | `python3 -m pytest tests -q` | 27 passed, 4 interop skipped (optional packages not installed in this run) |
| Interoperability (`tests/test_interop.py`, optional packages installed; earlier run on this branch's base) | `python3 -m pytest tests -q` | 4 passed |
| One-command demo | `python python/cursiv_demo` | DEMO PASSED: expected results identical, tampering detected (5 error codes), tampered copy refused at import, source unchanged |

## Faster record transfer (2026-11-06)

Raw data: `bench/results/2026-11-06-linux-transfer.json` (medians of 3 runs; before and after built from the same branch
on the same 4-vCPU Linux container, which is about half as fast as the one used on 2026-11-05).

| Path | Batch | Before (records/s) | After (records/s) |
|---|---|---|---|
| Station ingest (store API) | 100 | 7,341 | 14,613 |
| Station ingest (store API) | 1,000 | 8,270 | 17,198 |
| Station ingest (store API) | 1 / 10 | 1,261 / 4,553 | 1,221 / 4,616 (flush-bound; below the parallel threshold) |
| Robot outbox to station over HTTP (loopback) | 100 | 4,733 | 9,435 |
| Robot outbox to station over HTTP (loopback) | 500 | 5,252 | 11,210 |

What changed:
- **Parallel checks.** Signature verification was 84% of per-record station CPU (63 of 75 µs). The stateless checks
  now run across threads for batches of 32 or more; the stateful checks stay in order. `parallel_batch_checks_match_one_at_a_time`
  proves the outcomes are identical, with bad signatures, invalid observations, duplicates and gaps mixed in.
- **Cheaper serial path.** Receipt hashes are computed without building a JSON tree, with byte-identical results
  (`receipt_hash_is_unchanged`); leaf hashes and record lines come from the parallel stage.
- **Single parse.** The bridge parses a batch straight into envelopes. Agents send stored lines unchanged.
- **gzip.** Request bodies are accepted gzip-encoded, with the decompressed size capped (bombs get 413). Records are
  9.0 times smaller at level 6. The client compresses automatically when the station is not on loopback.
- **Tried and rejected:** HTTP keep-alive was 3.9 times slower with tiny_http, which does not set TCP_NODELAY and so
  waits for delayed ACKs.

On a slow link the wire size dominates. At 1 Mbit/s (125,000 bytes/s) that is about 71 records/s uncompressed and
about 640 records/s with gzip. These are computed from the measured 1,754 bytes per record and the 9.0x ratio, not
measured over a real radio, and ignore protocol overhead.

## Interoperability and scalability upgrade (2026-11-05, branch claude/interop-scalability)

| Suite | Result |
|---|---|
| Rust (`cargo test --release`): unit 8, faults 25, segments 7, API and converters 3, properties 11, doc test 1 | 55 passed, 0 failed; also on Rust 1.82 |
| `tests/segments.rs` | missing, reordered, duplicated, tampered, truncated, unsealed and swapped-seal segments all fail verification in both memory modes; standalone segment checks; format-1 packages and the committed sample still verify; store migration keeps bytes; rotation survives restarts and interrupted seal writes; read failures and unsupported versions never give "verified" |
| `tests/test_ros2.py` (live ROS 2 Jazzy, simulated publishers in another process) | passed: 5 topics; on every topic published = received + before_capture + lost (lost 0); recorded = received; 75 Temperature values equal their raw CDR; package verified; exported MCAP decodes with mcap-ros2-support without ROS |
| `tests/test_ros2_core.py`, `tests/test_mcap.py`, `tests/test_api.py` | 6 + 2 + 5 passed (backpressure and accounting, offline-first sync, MCAP round trip incl. a JSON channel, PROV parsed by the `prov` library) |
| `scripts/ros2_quickstart.sh` | passed: 1,066 records, every verdict pass |
| All Python (`pytest tests`) | 44 passed, 1 skipped (`ioos_qc`) |

Streaming verification benchmark (format 2, 3 robots, about 2 KB per record):

| Package | Records | Verify (s) | MB/s | Peak RSS streaming (MiB) | Peak RSS with records kept (MiB) |
|---|---|---|---|---|---|
| 0.1 GB | 50,199 | 2.74 | 36.5 | 28.8 | 142.1 |
| 1.0 GB | 502,008 | 27.23 | 36.8 | 50.1 | 1,484.3 |
| 2.0 GB | 1,004,016 | 53.26 | 37.7 | 96.4 | not run |
| 5.0 GB | 2,510,040 | 131.71 | 38.1 | 194.3 | not run |

CI on this branch (commit d4bea24, GitHub Actions):

| Job | Result |
|---|---|
| ubuntu-latest: build, Rust tests, clippy, pytest, sh demo, benchmark | passed |
| windows-latest: build, Rust tests, clippy | passed |
| windows-latest: pytest | 42 passed, 3 skipped (no Cursiv checkout, no `ioos_qc`, no ROS 2 on Windows) |
| windows-latest: `scripts/demo.ps1` | passed after a fix: its first full Windows run showed PowerShell 5.1 aborting on stderr from native commands (d4bea24) |
| Rust 1.82, cargo audit | passed |
| ROS 2 Jazzy (ubuntu-24.04): live-graph test, capture core, MCAP, `scripts/ros2_quickstart.sh` | passed on 42946e9 |

**Windows ingest is slow.** The CI benchmark (15,000 records) ingested 249 records/s on windows-latest, with batch-of-100
latency p50 79 ms, p95 1.6 s, p99 2.7 s. On Linux it is about 15,000 records/s. Verification on Windows ran at
11,084 records/s. The cost is the two fsyncs per batch (segment file and receipts), which are slow on that runner.
The simulated robots' per-record fsync is slow in the same way, which is why the Windows Python suite takes about
4.5 minutes. Not measured on a Windows 11 desktop. Grouping commits across batches is the obvious fix (roadmap).

Raw data: `bench/results/2026-11-05-linux-scale-streaming.json`. Linux cloud container, 4 vCPUs. This is software
on that computer, not robot hardware. The earlier format-1 verifier kept every record, about 3.3 KiB per record:
486 MiB for 150,000 records.

## Windows (GitHub Actions, `windows-latest`, Python 3.12.10)

| Check | Result |
|---|---|
| `cargo build --release`, `cargo test --release` (43 tests), clippy `-D warnings` | passed (runs 2 and 6) |
| `pytest tests` | **28 passed, 3 skipped in 406.89 s** (run 2, commit 881756a). This includes the three virtual missions, which reproduce the same signed chain heads as on Linux, so the floating-point concern (audit R7) did not occur. |
| `scripts\demo.ps1` | **not confirmed yet**: run 2 was cancelled as this step started, and run 6 had not reached it when this was written |

The Windows Python suite took about 10 times as long as on Linux (407 s vs about 40 s). The cause has not
been investigated; per-request fsync and process start-up on Windows are the likely candidates.

Run 1 found two real Windows defects. Git's line-ending conversion broke the signed fixtures (fixed with
`.gitattributes`, audit F16), and a symlink test assumed Linux.

## Virtual missions (simulated; `python -m cursiv_sim.missions run missions/<m>.json --check`)

Each mission is seeded, so a run reproduces its `*.expected.json` exactly, signed chain heads included.

| Mission | Platforms | Records | Injected failures (observed handling) | Science flags | Check |
|---|---|---|---|---|---|
| coastal-survey | buoy, AUV, drone, rover + analysis | 1,443 | 6 duplicate sends acknowledged; 50 corrupt uploads rejected; 53 packet losses retried; 20 station-full refusals; 1 robot restart; 1 station crash | calibration_expired 56, contradiction 5, duplicate_content 7, out_of_order_time 2, sampling_gap 1 | identical |
| buoy-baseline | analysis-01, buoy-02 | 488 | none (control) | none of: calibration_expired, sampling_gap, duplicate_content, out_of_order_time, contradiction, out_of_range, clock_drift, sensor_time_after_write, unit_mismatch | identical |
| drone-survey | analysis-01, drone-02 | 487 | corrupt uploads rejected 63; packet losses 48 | none of: out_of_range, contradiction, duplicate_content | identical |

## Fault scenarios (observed output)

| # | Scenario | Observed |
|---|---|---|
| 1 | Altered measurement | exit 1; integrity=fail; `chain`, `file_changed`, `record_signature` |
| 2 | Modified attachment | exit 1; attachments=fail; `attachment_changed` |
| 3 | Missing observation (last record) | exit 1; completeness=fail; `records_missing`, `station_count_mismatch` |
| 4 | Duplicate observation | resend → 200 duplicate; reused id → 409 `duplicate_observation_id` |
| 5 | Out-of-order timestamp | 1 `out_of_order_time` flag; integrity=pass |
| 6 | Sensor clock drift | `clock_drift` flagged for rover-02 only |
| 7 | Communication failure | bridge 43 → 43 while offline (18 queued on robot) → 61 after reconnect |
| 8 | Contradictory measurements | one contradiction group: `air_temperature: rover-02-pt100 vs rover-03-thermo` |
| 9 | Interrupted transfer | cut-off upload → 400; blob not present; full retry → 201 |
| 10 | Corrupted export | exit 1; `file_changed`, `receipts_mismatch`, `truncated_file` |
| 11 | Rebuilt hash chain | with trust store: authenticity=fail; without: authenticity=not_assessed, exit 1 |
| 12 | Untrusted key | impostor → 403 `untrusted_key`; forged signature → 400 `bad_signature`; incident logged |
| 13 | Partial sync | dropped after 20 → bridge 62/90; resumed → 90/90 |
| 14 | Restart | robot resumed from disk; lost-state fork refused by robot and bridge (409 `equivocation`); after station `kill -9` + restart, 181/181 |
| 15 | High-volume burst | 10 robots × 2,000 records in 1.61 s (12,395 records/s), 5 backpressure retries, 20,000 stored |
| 16 | Validly signed but wrong derived result | exit 3; integrity=pass; recomputed: 1 verified, 1 mismatch |
| 17 | Over-claimed findings | statuses well_supported, invalid, invalid; `ai_claim_marked_known`, `unsupported_claim` |

## Demo (30 steps)

Clean package: all five verdicts pass. Edited copy: integrity fail (`file_changed`, `record_signature`,
`chain`, `checkpoint_mismatch`). Offline rover-01 queued 45 records; the first reconnect dropped at 57/90;
the resumed sync delivered 33, giving 90/90. Final package: all verdicts pass. 240 synthetic observations.
Science found one contradiction group (the deliberately biased rover-03 thermometer against rover-02).

## Performance (`python -m cursiv_sim.bench`; current format: DSSE records, BagIt packages)

Raw data: `bench/results/2026-11-05-linux-cloud-container-dsse-bagit.json` (the earlier
custom-envelope run is kept in `bench/results/2026-11-05-linux-cloud-container.json`). Configuration: queue 256,
8 HTTP workers, client threads = min(32, agents), batches of 100, fsync per coalesced batch.
**Simulated agents are threads signing records on one computer, not robots.**

| Agents | Records | Client signing (rec/s) | Ingest (rec/s) | Batch latency p50 / p95 (ms) | Verify incl. science (rec/s) | Store B/record | Payload B/record | Restart after kill (s) | Bridge peak RSS (MiB) | Bridge CPU (s) |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 5,000 | 2,808 | 9,145 | 10.64 / 12.38 | 7,822 | 1,961 | 1,025 | 0.052 | 13.2 | 0.44 |
| 3 | 9,000 | 2,811 | 11,184 | 26.07 / 31.52 | 7,332 | 1,961 | 1,025 | 0.102 | 15.1 | 0.78 |
| 10 | 10,000 | 2,937 | 10,935 | 78.26 / 143.85 | 7,838 | 1,959 | 1,024 | 0.102 | 17.2 | 0.91 |
| 100 | 20,000 | 2,976 | 11,374 | 262.67 / 340.05 | 9,905 | 1,957 | 1,023 | 0.203 | 20.9 | 1.81 |
| 1,000 | 20,000 | 3,079 | 8,601 | 73.25 / 86.51 | 9,634 | 1,951 | 1,020 | 0.254 | 38.1 | 4.62 |

- Attachments: 50 × 1 MiB uploads at 198.5 MiB/s.
- Sync after an outage: 5,000 buffered records delivered in 0.525 s.
- Storage overhead: about 1.9× the payload. Moving to DSSE (base64 payload) raised it from about 1.75 KiB to 1.96 KiB per record; ingest and verify throughput are within run-to-run variation of the earlier run.
- The single-threaded Python client (signing about 3,300 records/s) is slower than the bridge; batch latency at 10–100 agents is mostly queueing behind 32 concurrent client threads.

## Rust core benchmark (`cargo run --release -p cursiv-evidence --example bench -- N 3`)

One process and three robots, in batches of 100 with an fsync per batch. Raw data: `bench/results/2026-11-05-linux-rust-*.json`.
**This measures software on a 4-vCPU cloud container. It says nothing about any robot computer.**

| Records | Package | Sign (rec/s) | Ingest (rec/s) | Batch p50 / p99 (ms) | Export (s) | Verify (rec/s) | Reopen after stop (s) | Peak RSS, bench (MiB) | Peak RSS, `cursiv-verify` alone (MiB) |
|---|---|---|---|---|---|---|---|---|---|
| 3,000 | 6.0 MB | 45,334 | 14,484 | 6.7 / 11.3 | 0.018 | 17,324 | 0.023 | 19.8 | 13.1 |
| 30,000 | 59.7 MB | 45,661 | 15,902 | 6.0 / 8.7 | 0.189 | 17,157 | 0.287 | 164.1 | 100.8 |
| 150,000 | 299.0 MB | 46,449 | 15,675 | 6.2 / 8.4 | 0.762 | 17,047 | 1.557 | 803.8 | 486.3 |

- Verifier memory grows linearly, at about 3.3 KiB per record, because the verifier holds every record in memory (audit R4).
- The standalone verifier ran without a trust store, so it exited 1 (authenticity not assessed). That is the designed behaviour.
- The 3 `clock_drift` flags are correct: the benchmark's sensor times are about 10 days earlier than the station's receipt times.

## Defect found by the benchmark and fixed

At 3 agents × 3,000 co-located readings the verifier's cross-sensor check produced 13.9 million
contradiction pairs and was killed for memory. The check is now bounded (2 million comparisons, 50
listed flags per sensor pair, every disagreeing pair still counted, an explicit
`agreement_check_truncated` flag). The same package now verifies in 1.2 s at 41 MiB peak.
Regression test: `dense_or_hostile_packages_cannot_explode_the_agreement_check`.

## Negative tests (inputs that must be rejected)

Bad signature, untrusted, revoked or out-of-window key, unknown fields, path-like ids, non-UTC
timestamps, synthetic/provenance mismatch, correction of an unknown record, gaps, forks, duplicate
observation ids, wrong Host (421), browser Origin (403), 9 MiB body (413), empty batch (400), export or
verify by path (400), non-loopback bind without a token (refused), wrong token (401), symlinks and `..`
paths in packages, truncated files, unlisted files.
