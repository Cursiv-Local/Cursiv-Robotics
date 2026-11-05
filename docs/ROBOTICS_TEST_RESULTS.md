# Test results

Recorded 2026-11-05 in a Linux cloud container. Every figure below was measured; nothing is estimated.
Windows and macOS were **not** tested in this iteration.

## Environment

| | |
|---|---|
| CPU | Intel Xeon Processor @ 2.10 GHz, 4 logical CPUs |
| Memory | 15.7 GiB |
| OS | Linux 6.18 x86_64, glibc 2.39 (Ubuntu 24.04) |
| Rust | rustc 1.97.0, `cargo --release` |
| Python | 3.13.18, cryptography; optional: bagit 1.9.0, securesystemslib 1.6.0, mcap 1.6.0, mcap-ros2-support 0.6.0, ioos_qc 3.0.0 |
| ROS 2 | not installed |

## Automated tests

| Suite | Command | Result |
|---|---|---|
| Rust unit tests (incl. DSSE PAE spec example, deterministic derivation ops) | `cargo test --release` | 6 passed |
| Rust evidence and fault tests (`crates/cursiv-evidence/tests/faults.rs`, incl. wrong derived results and findings rules) | `cargo test --release` | 18 passed |
| Clippy | `cargo clippy --release` | 0 warnings |
| Python core (`tests/test_sim.py`: network and input defences, token auth, DSSE PAE, ROS 2 mapping, Rust/Python Merkle agreement, demo, all 17 faults) | `python3 -m pytest tests -q` | 9 passed, 4 interop skipped without optional packages |
| Interoperability (`tests/test_interop.py`, optional packages installed) | `python3 -m pytest tests -q` | 4 passed: bagit-python validates packages and catches tampering; securesystemslib verifies every record and manifest as DSSE; a real ROS 2 CDR MCAP recording is imported, verified and traceable; QARTOD (ioos_qc 3.0.0) flags an implausible value and refuses a tampered package |
| Fault suite (`python -m cursiv_sim.faults`) | real bridge binary + `cursiv-verify` | **17/17 scenarios passed** |
| Demo (`python -m cursiv_sim.demo --steps 30`) | 12 steps | passed: 3/3 derived values recomputed, 2 findings (human and AI) supported with caveats |

Cursiv's own test suite was not run for this work, because the Cursiv repository was not changed (its
working tree was checked clean before and after).

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
