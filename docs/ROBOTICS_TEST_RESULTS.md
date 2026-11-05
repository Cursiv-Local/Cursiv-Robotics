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
| Python | 3.13.18, cryptography (system) |
| ROS 2 | not installed |

## Automated tests

| Suite | Command | Result |
|---|---|---|
| Rust unit tests | `cargo test --release` | 4 passed |
| Rust evidence and fault tests (`crates/cursiv-evidence/tests/faults.rs`) | `cargo test --release` | 16 passed |
| Clippy | `cargo clippy --release` | 0 warnings |
| Python (`tests/test_sim.py`: network and input defences, token auth, ROS 2 mapping, Rust/Python Merkle agreement, demo, all 15 faults) | `python3 -m pytest tests -q` | 8 passed |
| Fault suite (`python -m cursiv_sim.faults`) | real bridge binary + `cursiv-verify` | **15/15 scenarios passed** |
| Demo (`python -m cursiv_sim.demo --steps 30`) | 11 steps | passed |

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

## Demo (30 steps)

Clean package: all five verdicts pass. Edited copy: integrity fail (`file_changed`, `record_signature`,
`chain`, `checkpoint_mismatch`). Offline rover-01 queued 45 records; the first reconnect dropped at 57/90;
the resumed sync delivered 33, giving 90/90. Final package: all verdicts pass. 240 synthetic observations.
Science found one contradiction group (the deliberately biased rover-03 thermometer against rover-02).

## Performance (`python -m cursiv_sim.bench`; raw data: `bench/results/2026-11-05-linux-cloud-container.json`)

Configuration: queue 256, 8 HTTP workers, client threads = min(32, agents), batches of 100, fsync per
coalesced batch. **Simulated agents are threads signing records on one computer, not robots.**

| Agents | Records | Client signing (rec/s) | Ingest (rec/s) | Batch latency p50 / p95 (ms) | Verify incl. science (rec/s) | Store B/record | Payload B/record | Restart after kill (s) | Bridge peak RSS (MiB) | Bridge CPU (s) |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 5,000 | 3,154 | 10,150 | 9.7 / 11.3 | 7,778 | 1,752 | 1,025 | 0.05 | 11.9 | 0.39 |
| 3 | 9,000 | 3,406 | 12,517 | 23.7 / 27.8 | 8,222 | 1,751 | 1,025 | 0.10 | 14.6 | 0.72 |
| 10 | 10,000 | 3,393 | 12,115 | 69.4 / 136.5 | 9,577 | 1,750 | 1,024 | 0.10 | 16.7 | 0.79 |
| 100 | 20,000 | 3,422 | 12,437 | 247.3 / 294.5 | 8,753 | 1,749 | 1,023 | 0.20 | 21.4 | 1.67 |
| 1,000 | 20,000 | 3,156 | 9,837 | 62.8 / 80.7 | 10,283 | 1,745 | 1,020 | 0.22 | 37.7 | 4.33 |

- Attachments: 50 × 1 MiB uploads at 217 MiB/s.
- Sync after an outage: 5,000 buffered records delivered in 0.47 s.
- Storage overhead: about 1.7× the payload (envelope, signature, public key, receipts). Store growth is linear.
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
