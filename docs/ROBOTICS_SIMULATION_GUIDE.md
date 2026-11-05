# Simulation guide

No robots, GPU, cloud service or paid API needed. Everything the lab produces is
**synthetic** and labelled so in every record, package and report.

## Requirements

- Rust (stable, 1.82 or newer) — `rustup` from https://rustup.rs
- Python 3.11+ with `cryptography` (and `pytest` for the tests)

## Commands

Linux / macOS:

```bash
cargo build --release
python3 -m pip install cryptography pytest
cd python
python3 -m cursiv_sim.demo --steps 30 --out ../runs/demo     # the 11-step demonstration
python3 -m cursiv_sim.faults --out ../runs/faults            # all 15 fault scenarios
python3 -m cursiv_sim.bench --out ../bench/out               # benchmarks (several minutes)
cd .. && python3 -m pytest tests -q && cargo test --release
```

Windows (PowerShell), same steps: `cargo build --release`, `py -m pip install cryptography pytest`,
`cd python`, `py -m cursiv_sim.demo --steps 30 --out ..\runs\demo`. Windows was **not tested** in this
iteration. On Windows the robot key file's 0600 permission request has no effect, and the benchmark
cannot read the bridge's memory and CPU figures (it reports "not measured").

Optional interoperability extras (about 400 MB, mostly numpy/pandas/xarray for ioos_qc):

```bash
python3 -m pip install bagit securesystemslib mcap mcap-ros2-support ioos_qc
python3 -m pytest tests/test_interop.py -q                    # BagIt, DSSE, ROS 2 MCAP, QARTOD
cd python && python3 -m cursiv_sim.qartod ../runs/demo/store/exports/survey-final --trust ../runs/demo/trust.json
```

QARTOD note: the simulation compresses a survey into seconds, so readings are milliseconds apart. With
per-second rate-of-change thresholds this makes most simulated air-temperature readings SUSPECT, and the
flat-line test cannot run (reported as not evaluated). This is an artifact of simulated time, not a finding;
real deployments need thresholds from the instrument and the relevant QARTOD manual.

## What the demo does

| Step | What happens | Where to look |
|---|---|---|
| 1 | Starts `cursiv-bridge` on a free loopback port with a fresh store under `runs/demo/store` | console |
| 2 | Three robots get Ed25519 keys; the operator writes `runs/demo/trust.json` (enrollment is out of band) | `runs/demo/robots/*/robot.key` (never commit) |
| 3–4 | Survey mission "willow-basin-survey": rover-01 soil (moisture, pH, temperature), rover-02 air (temperature, humidity, pressure), rover-03 images (PNG attachments) plus air temperature | `/v1/status` |
| 5–6 | Export `survey-part-1`; the separate `cursiv-verify` binary checks it: five verdicts pass | `runs/demo/store/exports/survey-part-1` |
| 7–8 | A copy has one temperature edited; verification fails integrity (`record_signature`, `chain`, `file_changed`, `checkpoint_mismatch`) | `runs/demo/tampered/` |
| 9 | rover-01's link goes down; it keeps recording to its outbox; its first reconnect drops mid-transfer. rover-03's thermometer is biased by +4 °C (a *sensor* fault) | console |
| 10 | Reconnect: sync resumes from the bridge's head; nothing lost or duplicated | console |
| 11 | rover-02 and rover-03 derive mean air temperatures on board (and rover-02 a kelvin conversion); a human analyst and an AI assistant (exact model named) record findings citing them | console |
| 12 | Final package and `runs/demo/evidence-report.md`: the verifier recomputes all 3 derived values and marks both findings "supported with caveats", because the means inherit the contradiction flag from their input readings; verification passes; science flags the rover-02/rover-03 thermometer disagreement **without deciding which is right** | the report |

The demo exits 0 only if the clean package passes, the edited one fails, and the contradiction is flagged.

## The survey world (`python/cursiv_sim/world.py`)

A 0.02° patch near 45.10 N, 122.22 W. Fields are smooth deterministic functions plus seeded noise, so
co-located readings agree unless a fault is injected. Images are generated PNGs carrying a
"SYNTHETIC" text chunk.

## Fault injection (`python/cursiv_sim/faults.py`)

| # | Scenario | How it is injected | Expected |
|---|---|---|---|
| 1 | Altered measurement | edit a value in a package copy | integrity fail |
| 2 | Modified attachment | flip a byte in a blob | attachments fail |
| 3 | Missing observation | drop the last record (chain still links) | completeness fail via signed checkpoints |
| 4 | Duplicate observation | resend a record; reuse an observation id | 200 duplicate; 409 `duplicate_observation_id` |
| 5 | Out-of-order timestamp | a record with an earlier sensor time | science `out_of_order_time`, integrity pass |
| 6 | Sensor clock drift | rover-02's clock gains 7 s per observation | science `clock_drift` (inferred) |
| 7 | Communication failure | link down for several steps | records queue on the robot; delivered on reconnect |
| 8 | Contradictory measurements | rover-03 thermometer +3.5 °C | science `contradiction` for that sensor pair |
| 9 | Interrupted transfer | raw socket sends half an attachment | 400; nothing stored; retry succeeds |
| 10 | Corrupted export | truncate `receipts.jsonl` | integrity fail |
| 11 | Rebuilt hash chain | re-sign every record and the manifest with an attacker key | authenticity fail; without a trust store "not_assessed", never pass |
| 12 | Untrusted key | impostor key; forged signature | 403 `untrusted_key`; 400 `bad_signature`; incident logged |
| 13 | Partial sync | transfer dropped after 20 records | bridge partial; resume completes |
| 14 | Unexpected restart | robot rebuilt from disk; robot with lost state; station `kill -9` mid-burst | resumes; fork refused (`equivocation`); store recovers |
| 15 | High-volume burst | 10 robots × 2,000 records, queue of 4 | 503 backpressure + retries; all 20,000 stored |
| 16 | Validly signed but wrong derived result | a robot signs a mean that is off by 0.7 | integrity passes; recomputation reports a mismatch; exit 3 |
| 17 | Over-claimed findings | an AI model claims "known"; a finding cites nothing | both invalid; a cited, supported finding stays well supported |

## Writing your own agent

`agent.derive("mean", input_envelopes)` records a derived result the verifier can recompute, and
`agent.finding(statement, epistemic=..., author_kind=..., model=..., supports=[...])` records an interpretation.


Use `RobotAgent` (`python/cursiv_sim/robot.py`): `observation(...)` builds a record with explicit
unknowns, `record()` signs and fsyncs it, `upload()` sends attachments, `sync()` delivers from the
bridge's head and sends a checkpoint. Real-hardware agents must set `synthetic=False` and
`provenance.source="sensor"`, and must state their real time source.
