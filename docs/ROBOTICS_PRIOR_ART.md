# Prior art: existing open-source work, and what Cursiv Robotics reuses

Researched 2026-11-05 to avoid duplicating existing work. Licences marked **(verified)** were read from
installed package metadata; the others come from project pages and should be rechecked before any
code is vendored.

## Decision summary

| Area | Existing work | Decision |
|---|---|---|
| Signed envelope | **DSSE** (secure-systems-lab/dsse, Apache-2.0; used by in-toto and Sigstore/Rekor) | **Adopted.** Replaced our own envelope. Records verify with securesystemslib (MIT, verified) in `tests/test_interop.py` |
| Package format | **BagIt, RFC 8493**; bagit-python (public domain, verified) | **Adopted.** Packages are BagIt bags; bagit-python validates them and detects tampering |
| Sensor quality control | **IOOS QARTOD** manuals; **ioos_qc** reference implementation (Apache-2.0, verified) | **Adopted as an optional adapter** (`qartod.py`), not reimplemented. Our Rust checks keep only what QARTOD does not cover (calibration, provenance, cross-robot contradictions, synthetic labelling) |
| ROS 2 recordings | **MCAP** (rosbag2 default since Iron); `mcap` + `mcap-ros2-support` (MIT, verified) | **Adopted as an optional adapter** (`mcap_import.py`): real ROS 2 CDR messages, no ROS install |
| Robot black-box recorders | robot-black-box (MIT), RoboTrace (BSD-3), Black Block Recorder (research), Ethical Black Box draft standard | **Studied, not reused** (see below); closest in philosophy |
| Transparency / external anchoring | C2SP **tlog-checkpoint**, signed-note, transparency-dev witnesses/Tessera, Sigstore Rekor | **Roadmap.** Our Merkle tree is RFC 6962-style; next step is checkpoints in tlog-checkpoint form for independent witnesses |
| Image provenance | **C2PA** / Content Credentials, c2pa-rs (MIT/Apache per project page) | **Roadmap.** Verify C2PA manifests on image attachments when cameras produce them |
| Observation data model | OGC **SensorThings API** (FROST-Server reference implementation), ISO 19156 O&M | **Roadmap: mapping, not replacement.** Our observation fields map onto Thing/Sensor/Datastream/Observation |
| Provenance model | **W3C PROV**; `prov` Python library (MIT, verified) | **Roadmap:** PROV-JSON export of `provenance`/`processing` |

## Robotics evidence and black-box recorders

- **robot-black-box** (AAH20, MIT, TypeScript/Node 22). An offline-first recorder and verifier with producer, authority and witness keys, hash-chained events, content-addressed artifacts, a signed manifest, and separate integrity, completeness, anchoring and capture-quality verdicts. Developer preview: 14 commits, Linux-only CI, ROS 2 on its roadmap. It is the closest project in philosophy, and it independently reaches the same rule we follow: a signature does not prove an action was true. **Not reused**: a different language and runtime (Node vs. our dependency-light Rust verifier); its signing algorithm and envelope are not documented on its README; no multi-robot synchronization. Worth revisiting for interop once both formats stabilise (both could share DSSE). https://github.com/AAH20/robot-black-box
- **RoboTrace** (TU Darmstadt, BSD-3-Clause). A "modular and portable black box recorder" for ROS service robots, with an OpenSSL plugin. Its README does not document its storage or integrity design; no releases shown. Not reused. https://github.com/tu-darmstadt-ros-pkg/robo_trace
- **Black Block Recorder** (White et al., IEEE RA-L 2019; ROSCon 2019). rosbag2 storage plugin, SROS2 transport, signed and HMACed batches anchored to a Hyperledger Sawtooth ledger. A research prototype; the public image was last updated over six years ago. It confirms the design point we follow (batched signed integrity proofs plus external anchoring), without the ledger dependency. https://roscon.ros.org/2019/talks/roscon2019_black_bag_recorder.pdf
- **Ethical Black Box** (Winfield et al., arXiv 2205.06564). A draft open standard for robot "flight data recorders" (sensor, actuator and decision logs for accident investigation). Our scope is scientific evidence, not control decisions, but its record categories inform the roadmap. https://arxiv.org/pdf/2205.06564
- **ros2_medkit** added a tamper-evident append-only fault audit log (diagnostics, not scientific data). https://github.com/selfpatch/ros2_medkit/releases
- **rosbag2 / MCAP** have **no built-in signing** (rosbag2 README; community discussion). A hash manifest alone does not authenticate a recording (as noted in the leroy project's PR). This is the gap Cursiv Robotics fills, and why MCAP import attaches the recording to signed observations. https://github.com/ros2/rosbag2

## Signing, transparency and timestamps

- **DSSE**: `PAE(type, body) = "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body`; envelope `{payload (base64), payloadType, signatures[{keyid, sig}]}`; keyid is unauthenticated; payloadType is signed, which prevents cross-type replay. Apache-2.0. https://github.com/secure-systems-lab/dsse/blob/master/protocol.md
- **C2SP tlog-checkpoint**: a signed note `origin / tree size / base64 RFC 6962 root`, cosigned by witnesses with Ed25519. https://c2sp.org/tlog-checkpoint. **Tessera** (Go library, transparency-dev) and the transparency-dev **witness** implement this. Adopting it would let an independent party detect a station that rewrites its history (our main residual risk).
- **Sigstore Rekor** accepts DSSE entries, an option for teams that want a public log (it is online, so never a requirement here).

## Scientific validation

- **IOOS QARTOD** (NOAA/IOOS Quality Assurance of Real-Time Oceanographic Data). Flag scheme 1 GOOD, 2 UNKNOWN (not evaluated), 3 SUSPECT, 4 FAIL, 9 MISSING. **ioos_qc** provides gross range, spike, rate of change, flat line, location, climatology, attenuated signal and density inversion tests. Apache-2.0. https://ioos.github.io/ioos_qc/ . Known limitation, stated by its predecessor `ioos_qartod`: most tests assume regularly spaced time series. Our adapter reports a test that cannot run on a series as "not evaluated", never as a pass.
- How our Rust checks map to QARTOD flags: `out_of_range` = 4 (gross range fail span); `unit_mismatch`, `calibration_expired` and `missing_supporting_evidence` have no QARTOD equivalent (they are evidence or metadata checks); `contradiction` (cross-robot) has no direct QARTOD test (`qartod_compare` aggregates tests on one series, not across sensors).

## Interoperability standards to map to (not replace)

- **OGC SensorThings API** (ISO 19156 data model, REST and MQTT; FROST-Server is the reference implementation): Thing ↔ robot, Sensor ↔ `sensor`, Datastream ↔ (robot, sensor, observation_type), Observation ↔ observation (`phenomenonTime` = `sensor_time`, `resultTime` = receipt time, `resultQuality` = QARTOD flags).
- **W3C PROV** (Entity ↔ observation/attachment, Activity ↔ processing step, Agent ↔ robot/software). The `prov` library can serialise PROV-JSON, PROV-O and PROV-XML.
- **CCSDS** (space data systems) remains a review item before any space-link work (roadmap).

## What remains genuinely new here

No surveyed open-source project combines:
1. per-robot signed append-only logs that sync offline with gap/fork detection;
2. a dependency-light independent verifier with separate integrity, authenticity, completeness and attachment verdicts;
3. evidence packages valid under both BagIt and a signed manifest;
4. a strict separation of cryptographic verification from deterministic scientific QC (QARTOD);
5. mandatory synthetic-data labelling that propagates to everything derived from it;
6. **re-computation of derived results by the verifier** (a validly signed wrong number is caught);
7. **signed, evidence-linked findings** with epistemic labels, citation checks, caveat propagation through
   derivations, and a rule that an AI model is never the authority for a "known" statement.

Black-box recorders (above) answer "what did the machine do?". Items 6 and 7 answer "does this
scientific result follow from the recorded evidence?", which none of the surveyed projects attempts.

Each of these individually uses existing standards (DSSE, BagIt, RFC 6962 Merkle trees, QARTOD, MCAP).
