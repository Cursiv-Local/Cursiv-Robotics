# Attribution

Cursiv Robotics builds on **Cursiv** (https://github.com/Cursiv-Local/Cursiv),
MIT License, Copyright (c) 2026 Joshua Winkler.

No Cursiv source file is copied into this repository. These designs and conventions are
derived from Cursiv and reimplemented here:

| Here | Derived from Cursiv |
|---|---|
| Ed25519 envelopes; key id = first 16 hex of SHA-256(raw public key) | `cursiv_engine/core/devicekey.py` |
| Append-only records, reasoned corrections that keep the original, signed log heads | `cursiv_engine/core/fieldlog.py` |
| Per-device histories, key pinning and revocation (here: an operator trust store) | `cursiv_engine/core/fieldsync.py` |
| Refusing links, hard links and `..` paths when reading exports | `cursiv_engine/core/export_paths.py` |
| Host/Origin checks on a local HTTP service | `cursiv_engine/station/server.py` |
| real / derived / simulated labelling (here: the required `synthetic` flag) | `cursiv_engine/station/telemetry.py` |
| `crates/cursiv-evidence/src/legacy.rs` verifies Cursiv's `signature.json` (`cursiv-export-1`) | `fieldlog.sign_export` / `verify_export` |

The test fixture `crates/cursiv-evidence/tests/fixtures/cursiv-export` is a synthetic export
produced by Cursiv's own code for interoperability testing.

## Standards and specifications implemented (no code copied)

| Standard | Licence / source | Where |
|---|---|---|
| DSSE envelope and PAE (secure-systems-lab/dsse) | Apache-2.0 | `crates/cursiv-evidence/src/crypto.rs`, `python/cursiv_sim/identity.py` |
| BagIt File Packaging Format, RFC 8493 | IETF RFC | `crates/cursiv-evidence/src/package.rs`, `verify.rs` |
| RFC 6962 Merkle tree hashing (leaf/node prefixes) | IETF RFC | `crates/cursiv-evidence/src/merkle.rs` |
| IOOS QARTOD flag scheme | U.S. IOOS public manuals | `python/cursiv_sim/qartod.py` |
| phyphox export file format (ZIP, CSV variants, `meta/time.csv`, `meta/device.csv`), as written by phyphox-android `DataExport.java` | phyphox (RWTH Aachen University); format only, no phyphox code is used or copied | `python/cursiv_field/phyphox.py` |

## Third-party software used (as dependencies, not vendored)

| Package | Licence | Use |
|---|---|---|
| ed25519-dalek, sha2, serde, serde_json, base64, hex, rand_core, tiny_http (Rust) | their own (MIT/Apache-2.0 or BSD) | core |
| cryptography (Python) | Apache-2.0 / BSD | robot signing |
| ioos_qc (optional) | Apache-2.0 (Copyright IOOS) | QARTOD quality control adapter |
| mcap, mcap-ros2-support (optional) | MIT (Foxglove) | ROS 2 MCAP import |
| bagit (optional, tests) | Public domain (Library of Congress) | independent BagIt validation |
| securesystemslib (optional, tests) | MIT | independent DSSE verification |

Optional packages are never required by the core service or verifier. Their licences are
recorded from installed package metadata (2026-11-05); see `docs/ROBOTICS_PRIOR_ART.md`.
