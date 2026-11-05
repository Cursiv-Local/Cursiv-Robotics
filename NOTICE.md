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

Third-party Rust crates (ed25519-dalek, sha2, serde, serde_json, base64, hex, rand_core,
tiny_http) and the Python `cryptography` package are used under their own licenses.
