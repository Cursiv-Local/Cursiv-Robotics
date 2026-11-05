# Cursiv source audit for robotics reuse

Audited: `Cursiv-Local/Cursiv` at `e4de04a` (main, 2026-11-02, release U118 line).
Method: reading the source, then **running** the notebook headless in a throwaway
home folder (no PyQt imported) to confirm behaviour, including deliberate tampering.
The Cursiv repository was not modified.

Classification used below: **Verified** (exists and confirmed by running or by tests),
**Modify** (exists but needs changes for robotics), **Partial**, **Missing**.

## Summary

| # | Capability | Status | Reused how |
|---|---|---|---|
| 1 | Field Notebook | Verified (desktop) / Modify (robotics) | Design reused; code not imported |
| 2 | SHA-256 hash chain + verification | Verified, **integrity only** | Same idea, per robot, plus signatures |
| 3 | Digital signatures / trusted checkpoints | Partial | Ed25519 + key-id scheme reused; trust model strengthened |
| 4 | Evidence/attachment storage | Partial (photos only) | Content addressing reused, generalised |
| 5 | Timestamps and metadata | Partial | Replaced by sensor time + clock quality + receipts |
| 6 | Export / import | Verified | **Rust verifier checks real Cursiv exports**; link-refusal rules reused |
| 7 | Offline networking restrictions | Verified | Principle kept (loopback only); not linked into Rust |
| 8 | Research and document analysis | Verified (desktop) | Not reused: chat-oriented |
| 9 | Local AI / Ollama | Verified (desktop) | Deliberately not used for evidence or validation |
| 10 | Deterministic calculations | Verified | Concepts reused (haversine, units); future shared library |
| 11 | Workspace portability / team sync | Verified | Per-device logs + key pinning model reused |
| 12 | Memory and observation tracking | Verified (chat memory) | Not reused: not scientific evidence |
| 13 | APIs and integration points | Partial | Field Station server's Host/Origin checks reused; no robotics API existed |
| 14 | Security boundaries / authentication | Verified (desktop) | Vault/keystore stay desktop-only |
| 15 | Tests, benchmarks, limitations | Verified | ~2,900 tests; notebook-specific listed below |

No ROS, MAVLink or MQTT code exists in Cursiv (`grep` over `cursiv_engine` and `launcher`).

## 1. Field Notebook — `cursiv_engine/core/fieldlog.py` (1,195 lines)

- Functions: `add`/`_append` (write), `correct` (append-only correction with mandatory reason), `current` (corrected entries replaced in the view, originals kept), `verify` (chain check), `export`/`_export_into` (JSON, CSV, GeoJSON, HTML report), `sign_export`/`verify_export`, `parse` (plain-words entry parsing).
- Verified by running headless: three entries plus a correction, `verify()` clean, export signed, `verify_export()` clean; editing the exported CSV was reported (`observations.csv was changed after the export was signed`); editing a log line was reported (`entry 2 ... was changed after it was recorded`).
- Model: `measurements` are `{name, value (as typed string), number, unit}`; location `lat/lon` (WGS84) with optional accuracy and fix time; `recorded_utc` is the **write time, second precision**; `device`, `observer`, `sample_id`, `project`, photos.
- Missing for robotics: sensor timestamp separate from write time, clock quality, uncertainty, calibration, processing history, provenance chain, an explicit synthetic flag.
- Headless: **yes** (only `cryptography` and Cursiv's `private_store`/`vault`). Encryption applies only after the desktop's first-start passphrase.
- Scaling concern: one chain per device, and `_append` calls `_read()`, which rereads and parses the **whole log on every append** (O(n) per write, O(n²) for a stream). In encrypted mode the whole file is rewritten per entry. Fine for hand-entered field notes; not for sensor streams.
- Tests: `tests/test_fieldlog.py` (16), `tests/test_notebook_integrity_matrix.py` (14), `tests/test_integrity_attacks.py` (22).
- Decision: keep in the desktop app. Robotics uses per-robot logs with the same append-only/correction semantics.

## 2. Hash chain — `fieldlog._fingerprint`, `fieldlog.verify`

- SHA-256 over `json.dumps(entry without "hash", sort_keys=True, ensure_ascii=False, separators=(",",":"))`; each entry stores `prev` (the previous hash, `"genesis"` first) and `seq`.
- `verify()` checks `prev`, the recomputed hash and consecutive `seq`.
- **Verified limitation**: after editing an entry and recomputing every hash, `verify()` returned `[]`. A rebuilt chain is indistinguishable from the original. Cursiv says so itself (`CHECK_MEANS`: "it doesn't show who made them, or that the whole notebook wasn't rebuilt -- a signed export does").
- A hash chain here is **integrity, not authentication**.

## 3. Signatures and checkpoints — `core/devicekey.py`, `core/fieldsync.py`, `core/release_identity.py`

- `devicekey`: one Ed25519 key per installation (`cryptography`), key id = first 16 hex of SHA-256(raw public key), private key protected by DPAPI/Keychain (`keystore`) or passphrase (scrypt + Fernet) on drives. `sign()` returns `{signed, public_key, key_id, signature}` over Python canonical JSON. `head()`/`signed_head()` sign `{device, entries, seq, hash}`, which acts as a checkpoint over the whole chain.
- `devicekey.verify(envelope)` checks the signature against **the public key inside the envelope**. It shows the payload was not changed since signing; it does **not** show who signed. Anyone can generate a key and sign a rebuilt log.
- Authenticity comes from `fieldsync`: `pinned_key(device)` (trust on first use per device), refusal of a different key for a pinned device, `revoke()`/`revoked()`, phone ids bound to key ids. `fieldlog._signer()` labels "this installation's key / an imported team key / unknown".
- `release_identity.py` pins the owner's release key for installers (a separate, out-of-band trust anchor).
- No independent witness/timestamping of checkpoints; first-use pinning can be poisoned at first contact.
- Reused: Ed25519, the key-id rule, signed heads. Changed for robotics: signatures on **every record** (not only on export), an **operator-supplied trust store** (never trust-on-first-use, never keys taken from the package), key validity windows for rotation, revocation, and a station counter-checkpoint.

## 4. Evidence and attachments — `fieldlog.store_photo`, `photo_problems`

- Photos are copied to `photos/<sha256>.<ext>` (content-addressed), limited to 50 MB, with EXIF summary; `photo_problems()` re-hashes them.
- Only images. Robotics generalises this to any media type, streamed with a declared length and hash, kept separate from metadata.

## 5. Timestamps — `fieldlog._append`, `fieldsync._clock_ahead_minutes`

- `recorded_utc` and `recorded_local` (write time); `location_fix_utc` when given. Import warns when a device's clock appears ahead.
- Robotics needs sensor time, time source, offset/maximum error and the station's receipt time, all separately recorded. Implemented in the new model.

## 6. Export and import — `fieldlog.export`, `core/export_paths.py`, `core/fieldsync.py`

- `export_paths.inventory` refuses symlinks, junctions, hard links and special files; `valid_name` refuses absolute and `..` paths. These rules are reimplemented in the robotics verifier.
- **Reused directly by interoperation**: `cursiv-verify cursiv-export <dir>` verifies a real Cursiv `signature.json` (`cursiv-export-1`) in Rust, independently of Cursiv's Python. Tested against an export produced by Cursiv's own code (fixture in `crates/cursiv-evidence/tests/fixtures/cursiv-export`, including non-ASCII text), and a tampered copy is detected.
- `fieldsync.import_folder`, phone bundles via staging and `safe_zip` (no path tricks, size limits).

## 7. Offline networking — `core/netgate.py`

- One switch; an audit hook refuses any socket or DNS lookup to anything but loopback when offline. Tests: `tests/test_netgate.py` (20).
- Robotics keeps the principle: the bridge binds loopback only unless an API token is configured, the Python client disables environment proxies, nothing calls out. netgate itself is a Python audit hook and cannot police a Rust process.

## 8–9. Research documents and local AI — `core/documents.py`, `chat/*`, `core/ollama_host.py`

- Document import/retrieval and the chat pipeline (Ollama first, optional cloud keys) are desktop/chat features.
- Not reused. The robotics evidence path uses **no AI model**: integrity, authenticity and plausibility checks are deterministic. AI interpretation, when added later, must cite observation ids and be labelled (roadmap).

## 10. Deterministic calculations — `core/fieldcalc.py`, `core/calc.py`, `core/datecalc.py`

- Unit conversion, DMS/UTM coordinates, `distance_bearing` (great-circle), statistics with Student-t intervals, dilutions. Pure Python, headless. Tests: `tests/test_fieldcalc.py` (27).
- The Rust validator reimplements the haversine distance it needs. Future: share a unit/statistics library.

## 11. Workspace portability and team sync — `core/fieldsync.py`, `launcher/usb_sync.py`

- Each device keeps its own log; team folders hold per-device copies plus pinned keys; imports are signature-checked; `sample_clashes` reports conflicting sample ids. This **is** the per-robot-history model the fleet needs, and was followed.

## 12. Memory — `memory/semantic.py` and related

- Chat memory with origin tags. Not scientific evidence; not reused.

## 13. APIs — `station/server.py` (Field Station preview)

- Local web server: loopback/private clients only, Host-header and Origin checks, CSRF, sessions with rate limits. The Host and Origin defences are reused in the bridge.
- `station/telemetry.py` labels every reading real / derived / simulated / unavailable / stale. The same rule became the required `synthetic` flag.
- The Field Station itself (Raspberry Pi 5 preview, untested on hardware) was **not modified**.

## 14. Security boundaries — `core/vault.py`, `core/keystore.py`, `core/private_store.py`

- Encryption at rest (passphrase, scrypt + Fernet), device-bound key protection (DPAPI/Keychain). Desktop-only; the robotics service relies on file permissions (keys written 0600) and leaves at-rest encryption to the roadmap.

## 15. Tests and known limitations

- About 2,900 tests in Cursiv (168 test files). Notebook-related: those listed above, plus `test_fieldsync.py` (6), `test_export_paths.py` (3), Station `test_station_*` (44).
- Limitations confirmed: rebuilt chains pass `verify()`; envelope verification is self-consistency; trust on first use; single serialized chain per device; second-precision write timestamps.

## What was built new (and why)

- A **common observation model** with explicit unknowns, uncertainty, calibration, time quality, provenance, processing and a mandatory synthetic flag.
- **Per-robot signed records** (signature over exact payload bytes, so Rust and Python never need identical JSON serialisation), Merkle checkpoints and a station receipt chain.
- A **trust store** supplied out of band, with validity windows (rotation) and revocation.
- A **standalone verifier** with five separate verdicts, and a separate deterministic **science validator**.
