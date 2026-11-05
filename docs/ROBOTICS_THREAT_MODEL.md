# Threat model

All robot observations, packages, attachments and imported metadata are **untrusted input**.

## Assets

Integrity and provenance of recorded observations; private signing keys (robots, station);
the operator's trust store; availability of the ingestion service. Not assets of this
layer: robot motion or safety (out of scope by design).

## Trust boundaries

1. Sensor → robot agent. The agent signs what it is given; a lying sensor or a compromised robot produces authentic but false data. **Signatures never imply accuracy.**
2. Robot → bridge (loopback HTTP). Every record is signature-checked against the trust store before it is accepted.
3. Bridge → package → third party. The verifier needs only the package and the verifier's own trust store; it never trusts keys listed inside the package.
4. Operator → trust store. Out of band (a file), not changeable through the API.

## Threats and controls

| Threat | Control | Tested |
|---|---|---|
| Altered record or measurement | Signature over payload bytes; chain; checkpoint Merkle root; manifest hashes | Rust `fault_1`, fault suite 1 |
| Removed, inserted, reordered records | `seq`/`prev` chain; trusted checkpoints for trailing removal | Rust `fault_3`, suite 3 |
| Rebuilt hash chain (re-signed with attacker key) | Trust store rejects the key; genuine station checkpoint disagrees; no trust store gives "not_assessed", never "pass" | Rust `faults_10_11`, suite 11 |
| Identity spoofing / impostor robot | Per-robot keys in trust store; `403 untrusted_key` + incident | Rust `fault_12`, suite 12 |
| Replay of old records | Same seq + same hash is an idempotent duplicate (no effect); different content at a used seq is equivocation | Rust `fault_4`, `faults_13_14` |
| Robot restart with lost state (fork) | Equivocation detection at the bridge; the robot refuses to sync if the bridge holds more than it does | Suite 14 |
| Key compromise | Revocation in the trust store; rotation windows (`valid_from_seq`/`valid_until_seq`) | `key_rotation_window_is_enforced`, `fault_12` |
| Modified or swapped attachment | Content addressing; size + hash checked on upload and in the verifier | Rust `fault_2`, suite 2 |
| Interrupted or oversized upload | Declared length required; streamed hash; nothing kept unless complete; `max_attachment_bytes` | Rust `fault_9`, suite 9 |
| Path traversal / symlinks / hard links in packages | `safe_rel`, id charset `[a-z0-9._-]`, inventory refuses links and special files | `hostile_package_paths_and_links_are_refused` |
| Arbitrary file access via API | Export/verify accept names only (no paths), resolved under `<store>/exports` | `test_host_origin_size_and_unknown_routes_are_refused` |
| Malformed JSON, unknown fields | `serde(deny_unknown_fields)`; structural validation; 400/422 | `malformed_and_oversized_inputs_are_rejected` |
| Oversized payloads / memory exhaustion | 8 MiB JSON bodies; 1,000 records/batch; 4 MiB per JSONL line and 64 MiB per JSON file in the verifier; bounded science comparisons | `dense_or_hostile_packages_cannot_explode...` |
| Request floods (DoS) | Bounded queue → 503 + Retry-After; fixed worker pool | Suite 15 |
| DNS rebinding / browser CSRF | Host header must be loopback:port; requests with an `Origin` header refused for writes | Python test |
| Network exposure | Loopback bind by default; non-loopback refused without a ≥32-char bearer token; constant-time token compare | Python tests |
| Decompression bombs | No archive formats are accepted (packages are directories) | n/a |
| Unsafe deserialisation | Typed `serde` structs only; no code or pickle | design |
| Prompt injection via metadata | No AI model reads observations in this layer; future AI interpretation must treat metadata as data and cite record ids | design |
| Synthetic data passed off as real | `synthetic` required, must match `provenance.source`; mixed packages are an error; reports carry a banner | Rust `malformed...`, verifier `mixed_synthetic` |
| Commanding robots | No endpoint or code path sends commands; the robot reads only acceptance results and head counts | design |

## Residual risks (not solved here)

- **Key custody**: robot and station keys are files with 0600 permissions, not hardware-backed (TPM/HSM/secure element). A stolen robot key can sign false but "authentic" records until it is revoked.
- **Trust store integrity**: whoever can edit `trust.json` decides who is trusted.
- **No external timestamping or witness**: a station that holds its own key could rewrite its whole store and re-sign it. Mitigation: hand checkpoints to an independent party (roadmap: transparency log or RFC 3161).
- **Station clock** is assumed correct for drift and "future time" checks; these flags are labelled *assumed*.
- **TLS** is not provided; off-host use with `--token-file` should sit behind a TLS terminator on a trusted network.
- **Dependency vulnerabilities**: `cargo audit` was not run in this environment (not installed). Direct dependencies are few (ed25519-dalek, sha2, serde, serde_json, base64, hex, rand_core, tiny_http); add `cargo audit`/`cargo deny` to CI.
- **At-rest encryption** of the store is not implemented (Cursiv's vault is desktop-only).
- Live **ROS 2** input is unverified.
