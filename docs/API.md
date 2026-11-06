# Developer APIs

Stability labels:
- **Stable**: follows semantic versioning from version 1.0.0. Nothing breaks without a new major version.
- **Experimental**: may change in any release.
- **Internal**: public for tools and tests, but carries no promise.

| Interface | Version | Label |
|---|---|---|
| Rust `cursiv_evidence::api` | `API_VERSION` 1.0.0 | stable |
| Rust `cursiv_evidence::api::experimental` (segment checks, PROV, SensorThings) | none | experimental |
| Rust modules outside `api` (`store`, `verify`, `segment`, `science`, ...) | none | internal |
| Python `cursiv_robotics` | `API_VERSION` 1.0.0 | stable |
| Python `cursiv_robotics.experimental`, `cursiv_ros2` | none | experimental |
| HTTP ingestion API (`/v1/...`, [ROBOTICS_API.md](ROBOTICS_API.md), [openapi.json](openapi.json)) | v1 | stable |
| CLI `cursiv-verify package` and its exit codes | 1 | stable |
| CLI `cursiv-verify segment`, `cursiv-verify convert` | none | experimental |
| Evidence formats ([FORMATS.md](FORMATS.md)): record, checkpoint and seal schemas; package formats 1 and 2 | versioned in each schema | stable |

## Verification status (all interfaces)

| Status | Meaning | Treat as trusted evidence? |
|---|---|---|
| `verified` | Structure, integrity, authenticity, completeness and attachments all passed. | yes |
| `failed` | At least one verdict failed. | no |
| `incomplete` | Nothing failed, but authenticity or completeness could not be established (for example, no trust store). | no |

The verifier never panics on hostile input. Every problem becomes a finding, and read errors are structure
failures. Unsupported versions are refused. `all_pass()` and `Status::Verified` require `verified`.
Converters refuse anything else.

CLI exit codes for `package`: 0 verified (and all derived results and findings check out), 1 any other
status, 2 usage error, 3 verified but a derived result or finding is invalid.

## Rust (`cursiv-evidence`)

```toml
[dependencies]
cursiv-evidence = { git = "https://github.com/Cursiv-Local/Cursiv-Robotics" }
```

| Function | Does |
|---|---|
| `api::load_trust(path)` | Operator trust store (`cursiv-trust-1`) |
| `api::open_store(root, station_id, station_key, trust)` | Open or create a station store; migrates format 1 |
| `api::ingest(&mut store, &[Envelope]) -> Vec<Outcome>` | Per-record outcomes; `Err(StoreFailed)` only if the store cannot write |
| `api::checkpoint(&mut store, &Envelope)` | Robot-signed checkpoint; `Err(Rejected{code})` if refused |
| `api::export(&mut store, dest, Format::Segmented \| SingleFile)` | Atomic, signed package |
| `api::verify(dir, Some(&trust), Mode::Streaming \| Collect{max_records})` | `Verification { status, report }` |
| `api::experimental::verify_segment`, `to_prov_json`, `to_sensorthings` | See [INTEROPERABILITY.md](INTEROPERABILITY.md) |

`api::Error` is `#[non_exhaustive]`, so match it with a wildcard arm. Its variants are `Io`,
`InvalidInput`, `Rejected { code, detail }`, `StoreFailed`, `Unsupported` and
`NotVerified(Status)`. The rejection codes are the HTTP API's, for example `bad_signature`,
`untrusted_key`, `storage_full` and `equivocation`.

Records are built from `model::{Observation, Record}`, signed with `api::Identity::sign_json(api::RECORD_TYPE, &record)`
and chained by `prev` = the previous record's `payload_hash()`. The full flow is in
[`crates/cursiv-evidence/examples/quickstart.rs`](../crates/cursiv-evidence/examples/quickstart.rs):

```powershell
cargo run --release -p cursiv-evidence --example quickstart
```

## Python (`cursiv_robotics`)

Add `python/` to `sys.path`, or run from it. It needs Python 3.10+ and `cryptography`, and calls the
`cursiv-verify` binary, so the results are identical to the CLI and Rust.

| Function | Does |
|---|---|
| `verify(package, trust=None, *, science=False) -> Verification` | `.status`, `.verified`, `.verdicts`, `.report`; never raises for bad evidence |
| `convert(package, "prov" \| "sensorthings", trust, *, out=None) -> dict` | Raises `NotVerified` for unverified evidence |
| `discover(root) -> list[Path]` | Packages on a drive or folder; follows no links |
| `import_package(package, workspace, trust, *, quarantine=False) -> dict` | Verify, copy, re-verify; the source is never modified |
| Errors | `CursivError` ⊃ `ToolNotFound`, `NotVerified(status)` |

Experimental:
- `cursiv_robotics.experimental.StreamingAgent`
- `CaptureConfig`, `CaptureCore`
- `export_mcap`, `import_mcap`, `ros2_run`

Example: [`examples/python/quickstart.py`](../examples/python/quickstart.py).

## Evidence ingestion (HTTP)

The robot side is any language that can sign Ed25519 DSSE envelopes. Send them with
`POST /v1/observations` (one record or `{"records": [...]}`, optionally `Content-Encoding: gzip`; the decompressed body is limited to 8 MiB, and an unsupported encoding gets 415), `PUT /v1/attachments/<sha256>`, `POST /v1/checkpoints`
and `POST /v1/exports {"name", "format"}`. The full reference is in [ROBOTICS_API.md](ROBOTICS_API.md).

## Scientific metadata and provenance

The fields of `cursiv-observation-1` are:
- sensor and calibration
- sensor time and its time source
- location and its accuracy
- measurement, with value, original text, unit and uncertainty
- attachments
- provenance: source, software, `derived_from`
- processing steps
- quality flag
- correction of an earlier record
- claim: a finding with its epistemic label and its citations

The schema is strict (unknown fields are refused). A new field is a new schema version.
