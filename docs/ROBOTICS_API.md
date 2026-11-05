# Bridge API (v1)

Machine-readable: [`openapi.json`](openapi.json) (OpenAPI 3.1), also served at `GET /v1/openapi.json`.
Base URL: `http://127.0.0.1:8750`. Version 1 paths are stable; breaking changes get `/v2`.

## Access rules

- Binds loopback by default. A non-loopback `--bind` is refused unless `--token-file` is given (token ≥ 32 characters). With a token, every request except `/v1/health` needs `Authorization: Bearer <token>`.
- `Host` must be `127.0.0.1:<port>`, `localhost:<port>` or `[::1]:<port>` (any host with the right port when a token is configured), otherwise `421`.
- Any non-GET request carrying an `Origin` header is refused (`403`): web pages cannot write.
- JSON bodies ≤ 8 MiB; batches of 1–1,000 records; attachments need `Content-Length` and are capped (256 MiB default).
- The API never returns commands for robots.

## Signed envelopes

Everything a robot submits is an envelope:

```json
{"payload": "<exact JSON text>", "key_id": "<16 hex>", "public_key": "<base64 raw Ed25519>", "signature": "<base64>"}
```

`key_id` = first 16 hex characters of SHA-256(raw public key). The signature is over the
UTF-8 bytes of `payload`. Record hash = SHA-256(payload bytes).

Record payload (`cursiv-record-1`):

```json
{"schema":"cursiv-record-1","robot_id":"rover-02","seq":4,"prev":"<hash of record 3 or 'genesis'>",
 "written_time":"2026-11-05T04:00:52.120Z",
 "observation":{
   "schema":"cursiv-observation-1","observation_id":"rover-02-8c1f…","robot_id":"rover-02",
   "mission_id":"willow-basin-survey","observation_type":"air_temperature","synthetic":true,
   "sensor":{"sensor_id":"rover-02-pt100","sensor_type":"rtd","model":"sim-1",
             "calibration":{"calibrated_utc":"2026-10-01T00:00:00Z","valid_until_utc":"2027-04-01T00:00:00Z","reference":"…","certificate_sha256":null}},
   "sensor_time":"2026-11-05T04:00:52.118Z","time_source":"simulated","clock":null,
   "location":{"lat":45.104,"lon":-122.218,"alt_m":null,"crs":"EPSG:4326","horizontal_accuracy_m":1.5,"source":"simulated"},
   "measurement":{"value":16.184,"text":null,"unit":"degC","uncertainty":{"kind":"standard","value":0.15,"coverage_k":null}},
   "attachments":[],"provenance":{"source":"simulated","software":"cursiv-sim","software_version":"0.1.0","derived_from":[]},
   "processing":[],"quality":{"flag":"unassessed","basis":"…"},"correction":null}}
```

Rules: unknown values are `null` and never defaulted; `synthetic` must be true exactly when
`provenance.source` is `simulated`; ids are 1–64 of `[a-z0-9._-]`; times are RFC 3339 UTC with `Z`;
`time_source` ∈ `gnss, ntp, ptp, rtc_synced, rtc_unsynced, monotonic_only, simulated, unknown`;
uncertainty `kind` ∈ `standard, expanded (with coverage_k), bound`; unknown fields are rejected.

## Endpoints

| Method | Path | Purpose | Main responses |
|---|---|---|---|
| GET | `/v1/health` | Liveness (no auth) | 200 |
| GET | `/v1/status` | Robots, counts, heads, missions, recovery notes | 200 |
| GET | `/v1/robots/{id}/head` | `{count, head}`: where to resume | 200, 400 |
| POST | `/v1/observations` | One envelope, or `{"records":[…]}` | 201 accepted, 200 duplicate, 207 batch, 400, 403, 409, 413, 422, 503 |
| POST | `/v1/checkpoints` | Robot-signed checkpoint | 201, 409 equivocation |
| PUT | `/v1/attachments/{sha256}` | Raw bytes; must match hash and length | 201, 200 present, 400, 411, 413 |
| GET | `/v1/attachments/{sha256}` | Presence | 200, 404 |
| POST | `/v1/exports` | `{"name"}` → station-signed package under `<store>/exports/<name>` | 201, 400, 409 |
| POST | `/v1/verify` | `{"package"}` → the verifier's report (same code as the CLI) | 200, 400 |

Per-record outcome: `{"status":"accepted|duplicate|rejected","robot_id","seq","record_hash","missing_attachments"}`
or `{"status":"rejected","code","detail","expected_seq"}`. Rejection codes: `bad_signature`, `malformed`,
`invalid_observation`, `untrusted_key`, `revoked_key`, `key_out_of_window`, `gap` (with `expected_seq`),
`chain_mismatch`, `equivocation`, `duplicate_observation_id`, `unknown_correction_target`.

Retrying is always safe: an identical record returns `duplicate`.

## Command-line tools

```
cursiv-bridge keygen <key-file>
cursiv-bridge serve --store DIR --station-id ID --key FILE --trust trust.json [--bind 127.0.0.1:8750] [--token-file F] [--queue 256] [--workers 4]
cursiv-verify package <dir> [--trust trust.json] [--json] [--science [--profile p.json]] [--report-md out.md]
cursiv-verify cursiv-export <dir> [--key-id <16 hex>] [--json]      # existing Cursiv notebook exports
```

`cursiv-verify` exits 0 only when every verdict passes. Exit 1 means a verdict failed or could not be established; exit 2 is a usage error.

## Trust store (`cursiv-trust-1`)

```json
{"format":"cursiv-trust-1",
 "robots":{"rover-01":[{"key_id":"…","public_key":"…","status":"active","note":null,"valid_from_seq":null,"valid_until_seq":null}]},
 "stations":{"station-alpha":[{"key_id":"…","public_key":"…","status":"active","note":null,"valid_from_seq":null,"valid_until_seq":null}]}}
```

`status` ∈ `active`, `retired` (verifies history inside its window), `revoked` (verifies nothing).
Rotation: retire the old key with `valid_until_seq = N`, add the new one with `valid_from_seq = N+1`.

## ROS 2 adapter boundary

`python/cursiv_sim/ros2_adapter.py` maps `sensor_msgs/msg/{Temperature, RelativeHumidity, FluidPressure, Image}` and
`NavSatFix` (location) into observations. A ROS variance of 0 means unknown, so the uncertainty is set to null. ROS stamps get
`time_source: "unknown"` unless the caller states otherwise. Unit conversions are recorded in `processing`. The
`Ros2Forwarder` node only subscribes. **Live ROS 2 operation is unverified**: no ROS 2 installation was available.
