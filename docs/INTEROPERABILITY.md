# Interoperability

All converters are **experimental mappings**. Each takes only verified evidence: it refuses anything
else, or labels it when explicitly forced. Each writes the verification status into its output.

**No standards conformance is claimed**: no official conformance test suite was run for any target.
The tests check the outputs as follows:

| Target | Tool | Direction | Tested against |
|---|---|---|---|
| W3C PROV (PROV-JSON) | `cursiv-verify convert --to prov` | package → PROV | the W3C-community `prov` Python library parses every document and re-serialises it as PROV-N (`tests/test_api.py`); completeness checked in `tests/api.rs` |
| OGC SensorThings API 1.1 data model | `cursiv-verify convert --to sensorthings` | package → JSON entities (deep-insert shape) | required properties of each entity type per the specification's tables (`tests/api.rs`). Not posted to a SensorThings server. |
| MCAP | `cursiv_ros2.mcap_io` | both | `mcap` / `mcap-ros2-support` readers decode exported files, including from a live ROS 2 capture (`tests/test_mcap.py`, `tests/test_ros2.py`) |
| Foxglove-style workflows | MCAP export | package → MCAP | JSON channels with JSON Schema, and `foxglove.LocationFix` in the shape Foxglove publishes. **Not opened in Foxglove itself.** |
| ROS 2 | `cursiv_ros2` capture node | ROS graph → package | live ROS 2 Jazzy graph with simulated publishers (`tests/test_ros2.py`). **Not on a physical robot.** |
| BagIt (RFC 8493) | package format | both | `bagit-python` validates packages (`tests/test_interop.py`) |
| DSSE | every signed record, checkpoint, seal and manifest | both | `securesystemslib` verifies records and manifests (`tests/test_interop.py`) |

## Provenance carried across conversions

| Cursiv | PROV | SensorThings | MCAP (JSON channels) |
|---|---|---|---|
| Record (observation) | `entity cursiv:obs/<robot>/<id>` with `cursiv:record_sha256`, `cursiv:record_seq`, `cursiv:synthetic` | `Observation` with `parameters.{observation_id, record_sha256, record_seq, synthetic}` | message with `record_seq`, `record_sha256`, `synthetic` |
| Robot / sensor | `agent`s with `actedOnBehalfOf` (sensor for robot) | `Thing` / `Sensor` (calibration in `metadata`) | channel `/cursiv/<robot>/<type>` |
| Sensor time | `wasGeneratedBy` `prov:time` | `phenomenonTime` | `log_time` and `timestamp` |
| Written time | none | `resultTime` | none |
| Value, unit, uncertainty | `prov:value`, `cursiv:unit`, `cursiv:uncertainty` | `result`, `unitOfMeasurement` (UCUM where known), `resultQuality` | `value`, `unit`, `standard_uncertainty` |
| Location | `prov:location` (WKT point) | `FeatureOfInterest` (GeoJSON), last `Location` of the Thing | `foxglove.LocationFix` on `/cursiv/<robot>/location` |
| Processing steps | activity attribute `cursiv:processing` (JSON) | none (lost) | none (lost) |
| `derived_from` | `wasDerivedFrom` + `used` with the deriving activity | none (lost; derived values exported as Observations) | none |
| Correction | `wasDerivedFrom` typed `prov:Revision` with the reason | `parameters.corrects` | none |
| Finding (interpretation) | entity `cursiv:Interpretation`; author agent (human / AI with model); `wasDerivedFrom` with `cursiv:role` supports / contradicts | skipped (counted) | not exported |
| Attachment | entity `cursiv:blob/<sha256>` with media type and size | none | raw ROS 2 messages re-emitted byte for byte on their original topic, with the captured ros2msg schema |
| Package and verification | `prov:Collection` with `hadMember`; `cursiv:verification` | `verification` at top level | `cursiv.package` metadata record |

## What cannot be represented (lossy)

These lists are also embedded in every output (`losses`).

- **Signatures, hash chains, Merkle checkpoints and segment seals.** None of the targets has these concepts.
  Hashes and key ids are carried as attributes, but no consumer of PROV, SensorThings or MCAP can check them.
  **The package remains the evidence.** The converted files are views of it.
- **SensorThings** has no place for non-numeric observations (images, opaque ROS messages, capture accounting)
  or interpretations. These are skipped, and their count is reported as `skipped`. It also loses derivation
  links and processing steps. Robot positions are per-observation FeatureOfInterest, not HistoricalLocations.
  ObservedProperty definitions are `urn:cursiv:observation-type:<type>`; no external vocabulary is implied.
- **PROV** has no standard vocabulary for units, uncertainty, quality or epistemic labels, so they appear
  under the `cursiv:` prefix (`urn:cursiv:`).
- **MCAP JSON channels** keep values, units, uncertainty and record references, not the processing history.
  Raw ROS 2 messages are exact. A message type whose definition was not available at capture is
  exported without a schema and counted as `raw_without_schema`.
- **MCAP import** keeps every message's exact bytes, channel metadata, log and publish time, and sequence.
  Values are decoded only for ROS 2 CDR channels with a `ros2msg` schema. Other encodings (JSON, protobuf,
  ...) are kept opaque and labelled with their type and encoding.
