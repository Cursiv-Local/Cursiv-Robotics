# Cursiv integration contract (workspace contract 1; package formats 1 and 2)

**Status:** both sides are **implemented and tested in software**. The Robotics side covers the package
format, the reference importer and the sample package. The Cursiv side has been on Cursiv `main` since
Cursiv PR #88 (`core/robot_evidence.py`, user guide `docs/ROBOT-EVIDENCE.md`). It is **not yet in a Cursiv
release**: the latest release, 3.14-U118, does not include it. It has been tested with fixture and simulated
packages only, not with a package from a real drive, sensor or robot.

### Compatible versions

| Cursiv | Robotics importer it vendors | `cursiv-verify` it builds and bundles | Package formats |
|---|---|---|---|
| `main` after PR #88 (unreleased) | `48151c0` | `1e244e3` (`scripts/get_cursiv_verify.py`) | 1, 2 |
| next Cursiv change (to do) | this branch's hardened importer (fail-closed source and copy checks, completeness, timeout, "fully verified") | the same commit | 1, 2 |

Cursiv names the vendored commit in the header of `core/robot_evidence_import.py` and the verifier commit in
`scripts/get_cursiv_verify.py`. When either changes here, update both there in the same Cursiv change.

## Workflow

| Step | What happens | Where | Status |
|---|---|---|---|
| 1 | A robot or simulator completes a mission | robot agent / `cursiv_sim.missions` | implemented (simulated) |
| 2 | Evidence is packaged and signed | `cursiv-bridge` → `POST /v1/exports` (BagIt + station-signed DSSE manifest) | implemented |
| 3 | Transfer by USB, SSD or a local folder | any file copy; packages are plain folders | implemented |
| 4 | Discover packages | `cursiv_integration.importer.discover` (no symlinks followed, depth ≤ 4) | implemented (reference) |
| 5 | Verify integrity and provenance | `cursiv-verify package --json --science [--trust]` | implemented |
| 6 | Organise into a research workspace | `cursiv_integration.importer.import_package` | implemented (reference) |
| 7 | Generate a scientific report | `views/<package>/research-summary.md` → Cursiv `add document` and report writer | implemented: summary goes into Cursiv's documents (`robot evidence import`), answers cite records and are checked (Cursiv branch, unreleased) |

## The package (contract version 1)

A folder that is a valid BagIt 1.0 bag (RFC 8493):

```
bagit.txt                         BagIt-Version: 1.0
bag-info.txt                      includes "Cursiv-Package-Version: 1" or "2"
manifest-sha256.txt               SHA-256 of every data/ file (any BagIt tool can check fixity)
tagmanifest-sha256.txt
manifest.json                     DSSE envelope, payloadType application/vnd.cursiv.package-manifest.v1+json, signed by the station
data/robots/<robot>/records.jsonl one DSSE envelope per record (payloadType application/vnd.cursiv.record.v1+json), signed by the robot (format 1)
data/robots/<robot>/segments/     the same records split into sealed segments (format 2, the default; see docs/FORMATS.md)
data/robots/<robot>/checkpoints.jsonl
data/receipts.jsonl               when the station received each record
data/station-checkpoint.json      station-signed Merkle roots of every robot log and the receipts
data/blobs/sha256/<hex>           original attachments (images, recordings), named by SHA-256
data/keys/public-keys.json        keys seen in the package: informational, never trusted from here
data/README.txt
```

Record and observation schemas: `docs/ROBOTICS_API.md`. A package is recognised by `bagit.txt` + `data/` + a `manifest.json` with the
manifest payloadType. Importers must refuse an unknown `Cursiv-Package-Version` (tested). The reference importer reads
formats 1 and 2 (`SUPPORTED_PACKAGE_VERSIONS`), and `cursiv_integration.layout` lists a robot's record files in either format.

Compatibility rule: version 1 importers ignore unknown *files* in `data/` only if the signed manifest lists them, and refuse unknown
*fields* in records (the schema is strict). A breaking change gets `Cursiv-Package-Version: 2`.

## Import rules (implemented in the reference importer and required of Cursiv)

1. **Never modify the source, and fail closed if it changes.** The importer fingerprints every source file (path, size and
   content) before verification, then again after copying. If the source changed, or the copy is not byte-identical to that
   snapshot, the import is abandoned, the partial copy is removed, and the person is asked to import again from a stable source.
   It copies; it never moves.
2. **Verify before use.** Evidence enters `packages/` only if structure, integrity and attachments pass, completeness did not fail
   (no records missing), and authenticity is `pass`, or `not_assessed` when no trust store is supplied. Anything else is refused,
   or kept in `quarantine/` with `--quarantine` and marked QUARANTINED.
3. **Never present less than full verification as full verification.** `fully_verified` is true only when the verifier's status
   is `verified` (every verdict an unqualified pass), the science and reasoning checks ran on every record, no derived result or
   finding is invalid, and there are no scientific anomalies. Otherwise the result's `caveats` say why in plain words, and the
   research summary opens with "NOT FULLY VERIFIED" and the same reasons. Scientific problems do not stop an import; they stop it
   being called fully verified.
4. **Re-verify the copy.** The copy must also verify exactly like the source.
5. **Bounded verification time.** The verifier is stopped after `CURSIV_VERIFY_TIMEOUT` seconds (default 3600), and nothing is
   imported. A mission's science profile can be supplied with `--profile`; without one, the verifier's general profile applies
   (no mission region).
6. **Keys are never taken from packages.** Trust comes from the operator's `cursiv-trust-1` files (`--trust`, repeatable).
7. **Preserve everything.** Raw records, original attachments, provenance, processing history, uncertainty, calibration and the full verification report are kept. Derived views (`views/`) can be regenerated and are labelled as such.
8. **Synthetic stays synthetic**, and **interpretations stay interpretations**: AI-authored findings appear only under "Interpretations recorded with the evidence (claims, not observations)", with the model named.

Workspace layout:

```
workspace.json                  index: one entry per import (verdicts, counts, source, time, reasons)
packages/<name>/                exact copies of verified packages (the evidence)
quarantine/<name>/              packages that failed, only with --quarantine
views/<name>/observations.csv   every observation: id, sensor, time, value, unit, uncertainty, location, calibration, provenance, claim labels
views/<name>/<robot>.jsonl      decoded records per robot
views/<name>/verification.json  full verifier report (integrity, science, reasoning)
views/<name>/research-summary.md  citations to individual records; anomalies; derived results with recomputation status
```

## In the Cursiv application (implemented on Cursiv `main`, unreleased)

| # | What | Cursiv file(s) | State |
|---|---|---|---|
| 1 | Vendored importer and layout | `cursiv_engine/core/robot_evidence_import.py`, `robot_evidence_layout.py` | done; to be updated to the hardened importer |
| 2 | Ship `cursiv-verify` with the app | `scripts/get_cursiv_verify.py`, `launcher/build.spec` | bundled when built into `tools/`; CI builds it |
| 3 | Commands with a preview first: `robot evidence find / import / verify / show` | `cursiv_engine/core/robot_evidence.py`, `launcher/command_dispatch.py` | done; plain words only preview |
| 4 | Packages listed when a drive is compared | `launcher/usb_maker.py` | done; never imports |
| 5 | Robotics trust store, keys added deliberately (`robot trust add <file>` then `confirm`) | `~/.cursiv/robotics/trust.json` | done; **no trust on first use** |
| 6 | Import from Research Files | `launcher/research_workspace.py` | done; not yet run in the GUI |
| 7 | Summary in the document library | `cursiv_engine/core/documents.py` (`add`) | done |
| 8 | Citation check in answers | `cursiv_engine/chat/completion.py` | done: unknown `robot/observation_id`s are flagged |
| 9 | Tests | `tests/test_robot_evidence.py`, CI job `robot-evidence` (Windows, Linux) | done |

## Try it

```powershell
cd Cursiv-Robotics
cargo build --release
py -m cursiv_integration import examples\sample-package\sample-buoy-1-package --workspace .\workspace --trust examples\sample-package\trust.json
```
