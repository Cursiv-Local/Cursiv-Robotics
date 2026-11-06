# Cursiv integration contract (workspace contract 1; package formats 1 and 2)

**Status:** the Robotics side is **implemented and tested**: the package format, the reference importer, the
sample package, and ingestion of the research summary by Cursiv's own `core/documents.py`. The changes
inside the Cursiv application are **not made**. They are specified below and await the owner's approval
to change the Cursiv repository.

## Workflow

| Step | What happens | Where | Status |
|---|---|---|---|
| 1 | A robot or simulator completes a mission | robot agent / `cursiv_sim.missions` | implemented (simulated) |
| 2 | Evidence is packaged and signed | `cursiv-bridge` → `POST /v1/exports` (BagIt + station-signed DSSE manifest) | implemented |
| 3 | Transfer by USB, SSD or a local folder | any file copy; packages are plain folders | implemented |
| 4 | Discover packages | `cursiv_integration.importer.discover` (no symlinks followed, depth ≤ 4) | implemented (reference) |
| 5 | Verify integrity and provenance | `cursiv-verify package --json --science [--trust]` | implemented |
| 6 | Organise into a research workspace | `cursiv_integration.importer.import_package` | implemented (reference) |
| 7 | Generate a scientific report | `views/<package>/research-summary.md` → Cursiv `add document` and report writer | summary implemented; Cursiv report flow **not yet wired** |

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

1. **Never modify the source.** The importer fingerprints every source file before and after (`source_unchanged` in the result) and copies; it never moves.
2. **Verify before use.** Evidence enters `packages/` only if structure, integrity and attachments pass and authenticity is `pass`, or `not_assessed` when no trust store is supplied, which the summary then states. Anything else is refused, or kept in `quarantine/` with `--quarantine` and marked QUARANTINED.
3. **Re-verify the copy.** The copy must verify exactly like the source, otherwise the import is abandoned (disk or transfer fault).
4. **Keys are never taken from packages.** Trust comes from the operator's `cursiv-trust-1` files (`--trust`, repeatable).
5. **Preserve everything.** Raw records, original attachments, provenance, processing history, uncertainty, calibration and the full verification report are kept. Derived views (`views/`) can be regenerated and are labelled as such.
6. **Synthetic stays synthetic**, and **interpretations stay interpretations**: AI-authored findings appear only under "Interpretations recorded with the evidence (claims, not observations)", with the model named.

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

## Required changes in the Cursiv application (proposed, not made)

| # | Change | Cursiv file(s) | Notes |
|---|---|---|---|
| 1 | Vendor the importer (standard library only) | new `cursiv_engine/core/robotics_evidence.py` (copy of `python/cursiv_integration/importer.py`) | keep the MIT notice; pin `CONTRACT_VERSION = "1"` |
| 2 | Ship `cursiv-verify` with the app | `scripts/build_release.py`, `installer/cursiv_setup.iss` | include the binary in the signed release manifest (owner signing covers it) |
| 3 | Command `import evidence <folder or drive>` behind a confirm card | `launcher/commands_system.py`, `cursiv_engine/core/intent.py` | show the verdicts before importing; never auto-import |
| 4 | Offer discovered packages when a drive is attached | `launcher/usb_sync.py` (`plan_import`) | list only; the person confirms |
| 5 | Robotics trust store, managed in Settings | new `~/.cursiv/robotics-trust.json`; `launcher/settings_dialog.py` | **no trust-on-first-use** (unlike `fieldsync` team pins); keys added deliberately |
| 6 | Show the workspace in Research | `launcher/research_workspace.py` (`ResearchWorkspace`) | packages, verdicts, anomalies; open `research-summary.md` |
| 7 | Feed the summary to the document library and report writer | `cursiv_engine/core/documents.py` (`add`) | tested from this repo: `tests/test_integration.py::test_cursiv_document_library_ingests_the_research_summary` |
| 8 | Citation check in answers | `cursiv_engine/core/claims.py` / `core/verify.py` | flag cited `robot/observation_id`s that are not in an imported package |
| 9 | Tests in Cursiv | `tests/test_robotics_evidence.py` | reuse `examples/sample-package` and the tampered/untrusted cases from `tests/test_integration.py` |

## Try it

```powershell
cd Cursiv-Robotics
cargo build --release
py -m cursiv_integration import examples\sample-package\sample-buoy-1-package --workspace .\workspace --trust examples\sample-package\trust.json
```
