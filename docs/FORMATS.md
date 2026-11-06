# Evidence formats

| Format | Written by default | Read | Status |
|---|---|---|---|
| Package format 2 (segmented logs, sealed) | yes | yes | stable |
| Package format 1 (one `records.jsonl` per robot) | on request (`Format::SingleFile`, bridge `{"format": 1}`) | yes | stable, kept for compatibility |
| Store format 2 (station disk layout) | yes | yes | stable |
| Store format 1 | no | migrated on open | migration only |

## Package format 2

A BagIt 1.0 bag (RFC 8493), with `Cursiv-Package-Version: 2` in `bag-info.txt` and `"package_version": 2` in the
station-signed manifest. The two must agree.

```
data/robots/<robot>/segments/000001.jsonl       robot-signed DSSE records, seq 1..k
data/robots/<robot>/segments/000001.seal.json   station-signed seal of that segment
data/robots/<robot>/segments/000002.jsonl ...
data/robots/<robot>/checkpoints.jsonl           robot-signed checkpoints (count, head, Merkle root)
data/receipts.jsonl, data/station-checkpoint.json, data/blobs/sha256/<hex>, data/keys/public-keys.json
```

The other files are unchanged from format 1 ([CURSIV_INTEGRATION.md](CURSIV_INTEGRATION.md)).

### Segment seal (`application/vnd.cursiv.segment-seal.v1+json`, schema `cursiv-segment-seal-1`)

| Field | Meaning |
|---|---|
| `segment` | 1-based number. Must match the file name. |
| `first_seq`, `last_seq` | The record range. `first_seq` = previous seal's `last_seq` + 1. |
| `prev_hash`, `last_hash` | Payload hash of the record before the segment (or `genesis`), and of its last record. |
| `file_sha256`, `file_size` | The segment file's exact bytes. |
| `segment_merkle_root` | RFC 6962 root over this segment's record hashes. Allows the segment to be checked alone. |
| `log_merkle_root` | Root over records 1..`last_seq`. This is the value a robot checkpoint at `last_seq` states. |
| `prev_seal` | SHA-256 of the previous seal's payload (or `genesis`): the seals form a chain. |
| `station_id`, `robot_id`, `sealed_time` | |

What each attack breaks:

| Attack | Detected by |
|---|---|
| Segment removed | Gap in numbering (`segment_missing`). The next seal's `prev_seal` and `first_seq` no longer link, and the record chain breaks. |
| Segments reordered or renamed | `segment` ≠ file name; `first_seq` and `prev_hash` mismatch; record sequence |
| Segment duplicated under a new number | Seal number mismatch; the file is not in the manifest |
| Bytes changed | `file_sha256`; record signatures; segment and log Merkle roots |
| Truncated (interrupted copy) | Incomplete last line; `file_sha256` and `last_seq` |
| Seal swapped or forged | Seal signature (station key from the trust store); `prev_seal` chain |

`cursiv-verify segment 000003.jsonl --trust trust.json` checks one segment against its seal, with the
station and robot keys taken from the trust store. The log-wide checks need the whole package.

## Store format 2 (station disk)

The robot directories hold `segments/` as above. `store-format.json` contains `{"format": 2}`.
- **Rotation:** a segment is sealed and a new one started at 10,000 records or 64 MiB, whichever
  comes first (`Store::set_segment_limits`). Exporting seals the active segment first, so every
  package segment is sealed.
- **Crash safety:** records are fsynced before acknowledgement and seals are written atomically.
  A torn final line in the active segment is cut off on the next start, and the cut is reported
  in `recovery_notes` and `incidents.jsonl`. A leftover `.tmp` seal is discarded. A sealed
  segment that no longer matches its seal stops the store from starting.
- **Memory:** per record, a 32-byte hash and a 16-byte observation-id fingerprint.

### Migration from store format 1

On open, each `robots/<id>/records.jsonl` is renamed to `robots/<id>/segments/000001.jsonl`. The bytes are
unchanged, and the rename is atomic and idempotent. The note "format-1 log moved unchanged" is recorded. That
legacy segment is sealed at the next rotation or export. A robot directory holding both layouts is refused
rather than guessed at.

## Verification memory

The verifier reads each log file once, computing its SHA-256 and checking its records in the same
pass. It reads checkpoints first and takes Merkle roots from an incremental frontier (O(log n)).
Receipts are streamed. Per record it keeps a 32-byte hash, for matching receipts, and a 16-byte
observation-id fingerprint, for duplicate and correction checks. Memory therefore grows with the
record count, at about 80 bytes per record, but not with record or package size. In the
measurements below, a 5 GB package peaked at 194 MiB.

| Package | Records | Streaming verify | Peak RSS (streaming) | Peak RSS (records kept, `--science`) |
|---|---|---|---|---|
| 0.1 GB | 50,199 | 2.7 s | 28.8 MiB | 142 MiB |
| 1.0 GB | 502,008 | 27.2 s | 50.1 MiB | 1,484 MiB |
| 2.0 GB | 1,004,016 | 53.3 s | 96.4 MiB | not run |
| 5.0 GB | 2,510,040 | 131.7 s | 194.3 MiB | not run |

Measured on 2026-11-05 on a 4-vCPU Linux cloud container (`bench/results/2026-11-05-linux-scale-streaming.json`).
That is software on that computer, not robot hardware.
Reproduce with: `cd python && python -m cursiv_sim.bench_scale --sizes-gb 0.1 1 2 5 --dir <disk with 12 GB free>`.

Science and reasoning checks need the records in memory. They run only when every record fits
under `--max-records` (default 2,000,000). Otherwise they report `not_assessed` rather than run on
part of the data.
