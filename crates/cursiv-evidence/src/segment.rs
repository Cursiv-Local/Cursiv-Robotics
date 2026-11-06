//! Segmented evidence logs (package and store format 2).
//!
//! A robot's log is split into numbered segment files, `segments/000001.jsonl`,
//! `000002.jsonl`, ..., each closed by a station-signed **seal** (`000001.seal.json`). A seal
//! commits to:
//! - the segment's exact bytes (SHA-256 and size)
//! - its record range and the Merkle root of just its records
//! - the Merkle root of the whole log up to its last record
//! - the hash of the record before it and the hash of the previous seal
//!
//! So:
//! - a single segment can be checked on its own, given its seal and the keys
//!   ([`verify_segment`]);
//! - consecutive seals chain, so a missing, duplicated, reordered or substituted segment
//!   breaks the chain;
//! - a verifier can stream segment by segment in bounded memory.
//!
//! The robot's own signed checkpoints are unchanged and still cover records 1..count.

use crate::crypto::{sha256_hex, Envelope, Identity};
use crate::merkle::Frontier;
use crate::model::{Record, GENESIS};
use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Read};
use std::path::Path;

pub const SEAL_TYPE: &str = "application/vnd.cursiv.segment-seal.v1+json";
pub const SEAL_SCHEMA: &str = "cursiv-segment-seal-1";
/// Default rotation: whichever comes first.
pub const DEFAULT_SEGMENT_RECORDS: u64 = 10_000;
pub const DEFAULT_SEGMENT_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Seal {
    pub schema: String,
    pub station_id: String,
    pub robot_id: String,
    /// 1-based segment number
    pub segment: u64,
    pub first_seq: u64,
    pub last_seq: u64,
    /// payload hash of record first_seq - 1 ("genesis" for the first segment)
    pub prev_hash: String,
    /// payload hash of record last_seq
    pub last_hash: String,
    pub file_sha256: String,
    pub file_size: u64,
    /// Merkle root over this segment's records only
    pub segment_merkle_root: String,
    /// Merkle root over records 1..=last_seq (the same value a robot checkpoint at last_seq states)
    pub log_merkle_root: String,
    /// SHA-256 of the previous seal's payload ("genesis" for the first segment)
    pub prev_seal: String,
    pub sealed_time: String,
}

pub fn segment_name(n: u64) -> String {
    format!("{n:06}.jsonl")
}

pub fn seal_name(n: u64) -> String {
    format!("{n:06}.seal.json")
}

/// Parse "000123.jsonl" or "000123.seal.json" into (123, is_seal).
pub fn parse_name(name: &str) -> Option<(u64, bool)> {
    let (num, seal) = if let Some(n) = name.strip_suffix(".seal.json") {
        (n, true)
    } else {
        (name.strip_suffix(".jsonl")?, false)
    };
    if num.len() != 6 || !num.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let n: u64 = num.parse().ok()?;
    (n > 0).then_some((n, seal))
}

pub fn sign_seal(station: &Identity, seal: &Seal) -> Envelope {
    station.sign_json(SEAL_TYPE, seal)
}

/// Decode a seal envelope's payload (does not check the signature).
pub fn decode(env: &Envelope) -> Result<Seal, String> {
    if env.payload_type != SEAL_TYPE {
        return Err(format!("payloadType {:?} is not a segment seal", env.payload_type));
    }
    let s: Seal = env.body_text().ok_or("seal payload is not base64 UTF-8").and_then(|t| serde_json::from_str(&t).map_err(|_| "seal payload is not a segment seal"))
        .map_err(|e| e.to_string())?;
    if s.schema != SEAL_SCHEMA {
        return Err(format!("unsupported seal schema {:?}", s.schema));
    }
    Ok(s)
}

/// One line of a segment, as read by [`Lines`].
pub enum Line {
    Record(Vec<u8>),
    /// The final line did not end with a newline (cut off).
    Truncated(Vec<u8>),
    TooLong,
}

/// Line reader with a per-line cap that also hashes every byte it reads, so a file is read
/// once for both its SHA-256 and its records.
pub struct Lines<R: Read> {
    inner: BufReader<R>,
    hasher: sha2::Sha256,
    bytes: u64,
    max_line: usize,
    done: bool,
}

impl<R: Read> Lines<R> {
    pub fn new(r: R, max_line: usize) -> Self {
        use sha2::Digest;
        Lines { inner: BufReader::with_capacity(256 * 1024, r), hasher: sha2::Sha256::new(), bytes: 0, max_line, done: false }
    }

    /// Next line, or None at end of file. I/O errors are returned, never swallowed.
    pub fn next_line(&mut self) -> std::io::Result<Option<Line>> {
        use sha2::Digest;
        if self.done {
            return Ok(None);
        }
        let mut line = Vec::new();
        let n = (&mut self.inner).take(self.max_line as u64 + 1).read_until(b'\n', &mut line)?;
        if n == 0 {
            self.done = true;
            return Ok(None);
        }
        self.hasher.update(&line);
        self.bytes += n as u64;
        if line.len() > self.max_line {
            self.done = true;
            return Ok(Some(Line::TooLong));
        }
        if line.last() != Some(&b'\n') {
            self.done = true;
            return Ok(Some(Line::Truncated(line)));
        }
        line.pop();
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        Ok(Some(Line::Record(line)))
    }

    /// Hash and size of everything read. Reads the rest of the file first.
    pub fn finish(mut self) -> std::io::Result<(String, u64)> {
        use sha2::Digest;
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = self.inner.read(&mut buf)?;
            if n == 0 {
                break;
            }
            self.hasher.update(&buf[..n]);
            self.bytes += n as u64;
        }
        Ok((hex::encode(self.hasher.finalize()), self.bytes))
    }
}

/// Result of checking one segment on its own.
#[derive(Debug, Default, Serialize)]
pub struct SegmentCheck {
    pub records: u64,
    pub problems: Vec<String>,
}

/// Check one segment file against its seal without the rest of the log:
/// - the seal's signature (with `station_key_b64`) and the file's hash and size
/// - every record's signature (with `robot_key_b64`), its sequence and the chain from
///   the seal's `prev_hash`
/// - the segment's Merkle root
///
/// The log-wide root and the link to the previous seal need the previous segments; the full
/// package verifier checks those.
pub fn verify_segment(segment: &Path, seal_env: &Envelope, station_key_b64: &str, robot_key_b64: &str) -> SegmentCheck {
    let mut out = SegmentCheck::default();
    if !seal_env.verify_with_b64(station_key_b64) {
        out.problems.push("seal signature does not verify with the station key".into());
    }
    let seal = match decode(seal_env) {
        Ok(s) => s,
        Err(e) => {
            out.problems.push(e);
            return out;
        }
    };
    let f = match std::fs::File::open(segment) {
        Ok(f) => f,
        Err(e) => {
            out.problems.push(format!("cannot open segment: {e}"));
            return out;
        }
    };
    let mut lines = Lines::new(f, crate::verify::MAX_LINE);
    let mut prev = seal.prev_hash.clone();
    let mut expect = seal.first_seq;
    let mut seg_root = Frontier::new();
    loop {
        match lines.next_line() {
            Err(e) => {
                out.problems.push(format!("read error: {e}"));
                return out;
            }
            Ok(None) => break,
            Ok(Some(Line::TooLong)) => {
                out.problems.push("a line exceeds the size limit".into());
                break;
            }
            Ok(Some(Line::Truncated(_))) => {
                out.problems.push("the last line is incomplete (file cut off)".into());
                break;
            }
            Ok(Some(Line::Record(l))) => {
                let env: Envelope = match serde_json::from_slice(&l) {
                    Ok(e) => e,
                    Err(_) => {
                        out.problems.push(format!("record {expect} is not a signed envelope"));
                        break;
                    }
                };
                let hash = env.payload_hash();
                if !env.verify_with_b64(robot_key_b64) {
                    out.problems.push(format!("record {expect}: signature does not verify"));
                }
                match env.body_text().and_then(|t| serde_json::from_str::<Record>(&t).ok()) {
                    Some(r) if r.seq == expect && r.prev == prev && r.robot_id == seal.robot_id => {}
                    Some(_) => out.problems.push(format!("record {expect}: sequence, chain or robot does not match")),
                    None => out.problems.push(format!("record {expect}: payload is not a record")),
                }
                seg_root.push(&hash);
                prev = hash;
                expect += 1;
                out.records += 1;
            }
        }
    }
    match lines.finish() {
        Ok((sha, size)) if sha == seal.file_sha256 && size == seal.file_size => {}
        Ok(_) => out.problems.push("file bytes differ from the seal (changed, truncated or replaced)".into()),
        Err(e) => out.problems.push(format!("read error: {e}")),
    }
    if seal.last_seq < seal.first_seq || out.records != seal.last_seq - seal.first_seq + 1 || prev != seal.last_hash {
        out.problems.push("record count or last record differs from the seal".into());
    }
    if seg_root.root() != seal.segment_merkle_root {
        out.problems.push("segment Merkle root differs from the seal".into());
    }
    out
}

/// SHA-256 of a seal envelope's payload, used to chain seals.
pub fn seal_hash(env: &Envelope) -> String {
    env.payload_hash()
}

/// Genesis value for `prev_seal` and `prev_hash` of the first segment.
pub fn genesis() -> String {
    GENESIS.to_string()
}

/// Hash helper re-exported for callers that build seals.
pub fn sha256(bytes: &[u8]) -> String {
    sha256_hex(bytes)
}
