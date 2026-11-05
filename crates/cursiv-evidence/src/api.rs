//! Stable API, version 1.
//!
//! Everything here follows semantic versioning from `API_VERSION` 1.0.0 onwards: no breaking
//! change without a new major version. Items under [`experimental`] may change in any release.
//! The modules outside `api` (store, verify, segment, ...) are public for tools and tests, but only
//! what `api` re-exports is covered by the stability promise.
//!
//! ```no_run
//! use cursiv_evidence::api::{self, Format, Mode};
//! # fn main() -> Result<(), api::Error> {
//! let trust = api::load_trust("trust.json".as_ref())?;
//! let station = api::Identity::load("station.key".as_ref()).map_err(api::Error::InvalidInput)?;
//! let mut store = api::open_store("store".as_ref(), "station-a", station, trust.clone())?;
//! // ... robots submit signed records (Identity::sign_json) ...
//! api::export(&mut store, "pkg-1".as_ref(), Format::Segmented)?;
//! let v = api::verify("pkg-1".as_ref(), Some(&trust), Mode::Streaming);
//! assert!(v.status == api::Status::Verified, "{}", v.report.text());
//! # Ok(()) }
//! ```

use std::path::Path;

pub use crate::crypto::{Envelope, Identity, CHECKPOINT_TYPE, RECORD_TYPE};
pub use crate::model::{Checkpoint, Observation, Record};
pub use crate::store::{Outcome, Store};
pub use crate::trust::TrustStore;
pub use crate::verify::Report;

pub const API_VERSION: &str = "1.0.0";

/// Errors from the stable API. `#[non_exhaustive]`: match with a wildcard arm.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// A file could not be read or written.
    Io(String),
    /// Input that is not what the format requires (with the reason).
    InvalidInput(String),
    /// The store refused the operation (code as in the HTTP API, e.g. "storage_full").
    Rejected { code: String, detail: String },
    /// The store stopped accepting writes after an I/O failure; restart to recover from disk.
    StoreFailed(String),
    /// A format version this build does not read or write.
    Unsupported(String),
    /// Evidence did not verify, so the operation (e.g. a conversion) was refused.
    NotVerified(Status),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Io(e) => write!(f, "I/O error: {e}"),
            Error::InvalidInput(e) => write!(f, "invalid input: {e}"),
            Error::Rejected { code, detail } => write!(f, "rejected ({code}): {detail}"),
            Error::StoreFailed(e) => write!(f, "store failed: {e}"),
            Error::Unsupported(e) => write!(f, "unsupported: {e}"),
            Error::NotVerified(s) => write!(f, "evidence not verified (status {s:?})"),
        }
    }
}

impl std::error::Error for Error {}

/// Overall verification outcome. Only `Verified` may be treated as trusted evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Status {
    /// Every verdict passed: structure, integrity, authenticity, completeness, attachments.
    Verified,
    /// At least one verdict failed.
    Failed,
    /// Nothing failed, but authenticity or completeness could not be established (e.g. no trust store).
    Incomplete,
}

/// Package format to write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// Format 2: segmented logs with station seals (default).
    Segmented,
    /// Format 1: one records.jsonl per robot, for older verifiers and importers.
    SingleFile,
}

/// Memory mode for verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Records are streamed and not kept (memory independent of record size).
    Streaming,
    /// Records are kept in `Report::records` (needed for science checks and converters), up to the limit.
    Collect { max_records: u64 },
}

pub struct Verification {
    pub status: Status,
    pub report: Report,
}

pub fn load_trust(path: &Path) -> Result<TrustStore, Error> {
    TrustStore::load(path).map_err(Error::InvalidInput)
}

pub fn open_store(root: &Path, station_id: &str, station: Identity, trust: TrustStore) -> Result<Store, Error> {
    Store::open(root, station_id, station, trust).map_err(|e| if e.contains("not supported") { Error::Unsupported(e) } else { Error::InvalidInput(e) })
}

/// Ingest signed records. Per-record outcomes (accepted, duplicate, rejected with a code) are returned;
/// `Err` only when the store cannot write at all.
pub fn ingest(store: &mut Store, records: &[Envelope]) -> Result<Vec<Outcome>, Error> {
    store.ingest_batch(records).map_err(Error::StoreFailed)
}

/// Submit a robot-signed checkpoint (count, head, Merkle root).
pub fn checkpoint(store: &mut Store, checkpoint: &Envelope) -> Result<(), Error> {
    match store.ingest_checkpoint(checkpoint) {
        Outcome::Accepted { .. } => Ok(()),
        Outcome::Rejected { code, detail, .. } if code == "store_failed" => Err(Error::StoreFailed(detail)),
        Outcome::Rejected { code, detail, .. } => Err(Error::Rejected { code, detail }),
        Outcome::Duplicate { .. } => Ok(()),
    }
}

/// Export a signed package to `dest` (which must not exist). Atomic: no partial package is left behind.
pub fn export(store: &mut Store, dest: &Path, format: Format) -> Result<(), Error> {
    let format = match format { Format::Segmented => 2, Format::SingleFile => 1 };
    store.export_with(dest, crate::package::ExportOptions { format }).map(|_| ()).map_err(|e| {
        if store.failed().is_some() { Error::StoreFailed(e) } else { Error::Io(e) }
    })
}

/// Verify a package. Never panics on hostile input; any problem is a finding in the report.
pub fn verify(dir: &Path, trust: Option<&TrustStore>, mode: Mode) -> Verification {
    let opts = match mode {
        Mode::Streaming => crate::verify::VerifyOptions::streaming(),
        Mode::Collect { max_records } => crate::verify::VerifyOptions { collect_records: true, max_collected_records: max_records },
    };
    let report = crate::verify::verify_package_with(dir, trust, &opts);
    let status = match report.status.as_str() { "verified" => Status::Verified, "failed" => Status::Failed, _ => Status::Incomplete };
    Verification { status, report }
}

/// Items that may change in any release.
pub mod experimental {
    use super::*;

    /// Check one segment of a format-2 log against its seal (keys as base64 Ed25519 public keys).
    pub fn verify_segment(segment: &Path, seal: &Envelope, station_key_b64: &str, robot_key_b64: &str) -> crate::segment::SegmentCheck {
        crate::segment::verify_segment(segment, seal, station_key_b64, robot_key_b64)
    }

    /// W3C PROV-JSON from a verification collected with `Mode::Collect`. Refuses unverified evidence.
    pub fn to_prov_json(v: &Verification, package_name: &str) -> Result<serde_json::Value, Error> {
        if v.status != Status::Verified {
            return Err(Error::NotVerified(v.status));
        }
        crate::convert::to_prov_json(&v.report, package_name, false).map_err(Error::InvalidInput)
    }

    /// OGC SensorThings data model JSON from a verification collected with `Mode::Collect`.
    pub fn to_sensorthings(v: &Verification, package_name: &str) -> Result<serde_json::Value, Error> {
        if v.status != Status::Verified {
            return Err(Error::NotVerified(v.status));
        }
        crate::convert::to_sensorthings(&v.report, package_name, false).map_err(Error::InvalidInput)
    }
}
