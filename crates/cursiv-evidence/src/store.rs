//! Durable evidence store: one append-only, robot-signed log per robot, a
//! content-addressed attachment store, and the station's receipt ledger.
//!
//! Layout under the store root:
//!   robots/<robot_id>/records.jsonl      robot-signed envelopes (Record payloads), seq 1..n
//!   robots/<robot_id>/checkpoints.jsonl  robot-signed Checkpoint envelopes
//!   receipts.jsonl                       station receipt chain (when each record arrived)
//!   incidents.jsonl                      rejected or suspicious submissions (no payloads)
//!   blobs/sha256/<hex>                   attachments, named by their SHA-256
//!
//! Each robot's log is separate, so robots never contend for one serialized
//! chain (Cursiv's notebook keeps one chain per device and rereads it on every
//! append; that does not scale to sensor streams).

use crate::crypto::{is_sha256_hex, sha256_hex, Envelope, Identity};
use crate::merkle;
use crate::model::{self, Checkpoint, Record, GENESIS, RECORD_SCHEMA, CHECKPOINT_SCHEMA};
use crate::trust::{KeyVerdict, TrustStore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

pub const RECEIPT_SCHEMA: &str = "cursiv-receipt-1";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub schema: String,
    pub seq: u64,
    pub prev: String,
    pub station_id: String,
    pub robot_id: String,
    pub robot_seq: u64,
    pub record_hash: String,
    pub received_time: String,
    pub hash: String,
}

impl Receipt {
    pub fn compute_hash(&self) -> String {
        let mut body = serde_json::to_value(self).expect("receipt");
        body.as_object_mut().unwrap().remove("hash");
        sha256_hex(body.to_string().as_bytes())
    }
}

#[derive(Clone, Debug, Serialize, PartialEq)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Outcome {
    Accepted { robot_id: String, seq: u64, record_hash: String, missing_attachments: Vec<String> },
    Duplicate { robot_id: String, seq: u64, record_hash: String },
    Rejected { code: String, detail: String, expected_seq: Option<u64> },
}

impl Outcome {
    fn reject(code: &str, detail: impl Into<String>) -> Self {
        Outcome::Rejected { code: code.into(), detail: detail.into(), expected_seq: None }
    }
    pub fn http_status(&self) -> u16 {
        match self {
            Outcome::Accepted { .. } => 201,
            Outcome::Duplicate { .. } => 200,
            Outcome::Rejected { code, .. } => match code.as_str() {
                "bad_signature" | "malformed" => 400,
                "untrusted_key" | "revoked_key" | "key_out_of_window" => 403,
                "invalid_observation" | "unknown_correction_target" => 422,
                _ => 409,
            },
        }
    }
}

#[derive(Default, Clone)]
struct RobotState {
    hashes: Vec<String>,
    observation_ids: HashSet<String>,
    missions: BTreeMap<String, u64>,
}

impl RobotState {
    fn head(&self) -> String {
        self.hashes.last().cloned().unwrap_or_else(|| GENESIS.to_string())
    }
}

pub struct Store {
    root: PathBuf,
    pub station_id: String,
    station: Identity,
    trust: TrustStore,
    robots: BTreeMap<String, RobotState>,
    receipt_hashes: Vec<String>,
    pub recovery_notes: Vec<String>,
    pub max_attachment_bytes: u64,
}

fn append_lines(path: &Path, lines: &[String]) -> std::io::Result<()> {
    if lines.is_empty() {
        return Ok(());
    }
    let mut f = OpenOptions::new().create(true).append(true).open(path)?;
    let mut buf = String::with_capacity(lines.iter().map(|l| l.len() + 1).sum());
    for l in lines {
        buf.push_str(l);
        buf.push('\n');
    }
    f.write_all(buf.as_bytes())?;
    f.sync_data()
}

/// Read a JSONL file; a torn final line (crash mid-write) is cut off and reported.
/// Any other unreadable line is a hard error: the store will not start over corruption.
fn read_jsonl_recovering<T: for<'de> Deserialize<'de>>(path: &Path, notes: &mut Vec<String>) -> Result<Vec<T>, String> {
    let Ok(f) = File::open(path) else { return Ok(Vec::new()) };
    let mut reader = BufReader::new(f);
    let mut out = Vec::new();
    let mut good_len: u64 = 0;
    let mut line = String::new();
    let mut n = 0;
    loop {
        line.clear();
        let read = reader.read_line(&mut line).map_err(|e| e.to_string())?;
        if read == 0 {
            break;
        }
        n += 1;
        let complete = line.ends_with('\n');
        match serde_json::from_str::<T>(line.trim_end()) {
            Ok(v) if complete => {
                out.push(v);
                good_len += read as u64;
            }
            _ => {
                // Is this the last line? Then it is a torn write.
                let mut rest = String::new();
                reader.read_to_string(&mut rest).map_err(|e| e.to_string())?;
                if rest.trim().is_empty() {
                    let f = OpenOptions::new().write(true).open(path).map_err(|e| e.to_string())?;
                    f.set_len(good_len).map_err(|e| e.to_string())?;
                    f.sync_all().map_err(|e| e.to_string())?;
                    notes.push(format!("{}: removed an incomplete final line {n} (interrupted write)", path.display()));
                    break;
                }
                return Err(format!("{}: line {n} is unreadable and is not the last line; refusing to start", path.display()));
            }
        }
    }
    Ok(out)
}

impl Store {
    /// Open (or create) a store. Rebuilds in-memory indexes from disk and checks every
    /// robot log's chain; a broken chain on disk stops the store from starting.
    pub fn open(root: &Path, station_id: &str, station: Identity, trust: TrustStore) -> Result<Self, String> {
        if !model::valid_id(station_id) {
            return Err("station id must be 1-64 of [a-z0-9._-]".into());
        }
        fs::create_dir_all(root.join("robots")).map_err(|e| e.to_string())?;
        fs::create_dir_all(root.join("blobs/sha256")).map_err(|e| e.to_string())?;
        fs::create_dir_all(root.join("blobs/tmp")).map_err(|e| e.to_string())?;
        // Partial uploads never become blobs; leftovers from a crash are discarded.
        for e in fs::read_dir(root.join("blobs/tmp")).map_err(|e| e.to_string())?.flatten() {
            let _ = fs::remove_file(e.path());
        }
        let mut s = Store {
            root: root.to_path_buf(), station_id: station_id.into(), station, trust,
            robots: BTreeMap::new(), receipt_hashes: Vec::new(), recovery_notes: Vec::new(),
            max_attachment_bytes: 256 * 1024 * 1024,
        };
        let mut notes = Vec::new();
        for e in fs::read_dir(root.join("robots")).map_err(|e| e.to_string())?.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if !model::valid_id(&name) || !e.path().is_dir() {
                return Err(format!("unexpected entry robots/{name}"));
            }
            let envs: Vec<Envelope> = read_jsonl_recovering(&e.path().join("records.jsonl"), &mut notes)?;
            let mut st = RobotState::default();
            for (i, env) in envs.iter().enumerate() {
                let rec: Record = serde_json::from_str(&env.payload).map_err(|_| format!("robots/{name} record {} unreadable", i + 1))?;
                if rec.seq != i as u64 + 1 || rec.prev != st.head() || rec.robot_id != name {
                    return Err(format!("robots/{name}: chain broken at record {}; refusing to start", i + 1));
                }
                st.observation_ids.insert(rec.observation.observation_id.clone());
                *st.missions.entry(rec.observation.mission_id.clone()).or_default() += 1;
                st.hashes.push(env.payload_hash());
            }
            let _: Vec<Envelope> = read_jsonl_recovering(&e.path().join("checkpoints.jsonl"), &mut notes)?;
            s.robots.insert(name, st);
        }
        let receipts: Vec<Receipt> = read_jsonl_recovering(&root.join("receipts.jsonl"), &mut notes)?;
        let mut prev = GENESIS.to_string();
        for (i, r) in receipts.iter().enumerate() {
            if r.seq != i as u64 + 1 || r.prev != prev || r.compute_hash() != r.hash {
                return Err(format!("receipts.jsonl: chain broken at receipt {}; refusing to start", i + 1));
            }
            prev = r.hash.clone();
            s.receipt_hashes.push(r.hash.clone());
        }
        // A crash between writing a record and its receipt leaves records without receipts.
        let receipted: HashSet<(String, u64)> = receipts.iter().map(|r| (r.robot_id.clone(), r.robot_seq)).collect();
        let mut late = Vec::new();
        for (rid, st) in &s.robots {
            for (i, h) in st.hashes.iter().enumerate() {
                if !receipted.contains(&(rid.clone(), i as u64 + 1)) {
                    late.push((rid.clone(), i as u64 + 1, h.clone()));
                }
            }
        }
        if !late.is_empty() {
            notes.push(format!("{} record(s) had no receipt after an interruption; receipts added now, marked by their later time", late.len()));
            let lines = late.iter().map(|(r, q, h)| s.next_receipt(r, *q, h)).collect::<Vec<_>>();
            append_lines(&root.join("receipts.jsonl"), &lines).map_err(|e| e.to_string())?;
        }
        if !notes.is_empty() {
            for n in &notes {
                s.incident("recovery", None, n);
            }
        }
        s.recovery_notes = notes;
        Ok(s)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn station_public(&self) -> (String, String) {
        (self.station.key_id(), crate::crypto::public_b64(&self.station.public()))
    }

    pub fn trust(&self) -> &TrustStore {
        &self.trust
    }

    fn next_receipt(&mut self, robot_id: &str, robot_seq: u64, record_hash: &str) -> String {
        let mut r = Receipt {
            schema: RECEIPT_SCHEMA.into(),
            seq: self.receipt_hashes.len() as u64 + 1,
            prev: self.receipt_hashes.last().cloned().unwrap_or_else(|| GENESIS.into()),
            station_id: self.station_id.clone(),
            robot_id: robot_id.into(),
            robot_seq,
            record_hash: record_hash.into(),
            received_time: model::now_utc(),
            hash: String::new(),
        };
        r.hash = r.compute_hash();
        self.receipt_hashes.push(r.hash.clone());
        serde_json::to_string(&r).unwrap()
    }

    fn incident(&self, kind: &str, robot_id: Option<&str>, detail: &str) {
        let line = serde_json::json!({"time": model::now_utc(), "kind": kind, "robot_id": robot_id, "detail": detail}).to_string();
        let _ = append_lines(&self.root.join("incidents.jsonl"), &[line]);
    }

    fn check_key(&self, robot_id: &str, env: &Envelope, seq: Option<u64>) -> Result<(), Outcome> {
        match self.trust.robot_key(robot_id, &env.key_id, &env.public_key, seq) {
            KeyVerdict::Trusted => Ok(()),
            KeyVerdict::Revoked => Err(Outcome::reject("revoked_key", format!("key {} for {robot_id} is revoked", env.key_id))),
            KeyVerdict::OutOfWindow => Err(Outcome::reject("key_out_of_window", format!("key {} is not valid for {robot_id} at this sequence number", env.key_id))),
            _ => Err(Outcome::reject("untrusted_key", format!("key {} is not enrolled for {robot_id}", env.key_id))),
        }
    }

    /// Validate one record against the current state (and the records already accepted
    /// earlier in the same batch, reflected in `self`). Does not write.
    fn admit(&mut self, env: &Envelope) -> Result<(Record, String), Outcome> {
        if !env.signature_valid() {
            return Err(Outcome::reject("bad_signature", "signature does not match the payload and the key it names"));
        }
        let rec: Record = serde_json::from_str(&env.payload).map_err(|e| Outcome::reject("malformed", format!("payload is not a valid record: {e}")))?;
        if rec.schema != RECORD_SCHEMA || !model::valid_id(&rec.robot_id) {
            return Err(Outcome::reject("malformed", "unsupported record schema or robot id"));
        }
        if rec.observation.robot_id != rec.robot_id {
            return Err(Outcome::reject("invalid_observation", "observation.robot_id differs from the record's robot_id"));
        }
        let problems = rec.observation.structural_problems();
        if !problems.is_empty() {
            return Err(Outcome::reject("invalid_observation", problems.join("; ")));
        }
        self.check_key(&rec.robot_id, env, Some(rec.seq))?;
        let hash = env.payload_hash();
        let st = self.robots.entry(rec.robot_id.clone()).or_default();
        let count = st.hashes.len() as u64;
        if rec.seq == 0 {
            return Err(Outcome::reject("malformed", "seq starts at 1"));
        }
        if rec.seq <= count {
            if st.hashes[(rec.seq - 1) as usize] == hash {
                return Err(Outcome::Duplicate { robot_id: rec.robot_id, seq: rec.seq, record_hash: hash });
            }
            return Err(Outcome::reject("equivocation", format!(
                "{} already has a different record {}: two histories signed by the same robot (restart with lost state, or a forged fork)",
                rec.robot_id, rec.seq)));
        }
        if rec.seq > count + 1 {
            return Err(Outcome::Rejected { code: "gap".into(), detail: format!("expected seq {}, got {}", count + 1, rec.seq), expected_seq: Some(count + 1) });
        }
        if rec.prev != st.head() {
            return Err(Outcome::reject("chain_mismatch", "prev does not equal the hash of the robot's previous record"));
        }
        if st.observation_ids.contains(&rec.observation.observation_id) {
            return Err(Outcome::reject("duplicate_observation_id", format!("observation_id {} was already recorded with different content", rec.observation.observation_id)));
        }
        if let Some(c) = &rec.observation.correction {
            if !st.observation_ids.contains(&c.corrects_observation_id) {
                return Err(Outcome::reject("unknown_correction_target", format!("no earlier observation {} from {}", c.corrects_observation_id, rec.robot_id)));
            }
        }
        st.hashes.push(hash.clone());
        st.observation_ids.insert(rec.observation.observation_id.clone());
        *st.missions.entry(rec.observation.mission_id.clone()).or_default() += 1;
        Ok((rec, hash))
    }

    /// Ingest a batch. Accepted records are written and fsynced before this returns.
    /// Each envelope gets its own outcome; one bad record does not block the others.
    pub fn ingest_batch(&mut self, envs: &[Envelope]) -> Result<Vec<Outcome>, String> {
        let mut outcomes = Vec::with_capacity(envs.len());
        let mut per_robot: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut receipts = Vec::new();
        for env in envs {
            match self.admit(env) {
                Ok((rec, hash)) => {
                    let missing: Vec<String> = rec.observation.attachments.iter()
                        .filter(|a| !self.has_blob(&a.sha256)).map(|a| a.sha256.clone()).collect();
                    per_robot.entry(rec.robot_id.clone()).or_default().push(serde_json::to_string(env).unwrap());
                    receipts.push(self.next_receipt(&rec.robot_id, rec.seq, &hash));
                    outcomes.push(Outcome::Accepted { robot_id: rec.robot_id, seq: rec.seq, record_hash: hash, missing_attachments: missing });
                }
                Err(o) => {
                    if let Outcome::Rejected { code, detail, .. } = &o {
                        if matches!(code.as_str(), "equivocation" | "untrusted_key" | "revoked_key" | "key_out_of_window" | "bad_signature") {
                            let rid = serde_json::from_str::<Record>(&env.payload).ok().map(|r| r.robot_id);
                            self.incident(code, rid.as_deref(), &format!("{detail} (payload sha256 {})", env.payload_hash()));
                        }
                    }
                    outcomes.push(o);
                }
            }
        }
        // Records first, then receipts: a crash in between is repaired at the next open().
        for (rid, lines) in &per_robot {
            let dir = self.root.join("robots").join(rid);
            fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
            if let Err(e) = append_lines(&dir.join("records.jsonl"), lines) {
                return Err(format!("write failed for {rid}: {e}; restart the service to recover"));
            }
        }
        append_lines(&self.root.join("receipts.jsonl"), &receipts).map_err(|e| e.to_string())?;
        Ok(outcomes)
    }

    /// A robot's signed checkpoint. Accepted when it agrees with what was received,
    /// or when it claims records not yet received (which proves they are missing).
    pub fn ingest_checkpoint(&mut self, env: &Envelope) -> Outcome {
        if !env.signature_valid() {
            return Outcome::reject("bad_signature", "signature does not match");
        }
        let cp: Checkpoint = match serde_json::from_str(&env.payload) {
            Ok(c) => c,
            Err(e) => return Outcome::reject("malformed", format!("not a checkpoint: {e}")),
        };
        if cp.schema != CHECKPOINT_SCHEMA || !model::valid_id(&cp.robot_id) {
            return Outcome::reject("malformed", "unsupported checkpoint");
        }
        if let Err(o) = self.check_key(&cp.robot_id, env, None) {
            return o;
        }
        let st = self.robots.get(&cp.robot_id).cloned().unwrap_or_default();
        let have = st.hashes.len() as u64;
        if cp.count <= have && cp.count > 0 {
            let n = cp.count as usize;
            if st.hashes[n - 1] != cp.head || merkle::root(&st.hashes[..n]) != cp.merkle_root {
                self.incident("equivocation", Some(&cp.robot_id), "checkpoint disagrees with received records");
                return Outcome::reject("equivocation", "checkpoint head or Merkle root disagrees with the records received");
            }
        }
        let dir = self.root.join("robots").join(&cp.robot_id);
        if fs::create_dir_all(&dir).is_err()
            || append_lines(&dir.join("checkpoints.jsonl"), &[serde_json::to_string(env).unwrap()]).is_err() {
            return Outcome::reject("write_failed", "could not store checkpoint");
        }
        Outcome::Accepted { robot_id: cp.robot_id, seq: cp.count, record_hash: env.payload_hash(), missing_attachments: vec![] }
    }

    pub fn blob_path(&self, sha: &str) -> Option<PathBuf> {
        is_sha256_hex(sha).then(|| self.root.join("blobs/sha256").join(sha))
    }

    pub fn has_blob(&self, sha: &str) -> bool {
        self.blob_path(sha).is_some_and(|p| p.is_file())
    }

    pub fn blobs(&self) -> BlobStore {
        BlobStore { root: self.root.clone(), max_bytes: self.max_attachment_bytes }
    }

    pub fn robot_count(&self, robot_id: &str) -> u64 {
        self.robots.get(robot_id).map_or(0, |s| s.hashes.len() as u64)
    }

    pub fn status(&self) -> serde_json::Value {
        let robots: BTreeMap<_, _> = self.robots.iter().map(|(id, s)| {
            (id.clone(), serde_json::json!({"records": s.hashes.len(), "head": s.head(), "missions": s.missions}))
        }).collect();
        let mut missions: BTreeMap<String, u64> = BTreeMap::new();
        for s in self.robots.values() {
            for (m, n) in &s.missions {
                *missions.entry(m.clone()).or_default() += n;
            }
        }
        serde_json::json!({"station_id": self.station_id, "robots": robots, "missions": missions,
                           "receipts": self.receipt_hashes.len(), "recovery_notes": self.recovery_notes})
    }

    /// Station-signed checkpoint over every robot log and the receipt chain.
    pub fn station_checkpoint(&self) -> Envelope {
        let robots: BTreeMap<_, _> = self.robots.iter().map(|(id, s)| {
            (id.clone(), serde_json::json!({"count": s.hashes.len(), "head": s.head(), "merkle_root": merkle::root(&s.hashes)}))
        }).collect();
        self.station.sign_json(&serde_json::json!({
            "schema": "cursiv-station-checkpoint-1",
            "station_id": self.station_id,
            "signed_time": model::now_utc(),
            "robots": robots,
            "receipts": {"count": self.receipt_hashes.len(),
                         "head": self.receipt_hashes.last().cloned().unwrap_or_else(|| GENESIS.into()),
                         "merkle_root": merkle::root(&self.receipt_hashes)},
        }))
    }

    /// Write a self-contained evidence package to `dest` (must not exist).
    pub fn export(&self, dest: &Path) -> Result<serde_json::Value, String> {
        crate::package::export(self, dest, &self.station)
    }
}

/// Copy a file and return (sha256, size).
pub(crate) fn copy_hashed(src: &Path, dest: &Path) -> Result<(String, u64), String> {
    let mut input = File::open(src).map_err(|e| format!("{}: {e}", src.display()))?;
    if let Some(d) = dest.parent() {
        fs::create_dir_all(d).map_err(|e| e.to_string())?;
    }
    let mut out = File::create(dest).map_err(|e| e.to_string())?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut n_total = 0u64;
    loop {
        let n = input.read(&mut buf).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
        out.write_all(&buf[..n]).map_err(|e| e.to_string())?;
        n_total += n as u64;
    }
    out.sync_all().map_err(|e| e.to_string())?;
    let _ = input.seek(SeekFrom::Start(0));
    Ok((hex::encode(h.finalize()), n_total))
}

/// Attachment writer that can be used without holding the store lock (uploads can be slow).
#[derive(Clone)]
pub struct BlobStore {
    root: PathBuf,
    pub max_bytes: u64,
}

impl BlobStore {
    /// Store an attachment from a stream. The bytes must hash to `expected_sha` and be
    /// exactly `expected_len` long; otherwise nothing is kept (interrupted or altered transfer).
    pub fn put(&self, mut body: impl Read, expected_sha: &str, expected_len: u64) -> Result<bool, (u16, String)> {
        let dest = (is_sha256_hex(expected_sha).then(|| self.root.join("blobs/sha256").join(expected_sha))).ok_or((400, "sha256 must be 64 lowercase hex characters".to_string()))?;
        if expected_len > self.max_bytes {
            return Err((413, format!("attachment larger than the {} byte limit", self.max_bytes)));
        }
        if dest.is_file() {
            return Ok(false);
        }
        let tmp = self.root.join("blobs/tmp").join(format!("{expected_sha}.{}", std::process::id()));
        let mut f = File::create(&tmp).map_err(|e| (500, e.to_string()))?;
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; 64 * 1024];
        let mut total: u64 = 0;
        let result = loop {
            match body.read(&mut buf) {
                Ok(0) => break Ok(()),
                Ok(n) => {
                    total += n as u64;
                    if total > expected_len {
                        break Err((400, "more bytes than declared".to_string()));
                    }
                    hasher.update(&buf[..n]);
                    if let Err(e) = f.write_all(&buf[..n]) {
                        break Err((500, e.to_string()));
                    }
                }
                Err(e) => break Err((400, format!("transfer interrupted: {e}"))),
            }
        };
        let fail = |msg: (u16, String)| {
            let _ = fs::remove_file(&tmp);
            Err(msg)
        };
        if let Err(e) = result {
            return fail(e);
        }
        if total != expected_len {
            return fail((400, format!("transfer incomplete: {total} of {expected_len} bytes")));
        }
        if hex::encode(hasher.finalize()) != expected_sha {
            return fail((400, "attachment bytes do not match the declared sha256".into()));
        }
        if let Err(e) = f.sync_all() {
            return fail((500, e.to_string()));
        }
        fs::rename(&tmp, &dest).map_err(|e| (500, e.to_string()))?;
        Ok(true)
    }

}
