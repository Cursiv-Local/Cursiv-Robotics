//! Durable evidence store: one append-only, robot-signed log per robot, a
//! content-addressed attachment store, and the station's receipt ledger.
//!
//! Layout under the store root (store format 2):
//!   store-format.json                    {"format": 2}
//!   robots/<robot_id>/segments/NNNNNN.jsonl      robot-signed envelopes (Record payloads), in order
//!   robots/<robot_id>/segments/NNNNNN.seal.json  station seal of a full segment (see `segment`)
//!   robots/<robot_id>/checkpoints.jsonl  robot-signed Checkpoint envelopes
//!   receipts.jsonl                       station receipt chain (when each record arrived)
//!   incidents.jsonl                      rejected or suspicious submissions (no payloads)
//!   blobs/sha256/<hex>                   attachments, named by their SHA-256
//!
//! Each robot's log is separate, so robots never contend for one serialized
//! chain (Cursiv's notebook keeps one chain per device and rereads it on every
//! append; that does not scale to sensor streams).
//!
//! Memory: per record the store keeps a 32-byte hash and a 16-byte observation-id fingerprint,
//! never the record itself; Merkle roots are maintained incrementally.
//!
//! Format 1 stores (one `records.jsonl` per robot) are migrated on open by renaming that file
//! to `segments/000001.jsonl`: the bytes are unchanged, and the rename is atomic and idempotent.

use crate::crypto::{is_sha256_hex, sha256_hex, Envelope, Identity};
use crate::merkle::{self, Frontier};
use crate::model::{self, Checkpoint, Record, GENESIS, RECORD_SCHEMA, CHECKPOINT_SCHEMA};
use crate::segment::{self, Seal};
use crate::trust::{KeyVerdict, TrustStore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// A temp-file name no other writer (thread or process) can be using.
pub(crate) fn unique_tmp(dir: &Path, stem: &str) -> PathBuf {
    let n = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    dir.join(format!("{stem}.{}.{t}.{n}.tmp", std::process::id()))
}

fn tree_bytes(p: &Path) -> u64 {
    let Ok(rd) = fs::read_dir(p) else { return 0 };
    rd.flatten().map(|e| match e.file_type() {
        Ok(t) if t.is_dir() => tree_bytes(&e.path()),
        Ok(t) if t.is_file() => e.metadata().map(|m| m.len()).unwrap_or(0),
        _ => 0,
    }).sum()
}

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

/// The receipt without its hash, fields in alphabetical order: serde_json serialises this to
/// exactly the bytes of the sorted-key object the hash has always been defined over (tested in
/// `receipt_hash_is_unchanged`), without building a JSON tree per receipt.
#[derive(Serialize)]
struct ReceiptBody<'a> {
    prev: &'a str,
    received_time: &'a str,
    record_hash: &'a str,
    robot_id: &'a str,
    robot_seq: u64,
    schema: &'a str,
    seq: u64,
    station_id: &'a str,
}

impl Receipt {
    pub fn compute_hash(&self) -> String {
        let b = ReceiptBody { prev: &self.prev, received_time: &self.received_time, record_hash: &self.record_hash, robot_id: &self.robot_id,
                              robot_seq: self.robot_seq, schema: &self.schema, seq: self.seq, station_id: &self.station_id };
        sha256_hex(serde_json::to_string(&b).expect("receipt").as_bytes())
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
                "storage_full" => 507,
                "store_failed" => 503,
                "invalid_observation" | "unknown_correction_target" => 422,
                _ => 409,
            },
        }
    }
}

pub const STORE_FORMAT: u64 = 2;

/// 16-byte fingerprint of an observation id (collision chance negligible: 2^-64 at 4 billion ids).
pub(crate) fn id_fingerprint(id: &str) -> u128 {
    let d = Sha256::digest(id.as_bytes());
    u128::from_be_bytes(d[..16].try_into().unwrap())
}

pub(crate) fn hash_bytes(hex_hash: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    if let Ok(b) = hex::decode(hex_hash) {
        if b.len() == 32 {
            out.copy_from_slice(&b);
        }
    }
    out
}

#[derive(Clone)]
struct ActiveSegment {
    number: u64,
    first_seq: u64,
    records: u64,
    bytes: u64,
    prev_hash: String,
    hasher: Sha256,
    frontier: Frontier,
}

#[derive(Clone)]
struct RobotState {
    /// payload hash of every record, by seq - 1
    hashes: Vec<[u8; 32]>,
    head: String,
    log: Frontier,
    /// Merkle frontier of the records written to disk (lags `log` only inside ingest_batch)
    disk: Frontier,
    observation_ids: HashSet<u128>,
    missions: BTreeMap<String, u64>,
    keyids: BTreeSet<String>,
    active: ActiveSegment,
    /// payload hash of the last seal ("genesis" before the first)
    last_seal: String,
}

impl Default for RobotState {
    fn default() -> Self {
        RobotState {
            hashes: Vec::new(), head: GENESIS.into(), log: Frontier::new(), disk: Frontier::new(), observation_ids: HashSet::new(),
            missions: BTreeMap::new(), keyids: BTreeSet::new(), last_seal: GENESIS.into(),
            active: ActiveSegment { number: 1, first_seq: 1, records: 0, bytes: 0, prev_hash: GENESIS.into(), hasher: Sha256::new(), frontier: Frontier::new() },
        }
    }
}

impl RobotState {
    fn head(&self) -> String {
        self.head.clone()
    }
    fn count(&self) -> u64 {
        self.hashes.len() as u64
    }
    /// Merkle root over records 1..=n (n <= count). O(log n) for the current count, O(n) otherwise.
    fn root_at(&self, n: u64) -> String {
        if n == self.count() {
            return self.log.root();
        }
        let hs: Vec<String> = self.hashes[..n as usize].iter().map(hex::encode).collect();
        merkle::root(&hs)
    }
    fn accept(&mut self, hash: &str, obs_id: &str, mission: &str, keyid: &str) {
        self.accept_leaf(hash, merkle::leaf_hash(hash), obs_id, mission, keyid)
    }
    fn accept_leaf(&mut self, hash: &str, leaf: [u8; 32], obs_id: &str, mission: &str, keyid: &str) {
        self.hashes.push(hash_bytes(hash));
        self.log.push_leaf(leaf);
        self.head = hash.to_string();
        self.observation_ids.insert(id_fingerprint(obs_id));
        match self.missions.get_mut(mission) {
            Some(n) => *n += 1,
            None => {
                self.missions.insert(mission.to_string(), 1);
            }
        }
        if !self.keyids.contains(keyid) {
            self.keyids.insert(keyid.to_string());
        }
    }
}

/// Segment rotation limits (whichever is reached first).
#[derive(Clone, Copy, Debug)]
pub struct SegmentLimits {
    pub records: u64,
    pub bytes: u64,
}

impl Default for SegmentLimits {
    fn default() -> Self {
        SegmentLimits { records: segment::DEFAULT_SEGMENT_RECORDS, bytes: segment::DEFAULT_SEGMENT_BYTES }
    }
}

pub struct Store {
    root: PathBuf,
    pub station_id: String,
    station: Identity,
    trust: TrustStore,
    robots: BTreeMap<String, RobotState>,
    receipts: Frontier,
    receipt_head: String,
    pub recovery_notes: Vec<String>,
    pub segment_limits: SegmentLimits,
    pub max_attachment_bytes: u64,
    /// Set after a failed write. In-memory state may then be ahead of disk, so every further
    /// write is refused until the service restarts and rebuilds its state from disk.
    failed: Option<String>,
    /// Optional limit on the store's total size (records, receipts, attachments).
    quota: Option<u64>,
    used: Arc<AtomicU64>,
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

fn append_refs(path: &Path, lines: &[&String]) -> std::io::Result<()> {
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

fn make_seal(station_id: &str, rid: &str, active: &ActiveSegment, last_hash: &str, last_seq: u64, disk: &Frontier, prev_seal: &str) -> Seal {
    Seal {
        schema: segment::SEAL_SCHEMA.into(), station_id: station_id.into(), robot_id: rid.into(), segment: active.number,
        first_seq: active.first_seq, last_seq, prev_hash: active.prev_hash.clone(), last_hash: last_hash.into(),
        file_sha256: hex::encode(active.hasher.clone().finalize()), file_size: active.bytes,
        segment_merkle_root: active.frontier.root(), log_merkle_root: disk.root(), prev_seal: prev_seal.into(), sealed_time: model::now_utc(),
    }
}

fn write_seal(station: &Identity, segdir: &Path, seal: &Seal) -> std::io::Result<String> {
    let env = segment::sign_seal(station, seal);
    write_atomic(&segdir.join(segment::seal_name(seal.segment)), &serde_json::to_string_pretty(&env).unwrap())?;
    Ok(segment::seal_hash(&env))
}

/// Stream a JSONL file line by line. A torn final line (crash mid-write) is cut off and
/// reported; any other unreadable line is a hard error (the store will not start over
/// corruption). Returns the SHA-256 and length of the good bytes.
fn scan_jsonl(path: &Path, notes: &mut Vec<String>, mut each: impl FnMut(&str) -> Result<(), String>) -> Result<(String, u64), String> {
    let Ok(f) = File::open(path) else { return Ok((hex::encode(Sha256::digest(b"")), 0)) };
    let mut reader = BufReader::with_capacity(256 * 1024, f);
    let mut hasher = Sha256::new();
    let mut good_len: u64 = 0;
    let mut line = String::new();
    let mut n = 0;
    loop {
        line.clear();
        let read = reader.read_line(&mut line).map_err(|e| format!("{}: {e}", path.display()))?;
        if read == 0 {
            break;
        }
        n += 1;
        let complete = line.ends_with('\n');
        let parsed = if complete { each(line.trim_end()) } else { Err("incomplete".into()) };
        match parsed {
            Ok(()) => {
                hasher.update(line.as_bytes());
                good_len += read as u64;
            }
            Err(e) => {
                // Is this the last line? Then it is a torn write.
                let mut rest = String::new();
                reader.read_to_string(&mut rest).map_err(|e| e.to_string())?;
                if rest.trim().is_empty() && (!complete || e == "unparseable") {
                    let f = OpenOptions::new().write(true).open(path).map_err(|e| e.to_string())?;
                    f.set_len(good_len).map_err(|e| e.to_string())?;
                    f.sync_all().map_err(|e| e.to_string())?;
                    notes.push(format!("{}: removed an incomplete final line {n} (interrupted write)", path.display()));
                    break;
                }
                return Err(format!("{}: line {n}: {e}; refusing to start", path.display()));
            }
        }
    }
    Ok((hex::encode(hasher.finalize()), good_len))
}

fn parse_line<T: for<'de> Deserialize<'de>>(line: &str) -> Result<T, String> {
    serde_json::from_str(line).map_err(|_| "unparseable".to_string())
}

/// Look the signing key up in the trust store, verify the DSSE signature with it, then
/// check the key's status and validity window. A key the submitter names but the
/// operator did not enrol is untrusted, however valid its signature.
fn check_key(trust: &TrustStore, robot_id: &str, env: &Envelope, seq: Option<u64>) -> Result<(), Outcome> {
    let kid = env.keyid().to_string();
    let Some(k) = trust.robot(robot_id, &kid) else {
        return Err(Outcome::reject("untrusted_key", format!("key {kid} is not enrolled for {robot_id}")));
    };
    if !env.verify_with_b64(&k.public_key) {
        return Err(Outcome::reject("bad_signature", format!("signature does not verify with {robot_id}'s enrolled key {kid}")));
    }
    match TrustStore::verdict(k, seq) {
        KeyVerdict::Trusted => Ok(()),
        KeyVerdict::Revoked => Err(Outcome::reject("revoked_key", format!("key {kid} for {robot_id} is revoked"))),
        KeyVerdict::OutOfWindow => Err(Outcome::reject("key_out_of_window", format!("key {kid} is not valid for {robot_id} at this sequence number"))),
        _ => Err(Outcome::reject("untrusted_key", format!("key {kid} is not usable for {robot_id}"))),
    }
}

/// Batches at least this large are checked on several threads.
const PARALLEL_MIN: usize = 32;

/// A record that passed the stateless checks, with what the serial stage needs precomputed.
struct Ready {
    rec: Record,
    hash: String,
    leaf: [u8; 32],
    line: String,
}

type Prepared = Result<Ready, Outcome>;

/// Stateless checks of one envelope (see `Store::prepare_all`). Same order and codes as before.
fn prepare(trust: &TrustStore, env: &Envelope) -> Prepared {
    if env.payload_type != crate::crypto::RECORD_TYPE {
        return Err(Outcome::reject("malformed", format!("payloadType must be {}", crate::crypto::RECORD_TYPE)));
    }
    let text = env.body_text().ok_or_else(|| Outcome::reject("malformed", "payload is not base64 UTF-8"))?;
    let rec: Record = serde_json::from_str(&text).map_err(|e| Outcome::reject("malformed", format!("payload is not a valid record: {e}")))?;
    if rec.schema != RECORD_SCHEMA || !model::valid_id(&rec.robot_id) {
        return Err(Outcome::reject("malformed", "unsupported record schema or robot id"));
    }
    check_key(trust, &rec.robot_id, env, Some(rec.seq))?;
    if rec.observation.robot_id != rec.robot_id {
        return Err(Outcome::reject("invalid_observation", "observation.robot_id differs from the record's robot_id"));
    }
    let problems = rec.observation.structural_problems();
    if !problems.is_empty() {
        return Err(Outcome::reject("invalid_observation", problems.join("; ")));
    }
    let hash = env.payload_hash();
    let leaf = merkle::leaf_hash(&hash);
    let line = serde_json::to_string(env).expect("envelope");
    Ok(Ready { rec, hash, leaf, line })
}

/// Write a small file atomically (temp file, fsync, rename).
fn write_atomic(path: &Path, text: &str) -> std::io::Result<()> {
    let tmp = unique_tmp(path.parent().unwrap_or(Path::new(".")), ".write");
    {
        let mut f = File::create(&tmp)?;
        f.write_all(text.as_bytes())?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)
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
            robots: BTreeMap::new(), receipts: Frontier::new(), receipt_head: GENESIS.into(), recovery_notes: Vec::new(),
            segment_limits: SegmentLimits::default(),
            max_attachment_bytes: 256 * 1024 * 1024,
            failed: None, quota: None, used: Arc::new(AtomicU64::new(0)),
        };
        let mut notes = Vec::new();
        let format_file = root.join("store-format.json");
        if let Ok(t) = fs::read_to_string(&format_file) {
            let v: serde_json::Value = serde_json::from_str(&t).map_err(|_| "store-format.json is unreadable")?;
            if v["format"].as_u64() != Some(STORE_FORMAT) {
                return Err(format!("store format {} is not supported by this version (expects {STORE_FORMAT})", v["format"]));
            }
        }
        for e in fs::read_dir(root.join("robots")).map_err(|e| e.to_string())?.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if !model::valid_id(&name) || !e.path().is_dir() {
                return Err(format!("unexpected entry robots/{name}"));
            }
            let st = s.load_robot(&name, &e.path(), &mut notes)?;
            let _ = scan_jsonl(&e.path().join("checkpoints.jsonl"), &mut notes, |l| parse_line::<Envelope>(l).map(|_| ()))?;
            s.robots.insert(name, st);
        }
        // Receipts are streamed: only the chain head, a Merkle frontier and, per robot, the
        // highest receipted record are kept.
        let mut receipted: BTreeMap<String, u64> = BTreeMap::new();
        let (mut prev, mut frontier) = (GENESIS.to_string(), Frontier::new());
        let mut i = 0u64;
        scan_jsonl(&root.join("receipts.jsonl"), &mut notes, |l| {
            let r: Receipt = parse_line(l)?;
            i += 1;
            if r.seq != i || r.prev != prev || r.compute_hash() != r.hash {
                return Err(format!("receipts.jsonl: chain broken at receipt {i}"));
            }
            let m = receipted.entry(r.robot_id.clone()).or_default();
            *m = (*m).max(r.robot_seq);
            frontier.push(&r.hash);
            prev = r.hash;
            Ok(())
        })?;
        s.receipts = frontier;
        s.receipt_head = prev;
        // A crash between writing a record and its receipt leaves records without receipts.
        let mut late = Vec::new();
        for (rid, st) in &s.robots {
            let from = receipted.get(rid).copied().unwrap_or(0);
            for q in from + 1..=st.count() {
                late.push((rid.clone(), q, hex::encode(st.hashes[(q - 1) as usize])));
            }
        }
        if !late.is_empty() {
            notes.push(format!("{} record(s) had no receipt after an interruption; receipts added now, marked by their later time", late.len()));
            let lines = late.iter().map(|(r, q, h)| s.next_receipt(r, *q, h)).collect::<Vec<_>>();
            append_lines(&root.join("receipts.jsonl"), &lines).map_err(|e| e.to_string())?;
        }
        if !format_file.exists() {
            write_atomic(&format_file, &format!("{{\"format\": {STORE_FORMAT}}}\n")).map_err(|e| e.to_string())?;
        }
        if !notes.is_empty() {
            for n in &notes {
                s.incident("recovery", None, n);
            }
        }
        s.recovery_notes = notes;
        s.used.store(tree_bytes(root), Ordering::Relaxed);
        Ok(s)
    }

    /// Rebuild one robot's state from its segments, migrating a format-1 `records.jsonl` first.
    fn load_robot(&self, name: &str, dir: &Path, notes: &mut Vec<String>) -> Result<RobotState, String> {
        let segdir = dir.join("segments");
        let legacy = dir.join("records.jsonl");
        if legacy.is_file() {
            let has_segments = fs::read_dir(&segdir).map(|mut d| d.next().is_some()).unwrap_or(false);
            if has_segments {
                return Err(format!("robots/{name} has both records.jsonl and segments/; refusing to guess which is current"));
            }
            fs::create_dir_all(&segdir).map_err(|e| e.to_string())?;
            fs::rename(&legacy, segdir.join(segment::segment_name(1))).map_err(|e| format!("migrating robots/{name}: {e}"))?;
            notes.push(format!("robots/{name}: format-1 log moved unchanged to segments/000001.jsonl (store format 2)"));
        }
        let mut numbers: BTreeMap<u64, (bool, bool)> = BTreeMap::new();
        if let Ok(rd) = fs::read_dir(&segdir) {
            for e in rd.flatten() {
                let fname = e.file_name().to_string_lossy().to_string();
                if fname.ends_with(".tmp") {
                    let _ = fs::remove_file(e.path()); // an unfinished seal write
                    continue;
                }
                let Some((n, is_seal)) = segment::parse_name(&fname) else {
                    return Err(format!("unexpected file robots/{name}/segments/{fname}"));
                };
                let entry = numbers.entry(n).or_default();
                if is_seal { entry.1 = true } else { entry.0 = true }
            }
        }
        let mut st = RobotState::default();
        let last = numbers.keys().next_back().copied().unwrap_or(0);
        for (i, (&n, &(has_file, has_seal))) in numbers.iter().enumerate() {
            if n != i as u64 + 1 || !has_file {
                return Err(format!("robots/{name}: segment {} is missing; refusing to start", i + 1));
            }
            if !has_seal && n != last {
                return Err(format!("robots/{name}: segment {n} has no seal but is not the last segment"));
            }
            let path = segdir.join(segment::segment_name(n));
            st.active = ActiveSegment { number: n, first_seq: st.count() + 1, records: 0, bytes: 0, prev_hash: st.head(),
                                        hasher: Sha256::new(), frontier: Frontier::new() };
            let mut seg_records = 0u64;
            let mut seg_frontier = Frontier::new();
            let (sha, size) = scan_jsonl(&path, notes, |l| {
                let env: Envelope = parse_line(l)?;
                let rec: Record = env.body_text().and_then(|t| serde_json::from_str(&t).ok()).ok_or_else(|| "unparseable".to_string())?;
                let q = st.count() + 1;
                if rec.seq != q || rec.prev != st.head() || rec.robot_id != name {
                    return Err(format!("chain broken at record {q}"));
                }
                let hash = env.payload_hash();
                st.accept(&hash, &rec.observation.observation_id, &rec.observation.mission_id, env.keyid());
                st.active.hasher.update(l.as_bytes());
                st.active.hasher.update(b"\n");
                seg_frontier.push(&hash);
                seg_records += 1;
                Ok(())
            })?;
            if has_seal {
                let env: Envelope = fs::read_to_string(segdir.join(segment::seal_name(n))).ok()
                    .and_then(|t| serde_json::from_str(&t).ok()).ok_or(format!("robots/{name}: seal {n} unreadable"))?;
                let seal = segment::decode(&env).map_err(|e| format!("robots/{name}: seal {n}: {e}"))?;
                if seal.file_sha256 != sha || seal.file_size != size || seal.last_seq != st.count() || seal.prev_seal != st.last_seal {
                    return Err(format!("robots/{name}: segment {n} differs from its seal; refusing to start"));
                }
                st.last_seal = segment::seal_hash(&env);
                st.active = ActiveSegment { number: n + 1, first_seq: st.count() + 1, records: 0, bytes: 0, prev_hash: st.head(),
                                            hasher: Sha256::new(), frontier: Frontier::new() };
            } else {
                st.active.records = seg_records;
                st.active.bytes = size;
                st.active.frontier = seg_frontier;
            }
        }
        st.disk = st.log.clone();
        Ok(st)
    }

    /// Records per segment and bytes per segment before rotation.
    pub fn set_segment_limits(&mut self, limits: SegmentLimits) {
        self.segment_limits = SegmentLimits { records: limits.records.max(1), bytes: limits.bytes.max(1) };
    }

    /// Refuse writes that would take the store past `bytes` (HTTP 507), before anything changes.
    pub fn set_quota(&mut self, bytes: Option<u64>) {
        self.quota = bytes;
    }

    pub fn used_bytes(&self) -> u64 {
        self.used.load(Ordering::Relaxed)
    }

    pub fn failed(&self) -> Option<&str> {
        self.failed.as_deref()
    }

    /// Replace the trust store (operator action). Records already stored are not re-judged;
    /// the verifier judges packages against whichever trust store it is given.
    pub fn set_trust(&mut self, trust: TrustStore) {
        self.trust = trust;
    }

    fn fail(&mut self, what: String) -> String {
        let msg = format!("{what}; the store stopped accepting writes. Restart the service: it recovers from what is on disk");
        self.incident("store_failed", None, &msg);
        self.failed = Some(msg.clone());
        msg
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
            seq: self.receipts.count() + 1,
            prev: self.receipt_head.clone(),
            station_id: self.station_id.clone(),
            robot_id: robot_id.into(),
            robot_seq,
            record_hash: record_hash.into(),
            received_time: model::now_utc(),
            hash: String::new(),
        };
        r.hash = r.compute_hash();
        self.receipts.push(&r.hash);
        self.receipt_head = r.hash.clone();
        serde_json::to_string(&r).unwrap()
    }

    fn incident(&self, kind: &str, robot_id: Option<&str>, detail: &str) {
        let line = serde_json::json!({"time": model::now_utc(), "kind": kind, "robot_id": robot_id, "detail": detail}).to_string();
        let _ = append_lines(&self.root.join("incidents.jsonl"), &[line]);
    }

    fn check_key(&self, robot_id: &str, env: &Envelope, seq: Option<u64>) -> Result<(), Outcome> {
        check_key(&self.trust, robot_id, env, seq)
    }

    /// Validate one prepared record against the current state (and the records already accepted
    /// earlier in the same batch, reflected in `self`). Does not write.
    fn admit(&mut self, env: &Envelope, pre: Prepared) -> Result<Ready, Outcome> {
        let ready = pre?;
        let (rec, hash) = (&ready.rec, &ready.hash);
        let st = match self.robots.get_mut(&rec.robot_id) {
            Some(st) => st,
            None => self.robots.entry(rec.robot_id.clone()).or_default(),
        };
        let count = st.count();
        if rec.seq == 0 {
            return Err(Outcome::reject("malformed", "seq starts at 1"));
        }
        if rec.seq <= count {
            if st.hashes[(rec.seq - 1) as usize] == hash_bytes(hash) {
                return Err(Outcome::Duplicate { robot_id: rec.robot_id.clone(), seq: rec.seq, record_hash: hash.clone() });
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
        if st.observation_ids.contains(&id_fingerprint(&rec.observation.observation_id)) {
            return Err(Outcome::reject("duplicate_observation_id", format!("observation_id {} was already recorded with different content", rec.observation.observation_id)));
        }
        if let Some(c) = &rec.observation.correction {
            if !st.observation_ids.contains(&id_fingerprint(&c.corrects_observation_id)) {
                return Err(Outcome::reject("unknown_correction_target", format!("no earlier observation {} from {}", c.corrects_observation_id, rec.robot_id)));
            }
        }
        st.accept_leaf(hash, ready.leaf, &rec.observation.observation_id, &rec.observation.mission_id, env.keyid());
        Ok(ready)
    }

    /// The stateless checks of every envelope in a batch: decoding, schema, the signature against
    /// the robot's enrolled key, the key's status, and the observation's structure. Signature
    /// checks are about 85% of ingest CPU, so large batches are split across threads. The
    /// stateful checks (sequence, chain, duplicates) then run in order in `admit`.
    fn prepare_all(&self, envs: &[Envelope]) -> Vec<Prepared> {
        let threads = std::thread::available_parallelism().map_or(1, |n| n.get()).min(8);
        if threads < 2 || envs.len() < PARALLEL_MIN {
            return envs.iter().map(|e| prepare(&self.trust, e)).collect();
        }
        let chunk = envs.len().div_ceil(threads);
        let trust = &self.trust;
        std::thread::scope(|sc| {
            let parts: Vec<_> = envs.chunks(chunk).map(|c| sc.spawn(move || c.iter().map(|e| prepare(trust, e)).collect::<Vec<_>>())).collect();
            parts.into_iter().flat_map(|h| h.join().unwrap_or_else(|_| vec![])).collect()
        })
    }

    /// Ingest a batch. Accepted records are written and fsynced before this returns.
    /// Each envelope gets its own outcome; one bad record does not block the others.
    pub fn ingest_batch(&mut self, envs: &[Envelope]) -> Result<Vec<Outcome>, String> {
        if let Some(f) = &self.failed {
            return Err(f.clone());
        }
        if let Some(q) = self.quota {
            // envelope bytes plus a receipt line each; checked before any state changes
            let need: u64 = envs.iter().map(|e| e.payload.len() as u64 + 400).sum();
            if self.used_bytes() + need > q {
                return Ok(envs.iter().map(|_| Outcome::reject("storage_full", format!(
                    "the store is at its {q}-byte quota ({} used); nothing was written. Free space or raise --max-store-bytes, then resend", self.used_bytes()))).collect());
            }
        }
        let mut outcomes = Vec::with_capacity(envs.len());
        let mut per_robot: BTreeMap<String, Vec<(String, [u8; 32])>> = BTreeMap::new();
        let mut receipts = Vec::new();
        let prepared = self.prepare_all(envs);
        if prepared.len() != envs.len() {
            return Err(self.fail("a signature-checking thread failed".into()));
        }
        for (env, pre) in envs.iter().zip(prepared) {
            match self.admit(env, pre) {
                Ok(Ready { rec, hash, leaf, line }) => {
                    let missing: Vec<String> = rec.observation.attachments.iter()
                        .filter(|a| !self.has_blob(&a.sha256)).map(|a| a.sha256.clone()).collect();
                    receipts.push(self.next_receipt(&rec.robot_id, rec.seq, &hash));
                    match per_robot.get_mut(&rec.robot_id) {
                        Some(v) => v.push((line, leaf)),
                        None => {
                            per_robot.insert(rec.robot_id.clone(), vec![(line, leaf)]);
                        }
                    }
                    outcomes.push(Outcome::Accepted { robot_id: rec.robot_id, seq: rec.seq, record_hash: hash, missing_attachments: missing });
                }
                Err(o) => {
                    if let Outcome::Rejected { code, detail, .. } = &o {
                        if matches!(code.as_str(), "equivocation" | "untrusted_key" | "revoked_key" | "key_out_of_window" | "bad_signature") {
                            let rid = env.body_text().and_then(|t| serde_json::from_str::<Record>(&t).ok()).map(|r| r.robot_id);
                            self.incident(code, rid.as_deref(), &format!("{detail} (payload sha256 {})", env.payload_hash()));
                        }
                    }
                    outcomes.push(o);
                }
            }
        }
        // Records first, then receipts: a crash in between is repaired at the next open().
        // Any write failure (disk full, I/O error) stops the store: memory is now ahead of disk.
        let written: u64 = per_robot.values().flatten().map(|(l, _)| l.len() as u64 + 1).sum::<u64>()
            + receipts.iter().map(|l| l.len() as u64 + 1).sum::<u64>();
        for (rid, lines) in &per_robot {
            if let Err(e) = self.append_records(rid, lines) {
                return Err(self.fail(format!("write failed for {rid}: {e}")));
            }
        }
        if let Err(e) = append_lines(&self.root.join("receipts.jsonl"), &receipts) {
            return Err(self.fail(format!("receipt write failed: {e}")));
        }
        self.used.fetch_add(written, Ordering::Relaxed);
        Ok(outcomes)
    }

    /// A robot's signed checkpoint. Accepted when it agrees with what was received,
    /// or when it claims records not yet received (which proves they are missing).
    pub fn ingest_checkpoint(&mut self, env: &Envelope) -> Outcome {
        if let Some(f) = &self.failed {
            return Outcome::reject("store_failed", f.clone());
        }
        if env.payload_type != crate::crypto::CHECKPOINT_TYPE {
            return Outcome::reject("malformed", format!("payloadType must be {}", crate::crypto::CHECKPOINT_TYPE));
        }
        let cp: Checkpoint = match env.body_text().ok_or("payload is not base64 UTF-8".to_string()).and_then(|t| serde_json::from_str(&t).map_err(|e| e.to_string())) {
            Ok(c) => c,
            Err(e) => return Outcome::reject("malformed", format!("not a checkpoint: {e}")),
        };
        if cp.schema != CHECKPOINT_SCHEMA || !model::valid_id(&cp.robot_id) {
            return Outcome::reject("malformed", "unsupported checkpoint");
        }
        if let Err(o) = self.check_key(&cp.robot_id, env, None) {
            return o;
        }
        let disagrees = self.robots.get(&cp.robot_id).is_some_and(|st| {
            let n = cp.count;
            n > 0 && n <= st.count() && (hex::encode(st.hashes[(n - 1) as usize]) != cp.head || st.root_at(n) != cp.merkle_root)
        });
        if disagrees {
            self.incident("equivocation", Some(&cp.robot_id), "checkpoint disagrees with received records");
            return Outcome::reject("equivocation", "checkpoint head or Merkle root disagrees with the records received");
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
        BlobStore { root: self.root.clone(), max_bytes: self.max_attachment_bytes, quota: self.quota, used: self.used.clone(),
                    failed: self.failed.is_some() }
    }

    pub fn robot_count(&self, robot_id: &str) -> u64 {
        self.robots.get(robot_id).map_or(0, |s| s.count())
    }

    /// Key ids seen in a robot's records (for the package's informational key list).
    pub(crate) fn robot_keyids(&self, robot_id: &str) -> Vec<String> {
        self.robots.get(robot_id).map(|s| s.keyids.iter().cloned().collect()).unwrap_or_default()
    }

    pub(crate) fn robot_ids(&self) -> Vec<String> {
        self.robots.keys().cloned().collect()
    }

    /// Append accepted record lines to a robot's active segment, sealing and rotating it when
    /// it reaches the segment limits. Each segment write is fsynced; seals are written atomically.
    fn append_records(&mut self, rid: &str, lines: &[(String, [u8; 32])]) -> std::io::Result<()> {
        let segdir = self.root.join("robots").join(rid).join("segments");
        fs::create_dir_all(&segdir)?;
        let limits = self.segment_limits;
        let station_id = self.station_id.clone();
        let Some(st) = self.robots.get_mut(rid) else { return Ok(()) };
        // admit() already advanced the in-memory log; these are its last `lines.len()` records.
        let first_new = st.count() - lines.len() as u64 + 1;
        let mut chunk: Vec<&String> = Vec::new();
        for (k, (line, leaf)) in lines.iter().enumerate() {
            let seq = first_new + k as u64;
            let len = line.len() as u64 + 1;
            if st.active.records > 0 && (st.active.records >= limits.records || st.active.bytes + len > limits.bytes) {
                append_refs(&segdir.join(segment::segment_name(st.active.number)), &chunk)?;
                chunk.clear();
                let last_hash = hex::encode(st.hashes[(seq - 2) as usize]);
                let seal = make_seal(&station_id, rid, &st.active, &last_hash, seq - 1, &st.disk, &st.last_seal);
                st.last_seal = write_seal(&self.station, &segdir, &seal)?;
                st.active = ActiveSegment { number: st.active.number + 1, first_seq: seq, records: 0, bytes: 0, prev_hash: last_hash,
                                            hasher: Sha256::new(), frontier: Frontier::new() };
            }
            st.active.hasher.update(line.as_bytes());
            st.active.hasher.update(b"\n");
            st.active.frontier.push_leaf(*leaf);
            st.disk.push_leaf(*leaf);
            st.active.records += 1;
            st.active.bytes += len;
            chunk.push(line);
        }
        append_refs(&segdir.join(segment::segment_name(st.active.number)), &chunk)
    }

    /// Seal every robot's active segment (if it has records), so that everything stored so far is
    /// covered by seals. Called before an export; new records start a new segment.
    pub fn seal_active_segments(&mut self) -> Result<(), String> {
        if let Some(f) = &self.failed {
            return Err(f.clone());
        }
        let station_id = self.station_id.clone();
        let mut failure = None;
        for (rid, st) in self.robots.iter_mut() {
            if st.active.records == 0 {
                continue;
            }
            let segdir = self.root.join("robots").join(rid).join("segments");
            let seal = make_seal(&station_id, rid, &st.active, &st.head, st.count(), &st.disk, &st.last_seal);
            match write_seal(&self.station, &segdir, &seal) {
                Ok(h) => st.last_seal = h,
                Err(e) => {
                    failure = Some(format!("sealing a segment of {rid} failed: {e}"));
                    break;
                }
            }
            st.active = ActiveSegment { number: st.active.number + 1, first_seq: st.count() + 1, records: 0, bytes: 0, prev_hash: st.head.clone(),
                                        hasher: Sha256::new(), frontier: Frontier::new() };
        }
        match failure {
            Some(f) => Err(self.fail(f)),
            None => Ok(()),
        }
    }

    pub fn status(&self) -> serde_json::Value {
        let robots: BTreeMap<_, _> = self.robots.iter().map(|(id, s)| {
            (id.clone(), serde_json::json!({"records": s.count(), "head": s.head(), "missions": s.missions, "segment": s.active.number}))
        }).collect();
        let mut missions: BTreeMap<String, u64> = BTreeMap::new();
        for s in self.robots.values() {
            for (m, n) in &s.missions {
                *missions.entry(m.clone()).or_default() += n;
            }
        }
        serde_json::json!({"station_id": self.station_id, "robots": robots, "missions": missions,
                           "receipts": self.receipts.count(), "recovery_notes": self.recovery_notes, "store_format": STORE_FORMAT})
    }

    /// Station-signed checkpoint over every robot log and the receipt chain.
    pub fn station_checkpoint(&self) -> Envelope {
        let robots: BTreeMap<_, _> = self.robots.iter().map(|(id, s)| {
            (id.clone(), serde_json::json!({"count": s.count(), "head": s.head(), "merkle_root": s.log.root()}))
        }).collect();
        self.station.sign_json(crate::crypto::STATION_CHECKPOINT_TYPE, &serde_json::json!({
            "schema": "cursiv-station-checkpoint-1",
            "station_id": self.station_id,
            "signed_time": model::now_utc(),
            "robots": robots,
            "receipts": {"count": self.receipts.count(),
                         "head": self.receipt_head,
                         "merkle_root": self.receipts.root()},
        }))
    }

    /// Write a self-contained evidence package to `dest` (must not exist), in package format 2
    /// (segmented). Seals the active segments first.
    pub fn export(&mut self, dest: &Path) -> Result<serde_json::Value, String> {
        self.export_with(dest, crate::package::ExportOptions::default())
    }

    /// Export with options, e.g. package format 1 for older verifiers and importers.
    pub fn export_with(&mut self, dest: &Path, opts: crate::package::ExportOptions) -> Result<serde_json::Value, String> {
        self.seal_active_segments()?;
        crate::package::export(self, dest, &self.station, opts)
    }

    /// Segment files of a robot, in order (all sealed after `seal_active_segments`).
    pub(crate) fn segment_files(&self, robot_id: &str) -> Vec<(u64, PathBuf, Option<PathBuf>)> {
        let segdir = self.root.join("robots").join(robot_id).join("segments");
        let last = self.robots.get(robot_id).map_or(0, |s| s.active.number);
        (1..=last).filter_map(|n| {
            let f = segdir.join(segment::segment_name(n));
            let seal = segdir.join(segment::seal_name(n));
            f.is_file().then(|| (n, f, seal.is_file().then_some(seal)))
        }).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receipt_hash_is_unchanged() {
        let r = Receipt { schema: RECEIPT_SCHEMA.into(), seq: 7, prev: "ab\"c".into(), station_id: "st-1".into(), robot_id: "r-1".into(),
                          robot_seq: 3, record_hash: "f".repeat(64), received_time: "2026-11-06T00:00:00.000Z".into(), hash: String::new() };
        // the original definition: the sorted-key JSON object without "hash"
        let mut v = serde_json::to_value(&r).unwrap();
        v.as_object_mut().unwrap().remove("hash");
        assert_eq!(r.compute_hash(), sha256_hex(v.to_string().as_bytes()));
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
    quota: Option<u64>,
    used: Arc<AtomicU64>,
    failed: bool,
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
        if self.failed {
            return Err((503, "the store stopped accepting writes after a failure; restart the service".into()));
        }
        if self.quota.is_some_and(|q| self.used.load(Ordering::Relaxed) + expected_len > q) {
            return Err((507, "storing this attachment would exceed the store's quota; nothing was written".into()));
        }
        // unique per upload: two concurrent uploads of the same attachment must not share a temp file
        let tmp = unique_tmp(&self.root.join("blobs/tmp"), expected_sha);
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
        if dest.is_file() {
            // another upload of the same bytes finished first; content addressing makes them identical
            let _ = fs::remove_file(&tmp);
            return Ok(false);
        }
        fs::rename(&tmp, &dest).map_err(|e| (500, e.to_string()))?;
        self.used.fetch_add(expected_len, Ordering::Relaxed);
        Ok(true)
    }

}
