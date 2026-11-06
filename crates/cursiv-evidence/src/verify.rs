//! Independent verification of an evidence package. Needs no service, no GUI and no AI model.
//!
//! Five separate verdicts, never merged into one "valid":
//!   structure     the package is well formed and stays inside its folder
//!   integrity     nothing listed was changed, reordered or removed since signing
//!   authenticity  the signatures come from keys the operator's trust store accepts
//!   completeness  a trusted checkpoint states how many records exist, and they are all present
//!   attachments   every referenced attachment is present and unchanged
//! None of these says the measurements are scientifically correct (see `science`).

use crate::crypto::{sha256_hex, Envelope};
use crate::merkle;
use crate::model::{self, Checkpoint, Record, GENESIS};
use crate::package::{safe_rel, MANIFEST_SCHEMA};
use crate::store::Receipt;
use crate::trust::{KeyVerdict, TrustStore};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::io::{BufRead, BufReader, Read};
use std::path::Path;

pub const MAX_LINE: usize = 4 * 1024 * 1024;
pub const MAX_JSON_FILE: u64 = 64 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct Finding {
    /// structure | integrity | authenticity | completeness | attachments | corrections | provenance | labelling
    pub area: String,
    /// error | warning | info
    pub severity: String,
    pub code: String,
    pub message: String,
    pub robot_id: Option<String>,
    pub seq: Option<u64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Verdicts {
    pub structure: String,
    pub integrity: String,
    pub authenticity: String,
    pub completeness: String,
    pub attachments: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct RobotSummary {
    pub records: u64,
    pub head: String,
    pub trusted_checkpoint_count: Option<u64>,
    pub synthetic_records: u64,
    pub corrections: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct Report {
    pub schema: String,
    /// "verified" (every verdict passed), "failed" (any verdict failed) or "incomplete"
    /// (nothing failed, but authenticity or completeness could not be established).
    pub status: String,
    /// Package format read (1 or 2).
    pub package_version: u32,
    /// True when every record and receipt is in `records` / `receipts` (science can run).
    pub records_complete: bool,
    /// The outcome in plain sentences, most important first (for people, not programs; the
    /// verdicts and findings are the authoritative result).
    pub summary: Vec<String>,
    pub package: String,
    pub verified_time: String,
    pub trust_store: bool,
    pub verdicts: Verdicts,
    pub robots: BTreeMap<String, RobotSummary>,
    pub findings: Vec<Finding>,
    pub limits: Vec<String>,
    #[serde(skip)]
    pub records: Vec<(Record, String)>,
    #[serde(skip)]
    pub receipts: Vec<Receipt>,
}

struct Ctx {
    findings: Vec<Finding>,
}

impl Ctx {
    fn add(&mut self, area: &str, severity: &str, code: &str, message: impl Into<String>, robot: Option<&str>, seq: Option<u64>) {
        self.findings.push(Finding { area: area.into(), severity: severity.into(), code: code.into(), message: message.into(),
                                     robot_id: robot.map(String::from), seq });
    }
    fn err(&mut self, area: &str, code: &str, msg: impl Into<String>) {
        self.add(area, "error", code, msg, None, None)
    }
    fn errors_in(&self, area: &str) -> bool {
        self.findings.iter().any(|f| f.area == area && f.severity == "error")
    }
}

/// Files in the package; refuses symlinks, hard links and special files (as Cursiv's export_paths.inventory does).
fn inventory(root: &Path, ctx: &mut Ctx) -> BTreeMap<String, u64> {
    let mut out = BTreeMap::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(rd) = fs::read_dir(&dir) else {
            ctx.err("structure", "unreadable_dir", format!("cannot read {}", dir.display()));
            continue;
        };
        for e in rd.flatten() {
            let p = e.path();
            let Ok(meta) = fs::symlink_metadata(&p) else { continue };
            let rel = p.strip_prefix(root).unwrap().to_string_lossy().replace('\\', "/");
            if meta.file_type().is_symlink() {
                ctx.err("structure", "symlink", format!("{rel} is a symbolic link; packages may not contain links"));
            } else if meta.is_dir() {
                stack.push(p);
            } else if meta.is_file() {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::MetadataExt;
                    if meta.nlink() > 1 {
                        ctx.err("structure", "hard_link", format!("{rel} is hard-linked; packages may not contain links"));
                        continue;
                    }
                }
                out.insert(rel, meta.len());
            } else {
                ctx.err("structure", "special_file", format!("{rel} is not a regular file"));
            }
        }
    }
    out
}

fn file_sha256(path: &Path) -> Option<String> {
    let mut f = fs::File::open(path).ok()?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Some(hex::encode(h.finalize()))
}

fn read_json_file(path: &Path) -> Result<serde_json::Value, String> {
    let meta = fs::metadata(path).map_err(|e| e.to_string())?;
    if meta.len() > MAX_JSON_FILE {
        return Err("file exceeds the size limit".into());
    }
    serde_json::from_str(&fs::read_to_string(path).map_err(|e| e.to_string())?).map_err(|e| e.to_string())
}

/// JSONL lines with a per-line size cap (a hostile package cannot exhaust memory with one line).
fn read_lines(path: &Path, ctx: &mut Ctx, rel: &str) -> Vec<String> {
    let Ok(f) = fs::File::open(path) else { return vec![] };
    let mut r = BufReader::new(f);
    let mut out = Vec::new();
    let mut line = Vec::new();
    loop {
        line.clear();
        match r.by_ref().take(MAX_LINE as u64 + 1).read_until(b'\n', &mut line) {
            Ok(0) => break,
            Ok(_) => {
                if line.len() > MAX_LINE {
                    ctx.err("structure", "line_too_long", format!("{rel}: a line exceeds {MAX_LINE} bytes"));
                    break;
                }
                if !line.ends_with(b"\n") {
                    ctx.err("integrity", "truncated_file", format!("{rel}: last line is incomplete (file cut off)"));
                }
                match String::from_utf8(line.clone()) {
                    Ok(s) if !s.trim().is_empty() => out.push(s.trim_end().to_string()),
                    Ok(_) => {}
                    Err(_) => ctx.err("structure", "not_utf8", format!("{rel}: a line is not UTF-8")),
                }
            }
            Err(e) => {
                ctx.err("structure", "read_error", format!("{rel}: {e}"));
                break;
            }
        }
    }
    out
}

fn verdict_word(trust: Option<&TrustStore>, v: &KeyVerdict) -> &'static str {
    match (trust, v) {
        (None, _) => "no trust store",
        (_, KeyVerdict::Trusted) => "trusted",
        (_, KeyVerdict::Revoked) => "revoked",
        (_, KeyVerdict::OutOfWindow) => "outside its validity window",
        _ => "not in the trust store",
    }
}

/// Signature checking for DSSE envelopes, which carry no public key. The key comes from the
/// trust store when the signer is enrolled there; otherwise from the package's own key list,
/// which can show the content is unchanged relative to that key but never who holds it.
struct Signers<'a> {
    trust: Option<&'a TrustStore>,
    listed: HashMap<String, String>,
}

enum Owner<'a> {
    Robot(&'a str),
    Station(&'a str),
}

impl Signers<'_> {
    /// (Some(signature verifies) | None = no key known for this keyid, trust verdict)
    fn check(&self, env: &Envelope, owner: Owner, seq: Option<u64>) -> (Option<bool>, KeyVerdict) {
        let kid = env.keyid();
        let trusted = match (self.trust, &owner) {
            (Some(t), Owner::Robot(r)) => t.robot(r, kid),
            (Some(t), Owner::Station(s)) => t.station(s, kid),
            _ => None,
        };
        let key = trusted.map(|k| k.public_key.clone()).or_else(|| self.listed.get(kid).cloned());
        let ok = key.map(|k| env.verify_with_b64(&k));
        let verdict = match (self.trust, trusted) {
            (None, _) => KeyVerdict::NoTrustStore,
            (Some(_), None) => KeyVerdict::Unknown,
            (Some(_), Some(k)) => TrustStore::verdict(k, seq),
        };
        (ok, verdict)
    }
}

const TAG_FILES: [&str; 5] = ["bagit.txt", "bag-info.txt", "manifest-sha256.txt", "tagmanifest-sha256.txt", "manifest.json"];

/// RFC 8493 fixity: manifest-sha256.txt must list every data/ file with its hash, and
/// tagmanifest-sha256.txt the tag files. (Any BagIt tool checks the same.)
fn check_bag(dir: &Path, data: &BTreeMap<String, u64>, ctx: &mut Ctx, deferred: &mut BTreeMap<String, String>) {
    let Ok(bagit) = fs::read_to_string(dir.join("bagit.txt")) else { return };
    if !bagit.lines().any(|l| l.trim() == "BagIt-Version: 1.0") {
        ctx.err("structure", "bagit_version", "bagit.txt does not declare BagIt-Version 1.0");
    }
    let parse = |name: &str, ctx: &mut Ctx| -> BTreeMap<String, String> {
        let text = fs::read_to_string(dir.join(name)).unwrap_or_default();
        if text.is_empty() {
            ctx.err("integrity", "bag_manifest", format!("{name} is missing or empty"));
        }
        text.lines().filter_map(|l| {
            let (h, p) = l.split_once(char::is_whitespace)?;
            Some((p.trim_start().to_string(), h.to_ascii_lowercase()))
        }).collect()
    };
    let payload = parse("manifest-sha256.txt", ctx);
    for (path, hash) in &payload {
        let rel = path.strip_prefix("data/").unwrap_or("");
        if !safe_rel(path) || rel.is_empty() || !data.contains_key(rel) {
            ctx.err("integrity", "bag_manifest", format!("manifest-sha256.txt lists {path:?}, which is not a data file"));
        } else if log_file(rel).is_some() {
            deferred.insert(path.clone(), hash.clone());
        } else if file_sha256(&dir.join(path)).as_deref() != Some(hash.as_str()) {
            ctx.err("integrity", "bag_fixity", format!("{path} does not match manifest-sha256.txt"));
        }
    }
    for rel in data.keys() {
        if !payload.contains_key(&format!("data/{rel}")) {
            ctx.err("integrity", "bag_manifest", format!("data/{rel} is not in manifest-sha256.txt"));
        }
    }
    for (path, hash) in parse("tagmanifest-sha256.txt", ctx) {
        if !TAG_FILES.contains(&path.as_str()) || file_sha256(&dir.join(&path)).as_deref() != Some(hash.as_str()) {
            ctx.err("integrity", "bag_fixity", format!("tag file {path} does not match tagmanifest-sha256.txt"));
        }
    }
}

fn listed_keys(dir: &Path) -> HashMap<String, String> {
    read_json_file(&dir.join("keys/public-keys.json")).ok()
        .and_then(|v| v["keys"].as_object().map(|o| o.iter().filter_map(|(k, v)| Some((k.clone(), v["public_key"].as_str()?.to_string()))).collect()))
        .unwrap_or_default()
}

/// How much the verifier keeps in memory.
#[derive(Clone, Debug)]
pub struct VerifyOptions {
    /// Keep decoded records (and receipts) in the report for the science and reasoning checks.
    /// Without it, memory does not depend on record sizes: per record only a 32-byte hash and a
    /// 16-byte observation-id fingerprint are kept (for receipts, duplicates and corrections).
    pub collect_records: bool,
    /// Upper limit when collecting; beyond it `records_complete` is false and the science checks
    /// must report "not assessed" rather than run on a partial set.
    pub max_collected_records: u64,
}

impl Default for VerifyOptions {
    fn default() -> Self {
        VerifyOptions { collect_records: true, max_collected_records: 2_000_000 }
    }
}

impl VerifyOptions {
    /// Bounded memory: no records kept.
    pub fn streaming() -> Self {
        VerifyOptions { collect_records: false, max_collected_records: 0 }
    }
}

/// A robot log file: v1 robots/<id>/records.jsonl, v2 robots/<id>/segments/NNNNNN.jsonl.
fn log_file(rel: &str) -> Option<(String, Option<u64>)> {
    let rest = rel.strip_prefix("robots/")?;
    let (id, file) = rest.split_once('/')?;
    if !model::valid_id(id) {
        return None;
    }
    if file == "records.jsonl" {
        return Some((id.to_string(), None));
    }
    let name = file.strip_prefix("segments/")?;
    match crate::segment::parse_name(name)? {
        (n, false) => Some((id.to_string(), Some(n))),
        _ => None,
    }
}

fn package_version(dir: &Path) -> Option<u32> {
    let info = fs::read_to_string(dir.join("bag-info.txt")).ok()?;
    info.lines().find_map(|l| l.strip_prefix("Cursiv-Package-Version:")).and_then(|v| v.trim().parse().ok())
}

struct Checkpt {
    count: u64,
    head: String,
    root: String,
    trusted: bool,
}

/// Per-robot streaming state.
struct RobotPass<'a> {
    rid: &'a str,
    prev: String,
    frontier: merkle::Frontier,
    hashes: Vec<[u8; 32]>,
    ids: HashMap<u128, u64>,
    summary: RobotSummary,
    targets: BTreeSet<u64>,
    at: HashMap<u64, (String, String)>,
    stopped: bool,
}

/// Everything the record pass needs that is shared across robots.
struct Shared<'a> {
    signers: &'a Signers<'a>,
    trust: Option<&'a TrustStore>,
    blobs_ok: &'a HashMap<String, bool>,
    files: &'a BTreeMap<String, u64>,
    pending_derived: Vec<(String, u64, String)>,
    derived_truncated: bool,
    authentic_ok: bool,
    collect: bool,
    max_collect: u64,
    records: Vec<(Record, String)>,
    records_complete: bool,
}

const MAX_PENDING_DERIVED: usize = 1_000_000;

impl RobotPass<'_> {
    fn record(&mut self, line: &[u8], sh: &mut Shared, ctx: &mut Ctx) {
        if self.stopped {
            return;
        }
        let rid = self.rid;
        let expect_seq = self.hashes.len() as u64 + 1;
        let env: Envelope = match serde_json::from_slice(line) {
            Ok(e) => e,
            Err(_) => {
                ctx.add("integrity", "error", "unreadable_record", format!("record {expect_seq} is not a signed record"), Some(rid), Some(expect_seq));
                self.stopped = true;
                return;
            }
        };
        let hash = env.payload_hash();
        let (sig_ok, v) = sh.signers.check(&env, Owner::Robot(rid), Some(expect_seq));
        match sig_ok {
            Some(false) => ctx.add("integrity", "error", "record_signature", "record content does not match its signature (altered after signing)", Some(rid), Some(expect_seq)),
            None => ctx.add("integrity", "error", "signature_unverifiable", format!("no public key for signer {}: neither the trust store nor the package names it", env.keyid()), Some(rid), Some(expect_seq)),
            Some(true) => {}
        }
        if env.payload_type != crate::crypto::RECORD_TYPE {
            ctx.add("structure", "error", "payload_type", format!("payloadType {:?} is not a record", env.payload_type), Some(rid), Some(expect_seq));
        }
        let rec: Record = match env.body_text().ok_or_else(|| "payload is not base64 UTF-8".to_string()).and_then(|t| serde_json::from_str(&t).map_err(|e| e.to_string())) {
            Ok(r) => r,
            Err(e) => {
                ctx.add("structure", "error", "bad_record", format!("payload is not a record: {e}"), Some(rid), Some(expect_seq));
                self.push(&hash);
                return;
            }
        };
        if rec.robot_id != rid || rec.observation.robot_id != rid {
            ctx.add("integrity", "error", "wrong_robot", "record names a different robot than its log", Some(rid), Some(rec.seq));
        }
        if rec.seq != expect_seq {
            ctx.add("integrity", "error", "sequence", format!("expected record {expect_seq}, found {} (records removed, inserted or reordered)", rec.seq), Some(rid), Some(rec.seq));
        }
        if rec.prev != self.prev {
            ctx.add("integrity", "error", "chain", "record does not follow the record before it", Some(rid), Some(rec.seq));
        }
        if sh.trust.is_some() && v != KeyVerdict::Trusted {
            sh.authentic_ok = false;
            ctx.add("authenticity", "error", "untrusted_signer", format!("signed by key {} ({})", env.keyid(), verdict_word(sh.trust, &v)), Some(rid), Some(rec.seq));
        }
        for p in rec.observation.structural_problems() {
            ctx.add("structure", "error", "invalid_observation", p, Some(rid), Some(rec.seq));
        }
        let fp = crate::store::id_fingerprint(&rec.observation.observation_id);
        if let Some(first) = self.ids.insert(fp, rec.seq) {
            ctx.add("integrity", "error", "duplicate_observation", format!("observation_id {} also at record {first}", rec.observation.observation_id), Some(rid), Some(rec.seq));
            self.ids.insert(fp, first);
        }
        if let Some(c) = &rec.observation.correction {
            self.summary.corrections += 1;
            match self.ids.get(&crate::store::id_fingerprint(&c.corrects_observation_id)) {
                Some(s) if *s < rec.seq => ctx.add("corrections", "info", "correction", format!("corrects {} (record {s}, which is preserved): {}", c.corrects_observation_id, c.reason), Some(rid), Some(rec.seq)),
                _ => ctx.add("corrections", "error", "correction_target_missing", format!("corrects {}, which is not an earlier record of this robot", c.corrects_observation_id), Some(rid), Some(rec.seq)),
            }
        }
        for a in &rec.observation.attachments {
            match sh.blobs_ok.get(&a.sha256) {
                None => ctx.add("attachments", "error", "attachment_missing", format!("attachment {} ({}) is not in the package", &a.sha256[..12.min(a.sha256.len())], a.role), Some(rid), Some(rec.seq)),
                Some(false) => {}
                Some(true) => {
                    if sh.files.get(&format!("blobs/sha256/{}", a.sha256)) != Some(&a.size) {
                        ctx.add("attachments", "error", "attachment_size", "attachment size differs from the record", Some(rid), Some(rec.seq));
                    }
                }
            }
        }
        if rec.observation.synthetic {
            self.summary.synthetic_records += 1;
        }
        for d in &rec.observation.provenance.derived_from {
            if sh.pending_derived.len() < MAX_PENDING_DERIVED {
                sh.pending_derived.push((rid.to_string(), rec.seq, d.clone()));
            } else {
                sh.derived_truncated = true;
            }
        }
        if sh.collect {
            if (sh.records.len() as u64) < sh.max_collect {
                sh.records.push((rec, hash.clone()));
            } else {
                sh.records_complete = false;
            }
        }
        self.push(&hash);
    }

    fn push(&mut self, hash: &str) {
        self.hashes.push(crate::store::hash_bytes(hash));
        self.frontier.push(hash);
        self.prev = hash.to_string();
        let n = self.frontier.count();
        if self.targets.contains(&n) {
            self.at.insert(n, (self.prev.clone(), self.frontier.root()));
        }
    }
}

/// Stream one log file through the record pass. Returns the SHA-256 and size of its bytes
/// (None after a read error, which is always reported as a structure failure).
fn stream_file(path: &Path, rel: &str, pass: &mut RobotPass, sh: &mut Shared, ctx: &mut Ctx) -> Option<(String, u64)> {
    use crate::segment::{Line, Lines};
    let f = match fs::File::open(path) {
        Ok(f) => f,
        Err(e) => {
            ctx.err("structure", "read_error", format!("{rel}: {e}"));
            return None;
        }
    };
    let mut lines = Lines::new(f, MAX_LINE);
    loop {
        match lines.next_line() {
            Err(e) => {
                ctx.err("structure", "read_error", format!("{rel}: {e}"));
                return None;
            }
            Ok(None) => break,
            Ok(Some(Line::TooLong)) => {
                ctx.err("structure", "line_too_long", format!("{rel}: a line exceeds {MAX_LINE} bytes"));
                pass.stopped = true;
            }
            Ok(Some(Line::Truncated(l))) => {
                ctx.err("integrity", "truncated_file", format!("{rel}: last line is incomplete (file cut off)"));
                if !l.iter().all(|b| b.is_ascii_whitespace()) {
                    pass.record(&l, sh, ctx);
                }
            }
            Ok(Some(Line::Record(l))) => {
                if !l.iter().all(|b| b.is_ascii_whitespace()) {
                    pass.record(&l, sh, ctx);
                }
            }
        }
    }
    match lines.finish() {
        Ok(r) => Some(r),
        Err(e) => {
            ctx.err("structure", "read_error", format!("{rel}: {e}"));
            None
        }
    }
}

pub fn verify_package(dir: &Path, trust: Option<&TrustStore>) -> Report {
    verify_package_with(dir, trust, &VerifyOptions::default())
}

pub fn verify_package_with(dir: &Path, trust: Option<&TrustStore>, opts: &VerifyOptions) -> Report {
    let mut ctx = Ctx { findings: Vec::new() };
    let mut robots: BTreeMap<String, RobotSummary> = BTreeMap::new();
    let mut receipts_out: Vec<Receipt> = Vec::new();
    let mut completeness_ok = true;
    let mut completeness_established = true;
    let mut version = 0u32;

    if fs::symlink_metadata(dir).map(|m| m.file_type().is_symlink()).unwrap_or(false) || !dir.is_dir() {
        ctx.err("structure", "not_a_package", format!("{} is not a directory (or is a link)", dir.display()));
        return finish(dir, trust, ctx, robots, Vec::new(), receipts_out, false, false, false, version, false);
    }
    // BagIt layout (RFC 8493): tag files at the root, evidence under data/.
    let all = inventory(dir, &mut ctx);
    let root = &dir.join("data");
    if !dir.join("bagit.txt").is_file() || !root.is_dir() {
        ctx.err("structure", "not_a_bag", "not a BagIt bag (bagit.txt and data/ are required)");
    }
    let mut files: BTreeMap<String, u64> = BTreeMap::new();
    for (name, size) in &all {
        match name.strip_prefix("data/") {
            Some(rel) => {
                files.insert(rel.to_string(), *size);
            }
            None if TAG_FILES.contains(&name.as_str()) => {}
            None => ctx.err("integrity", "file_unlisted", format!("{name} is not part of the bag (added after it was made)")),
        }
    }
    let has_segments = files.keys().any(|n| log_file(n).is_some_and(|(_, s)| s.is_some()) || n.contains("/segments/"));
    let has_v1_logs = files.keys().any(|n| log_file(n).is_some_and(|(_, s)| s.is_none()));
    version = match package_version(dir) {
        Some(v) if crate::package::SUPPORTED_PACKAGE_VERSIONS.contains(&v) => v,
        Some(v) => {
            ctx.err("structure", "unsupported_version", format!("Cursiv-Package-Version {v} is not supported by this verifier (supports 1 and 2)"));
            v
        }
        None => 1, // packages written before the version line was added
    };
    if (version == 1 && has_segments) || (version == 2 && has_v1_logs) {
        ctx.err("structure", "layout_version", format!("the package declares format {version} but contains {} logs", if has_segments { "segmented" } else { "format-1" }));
    }
    // Log files are hashed while their records are read (one pass); their expected hashes wait here.
    let mut expect_manifest: BTreeMap<String, String> = BTreeMap::new();
    let mut expect_bag: BTreeMap<String, String> = BTreeMap::new();
    check_bag(dir, &files, &mut ctx, &mut expect_bag);
    let signers = Signers { trust, listed: listed_keys(root) };

    // 1. Manifest
    let manifest: Option<Envelope> = match read_json_file(&dir.join("manifest.json")).and_then(|v| serde_json::from_value(v).map_err(|e| e.to_string())) {
        Ok(m) => Some(m),
        Err(e) => {
            ctx.err("structure", "no_manifest", format!("manifest.json is missing or unreadable ({e}): nothing establishes which files belong to the package"));
            None
        }
    };
    let mut listed: BTreeMap<String, (String, u64)> = BTreeMap::new();
    let mut station_id = String::new();
    let mut authentic_ok = trust.is_some();
    if let Some(m) = &manifest {
        let body: serde_json::Value = m.body_text().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default();
        if body["schema"] != MANIFEST_SCHEMA || m.payload_type != crate::crypto::MANIFEST_TYPE {
            ctx.err("structure", "manifest_schema", "manifest is not a cursiv-package-1 manifest");
        }
        if let Some(mv) = body["package_version"].as_u64() {
            if mv != version as u64 {
                ctx.err("integrity", "version_mismatch", format!("the signed manifest says format {mv}, bag-info.txt says {version}"));
            }
        } else if version == 2 {
            ctx.err("integrity", "version_mismatch", "bag-info.txt says format 2 but the signed manifest does not");
        }
        station_id = body["station_id"].as_str().unwrap_or("").to_string();
        let (ok, v) = signers.check(m, Owner::Station(&station_id), None);
        match ok {
            Some(false) => ctx.err("integrity", "manifest_signature", "manifest.json signature does not match its contents"),
            None => ctx.err("integrity", "signature_unverifiable", format!("no public key for manifest signer {}: the manifest cannot be checked", m.keyid())),
            Some(true) => {}
        }
        if trust.is_some() && v != KeyVerdict::Trusted {
            authentic_ok = false;
            ctx.err("authenticity", "untrusted_station", format!("manifest signed by station key {} ({})", m.keyid(), verdict_word(trust, &v)));
        }
        if let Some(obj) = body["files"].as_object() {
            for (name, v) in obj {
                if !safe_rel(name) {
                    ctx.err("structure", "unsafe_path", format!("manifest names an unsafe path {name:?}"));
                    continue;
                }
                listed.insert(name.clone(), (v["sha256"].as_str().unwrap_or("").to_string(), v["size"].as_u64().unwrap_or(u64::MAX)));
            }
        }
        for (name, (sha, size)) in &listed {
            match files.get(name) {
                None => ctx.err("integrity", "file_missing", format!("{name} is listed in the manifest but missing")),
                Some(actual) if actual != size => ctx.err("integrity", "file_changed", format!("{name} size changed ({actual} bytes, manifest says {size})")),
                Some(_) if log_file(name).is_some() => {
                    expect_manifest.insert(name.clone(), sha.clone());
                }
                Some(_) => {
                    if file_sha256(&root.join(name)).as_deref() != Some(sha.as_str()) {
                        ctx.err("integrity", "file_changed", format!("{name} was changed after the package was signed"));
                    }
                }
            }
        }
        for name in files.keys() {
            if !listed.contains_key(name) {
                ctx.err("integrity", "file_unlisted", format!("{name} is not in the manifest (added after signing)"));
            }
        }
    }

    // 2. Attachments present in the package
    let mut blobs_ok: HashMap<String, bool> = HashMap::new();
    for name in files.keys().filter(|n| n.starts_with("blobs/sha256/")) {
        let sha = &name["blobs/sha256/".len()..];
        let good = crate::crypto::is_sha256_hex(sha) && file_sha256(&root.join(name)).as_deref() == Some(sha);
        if !good {
            ctx.err("attachments", "attachment_changed", format!("{name}: contents do not match the SHA-256 in its name"));
        }
        blobs_ok.insert(sha.to_string(), good);
    }

    // 3. Robot logs
    let mut robot_ids: BTreeSet<String> = BTreeSet::new();
    let mut segments: BTreeMap<String, BTreeMap<u64, (bool, bool)>> = BTreeMap::new();
    for n in files.keys().filter(|n| n.starts_with("robots/")) {
        let ok = match n.strip_prefix("robots/").and_then(|r| r.split_once('/')) {
            Some((id, "checkpoints.jsonl")) if model::valid_id(id) => {
                robot_ids.insert(id.to_string());
                true
            }
            Some((id, f)) if model::valid_id(id) => match f.strip_prefix("segments/").and_then(crate::segment::parse_name) {
                Some((num, is_seal)) if version == 2 => {
                    robot_ids.insert(id.to_string());
                    let e = segments.entry(id.to_string()).or_default().entry(num).or_default();
                    if is_seal { e.1 = true } else { e.0 = true }
                    true
                }
                _ if f == "records.jsonl" && version == 1 => {
                    robot_ids.insert(id.to_string());
                    true
                }
                _ => false,
            },
            _ => false,
        };
        if !ok {
            ctx.err("structure", "unexpected_file", format!("{n} is not part of the package format"));
        }
    }
    let mut sh = Shared {
        signers: &signers, trust, blobs_ok: &blobs_ok, files: &files, pending_derived: Vec::new(),
        derived_truncated: false, authentic_ok, collect: opts.collect_records, max_collect: opts.max_collected_records,
        records: Vec::new(), records_complete: opts.collect_records,
    };
    let mut robot_hashes: HashMap<String, Vec<[u8; 32]>> = HashMap::new();
    let mut robot_ids_seen: Vec<HashMap<u128, u64>> = Vec::new();
    for rid in &robot_ids {
        // Robot checkpoints first, so their roots can be taken from the stream at the right counts.
        let crel = format!("robots/{rid}/checkpoints.jsonl");
        let mut checkpoints: Vec<Checkpt> = Vec::new();
        for line in read_lines(&root.join(&crel), &mut ctx, &crel) {
            let Ok(env) = serde_json::from_str::<Envelope>(&line) else {
                ctx.add("integrity", "error", "unreadable_checkpoint", "checkpoint line is not a signed envelope", Some(rid), None);
                continue;
            };
            let Some(cp) = env.body_text().and_then(|t| serde_json::from_str::<Checkpoint>(&t).ok()) else {
                ctx.add("structure", "error", "bad_checkpoint", "checkpoint payload is invalid", Some(rid), None);
                continue;
            };
            let (sig_ok, v) = signers.check(&env, Owner::Robot(rid), None);
            if sig_ok != Some(true) || env.payload_type != crate::crypto::CHECKPOINT_TYPE {
                ctx.add("integrity", "error", "checkpoint_signature", "checkpoint altered after signing, or its signer's key is unknown", Some(rid), None);
                continue;
            }
            if cp.robot_id != *rid {
                ctx.add("integrity", "error", "checkpoint_robot", "checkpoint names another robot", Some(rid), None);
                continue;
            }
            let trusted = v == KeyVerdict::Trusted;
            if !trusted && trust.is_some() {
                ctx.add("authenticity", "warning", "untrusted_checkpoint", format!("checkpoint signed by key {} ({}) is ignored for completeness", env.keyid(), verdict_word(trust, &v)), Some(rid), None);
            }
            checkpoints.push(Checkpt { count: cp.count, head: cp.head, root: cp.merkle_root, trusted });
        }
        let mut pass = RobotPass {
            rid, prev: GENESIS.into(), frontier: merkle::Frontier::new(), hashes: Vec::new(), ids: HashMap::new(),
            summary: RobotSummary { records: 0, head: GENESIS.into(), trusted_checkpoint_count: None, synthetic_records: 0, corrections: 0 },
            targets: checkpoints.iter().map(|c| c.count).collect(), at: HashMap::new(), stopped: false,
        };
        let mut streamed: Vec<(String, Option<(String, u64)>)> = Vec::new();
        if version == 2 {
            let segs = segments.get(rid).cloned().unwrap_or_default();
            let mut last_seal = GENESIS.to_string();
            let max = segs.keys().next_back().copied().unwrap_or(0);
            for n in 1..=max {
                let (has_file, has_seal) = segs.get(&n).copied().unwrap_or((false, false));
                let frel = format!("robots/{rid}/segments/{}", crate::segment::segment_name(n));
                let srel = format!("robots/{rid}/segments/{}", crate::segment::seal_name(n));
                if !has_file {
                    ctx.add("integrity", "error", "segment_missing", format!("segment {n} is missing (records removed)"), Some(rid), None);
                    // continue with the next segment: its seal will not link, which is reported too
                    continue;
                }
                let seal = if has_seal {
                    match read_json_file(&root.join(&srel)).and_then(|v| serde_json::from_value::<Envelope>(v).map_err(|e| e.to_string())) {
                        Ok(env) => Some(env),
                        Err(e) => {
                            ctx.add("integrity", "error", "seal_unreadable", format!("seal of segment {n} is unreadable: {e}"), Some(rid), None);
                            None
                        }
                    }
                } else {
                    ctx.add("integrity", "error", "segment_unsealed", format!("segment {n} has no seal"), Some(rid), None);
                    None
                };
                let first_seq = pass.hashes.len() as u64 + 1;
                let prev_before = pass.prev.clone();
                let decoded = seal.as_ref().map(|env| {
                    let (sig_ok, v) = signers.check(env, Owner::Station(&station_id), None);
                    if sig_ok != Some(true) {
                        ctx.add("integrity", "error", "seal_signature", format!("seal of segment {n} does not verify with the station key"), Some(rid), None);
                    }
                    if trust.is_some() && v != KeyVerdict::Trusted {
                        sh.authentic_ok = false;
                        ctx.add("authenticity", "error", "untrusted_seal", format!("seal of segment {n} signed by key {} ({})", env.keyid(), verdict_word(trust, &v)), Some(rid), None);
                    }
                    (crate::segment::decode(env), crate::segment::seal_hash(env))
                });
                let hashed = stream_file(&root.join(&frel), &frel, &mut pass, &mut sh, &mut ctx);
                if let Some((dec, seal_hash)) = decoded {
                    match dec {
                        Err(e) => ctx.add("structure", "error", "bad_seal", format!("seal of segment {n}: {e}"), Some(rid), None),
                        Ok(s) => {
                            let mut bad: Vec<&str> = Vec::new();
                            if s.robot_id != *rid || s.station_id != station_id { bad.push("robot or station") }
                            if s.segment != n { bad.push("segment number (segments renamed, duplicated or reordered)") }
                            if s.first_seq != first_seq || s.prev_hash != prev_before { bad.push("start (does not continue the previous segment)") }
                            if s.prev_seal != last_seal { bad.push("previous seal (a segment before it is missing or substituted)") }
                            if s.last_seq != pass.hashes.len() as u64 || s.last_hash != pass.prev { bad.push("last record") }
                            if hashed.as_ref().is_some_and(|(sha, size)| *sha != s.file_sha256 || *size != s.file_size) { bad.push("file bytes") }
                            if s.log_merkle_root != pass.frontier.root() { bad.push("log Merkle root") }
                            if !bad.is_empty() {
                                ctx.add("integrity", "error", "segment_seal_mismatch", format!("segment {n} differs from its seal: {}", bad.join(", ")), Some(rid), None);
                            }
                            last_seal = seal_hash;
                        }
                    }
                }
                streamed.push((frel, hashed));
            }
            for n in segs.keys() {
                if *n == 0 || *n > max {
                    ctx.add("structure", "error", "segment_number", format!("segment {n} is out of range"), Some(rid), None);
                }
            }
        } else {
            let rel = format!("robots/{rid}/records.jsonl");
            if files.contains_key(&rel) {
                let hashed = stream_file(&root.join(&rel), &rel, &mut pass, &mut sh, &mut ctx);
                streamed.push((rel, hashed));
            }
        }
        // the one-pass hashes of the log files, against the manifest and the bag
        for (rel, hashed) in streamed {
            if let Some((sha, _)) = hashed {
                if expect_manifest.remove(&rel).is_some_and(|m| m != sha) {
                    ctx.err("integrity", "file_changed", format!("{rel} was changed after the package was signed"));
                }
                if expect_bag.remove(&format!("data/{rel}")).is_some_and(|b| b != sha) {
                    ctx.err("integrity", "bag_fixity", format!("data/{rel} does not match manifest-sha256.txt"));
                }
            }
        }
        let count = pass.hashes.len() as u64;
        pass.summary.records = count;
        pass.summary.head = pass.prev.clone();
        for cp in &checkpoints {
            if cp.count > count {
                if cp.trusted {
                    completeness_ok = false;
                    ctx.add("completeness", "error", "records_missing", format!(
                        "the robot's signed checkpoint says it wrote {} records; the package has {} (records {}..{} missing)",
                        cp.count, count, count + 1, cp.count), Some(rid), None);
                }
            } else if cp.count > 0 {
                let matches = pass.at.get(&cp.count).is_some_and(|(h, r)| *h == cp.head && *r == cp.root);
                if !matches {
                    ctx.add("integrity", "error", "checkpoint_mismatch", format!(
                        "records 1..{} differ from what the robot signed in its checkpoint (history rewritten or forked)", cp.count), Some(rid), None);
                }
            }
            if cp.trusted {
                pass.summary.trusted_checkpoint_count = Some(pass.summary.trusted_checkpoint_count.unwrap_or(0).max(cp.count));
            }
        }
        if pass.summary.trusted_checkpoint_count.is_none_or(|c| c < pass.summary.records) {
            completeness_established = false;
        }
        robots.insert(rid.clone(), pass.summary);
        robot_hashes.insert(rid.clone(), pass.hashes);
        robot_ids_seen.push(pass.ids);
    }
    // log files listed but never read (e.g. under an invalid robot id) are hashed the ordinary way
    for (rel, sha) in expect_manifest {
        if file_sha256(&root.join(&rel)).as_deref() != Some(sha.as_str()) {
            ctx.err("integrity", "file_changed", format!("{rel} was changed after the package was signed"));
        }
    }
    for (path, sha) in expect_bag {
        if file_sha256(&dir.join(&path)).as_deref() != Some(sha.as_str()) {
            ctx.err("integrity", "bag_fixity", format!("{path} does not match manifest-sha256.txt"));
        }
    }
    authentic_ok = sh.authentic_ok;

    // 4. Station checkpoint and receipts
    match read_json_file(&root.join("station-checkpoint.json")).and_then(|v| serde_json::from_value::<Envelope>(v).map_err(|e| e.to_string())) {
        Err(_) => ctx.err("completeness", "no_station_checkpoint", "station-checkpoint.json is missing or unreadable"),
        Ok(env) => {
            let body: serde_json::Value = env.body_text().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default();
            let sid = body["station_id"].as_str().unwrap_or("").to_string();
            let (sig_ok, sv) = signers.check(&env, Owner::Station(&sid), None);
            if sig_ok != Some(true) || env.payload_type != crate::crypto::STATION_CHECKPOINT_TYPE {
                ctx.err("integrity", "station_checkpoint_signature", "station checkpoint altered after signing, or its signer's key is unknown");
            }
            if trust.is_some() && sv != KeyVerdict::Trusted {
                authentic_ok = false;
                ctx.err("authenticity", "untrusted_station", format!("station checkpoint signed by key {} ({})", env.keyid(), verdict_word(trust, &sv)));
            }
            let station_trusted = sv == KeyVerdict::Trusted && sig_ok == Some(true);
            if let Some(obj) = body["robots"].as_object() {
                for (rid, v) in obj {
                    let count = v["count"].as_u64().unwrap_or(0);
                    let have = robots.get(rid).map_or(0, |r| r.records);
                    if have != count {
                        if station_trusted {
                            completeness_ok = false;
                        }
                        ctx.add("completeness", "error", "station_count_mismatch",
                            format!("station checkpoint lists {count} records for {rid}; the package has {have}"), Some(rid), None);
                    } else if let Some(r) = robots.get_mut(rid) {
                        if v["head"].as_str() != Some(r.head.as_str()) {
                            ctx.add("integrity", "error", "station_head_mismatch", format!("{rid}'s log head differs from the station checkpoint"), Some(rid), None);
                        } else if station_trusted {
                            r.trusted_checkpoint_count = Some(r.trusted_checkpoint_count.unwrap_or(0).max(count));
                        }
                    }
                }
                for rid in robots.keys() {
                    if !obj.contains_key(rid) {
                        ctx.add("integrity", "error", "robot_not_in_checkpoint", format!("{rid} is in the package but not in the station checkpoint"), Some(rid), None);
                    }
                }
            }
            if station_trusted {
                completeness_established = robots.values().all(|r| r.trusted_checkpoint_count.is_some_and(|c| c >= r.records));
            }
            // receipts, streamed
            let mut prev = GENESIS.to_string();
            let mut frontier = merkle::Frontier::new();
            let mut i = 0u64;
            if let Ok(f) = fs::File::open(root.join("receipts.jsonl")) {
                let mut lines = crate::segment::Lines::new(f, MAX_LINE);
                loop {
                    let l = match lines.next_line() {
                        Ok(Some(crate::segment::Line::Record(l))) => l,
                        Ok(Some(crate::segment::Line::Truncated(_))) => {
                            ctx.err("integrity", "truncated_file", "receipts.jsonl: last line is incomplete (file cut off)");
                            break;
                        }
                        Ok(Some(crate::segment::Line::TooLong)) => {
                            ctx.err("structure", "line_too_long", "receipts.jsonl: a line exceeds the size limit");
                            break;
                        }
                        Ok(None) => break,
                        Err(e) => {
                            ctx.err("structure", "read_error", format!("receipts.jsonl: {e}"));
                            break;
                        }
                    };
                    if l.iter().all(|b| b.is_ascii_whitespace()) {
                        continue;
                    }
                    i += 1;
                    match serde_json::from_slice::<Receipt>(&l) {
                        Ok(r) => {
                            if r.seq != i || r.prev != prev || r.compute_hash() != r.hash {
                                ctx.add("integrity", "error", "receipt_chain", format!("receipt {i} breaks the receipt chain"), None, None);
                            }
                            let known = robot_hashes.get(&r.robot_id).and_then(|h| h.get((r.robot_seq as usize).wrapping_sub(1)))
                                .is_some_and(|h| *h == crate::store::hash_bytes(&r.record_hash));
                            if !known {
                                ctx.add("provenance", "warning", "receipt_orphan", format!("receipt {i} refers to a record not in the package"), Some(&r.robot_id), Some(r.robot_seq));
                            }
                            prev = r.hash.clone();
                            frontier.push(&r.hash);
                            if opts.collect_records && (receipts_out.len() as u64) < opts.max_collected_records {
                                receipts_out.push(r);
                            }
                        }
                        Err(_) => ctx.add("integrity", "error", "receipt_unreadable", format!("receipt line {i} unreadable"), None, None),
                    }
                }
            }
            let rc = &body["receipts"];
            if rc["count"].as_u64() != Some(frontier.count()) || rc["merkle_root"].as_str() != Some(frontier.root().as_str()) {
                ctx.err("integrity", "receipts_mismatch", "receipts differ from the station checkpoint");
            }
        }
    }

    // 5. Provenance links
    for (rid, seq, d) in &sh.pending_derived {
        let fp = crate::store::id_fingerprint(d);
        if !robot_ids_seen.iter().any(|m| m.contains_key(&fp)) {
            ctx.add("provenance", "warning", "derived_from_missing", format!("derived from {d}, which is not in the package"), Some(rid), Some(*seq));
        }
    }
    if sh.derived_truncated {
        ctx.add("provenance", "info", "provenance_check_truncated", format!("only the first {MAX_PENDING_DERIVED} derived_from links were checked"), None, None);
    }
    let synth: u64 = robots.values().map(|r| r.synthetic_records).sum();
    let total: u64 = robots.values().map(|r| r.records).sum();
    if synth > 0 && synth < total {
        ctx.err("labelling", "mixed_synthetic", format!("{synth} of {total} records are synthetic: simulated and real data are mixed in one package"));
    } else if synth > 0 {
        ctx.add("labelling", "info", "synthetic", format!("all {total} records are SYNTHETIC (simulated); not real-world evidence"), None, None);
    }
    let attachments_ok = !ctx.errors_in("attachments");
    let records_complete = sh.records_complete;
    if opts.collect_records && !records_complete {
        ctx.add("limits", "info", "records_not_collected", format!(
            "more than {} records: records were verified but not kept, so science and reasoning checks cannot run on this package as a whole", opts.max_collected_records), None, None);
    }
    let records = sh.records;
    finish(dir, trust, ctx, robots, records, receipts_out, attachments_ok, completeness_ok, completeness_established && completeness_ok && authentic_ok, version, records_complete)
}

#[allow(clippy::too_many_arguments)]
fn finish(dir: &Path, trust: Option<&TrustStore>, ctx: Ctx, robots: BTreeMap<String, RobotSummary>, records: Vec<(Record, String)>,
          receipts: Vec<Receipt>, attachments_ok: bool, completeness_ok: bool, completeness_established: bool, package_version: u32,
          records_complete: bool) -> Report {
    let structure_ok = !ctx.errors_in("structure");
    let integrity_ok = !ctx.errors_in("integrity") && !ctx.errors_in("corrections");
    let auth = if trust.is_none() {
        "not_assessed: no trust store supplied; signatures can only show the content matches the keys named inside the package".to_string()
    } else if ctx.errors_in("authenticity") {
        "fail".into()
    } else {
        "pass".into()
    };
    let completeness = if !completeness_ok {
        "fail".to_string()
    } else if completeness_established {
        "pass".into()
    } else {
        "not_established: no trusted checkpoint covers every record".into()
    };
    let mut limits = vec![
        "Integrity and authenticity do not establish that any measurement is scientifically correct or that a sensor worked.".to_string(),
        "A valid signature shows who signed; it does not show the signer's sensor was calibrated or honest.".into(),
    ];
    if trust.is_none() || completeness != "pass" {
        limits.push("A hash chain that checks out internally can be rebuilt by anyone who rewrites it; without trusted signatures and a trusted checkpoint it does not prove an untampered original history.".into());
    }
    let verdicts = Verdicts {
        structure: if structure_ok { "pass" } else { "fail" }.into(),
        integrity: if integrity_ok { "pass" } else { "fail" }.into(),
        authenticity: auth,
        completeness,
        attachments: if attachments_ok { "pass" } else { "fail" }.into(),
    };
    let words = [&verdicts.structure, &verdicts.integrity, &verdicts.authenticity, &verdicts.completeness, &verdicts.attachments];
    // "verified" only when every verdict is an unqualified pass; anything not assessed is "incomplete".
    let status = if words.iter().any(|w| w.starts_with("fail")) {
        "failed"
    } else if words.iter().all(|w| w.as_str() == "pass") {
        "verified"
    } else {
        "incomplete"
    };
    let summary = plain_summary(status, &verdicts, &ctx.findings, &robots, trust.is_some());
    Report {
        schema: "cursiv-verification-report-1".into(),
        status: status.into(),
        summary,
        package_version,
        records_complete,
        package: dir.display().to_string(),
        verified_time: model::now_utc(),
        trust_store: trust.is_some(),
        verdicts,
        robots,
        findings: ctx.findings,
        limits,
        records,
        receipts,
    }
}

/// What each finding code means, said plainly. `{n}` is the number of findings with that code.
fn plain(code: &str) -> Option<&'static str> {
    Some(match code {
        "record_signature" => "{n} record(s) were changed after they were signed: their signatures no longer match their contents.",
        "file_changed" | "bag_fixity" => "{n} file(s) were changed after the package was signed.",
        "file_missing" => "{n} file(s) listed in the package are missing.",
        "file_unlisted" => "{n} file(s) were added to the package after it was signed.",
        "chain" | "sequence" => "Records were removed, inserted or reordered ({n} break(s) in a robot's sequence of records).",
        "checkpoint_mismatch" => "A robot's own signed checkpoint disagrees with its records: its history was rewritten or forked.",
        "records_missing" => "Records are missing: a robot signed a checkpoint for more records than the package holds.",
        "station_count_mismatch" => "The station's checkpoint lists a different number of records than the package holds.",
        "segment_missing" => "{n} segment file(s) of a robot's log are missing.",
        "segment_seal_mismatch" => "{n} log segment(s) do not match their station seal (changed, cut off, renamed or out of order).",
        "segment_unsealed" => "{n} log segment(s) have no station seal.",
        "truncated_file" => "{n} file(s) end in an incomplete line: the copy was cut off (an interrupted transfer?).",
        "untrusted_signer" => "{n} record(s) were signed by a key your trust store does not accept (unknown, revoked or outside its dates).",
        "untrusted_station" | "untrusted_seal" => "The station that signed this package is not trusted by your trust store.",
        "signature_unverifiable" => "{n} signature(s) could not be checked: no key for the signer is known.",
        "attachment_changed" => "{n} attachment(s) (images, recordings) were changed.",
        "attachment_missing" => "{n} attachment(s) the records refer to are not in the package.",
        "duplicate_observation" => "{n} observation id(s) appear twice.",
        "correction_target_missing" => "{n} correction(s) refer to a record that is not in the package.",
        "mixed_synthetic" => "Simulated and real records are mixed in one package.",
        "invalid_observation" => "{n} record(s) do not meet the observation format.",
        "unsupported_version" | "layout_version" | "version_mismatch" => "The package format is not one this verifier reads, or its labels disagree.",
        "read_error" | "unreadable_dir" => "Part of the package could not be read (disk or permission problem).",
        "symlink" | "hard_link" | "special_file" | "unsafe_path" => "The package contains links or paths outside itself, which packages may not.",
        "no_manifest" | "not_a_bag" | "not_a_package" => "This is not a complete Cursiv Robotics evidence package.",
        _ => return None,
    })
}

fn plain_summary(status: &str, v: &Verdicts, findings: &[Finding], robots: &BTreeMap<String, RobotSummary>, trusted: bool) -> Vec<String> {
    let records: u64 = robots.values().map(|r| r.records).sum();
    let synthetic: u64 = robots.values().map(|r| r.synthetic_records).sum();
    let mut out = vec![match status {
        "verified" => format!("Verified: {records} record(s) from {} robot(s) are complete, unchanged since signing, and signed by keys you trust.", robots.len()),
        "failed" => "NOT VERIFIED: do not use this package as evidence until the problems below are explained.".to_string(),
        _ => "Not fully verified: nothing was found altered, but who signed it or whether it is complete could not be established.".to_string(),
    }];
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    let mut order: Vec<&str> = Vec::new();
    for f in findings.iter().filter(|f| f.severity == "error") {
        let c = counts.entry(f.code.as_str()).or_insert(0);
        if *c == 0 {
            order.push(f.code.as_str());
        }
        *c += 1;
    }
    let mut said = std::collections::HashSet::new();
    for code in order {
        let line = match plain(code) {
            Some(t) => t.replace("{n}", &counts[code].to_string()),
            None => findings.iter().find(|f| f.code == code).map(|f| f.message.clone()).unwrap_or_default(),
        };
        if said.insert(line.clone()) {
            out.push(line);
        }
    }
    if !trusted {
        out.push("No trust store was given, so the signatures only show the records match the keys named inside the package, not who holds them.".into());
    } else if v.completeness.starts_with("not_established") {
        out.push("No trusted checkpoint covers every record, so completeness is not established.".into());
    }
    if synthetic > 0 {
        out.push(format!("{synthetic} of {records} record(s) are SYNTHETIC (simulated), not real-world evidence."));
    }
    out.push("A valid signature shows who recorded a value and that it is unchanged; it does not show the value is scientifically correct.".into());
    out
}

impl Report {
    pub fn all_pass(&self) -> bool {
        let v = &self.verdicts;
        self.status == "verified" && [&v.structure, &v.integrity, &v.authenticity, &v.completeness, &v.attachments].iter().all(|s| s.as_str() == "pass")
    }

    pub fn text(&self) -> String {
        let v = &self.verdicts;
        let mut s = format!("Cursiv evidence verification: {}\n\n", self.package);
        for line in &self.summary {
            s += &format!("{line}\n");
        }
        s += "\n";
        for (k, val) in [("Structure", &v.structure), ("Integrity", &v.integrity), ("Authenticity", &v.authenticity),
                         ("Completeness", &v.completeness), ("Attachments", &v.attachments)] {
            s += &format!("  {k:<13} {val}\n");
        }
        s += "\nRobots:\n";
        for (id, r) in &self.robots {
            s += &format!("  {id}: {} records, head {}, trusted checkpoint covers {}, {} synthetic, {} corrections\n",
                          r.records, &r.head[..12.min(r.head.len())],
                          r.trusted_checkpoint_count.map_or("none".to_string(), |c| c.to_string()), r.synthetic_records, r.corrections);
        }
        let problems: Vec<&Finding> = self.findings.iter().filter(|f| f.severity != "info").collect();
        s += &format!("\nFindings ({} problems):\n", problems.len());
        for f in self.findings.iter().filter(|f| f.severity != "info").take(200) {
            let at = match (&f.robot_id, f.seq) {
                (Some(r), Some(q)) => format!(" [{r} #{q}]"),
                (Some(r), None) => format!(" [{r}]"),
                _ => String::new(),
            };
            s += &format!("  {} {}/{}{}: {}\n", f.severity.to_uppercase(), f.area, f.code, at, f.message);
        }
        for f in self.findings.iter().filter(|f| f.severity == "info" && f.area == "labelling") {
            s += &format!("  NOTE {}\n", f.message);
        }
        s += "\nWhat this does not show:\n";
        for l in &self.limits {
            s += &format!("  - {l}\n");
        }
        s
    }
}

/// Hash of a record payload as stored (exposed for tools and tests).
pub fn record_hash(payload: &str) -> String {
    sha256_hex(payload.as_bytes())
}
