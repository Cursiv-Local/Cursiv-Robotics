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
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
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
fn check_bag(dir: &Path, data: &BTreeMap<String, u64>, ctx: &mut Ctx) {
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

pub fn verify_package(dir: &Path, trust: Option<&TrustStore>) -> Report {
    let mut ctx = Ctx { findings: Vec::new() };
    let mut robots: BTreeMap<String, RobotSummary> = BTreeMap::new();
    let mut all_records: Vec<(Record, String)> = Vec::new();
    let mut receipts_out: Vec<Receipt> = Vec::new();
    let mut authentic_ok = trust.is_some();
    let mut completeness_ok = true;
    let mut completeness_established = true;

    if fs::symlink_metadata(dir).map(|m| m.file_type().is_symlink()).unwrap_or(false) || !dir.is_dir() {
        ctx.err("structure", "not_a_package", format!("{} is not a directory (or is a link)", dir.display()));
        return finish(dir, trust, ctx, robots, all_records, receipts_out, false, false, false);
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
    check_bag(dir, &files, &mut ctx);
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
    if let Some(m) = &manifest {
        let body: serde_json::Value = m.body_text().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default();
        if body["schema"] != MANIFEST_SCHEMA || m.payload_type != crate::crypto::MANIFEST_TYPE {
            ctx.err("structure", "manifest_schema", "manifest is not a cursiv-package-1 manifest");
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
    let robot_ids: BTreeSet<String> = files.keys().filter_map(|n| {
        let rest = n.strip_prefix("robots/")?;
        let (id, file) = rest.split_once('/')?;
        if !model::valid_id(id) || !matches!(file, "records.jsonl" | "checkpoints.jsonl") {
            return None;
        }
        Some(id.to_string())
    }).collect();
    for n in files.keys().filter(|n| n.starts_with("robots/")) {
        let ok = n.strip_prefix("robots/").and_then(|r| r.split_once('/'))
            .is_some_and(|(id, f)| model::valid_id(id) && matches!(f, "records.jsonl" | "checkpoints.jsonl"));
        if !ok {
            ctx.err("structure", "unexpected_file", format!("{n} is not part of the package format"));
        }
    }
    let mut hash_to_record: HashMap<String, (String, u64)> = HashMap::new();
    let mut all_obs_ids: HashSet<(String, String)> = HashSet::new();
    for rid in &robot_ids {
        let rel = format!("robots/{rid}/records.jsonl");
        let lines = read_lines(&root.join(&rel), &mut ctx, &rel);
        let mut prev = GENESIS.to_string();
        let mut hashes = Vec::new();
        let mut seen_ids: HashMap<String, u64> = HashMap::new();
        let mut summary = RobotSummary { records: 0, head: GENESIS.into(), trusted_checkpoint_count: None, synthetic_records: 0, corrections: 0 };
        for (i, line) in lines.iter().enumerate() {
            let expect_seq = i as u64 + 1;
            let env: Envelope = match serde_json::from_str(line) {
                Ok(e) => e,
                Err(_) => {
                    ctx.add("integrity", "error", "unreadable_record", format!("line {expect_seq} is not a signed record"), Some(rid), Some(expect_seq));
                    break;
                }
            };
            let hash = env.payload_hash();
            let (sig_ok, v) = signers.check(&env, Owner::Robot(rid), Some(expect_seq));
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
                    prev = hash.clone();
                    hashes.push(hash);
                    continue;
                }
            };
            if rec.robot_id != *rid || rec.observation.robot_id != *rid {
                ctx.add("integrity", "error", "wrong_robot", "record names a different robot than its log", Some(rid), Some(rec.seq));
            }
            if rec.seq != expect_seq {
                ctx.add("integrity", "error", "sequence", format!("expected record {expect_seq}, found {} (records removed, inserted or reordered)", rec.seq), Some(rid), Some(rec.seq));
            }
            if rec.prev != prev {
                ctx.add("integrity", "error", "chain", "record does not follow the record before it", Some(rid), Some(rec.seq));
            }
            if trust.is_some() && v != KeyVerdict::Trusted {
                authentic_ok = false;
                ctx.add("authenticity", "error", "untrusted_signer", format!("signed by key {} ({})", env.keyid(), verdict_word(trust, &v)), Some(rid), Some(rec.seq));
            }
            for p in rec.observation.structural_problems() {
                ctx.add("structure", "error", "invalid_observation", p, Some(rid), Some(rec.seq));
            }
            if let Some(first) = seen_ids.insert(rec.observation.observation_id.clone(), rec.seq) {
                ctx.add("integrity", "error", "duplicate_observation", format!("observation_id {} also at record {first}", rec.observation.observation_id), Some(rid), Some(rec.seq));
            }
            if let Some(c) = &rec.observation.correction {
                summary.corrections += 1;
                match seen_ids.get(&c.corrects_observation_id) {
                    Some(s) if *s < rec.seq => ctx.add("corrections", "info", "correction", format!("corrects {} (record {s}, which is preserved): {}", c.corrects_observation_id, c.reason), Some(rid), Some(rec.seq)),
                    _ => ctx.add("corrections", "error", "correction_target_missing", format!("corrects {}, which is not an earlier record of this robot", c.corrects_observation_id), Some(rid), Some(rec.seq)),
                }
            }
            for a in &rec.observation.attachments {
                match blobs_ok.get(&a.sha256) {
                    None => ctx.add("attachments", "error", "attachment_missing", format!("attachment {} ({}) is not in the package", &a.sha256[..12.min(a.sha256.len())], a.role), Some(rid), Some(rec.seq)),
                    Some(false) => {}
                    Some(true) => {
                        if files.get(&format!("blobs/sha256/{}", a.sha256)) != Some(&a.size) {
                            ctx.add("attachments", "error", "attachment_size", "attachment size differs from the record", Some(rid), Some(rec.seq));
                        }
                    }
                }
            }
            if rec.observation.synthetic {
                summary.synthetic_records += 1;
            }
            all_obs_ids.insert((rid.clone(), rec.observation.observation_id.clone()));
            hash_to_record.insert(hash.clone(), (rid.clone(), rec.seq));
            all_records.push((rec, hash.clone()));
            prev = hash.clone();
            hashes.push(hash);
        }
        summary.records = hashes.len() as u64;
        summary.head = prev.clone();

        // Robot checkpoints
        let crel = format!("robots/{rid}/checkpoints.jsonl");
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
            let trusted = v == KeyVerdict::Trusted;
            if cp.robot_id != *rid {
                ctx.add("integrity", "error", "checkpoint_robot", "checkpoint names another robot", Some(rid), None);
                continue;
            }
            if cp.count > hashes.len() as u64 {
                if trusted {
                    completeness_ok = false;
                    ctx.add("completeness", "error", "records_missing", format!(
                        "the robot's signed checkpoint says it wrote {} records; the package has {} (records {}..{} missing)",
                        cp.count, hashes.len(), hashes.len() + 1, cp.count), Some(rid), None);
                }
            } else if cp.count > 0 {
                let n = cp.count as usize;
                if hashes[n - 1] != cp.head || merkle::root(&hashes[..n]) != cp.merkle_root {
                    ctx.add("integrity", "error", "checkpoint_mismatch", format!(
                        "records 1..{n} differ from what the robot signed in its checkpoint (history rewritten or forked)"), Some(rid), None);
                }
            }
            if trusted {
                summary.trusted_checkpoint_count = Some(summary.trusted_checkpoint_count.unwrap_or(0).max(cp.count));
            } else if trust.is_some() {
                ctx.add("authenticity", "warning", "untrusted_checkpoint", format!("checkpoint signed by key {} ({}) is ignored for completeness", env.keyid(), verdict_word(trust, &v)), Some(rid), None);
            }
        }
        if summary.trusted_checkpoint_count.is_none_or(|c| c < summary.records) {
            completeness_established = false;
        }
        robots.insert(rid.clone(), summary);
    }

    // 4. Station checkpoint
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
            // receipts
            let lines = read_lines(&root.join("receipts.jsonl"), &mut ctx, "receipts.jsonl");
            let mut prev = GENESIS.to_string();
            let mut rh = Vec::new();
            for (i, l) in lines.iter().enumerate() {
                match serde_json::from_str::<Receipt>(l) {
                    Ok(r) => {
                        if r.seq != i as u64 + 1 || r.prev != prev || r.compute_hash() != r.hash {
                            ctx.add("integrity", "error", "receipt_chain", format!("receipt {} breaks the receipt chain", i + 1), None, None);
                        }
                        if hash_to_record.get(&r.record_hash) != Some(&(r.robot_id.clone(), r.robot_seq)) {
                            ctx.add("provenance", "warning", "receipt_orphan", format!("receipt {} refers to a record not in the package", i + 1), Some(&r.robot_id), Some(r.robot_seq));
                        }
                        prev = r.hash.clone();
                        rh.push(r.hash.clone());
                        receipts_out.push(r);
                    }
                    Err(_) => ctx.add("integrity", "error", "receipt_unreadable", format!("receipt line {} unreadable", i + 1), None, None),
                }
            }
            let rc = &body["receipts"];
            if rc["count"].as_u64() != Some(rh.len() as u64) || rc["merkle_root"].as_str() != Some(merkle::root(&rh).as_str()) {
                ctx.err("integrity", "receipts_mismatch", "receipts differ from the station checkpoint");
            }
        }
    }

    // 5. Provenance links
    for (rec, _) in &all_records {
        for d in &rec.observation.provenance.derived_from {
            if !all_obs_ids.contains(&(rec.robot_id.clone(), d.clone())) && !all_obs_ids.iter().any(|(_, o)| o == d) {
                ctx.add("provenance", "warning", "derived_from_missing", format!("derived from {d}, which is not in the package"), Some(&rec.robot_id), Some(rec.seq));
            }
        }
    }
    let synth: u64 = robots.values().map(|r| r.synthetic_records).sum();
    let total: u64 = robots.values().map(|r| r.records).sum();
    if synth > 0 && synth < total {
        ctx.err("labelling", "mixed_synthetic", format!("{synth} of {total} records are synthetic: simulated and real data are mixed in one package"));
    } else if synth > 0 {
        ctx.add("labelling", "info", "synthetic", format!("all {total} records are SYNTHETIC (simulated); not real-world evidence"), None, None);
    }
    let _ = station_id;
    let attachments_ok = !ctx.errors_in("attachments");
    finish(dir, trust, ctx, robots, all_records, receipts_out, attachments_ok, completeness_ok, completeness_established && completeness_ok && authentic_ok)
}

#[allow(clippy::too_many_arguments)]
fn finish(dir: &Path, trust: Option<&TrustStore>, ctx: Ctx, robots: BTreeMap<String, RobotSummary>, records: Vec<(Record, String)>,
          receipts: Vec<Receipt>, attachments_ok: bool, completeness_ok: bool, completeness_established: bool) -> Report {
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
    Report {
        schema: "cursiv-verification-report-1".into(),
        package: dir.display().to_string(),
        verified_time: model::now_utc(),
        trust_store: trust.is_some(),
        verdicts: Verdicts {
            structure: if structure_ok { "pass" } else { "fail" }.into(),
            integrity: if integrity_ok { "pass" } else { "fail" }.into(),
            authenticity: auth,
            completeness,
            attachments: if attachments_ok { "pass" } else { "fail" }.into(),
        },
        robots,
        findings: ctx.findings,
        limits,
        records,
        receipts,
    }
}

impl Report {
    pub fn all_pass(&self) -> bool {
        let v = &self.verdicts;
        [&v.structure, &v.integrity, &v.authenticity, &v.completeness, &v.attachments].iter().all(|s| s.as_str() == "pass")
    }

    pub fn text(&self) -> String {
        let v = &self.verdicts;
        let mut s = format!("Cursiv evidence verification: {}\n\n", self.package);
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
