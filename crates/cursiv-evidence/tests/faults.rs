//! End-to-end evidence tests: a test robot signs records, the store ingests them,
//! a package is exported, and the independent verifier checks it. Each fault is
//! introduced deliberately and must be detected (or, for operational faults,
//! recovered from).

use cursiv_evidence::crypto::{public_b64, sha256_hex, Envelope, Identity, CHECKPOINT_TYPE, MANIFEST_TYPE, RECORD_TYPE};
use base64::Engine;
use cursiv_evidence::merkle;
use cursiv_evidence::model::*;
use cursiv_evidence::model::Claim;
use cursiv_evidence::science::{self, Profile};
use cursiv_evidence::store::{Outcome, Store};
use cursiv_evidence::trust::{TrustStore, TrustedKey};
use cursiv_evidence::{legacy, verify};
use std::fs;
use std::path::{Path, PathBuf};

fn tmp(name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("cursiv-faults-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&p);
    fs::create_dir_all(&p).unwrap();
    p
}

fn tk(id: &Identity) -> TrustedKey {
    TrustedKey { key_id: id.key_id(), public_key: public_b64(&id.public()), status: "active".into(), note: None, valid_from_seq: None, valid_until_seq: None }
}

struct Robot {
    id: String,
    key: Identity,
    hashes: Vec<String>,
}

impl Robot {
    fn new(id: &str, seed: u8) -> Self {
        Robot { id: id.into(), key: Identity::from_seed([seed; 32]), hashes: vec![] }
    }

    fn obs(&self, n: u64, ty: &str, value: f64, t: &str) -> Observation {
        Observation {
            schema: OBSERVATION_SCHEMA.into(),
            observation_id: format!("{}-obs-{n:05}", self.id),
            robot_id: self.id.clone(),
            mission_id: "survey-1".into(),
            observation_type: ty.into(),
            synthetic: true,
            sensor: Sensor { sensor_id: format!("{}-s1", self.id), sensor_type: "probe".into(), model: None,
                             calibration: Some(Calibration { calibrated_utc: Some("2026-10-01T00:00:00Z".into()), valid_until_utc: Some("2027-10-01T00:00:00Z".into()), reference: None, certificate_sha256: None }) },
            sensor_time: Some(t.into()),
            time_source: TimeSource::Simulated,
            clock: None,
            location: Some(Location { lat: 45.1, lon: -122.2, alt_m: None, crs: "EPSG:4326".into(), horizontal_accuracy_m: Some(2.0), source: "simulated".into() }),
            measurement: Some(Measurement { value: Some(value), text: None, unit: "degC".into(), uncertainty: Some(Uncertainty { kind: "standard".into(), value: 0.2, coverage_k: None }) }),
            attachments: vec![],
            provenance: Provenance { source: "simulated".into(), software: "faults-test".into(), software_version: "1".into(), derived_from: vec![] },
            processing: vec![],
            quality: None,
            correction: None,
            claim: None,
        }
    }

    fn record(&mut self, o: Observation) -> Envelope {
        let rec = Record { schema: RECORD_SCHEMA.into(), robot_id: self.id.clone(), seq: self.hashes.len() as u64 + 1,
                           prev: self.hashes.last().cloned().unwrap_or_else(|| GENESIS.into()), written_time: None, observation: o };
        let env = self.key.sign_json(RECORD_TYPE, &rec);
        self.hashes.push(env.payload_hash());
        env
    }

    fn checkpoint(&self) -> Envelope {
        self.key.sign_json(CHECKPOINT_TYPE, &Checkpoint { schema: CHECKPOINT_SCHEMA.into(), robot_id: self.id.clone(), count: self.hashes.len() as u64,
            head: self.hashes.last().cloned().unwrap_or_else(|| GENESIS.into()), merkle_root: merkle::root(&self.hashes), signed_time: None })
    }
}

struct Lab {
    dir: PathBuf,
    store: Store,
    robots: Vec<Robot>,
    trust: TrustStore,
    station: [u8; 32],
}

fn lab(name: &str) -> Lab {
    let dir = tmp(name);
    let robots = vec![Robot::new("rover-01", 1), Robot::new("rover-02", 2), Robot::new("rover-03", 3)];
    let station = [9u8; 32];
    let mut trust = TrustStore { format: "cursiv-trust-1".into(), ..Default::default() };
    for r in &robots {
        trust.robots.insert(r.id.clone(), vec![tk(&r.key)]);
    }
    trust.stations.insert("station-a".into(), vec![tk(&Identity::from_seed(station))]);
    let store = Store::open(&dir.join("store"), "station-a", Identity::from_seed(station), trust.clone()).unwrap();
    Lab { dir, store, robots, trust, station }
}

impl Lab {
    /// Each robot writes `n` records and a checkpoint.
    fn survey(&mut self, n: u64) {
        for i in 0..self.robots.len() {
            let mut envs = vec![];
            for k in 0..n {
                let r = &mut self.robots[i];
                let o = r.obs(k + 1, "air_temperature", 14.0 + k as f64 * 0.1, &format!("2026-11-05T10:{:02}:00Z", k % 60));
                envs.push(r.record(o));
            }
            for o in self.store.ingest_batch(&envs).unwrap() {
                assert!(matches!(o, Outcome::Accepted { .. }), "{o:?}");
            }
            let cp = self.robots[i].checkpoint();
            assert!(matches!(self.store.ingest_checkpoint(&cp), Outcome::Accepted { .. }));
        }
    }

    fn export(&self, name: &str) -> PathBuf {
        let p = self.dir.join(name);
        self.store.export(&p).unwrap();
        p
    }

    fn verify(&self, p: &Path) -> verify::Report {
        verify::verify_package(p, Some(&self.trust))
    }
}

fn codes(r: &verify::Report) -> Vec<String> {
    r.findings.iter().filter(|f| f.severity == "error").map(|f| f.code.clone()).collect()
}

/// Re-sign the manifest so file hashes match: models an attacker who rewrote the
/// files and the manifest but does not hold the station key (uses their own key).
fn reseal_with(pkg: &Path, attacker: &Identity) {
    let m: Envelope = serde_json::from_str(&fs::read_to_string(pkg.join("manifest.json")).unwrap()).unwrap();
    let mut body: serde_json::Value = serde_json::from_str(&m.body_text().unwrap()).unwrap();
    for (name, v) in body["files"].as_object_mut().unwrap() {
        let b = fs::read(pkg.join("data").join(name)).unwrap();
        v["sha256"] = sha256_hex(&b).into();
        v["size"] = b.len().into();
    }
    fs::write(pkg.join("manifest.json"), serde_json::to_string(&attacker.sign_json(MANIFEST_TYPE, &body)).unwrap()).unwrap();
}

/// The attacker also lists their own key in the package, so the rebuilt package is internally consistent.
fn list_key(pkg: &Path, who: &Identity) {
    let f = pkg.join("data/keys/public-keys.json");
    let mut v: serde_json::Value = serde_json::from_str(&fs::read_to_string(&f).unwrap()).unwrap();
    v["keys"][who.key_id()] = serde_json::json!({"public_key": public_b64(&who.public()), "seen_for": "attacker"});
    fs::write(&f, v.to_string()).unwrap();
}

/// Edit the decoded body of record line `n`, keeping its signature (an in-place forgery).
fn rewrite_line(path: &Path, n: usize, f: impl Fn(&str) -> String) {
    let text = fs::read_to_string(path).unwrap();
    let mut lines: Vec<String> = text.lines().map(String::from).collect();
    let mut env: Envelope = serde_json::from_str(&lines[n]).unwrap();
    env.payload = base64::engine::general_purpose::STANDARD.encode(f(&env.body_text().unwrap()));
    lines[n] = serde_json::to_string(&env).unwrap();
    fs::write(path, lines.join("\n") + "\n").unwrap();
}

#[test]
fn clean_three_robot_package_passes_every_verdict() {
    let mut l = lab("clean");
    l.survey(20);
    let p = l.export("pkg");
    let r = l.verify(&p);
    assert!(r.all_pass(), "{}", r.text());
    assert_eq!(r.robots.len(), 3);
    assert!(r.robots.values().all(|x| x.records == 20 && x.trusted_checkpoint_count == Some(20)));
}

#[test]
fn fault_1_altered_measurement_is_detected() {
    let mut l = lab("altered");
    l.survey(5);
    let p = l.export("pkg");
    rewrite_line(&p.join("data/robots/rover-02/records.jsonl"), 2, |line| line.replace("14.2", "19.2"));
    let r = l.verify(&p);
    assert_eq!(r.verdicts.integrity, "fail");
    let c = codes(&r);
    assert!(c.contains(&"record_signature".to_string()) && c.contains(&"file_changed".to_string()), "{c:?}");
}

#[test]
fn fault_2_modified_attachment_is_detected() {
    let mut l = lab("attach");
    let blob = b"synthetic image bytes".to_vec();
    let sha = sha256_hex(&blob);
    assert!(l.store.blobs().put(&blob[..], &sha, blob.len() as u64).unwrap());
    let r1 = &mut l.robots[2];
    let mut o = r1.obs(1, "image", 0.0, "2026-11-05T10:00:00Z");
    o.measurement = None;
    o.attachments.push(AttachmentRef { sha256: sha.clone(), size: blob.len() as u64, media_type: "image/png".into(), role: "raw".into() });
    let env = r1.record(o);
    l.store.ingest_batch(&[env]).unwrap();
    let p = l.export("pkg");
    assert!(l.verify(&p).all_pass() || l.verify(&p).verdicts.completeness != "pass");
    fs::write(p.join("data/blobs/sha256").join(&sha), b"synthetic image bytez").unwrap();
    let r = l.verify(&p);
    assert_eq!(r.verdicts.attachments, "fail");
    assert!(codes(&r).contains(&"attachment_changed".to_string()));
}

#[test]
fn fault_3_missing_observation_is_detected_by_chain_and_checkpoint() {
    let mut l = lab("missing");
    l.survey(6);
    let p = l.export("pkg");
    let f = p.join("data/robots/rover-01/records.jsonl");
    let text = fs::read_to_string(&f).unwrap();
    let kept: Vec<&str> = text.lines().enumerate().filter(|(i, _)| *i != 3).map(|(_, l)| l).collect();
    fs::write(&f, kept.join("\n") + "\n").unwrap();
    let r = l.verify(&p);
    let c = codes(&r);
    assert!(c.contains(&"sequence".to_string()) && c.contains(&"chain".to_string()), "{c:?}");
    assert_eq!(r.verdicts.completeness, "fail");
    // Removing the LAST record leaves a valid chain; only the signed checkpoints catch it.
    let mut l2 = lab("missing-tail");
    l2.survey(6);
    let p2 = l2.export("pkg");
    let f2 = p2.join("data/robots/rover-01/records.jsonl");
    let t2 = fs::read_to_string(&f2).unwrap();
    fs::write(&f2, t2.lines().take(5).collect::<Vec<_>>().join("\n") + "\n").unwrap();
    let r2 = l2.verify(&p2);
    assert!(codes(&r2).contains(&"records_missing".to_string()), "{:?}", codes(&r2));
    assert_eq!(r2.verdicts.completeness, "fail");
}

#[test]
fn fault_4_duplicates_are_idempotent_or_rejected() {
    let mut l = lab("dup");
    let r = &mut l.robots[0];
    let e1 = r.record(r.obs(1, "air_temperature", 10.0, "2026-11-05T10:00:00Z"));
    assert!(matches!(l.store.ingest_batch(std::slice::from_ref(&e1)).unwrap()[0], Outcome::Accepted { .. }));
    assert!(matches!(l.store.ingest_batch(&[e1]).unwrap()[0], Outcome::Duplicate { .. }), "retry is idempotent");
    let r = &mut l.robots[0];
    let again = r.obs(1, "air_temperature", 11.0, "2026-11-05T10:01:00Z"); // same observation_id, new content
    let e2 = r.record(again);
    match &l.store.ingest_batch(&[e2]).unwrap()[0] {
        Outcome::Rejected { code, .. } => assert_eq!(code, "duplicate_observation_id"),
        o => panic!("{o:?}"),
    }
}

#[test]
fn faults_10_11_corrupted_export_and_rebuilt_chain() {
    let mut l = lab("rebuilt");
    l.survey(8);
    // 10: truncated export file
    let p = l.export("pkg-trunc");
    let f = p.join("data/receipts.jsonl");
    let b = fs::read(&f).unwrap();
    fs::write(&f, &b[..b.len() - 40]).unwrap();
    let r = l.verify(&p);
    assert_eq!(r.verdicts.integrity, "fail");
    assert!(codes(&r).contains(&"truncated_file".to_string()) || codes(&r).contains(&"file_changed".to_string()));

    // 11: attacker edits a value, rebuilds the whole chain and re-signs every record and the
    // manifest with their own keys. Internally consistent; must not pass authenticity.
    let p = l.export("pkg-rebuilt");
    let attacker = Identity::from_seed([66u8; 32]);
    let f = p.join("data/robots/rover-03/records.jsonl");
    let mut prev = GENESIS.to_string();
    let mut out = String::new();
    let mut hashes = vec![];
    for line in fs::read_to_string(&f).unwrap().lines() {
        let env: Envelope = serde_json::from_str(line).unwrap();
        let mut rec: Record = serde_json::from_str(&env.body_text().unwrap()).unwrap();
        rec.prev = prev.clone();
        if rec.seq == 4 {
            rec.observation.measurement.as_mut().unwrap().value = Some(99.0);
        }
        let e = attacker.sign_json(RECORD_TYPE, &rec);
        prev = e.payload_hash();
        hashes.push(prev.clone());
        out += &serde_json::to_string(&e).unwrap();
        out.push('\n');
    }
    fs::write(&f, out).unwrap();
    let cp = attacker.sign_json(CHECKPOINT_TYPE, &Checkpoint { schema: CHECKPOINT_SCHEMA.into(), robot_id: "rover-03".into(), count: 8, head: prev.clone(), merkle_root: merkle::root(&hashes), signed_time: None });
    fs::write(p.join("data/robots/rover-03/checkpoints.jsonl"), serde_json::to_string(&cp).unwrap() + "\n").unwrap();
    list_key(&p, &attacker);
    reseal_with(&p, &attacker);
    let r = l.verify(&p);
    assert_eq!(r.verdicts.authenticity, "fail", "{}", r.text());
    assert!(codes(&r).contains(&"untrusted_signer".to_string()));
    assert!(codes(&r).contains(&"station_head_mismatch".to_string()), "the genuine station checkpoint disagrees");
    // Without a trust store the rebuilt chain is internally consistent: it must NOT be reported as authentic.
    let r = verify::verify_package(&p, None);
    assert!(r.verdicts.authenticity.starts_with("not_assessed"));
    assert!(r.limits.iter().any(|x| x.contains("rebuilt")));
    assert!(!r.all_pass());
}

#[test]
fn fault_12_untrusted_and_revoked_keys_are_refused_at_ingest_and_in_packages() {
    let mut l = lab("keys");
    let mut impostor = Robot::new("rover-01", 77);
    let o = impostor.obs(1, "air_temperature", 1.0, "2026-11-05T10:00:00Z");
    let e = impostor.record(o);
    match &l.store.ingest_batch(&[e]).unwrap()[0] {
        Outcome::Rejected { code, .. } => assert_eq!(code, "untrusted_key"),
        o => panic!("{o:?}"),
    }
    l.survey(3);
    let p = l.export("pkg");
    let mut t = l.trust.clone();
    t.robots.get_mut("rover-02").unwrap()[0].status = "revoked".into();
    let r = verify::verify_package(&p, Some(&t));
    assert_eq!(r.verdicts.authenticity, "fail");
}

#[test]
fn key_rotation_window_is_enforced() {
    let mut l = lab("rotate");
    let new_key = Identity::from_seed([42u8; 32]);
    let mut old = tk(&l.robots[0].key);
    old.status = "retired".into();
    old.valid_until_seq = Some(2);
    let mut new = tk(&new_key);
    new.valid_from_seq = Some(3);
    l.trust.robots.insert("rover-01".into(), vec![old, new]);
    l.store = Store::open(&l.dir.join("store"), "station-a", Identity::from_seed(l.station), l.trust.clone()).unwrap();
    let r = &mut l.robots[0];
    let a = r.record(r.obs(1, "air_temperature", 1.0, "2026-11-05T10:00:00Z"));
    let b = r.record(r.obs(2, "air_temperature", 1.0, "2026-11-05T10:01:00Z"));
    let c_old = r.record(r.obs(3, "air_temperature", 1.0, "2026-11-05T10:02:00Z")); // old key past its window
    let out = l.store.ingest_batch(&[a, b, c_old]).unwrap();
    assert!(matches!(out[2], Outcome::Rejected { ref code, .. } if code == "key_out_of_window"), "{out:?}");
    l.robots[0].hashes.pop();
    l.robots[0].key = new_key;
    let r = &mut l.robots[0];
    let c = r.record(r.obs(3, "air_temperature", 1.0, "2026-11-05T10:02:00Z"));
    assert!(matches!(l.store.ingest_batch(&[c]).unwrap()[0], Outcome::Accepted { .. }));
}

#[test]
fn faults_13_14_partial_sync_restart_recovery_and_fork_detection() {
    let mut l = lab("restart");
    let r = &mut l.robots[0];
    let envs: Vec<Envelope> = (1..=6).map(|k| { let o = r.obs(k, "air_temperature", 5.0, "2026-11-05T10:00:00Z"); r.record(o) }).collect();
    // 13: only part arrives, out of order
    let out = l.store.ingest_batch(&[envs[0].clone(), envs[1].clone(), envs[4].clone()]).unwrap();
    assert!(matches!(out[2], Outcome::Rejected { ref code, expected_seq: Some(3), .. } if code == "gap"));
    // 14: station restarts mid-write: torn final line
    let f = l.dir.join("store/robots/rover-01/records.jsonl");
    let mut text = fs::read_to_string(&f).unwrap();
    text.push_str("{\"payload\":\"{\\\"schema\\\":");
    fs::write(&f, text).unwrap();
    let mut store = Store::open(&l.dir.join("store"), "station-a", Identity::from_seed(l.station), l.trust.clone()).unwrap();
    assert!(store.recovery_notes.iter().any(|n| n.contains("incomplete final line")), "{:?}", store.recovery_notes);
    assert_eq!(store.robot_count("rover-01"), 2);
    // resume from the head the station reports; retries of 1-2 are harmless
    let out = store.ingest_batch(&envs).unwrap();
    assert!(matches!(out[0], Outcome::Duplicate { .. }) && out[2..].iter().all(|o| matches!(o, Outcome::Accepted { .. })), "{out:?}");
    // robot restarts having lost its state: a new history from seq 1 is a fork
    let mut amnesiac = Robot::new("rover-01", 1);
    let o = amnesiac.obs(900, "air_temperature", 5.0, "2026-11-05T11:00:00Z");
    let fork = amnesiac.record(o);
    assert!(matches!(store.ingest_batch(&[fork]).unwrap()[0], Outcome::Rejected { ref code, .. } if code == "equivocation"));
    assert!(fs::read_to_string(l.dir.join("store/incidents.jsonl")).unwrap().contains("equivocation"));
}

#[test]
fn fault_9_interrupted_attachment_transfer_keeps_nothing() {
    let l = lab("upload");
    let blob = vec![7u8; 100_000];
    let sha = sha256_hex(&blob);
    let short = &blob[..60_000];
    let e = l.store.blobs().put(short, &sha, blob.len() as u64).unwrap_err();
    assert!(e.1.contains("incomplete"), "{e:?}");
    assert!(!l.store.has_blob(&sha));
    let mut wrong = blob.clone();
    wrong[5] = 0;
    assert!(l.store.blobs().put(&wrong[..], &sha, blob.len() as u64).is_err());
    assert!(fs::read_dir(l.dir.join("store/blobs/tmp")).unwrap().next().is_none(), "no partial files left");
    assert!(l.store.blobs().put(&blob[..], &sha, blob.len() as u64).unwrap());
}

#[test]
fn science_flags_range_time_drift_and_contradiction_separately_from_integrity() {
    let mut l = lab("science");
    let (a, b) = l.robots.split_at_mut(1);
    let (r1, r2) = (&mut a[0], &mut b[0]);
    let mut envs1 = vec![];
    for k in 0..8u64 {
        envs1.push(r1.record(r1.obs(k + 1, "air_temperature", 15.0, &format!("2026-11-05T10:0{k}:00Z"))));
    }
    let mut hot = r2.obs(1, "air_temperature", 21.0, "2026-11-05T10:03:10Z");
    hot.location.as_mut().unwrap().lat = 45.1001;
    let mut crazy = r2.obs(2, "air_temperature", 75.0, "2026-11-05T10:04:00Z");
    crazy.sensor.calibration = None;
    let backwards = r2.obs(3, "air_temperature", 15.1, "2026-11-05T09:00:00Z");
    let envs2 = vec![r2.record(hot), r2.record(crazy), r2.record(backwards)];
    l.store.ingest_batch(&envs1).unwrap();
    l.store.ingest_batch(&envs2).unwrap();
    let p = l.export("pkg");
    let rep = verify::verify_package(&p, Some(&l.trust));
    assert_eq!(rep.verdicts.integrity, "pass", "science problems are not integrity problems");
    let s = science::validate(&rep.records, &rep.receipts, &Profile::survey_default());
    for code in ["contradiction", "out_of_range", "calibration_unknown", "out_of_order_time"] {
        assert!(s.counts.contains_key(code), "missing {code}: {:?}", s.counts);
    }
    let c = s.flags.iter().find(|f| f.code == "contradiction").unwrap();
    assert!(c.message.contains("not determined"));
}

#[test]
fn corrections_preserve_the_original() {
    let mut l = lab("correct");
    let r = &mut l.robots[0];
    let a = r.record(r.obs(1, "air_temperature", 10.0, "2026-11-05T10:00:00Z"));
    let mut fix = r.obs(2, "air_temperature", 10.4, "2026-11-05T10:00:00Z");
    fix.correction = Some(Correction { corrects_observation_id: "rover-01-obs-00001".into(), reason: "sensor offset found at calibration".into() });
    let b = r.record(fix);
    l.store.ingest_batch(&[a, b]).unwrap();
    let mut bad = r.obs(3, "air_temperature", 1.0, "2026-11-05T10:00:00Z");
    bad.correction = Some(Correction { corrects_observation_id: "never-recorded".into(), reason: "x".into() });
    let e = r.record(bad);
    assert!(matches!(l.store.ingest_batch(&[e]).unwrap()[0], Outcome::Rejected { ref code, .. } if code == "unknown_correction_target"));
    let p = l.export("pkg");
    let rep = verify::verify_package(&p, Some(&l.trust));
    assert_eq!(rep.robots["rover-01"].records, 2);
    assert_eq!(rep.robots["rover-01"].corrections, 1);
    let s = science::validate(&rep.records, &rep.receipts, &Profile::survey_default());
    assert_eq!((s.observations, s.current_observations, s.corrected), (2, 1, 1));
}

#[test]
fn hostile_package_paths_and_links_are_refused() {
    let mut l = lab("hostile");
    l.survey(2);
    let p = l.export("pkg");
    fs::create_dir_all(p.join("data/blobs/sha256")).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink("/etc/passwd", p.join("data/blobs/sha256/link")).unwrap();
    let r = l.verify(&p);
    assert_eq!(r.verdicts.structure, "fail");
    // manifest naming ../ paths
    let m: Envelope = serde_json::from_str(&fs::read_to_string(p.join("manifest.json")).unwrap()).unwrap();
    let mut body: serde_json::Value = serde_json::from_str(&m.body_text().unwrap()).unwrap();
    body["files"]["../../etc/passwd"] = serde_json::json!({"sha256": "0".repeat(64), "size": 1});
    fs::write(p.join("manifest.json"), serde_json::to_string(&Identity::from_seed(l.station).sign_json(MANIFEST_TYPE, &body)).unwrap()).unwrap();
    let r = l.verify(&p);
    assert!(codes(&r).contains(&"unsafe_path".to_string()));
}

#[test]
fn malformed_and_oversized_inputs_are_rejected() {
    let mut l = lab("malformed");
    let r = &mut l.robots[0];
    let mut o = r.obs(1, "air_temperature", 1.0, "2026-11-05T10:00:00+02:00");
    o.robot_id = "../../etc".into();
    let e = r.record(o);
    assert!(matches!(l.store.ingest_batch(&[e]).unwrap()[0], Outcome::Rejected { .. }));
    let mut o = l.robots[0].obs(1, "air_temperature", 1.0, "2026-11-05T10:00:00Z");
    o.synthetic = false; // claims real data while provenance says simulated
    let r = &mut l.robots[0];
    r.hashes.clear();
    let e = r.record(o);
    assert!(matches!(l.store.ingest_batch(&[e]).unwrap()[0], Outcome::Rejected { ref code, .. } if code == "invalid_observation"));
    let garbage = Envelope { payload: "{\"schema\":\"cursiv-record-1\"".into(), payload_type: RECORD_TYPE.into(), signatures: vec![] };
    assert!(matches!(l.store.ingest_batch(&[garbage]).unwrap()[0], Outcome::Rejected { ref code, .. } if code == "malformed"));
    let o1 = l.robots[1].obs(1, "air_temperature", 1.0, "2026-11-05T10:00:00Z");
    let mut forged = l.robots[1].record(o1);
    let o2 = l.robots[2].obs(1, "air_temperature", 1.0, "2026-11-05T10:00:00Z");
    forged.signatures[0].sig = l.robots[2].record(o2).signatures[0].sig.clone();
    assert!(matches!(l.store.ingest_batch(&[forged]).unwrap()[0], Outcome::Rejected { ref code, .. } if code == "bad_signature"));
    l.robots[1].hashes.clear();
    let unknown_field = l.robots[1].key.sign_payload(RECORD_TYPE, "{\"schema\":\"cursiv-record-1\",\"robot_id\":\"rover-02\",\"seq\":1,\"prev\":\"genesis\",\"written_time\":null,\"observation\":{},\"extra\":1}");
    assert!(matches!(l.store.ingest_batch(&[unknown_field]).unwrap()[0], Outcome::Rejected { ref code, .. } if code == "malformed"));
}

#[test]
fn legacy_cursiv_notebook_export_verifies_and_tampering_is_detected() {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/cursiv-export");
    let r = legacy::verify_cursiv_export(&fixture, None);
    assert!(r.signature_valid && r.problems.is_empty(), "{:?}", r.problems);
    assert_eq!(r.entries_exported, Some(3));
    assert_eq!(r.key_trusted, None, "no expected key given: authenticity not established");
    let r = legacy::verify_cursiv_export(&fixture, Some("0000000000000000"));
    assert!(!r.problems.is_empty());
    let copy = tmp("legacy");
    for e in fs::read_dir(&fixture).unwrap().flatten() {
        fs::copy(e.path(), copy.join(e.file_name())).unwrap();
    }
    let csv = copy.join("observations.csv");
    fs::write(&csv, fs::read_to_string(&csv).unwrap().replace("21.60", "29.90")).unwrap();
    let r = legacy::verify_cursiv_export(&copy, None);
    assert!(r.problems.iter().any(|p| p.contains("observations.csv was changed")), "{:?}", r.problems);
}

#[test]
fn dense_or_hostile_packages_cannot_explode_the_agreement_check() {
    // Found by the benchmark: 3 agents x 3000 co-located readings produced 13.9 million
    // contradiction flags and the verifier was killed for memory. Work and output are bounded.
    let mut a = Robot::new("rover-01", 1);
    let mut b = Robot::new("rover-02", 2);
    let mut records = vec![];
    for k in 0..2500u64 {
        for (r, v) in [(&mut a, 10.0), (&mut b, 20.0)] {
            let e = r.record(r.obs(k + 1, "air_temperature", v, "2026-11-05T10:00:00Z"));
            records.push((serde_json::from_str::<Record>(&e.body_text().unwrap()).unwrap(), e.payload_hash()));
        }
    }
    let t = std::time::Instant::now();
    let s = science::validate(&records, &[], &Profile::survey_default());
    assert!(t.elapsed().as_secs() < 30);
    assert!(s.counts["contradiction"] > 1_000_000, "every disagreeing pair is still counted: {:?}", s.counts);
    assert!(s.flags.iter().filter(|f| f.code == "contradiction").count() <= science::MAX_FLAGS_PER_GROUP);
    assert!(s.counts.contains_key("agreement_check_truncated"));
}

// ---- reproducible derivations and evidence-linked findings -------------------------------

fn derived(r: &Robot, n: u64, op: &str, inputs: &[&Observation], value: f64, with_step: bool) -> Observation {
    let mut o = r.obs(n, "air_temperature_mean", value, "2026-11-05T10:30:00Z");
    o.provenance.source = "derived".into();
    o.provenance.derived_from = inputs.iter().map(|i| format!("{}/{}", i.robot_id, i.observation_id)).collect();
    if with_step {
        o.processing.push(ProcessingStep { step: "cursiv.derive".into(), software: "t".into(), version: "1".into(),
                                           parameters: Some(serde_json::json!({"op": op, "params": {}})) });
    }
    o
}

fn finding(r: &Robot, n: u64, epistemic: &str, author_kind: &str, supports: &[&Observation], synthetic: bool) -> Observation {
    let mut o = r.obs(n, "finding", 0.0, "2026-11-05T11:00:00Z");
    o.measurement = None;
    o.synthetic = synthetic;
    o.provenance.source = "interpretation".into();
    o.claim = Some(Claim { statement: "the site is warmer in the east".into(), epistemic: epistemic.into(), author_kind: author_kind.into(),
                           model: (author_kind == "ai_model").then(|| "example-model".into()),
                           supports: supports.iter().map(|i| format!("{}/{}", i.robot_id, i.observation_id)).collect(),
                           contradicts: vec![], assumptions: vec![] });
    o
}

fn reason(l: &Lab, name: &str) -> (verify::Report, cursiv_evidence::reasoning::ReasoningReport) {
    let rep = l.verify(&l.export(name));
    let sci = science::validate(&rep.records, &rep.receipts, &Profile::survey_default());
    let rs = cursiv_evidence::reasoning::analyse(&rep.records, Some(&sci));
    (rep, rs)
}

#[test]
fn a_validly_signed_but_wrong_derived_result_is_caught_by_recomputation() {
    let mut l = lab("derive");
    let r = &mut l.robots[0];
    let ins: Vec<Observation> = (1..=4).map(|k| r.obs(k, "air_temperature", 10.0 + k as f64, "2026-11-05T10:00:00Z")).collect();
    let mut envs: Vec<Envelope> = ins.iter().map(|o| r.record(o.clone())).collect();
    let refs: Vec<&Observation> = ins.iter().collect();
    envs.push(r.record(derived(r, 10, "mean", &refs, 12.5, true)));         // correct: (11+12+13+14)/4
    envs.push(r.record(derived(r, 11, "mean", &refs, 13.1, true)));         // wrong, but properly signed
    envs.push(r.record(derived(r, 12, "mean", &refs, 12.5, false)));        // no method stated
    let mut ghost = r.obs(99, "air_temperature", 0.0, "2026-11-05T10:00:00Z");
    ghost.observation_id = "never-recorded".into();
    envs.push(r.record(derived(r, 13, "mean", &[&ghost], 0.0, true)));      // cites a missing input
    let mut real = derived(r, 14, "mean", &refs, 12.5, true);
    real.synthetic = true;
    envs.push(r.record(real));
    for o in l.store.ingest_batch(&envs).unwrap() {
        assert!(matches!(o, Outcome::Accepted { .. }), "{o:?}");
    }
    let (rep, rs) = reason(&l, "pkg");
    assert_eq!(rep.verdicts.integrity, "pass", "a wrong result can be perfectly signed: integrity is not correctness");
    assert_eq!(rs.derivations["verified"], 2);
    assert_eq!(rs.derivations["mismatch"], 1);
    assert_eq!(rs.derivations["not_reproducible"], 1);
    assert_eq!(rs.derivations["inputs_missing"], 1);
    assert!(rs.flags.iter().any(|f| f.code == "derivation_mismatch" && f.message.contains("recomputes to 12.5")));
}

#[test]
fn findings_are_checked_against_the_evidence_they_cite() {
    let mut l = lab("findings");
    let (a, b) = l.robots.split_at_mut(1);
    let (rover, analyst) = (&mut a[0], &mut b[0]);
    let o1 = rover.obs(1, "air_temperature", 15.0, "2026-11-05T10:00:00Z");
    let mut fix = rover.obs(2, "air_temperature", 15.4, "2026-11-05T10:00:00Z");
    fix.correction = Some(Correction { corrects_observation_id: o1.observation_id.clone(), reason: "offset".into() });
    let envs = vec![rover.record(o1.clone()), rover.record(fix.clone())];
    l.store.ingest_batch(&envs).unwrap();
    let mut ghost = o1.clone();
    ghost.observation_id = "rover-01-missing".into();
    let cases = [
        finding(analyst, 1, "inferred", "human", &[&fix], true),     // well supported
        finding(analyst, 2, "known", "ai_model", &[&fix], true),     // AI cannot be the authority for "known"
        finding(analyst, 3, "inferred", "human", &[], true),         // cites nothing
        finding(analyst, 4, "inferred", "human", &[&ghost], true),   // cites a record that does not exist
        finding(analyst, 5, "inferred", "human", &[&o1], true),      // cites a value that was later corrected
        finding(analyst, 6, "inferred", "human", &[&fix], false),    // about synthetic data, not marked synthetic
        finding(analyst, 7, "assumed", "human", &[], true),          // an assumption may stand without support
    ];
    let envs: Vec<Envelope> = cases.into_iter().map(|o| analyst.record(o)).collect();
    for o in l.store.ingest_batch(&envs).unwrap() {
        assert!(matches!(o, Outcome::Accepted { .. }), "{o:?}");
    }
    // structural rules at ingest: an AI claim must name its model; a claim needs source "interpretation"
    let mut nameless = finding(analyst, 8, "inferred", "ai_model", &[&fix], true);
    nameless.claim.as_mut().unwrap().model = None;
    let e = analyst.record(nameless);
    assert!(matches!(l.store.ingest_batch(&[e]).unwrap()[0], Outcome::Rejected { ref code, .. } if code == "invalid_observation"));
    let (_, rs) = reason(&l, "pkg");
    let status: Vec<&str> = rs.findings.iter().map(|f| f.status.as_str()).collect();
    assert_eq!(status, ["well_supported", "invalid", "invalid", "invalid", "supported_with_caveats", "invalid", "unsupported"]);
    for code in ["ai_claim_marked_known", "unsupported_claim", "citation_missing", "citation_superseded", "synthetic_propagation"] {
        assert!(rs.flags.iter().any(|f| f.code == code), "missing {code}");
    }
}

// ---- reliability: storage exhaustion, failed writes, concurrent uploads, atomic export ------

#[test]
fn storage_quota_refuses_cleanly_and_nothing_changes() {
    let mut l = lab("quota");
    l.survey(2);
    let used = l.store.used_bytes();
    l.store.set_quota(Some(used + 500));
    let r = &mut l.robots[0];
    let envs: Vec<Envelope> = (10..14).map(|k| { let o = r.obs(k, "air_temperature", 1.0, "2026-11-05T10:00:00Z"); r.record(o) }).collect();
    let out = l.store.ingest_batch(&envs).unwrap();
    assert!(out.iter().all(|o| matches!(o, Outcome::Rejected { code, .. } if code == "storage_full")), "{out:?}");
    assert_eq!(out[0].http_status(), 507);
    assert_eq!(l.store.robot_count("rover-01"), 2, "nothing admitted");
    let blob = vec![1u8; 10_000];
    assert_eq!(l.store.blobs().put(&blob[..], &sha256_hex(&blob), blob.len() as u64).unwrap_err().0, 507);
    l.store.set_quota(None);
    assert!(l.store.ingest_batch(&envs).unwrap().iter().all(|o| matches!(o, Outcome::Accepted { .. })), "resend after freeing space works");
}

#[test]
fn a_failed_write_stops_the_store_and_restart_recovers_from_disk() {
    let mut l = lab("failstop");
    l.survey(3);
    let f = l.dir.join("store/robots/rover-01/records.jsonl");
    let aside = l.dir.join("aside.jsonl");
    fs::rename(&f, &aside).unwrap();
    fs::create_dir(&f).unwrap(); // the next append cannot open the file: an I/O failure
    let r = &mut l.robots[0];
    let o = r.obs(50, "air_temperature", 1.0, "2026-11-05T10:00:00Z");
    let e = r.record(o);
    assert!(l.store.ingest_batch(std::slice::from_ref(&e)).is_err());
    assert!(l.store.failed().is_some());
    assert!(l.store.ingest_batch(std::slice::from_ref(&e)).is_err(), "no further writes once memory may be ahead of disk");
    assert!(matches!(l.store.ingest_checkpoint(&l.robots[1].checkpoint()), Outcome::Rejected { ref code, .. } if code == "store_failed"));
    fs::remove_dir(&f).unwrap();
    fs::rename(&aside, &f).unwrap();
    let mut store = Store::open(&l.dir.join("store"), "station-a", Identity::from_seed(l.station), l.trust.clone()).unwrap();
    assert_eq!(store.robot_count("rover-01"), 3, "state rebuilt from disk; the failed record was never stored");
    assert!(matches!(store.ingest_batch(&[e]).unwrap()[0], Outcome::Accepted { .. }), "and can now be resent");
}

#[test]
fn concurrent_uploads_of_the_same_attachment_do_not_corrupt_it() {
    let l = lab("uploads");
    let blob: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    let sha = sha256_hex(&blob);
    let blobs = l.store.blobs();
    let handles: Vec<_> = (0..8).map(|_| {
        let (b, data, sha) = (blobs.clone(), blob.clone(), sha.clone());
        std::thread::spawn(move || b.put(&data[..], &sha, data.len() as u64))
    }).collect();
    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert!(results.iter().all(|r| r.is_ok()), "{results:?}");
    assert!(results.iter().any(|r| matches!(r, Ok(true))));
    assert_eq!(sha256_hex(&fs::read(l.dir.join("store/blobs/sha256").join(&sha)).unwrap()), sha);
    assert!(fs::read_dir(l.dir.join("store/blobs/tmp")).unwrap().next().is_none());
}

#[test]
fn an_interrupted_export_leaves_no_package_behind() {
    let mut l = lab("atomic-export");
    l.survey(2);
    fs::create_dir(l.dir.join("store/blobs/sha256").join("not-a-file")).unwrap(); // copying it fails mid-export
    let dest = l.dir.join("exports/pkg");
    assert!(l.store.export(&dest).is_err());
    assert!(!dest.exists());
    assert!(fs::read_dir(l.dir.join("exports")).unwrap().next().is_none(), "no partial folder left");
    fs::remove_dir(l.dir.join("store/blobs/sha256/not-a-file")).unwrap();
    l.store.export(&dest).unwrap();
    assert!(l.store.export(&dest).is_err(), "never overwrites an existing package");
    assert!(l.verify(&dest).all_pass());
}

#[test]
fn trust_store_reload_takes_effect_immediately() {
    let mut l = lab("reload");
    let mut t = l.trust.clone();
    t.robots.get_mut("rover-01").unwrap()[0].status = "revoked".into();
    l.store.set_trust(t);
    let r = &mut l.robots[0];
    let e = r.record(r.obs(1, "air_temperature", 1.0, "2026-11-05T10:00:00Z"));
    assert!(matches!(l.store.ingest_batch(&[e]).unwrap()[0], Outcome::Rejected { ref code, .. } if code == "revoked_key"));
}

// ---- scientific checks: units, duplicates, gaps, timestamps, uncertainty propagation ---------

#[test]
fn units_duplicates_gaps_and_timestamps_are_checked() {
    let mut l = lab("units");
    let r = &mut l.robots[0];
    let mut f = r.obs(1, "air_temperature", 140.0, "2026-11-05T10:00:00Z"); // 140 degF = 60 degC: in range after conversion
    f.measurement.as_mut().unwrap().unit = "degF".into();
    let mut hot = r.obs(2, "air_temperature", 200.0, "2026-11-05T10:01:00Z"); // 200 degF = 93 degC: out of range
    hot.measurement.as_mut().unwrap().unit = "degF".into();
    let mut odd = r.obs(3, "air_temperature", 1.0, "2026-11-05T10:02:00Z");
    odd.measurement.as_mut().unwrap().unit = "furlongs".into();
    let a = r.obs(4, "air_temperature", 15.0, "2026-11-05T10:03:00Z");
    let mut replay = a.clone();
    replay.observation_id = "rover-01-replayed".into(); // same reading, new id
    let late = r.obs(6, "air_temperature", 15.0, "2026-11-05T11:30:00Z"); // long gap
    let envs = [f, hot, odd, a, replay, late].map(|o| r.record(o));
    let mut early_write = r.obs(7, "air_temperature", 15.0, "2026-11-05T12:00:00Z");
    early_write.observation_id = "rover-01-written-early".into();
    let rec = Record { schema: RECORD_SCHEMA.into(), robot_id: "rover-01".into(), seq: r.hashes.len() as u64 + 1, prev: r.hashes.last().unwrap().clone(),
                       written_time: Some("2026-11-05T11:00:00Z".into()), observation: early_write };
    let e = r.key.sign_json(RECORD_TYPE, &rec);
    r.hashes.push(e.payload_hash());
    let mut all = envs.to_vec();
    all.push(e);
    l.store.ingest_batch(&all).unwrap();
    let rep = l.verify(&l.export("pkg"));
    let mut prof = Profile::survey_default();
    prof.types.get_mut("air_temperature").unwrap().expected_interval_s = Some(60.0);
    let s = science::validate(&rep.records, &rep.receipts, &prof);
    let n = |c: &str| s.counts.get(c).copied().unwrap_or(0);
    assert_eq!(n("unit_converted"), 2, "{:?}", s.counts);
    assert_eq!(n("out_of_range"), 1, "only the 200 degF reading is out of range in degC");
    assert_eq!(n("unit_unrecognized"), 1);
    assert_eq!(n("unit_mismatch"), 1, "no conversion exists from furlongs");
    assert_eq!(n("duplicate_content"), 1);
    assert!(n("sampling_gap") >= 1);
    assert_eq!(n("sensor_time_after_write"), 1);
}

#[test]
fn derived_uncertainty_is_propagated_and_checked() {
    let mut l = lab("uncert");
    let r = &mut l.robots[0];
    let ins: Vec<Observation> = (1..=4).map(|k| r.obs(k, "air_temperature", 10.0 + k as f64, "2026-11-05T10:00:00Z")).collect(); // u = 0.2 each
    let mut envs: Vec<Envelope> = ins.iter().map(|o| r.record(o.clone())).collect();
    let refs: Vec<&Observation> = ins.iter().collect();
    let with_u = |o: &mut Observation, u: Option<f64>| o.measurement.as_mut().unwrap().uncertainty = u.map(|v| Uncertainty { kind: "standard".into(), value: v, coverage_k: None });
    let mut good = derived(r, 10, "mean", &refs, 12.5, true);
    with_u(&mut good, Some(0.1));                       // sqrt(4 * 0.04) / 4 = 0.1
    let mut overclaimed = derived(r, 11, "mean", &refs, 12.5, true);
    with_u(&mut overclaimed, Some(0.01));               // claims 10x more precision than the inputs allow
    let mut no_inputs_u: Vec<Observation> = ins.clone();
    for (k, o) in no_inputs_u.iter_mut().enumerate() {
        o.observation_id = format!("rover-01-nou-{k}");
        o.measurement.as_mut().unwrap().uncertainty = None;
    }
    envs.extend(no_inputs_u.iter().map(|o| r.record(o.clone())));
    let nrefs: Vec<&Observation> = no_inputs_u.iter().collect();
    let mut invented = derived(r, 12, "mean", &nrefs, 12.5, true);
    with_u(&mut invented, Some(0.1));                   // an uncertainty from inputs that have none
    for o in [good, overclaimed, invented] {
        envs.push(r.record(o));
    }
    l.store.ingest_batch(&envs).unwrap();
    let (_, rs) = reason(&l, "pkg");
    assert_eq!(rs.derivations["verified"], 3, "the values all match");
    assert_eq!(rs.derivations["uncertainty_verified"], 1);
    assert!(rs.flags.iter().any(|f| f.code == "uncertainty_mismatch"));
    assert!(rs.flags.iter().any(|f| f.code == "uncertainty_unsupported"));
}
