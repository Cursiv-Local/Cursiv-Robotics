//! Segmented logs (package and store format 2): continuity between segments, detection of
//! missing / reordered / duplicated / tampered / truncated segments, standalone segment checks,
//! format-1 compatibility, store migration, rotation across restarts, and interrupted writes.

use cursiv_evidence::crypto::{public_b64, Envelope, Identity, CHECKPOINT_TYPE, RECORD_TYPE};
use cursiv_evidence::merkle;
use cursiv_evidence::model::*;
use cursiv_evidence::package::ExportOptions;
use cursiv_evidence::segment;
use cursiv_evidence::store::{Outcome, SegmentLimits, Store};
use cursiv_evidence::trust::{TrustStore, TrustedKey};
use cursiv_evidence::verify::{self, VerifyOptions};
use std::fs;
use std::path::{Path, PathBuf};

fn tmp(name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("cursiv-seg-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&p);
    fs::create_dir_all(&p).unwrap();
    p
}

fn tk(id: &Identity) -> TrustedKey {
    TrustedKey { key_id: id.key_id(), public_key: public_b64(&id.public()), status: "active".into(), note: None, valid_from_seq: None, valid_until_seq: None }
}

struct Bot {
    key: Identity,
    hashes: Vec<String>,
}

impl Bot {
    fn next(&mut self, n: u64) -> Envelope {
        let rid = "probe-01";
        let obs = Observation {
            schema: OBSERVATION_SCHEMA.into(), observation_id: format!("{rid}-obs-{n:06}"), robot_id: rid.into(), mission_id: "seg".into(),
            observation_type: "air_temperature".into(), synthetic: true,
            sensor: Sensor { sensor_id: format!("{rid}-t1"), sensor_type: "thermistor".into(), model: None, calibration: None },
            sensor_time: Some(format_utc(1_793_000_000.0 + n as f64 * 60.0)), time_source: TimeSource::Simulated, clock: None, location: None,
            measurement: Some(Measurement { value: Some(10.0 + (n as f64 / 50.0).sin()), text: None, unit: "degC".into(),
                                            uncertainty: Some(Uncertainty { kind: "standard".into(), value: 0.2, coverage_k: None }) }),
            attachments: vec![], provenance: Provenance { source: "simulated".into(), software: "seg-test".into(), software_version: "1".into(), derived_from: vec![] },
            processing: vec![], quality: None, correction: None, claim: None,
        };
        let rec = Record { schema: RECORD_SCHEMA.into(), robot_id: rid.into(), seq: self.hashes.len() as u64 + 1,
                           prev: self.hashes.last().cloned().unwrap_or_else(|| GENESIS.into()), written_time: None, observation: obs };
        let env = self.key.sign_json(RECORD_TYPE, &rec);
        self.hashes.push(env.payload_hash());
        env
    }
    fn checkpoint(&self) -> Envelope {
        self.key.sign_json(CHECKPOINT_TYPE, &Checkpoint { schema: CHECKPOINT_SCHEMA.into(), robot_id: "probe-01".into(), count: self.hashes.len() as u64,
            head: self.hashes.last().unwrap().clone(), merkle_root: merkle::root(&self.hashes), signed_time: None })
    }
}

struct Lab {
    dir: PathBuf,
    store: Store,
    bot: Bot,
    trust: TrustStore,
}

const STATION: [u8; 32] = [42; 32];

fn lab(name: &str, per_segment: u64) -> Lab {
    let dir = tmp(name);
    let bot = Bot { key: Identity::from_seed([41; 32]), hashes: vec![] };
    let mut trust = TrustStore { format: "cursiv-trust-1".into(), ..Default::default() };
    trust.robots.insert("probe-01".into(), vec![tk(&bot.key)]);
    trust.stations.insert("station-s".into(), vec![tk(&Identity::from_seed(STATION))]);
    let mut store = Store::open(&dir.join("store"), "station-s", Identity::from_seed(STATION), trust.clone()).unwrap();
    store.set_segment_limits(SegmentLimits { records: per_segment, bytes: u64::MAX });
    Lab { dir, store, bot, trust }
}

impl Lab {
    fn add(&mut self, n: u64) {
        let start = self.bot.hashes.len() as u64 + 1;
        let envs: Vec<Envelope> = (start..start + n).map(|k| self.bot.next(k)).collect();
        for chunk in envs.chunks(4) {
            for o in self.store.ingest_batch(chunk).unwrap() {
                assert!(matches!(o, Outcome::Accepted { .. }), "{o:?}");
            }
        }
        assert!(matches!(self.store.ingest_checkpoint(&self.bot.checkpoint()), Outcome::Accepted { .. }));
    }
    fn reopen(&mut self, per_segment: u64) {
        self.store = Store::open(&self.dir.join("store"), "station-s", Identity::from_seed(STATION), self.trust.clone()).unwrap();
        self.store.set_segment_limits(SegmentLimits { records: per_segment, bytes: u64::MAX });
    }
    fn export(&mut self, name: &str) -> PathBuf {
        let p = self.dir.join(name);
        self.store.export(&p).unwrap();
        p
    }
}

fn copy_tree(from: &Path, to: &Path) {
    for e in fs::read_dir(from).unwrap().flatten() {
        let d = to.join(e.file_name());
        if e.path().is_dir() {
            fs::create_dir_all(&d).unwrap();
            copy_tree(&e.path(), &d);
        } else {
            fs::copy(e.path(), d).unwrap();
        }
    }
}

fn copy_pkg(p: &Path, name: &str) -> PathBuf {
    let d = p.with_file_name(name);
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    copy_tree(p, &d);
    d
}

fn errors(r: &verify::Report) -> Vec<String> {
    r.findings.iter().filter(|f| f.severity == "error").map(|f| f.code.clone()).collect()
}

fn segdir(p: &Path) -> PathBuf {
    p.join("data/robots/probe-01/segments")
}

#[test]
fn a_segmented_package_verifies_in_streaming_and_collecting_mode_alike() {
    let mut l = lab("clean", 7);
    l.add(30);
    let p = l.export("pkg");
    let names: Vec<String> = fs::read_dir(segdir(&p)).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().to_string()).collect();
    assert_eq!(names.iter().filter(|n| n.ends_with(".seal.json")).count(), 5, "30 records / 7 per segment = 5 sealed segments: {names:?}");
    let full = verify::verify_package(&p, Some(&l.trust));
    assert!(full.all_pass(), "{}", full.text());
    assert_eq!((full.status.as_str(), full.package_version, full.records.len()), ("verified", 2, 30));
    let lean = verify::verify_package_with(&p, Some(&l.trust), &VerifyOptions::streaming());
    assert!(lean.all_pass() && lean.records.is_empty() && !lean.records_complete);
    assert_eq!(lean.robots["probe-01"].head, full.robots["probe-01"].head);
    // a capped collection says so instead of pretending to be complete
    let capped = verify::verify_package_with(&p, Some(&l.trust), &VerifyOptions { collect_records: true, max_collected_records: 10 });
    assert!(capped.all_pass() && !capped.records_complete && capped.records.len() == 10);
    assert!(capped.findings.iter().any(|f| f.code == "records_not_collected"));
}

#[test]
fn every_segment_can_be_checked_on_its_own() {
    let mut l = lab("alone", 5);
    l.add(12);
    let p = l.export("pkg");
    let sk = public_b64(&Identity::from_seed(STATION).public());
    let rk = public_b64(&l.bot.key.public());
    for n in 1..=3 {
        let seal: Envelope = serde_json::from_str(&fs::read_to_string(segdir(&p).join(segment::seal_name(n))).unwrap()).unwrap();
        let r = segment::verify_segment(&segdir(&p).join(segment::segment_name(n)), &seal, &sk, &rk);
        assert!(r.problems.is_empty(), "segment {n}: {:?}", r.problems);
        assert_eq!(r.records, if n < 3 { 5 } else { 2 });
    }
    // a segment checked against the wrong seal, or with a changed byte, fails on its own
    let seal1: Envelope = serde_json::from_str(&fs::read_to_string(segdir(&p).join(segment::seal_name(1))).unwrap()).unwrap();
    assert!(!segment::verify_segment(&segdir(&p).join(segment::segment_name(2)), &seal1, &sk, &rk).problems.is_empty());
    let bad = copy_pkg(&p, "bad");
    let f = segdir(&bad).join(segment::segment_name(2));
    let mut b = fs::read(&f).unwrap();
    b[40] ^= 1;
    fs::write(&f, b).unwrap();
    let seal2: Envelope = serde_json::from_str(&fs::read_to_string(segdir(&bad).join(segment::seal_name(2))).unwrap()).unwrap();
    assert!(!segment::verify_segment(&f, &seal2, &sk, &rk).problems.is_empty());
    // and a seal signed by someone else is refused
    assert!(!segment::verify_segment(&segdir(&p).join(segment::segment_name(1)), &seal1, &rk, &rk).problems.is_empty());
}

#[test]
fn missing_reordered_duplicated_tampered_and_truncated_segments_are_detected() {
    let mut l = lab("attacks", 4);
    l.add(16);
    let p = l.export("pkg");
    assert!(verify::verify_package(&p, Some(&l.trust)).all_pass());
    let check = |name: &str, f: &dyn Fn(&Path), expect: &[&str]| {
        let d = copy_pkg(&p, name);
        f(&segdir(&d));
        for opts in [VerifyOptions::default(), VerifyOptions::streaming()] {
            let r = verify::verify_package_with(&d, Some(&l.trust), &opts);
            assert!(!r.all_pass() && r.status == "failed", "{name}: {}", r.text());
            let errs = errors(&r);
            for e in expect {
                assert!(errs.iter().any(|c| c == e), "{name}: expected {e} in {errs:?}");
            }
        }
    };
    check("missing", &|s| {
        fs::remove_file(s.join(segment::segment_name(2))).unwrap();
        fs::remove_file(s.join(segment::seal_name(2))).unwrap();
    }, &["segment_missing", "segment_seal_mismatch", "file_missing", "chain"]);
    check("missing-last", &|s| {
        fs::remove_file(s.join(segment::segment_name(4))).unwrap();
        fs::remove_file(s.join(segment::seal_name(4))).unwrap();
    }, &["file_missing"]);
    check("reordered", &|s| {
        for (a, b) in [(segment::segment_name(2), segment::segment_name(3)), (segment::seal_name(2), segment::seal_name(3))] {
            let t = s.join("swap");
            fs::rename(s.join(&a), &t).unwrap();
            fs::rename(s.join(&b), s.join(&a)).unwrap();
            fs::rename(&t, s.join(&b)).unwrap();
        }
    }, &["segment_seal_mismatch", "sequence", "chain"]);
    check("duplicated", &|s| {
        fs::copy(s.join(segment::segment_name(2)), s.join(segment::segment_name(5))).unwrap();
        fs::copy(s.join(segment::seal_name(2)), s.join(segment::seal_name(5))).unwrap();
    }, &["segment_seal_mismatch", "file_unlisted"]);
    check("tampered", &|s| {
        let f = s.join(segment::segment_name(3));
        let t = fs::read_to_string(&f).unwrap();
        let mut lines: Vec<String> = t.lines().map(String::from).collect();
        let mut env: Envelope = serde_json::from_str(&lines[1]).unwrap();
        let body = env.body_text().unwrap().replacen("\"value\":1", "\"value\":2", 1);
        env.payload = base64_encode(body.as_bytes());
        lines[1] = serde_json::to_string(&env).unwrap();
        fs::write(&f, lines.join("\n") + "\n").unwrap();
    }, &["file_changed", "segment_seal_mismatch"]);
    check("truncated", &|s| {
        let f = s.join(segment::segment_name(3));
        let b = fs::read(&f).unwrap();
        fs::write(&f, &b[..b.len() - 37]).unwrap(); // an interrupted copy
    }, &["truncated_file", "segment_seal_mismatch"]);
    check("seal-swapped-between-robots-or-stations", &|s| {
        fs::copy(s.join(segment::seal_name(1)), s.join(segment::seal_name(2))).unwrap();
    }, &["segment_seal_mismatch"]);
    check("unsealed", &|s| {
        fs::remove_file(s.join(segment::seal_name(3))).unwrap();
    }, &["segment_unsealed"]);
}

fn base64_encode(b: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(b)
}

#[test]
fn format_1_packages_are_still_written_and_verified() {
    let mut l = lab("v1", 4);
    l.add(10);
    let p2 = l.export("pkg2");
    let p1 = l.dir.join("pkg1");
    l.store.export_with(&p1, ExportOptions { format: 1 }).unwrap();
    assert!(p1.join("data/robots/probe-01/records.jsonl").is_file());
    assert!(fs::read_to_string(p1.join("bag-info.txt")).unwrap().contains("Cursiv-Package-Version: 1"));
    let (r1, r2) = (verify::verify_package(&p1, Some(&l.trust)), verify::verify_package(&p2, Some(&l.trust)));
    assert!(r1.all_pass() && r2.all_pass(), "{}\n{}", r1.text(), r2.text());
    assert_eq!((r1.package_version, r2.package_version), (1, 2));
    assert_eq!(r1.robots["probe-01"].head, r2.robots["probe-01"].head);
    // the format-1 log is exactly the segments concatenated
    let mut cat = Vec::new();
    for n in 1..=3 {
        cat.extend(fs::read(segdir(&p2).join(segment::segment_name(n))).unwrap());
    }
    assert_eq!(cat, fs::read(p1.join("data/robots/probe-01/records.jsonl")).unwrap());
    // a package may not claim one format and contain the other
    let mixed = copy_pkg(&p1, "mixed");
    let info = mixed.join("bag-info.txt");
    fs::write(&info, fs::read_to_string(&info).unwrap().replace("Version: 1", "Version: 2")).unwrap();
    let r = verify::verify_package(&mixed, Some(&l.trust));
    assert!(!r.all_pass() && errors(&r).iter().any(|c| c == "layout_version" || c == "version_mismatch"), "{:?}", errors(&r));
    // the sample package in the repository (format 1, made before format 2 existed) still verifies
    let sample = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/sample-package");
    let trust = TrustStore::load(&sample.join("trust.json")).unwrap();
    let r = verify::verify_package(&sample.join("sample-buoy-1-package"), Some(&trust));
    assert!(r.all_pass() && r.package_version == 1, "{}", r.text());
}

#[test]
fn a_format_1_store_is_migrated_without_changing_its_bytes() {
    let mut l = lab("migrate", 1_000_000);
    l.add(9);
    drop(std::mem::replace(&mut l.store, Store::open(&tmp("scratch"), "station-s", Identity::from_seed(STATION), l.trust.clone()).unwrap()));
    // turn the store back into format 1: one records.jsonl per robot, no format marker
    let rdir = l.dir.join("store/robots/probe-01");
    fs::rename(rdir.join("segments/000001.jsonl"), rdir.join("records.jsonl")).unwrap();
    fs::remove_dir(rdir.join("segments")).unwrap();
    fs::remove_file(l.dir.join("store/store-format.json")).unwrap();
    let before = fs::read(rdir.join("records.jsonl")).unwrap();
    l.reopen(4);
    assert!(l.store.recovery_notes.iter().any(|n| n.contains("format-1 log moved unchanged")), "{:?}", l.store.recovery_notes);
    assert_eq!(fs::read(rdir.join("segments/000001.jsonl")).unwrap(), before, "migration must not change a byte");
    assert_eq!(l.store.robot_count("probe-01"), 9);
    l.add(6); // the migrated segment exceeds the new limit: it is sealed and new records rotate
    let p = l.export("pkg");
    let r = verify::verify_package(&p, Some(&l.trust));
    assert!(r.all_pass() && r.robots["probe-01"].records == 15, "{}", r.text());
    // both layouts at once is refused rather than guessed
    fs::write(rdir.join("records.jsonl"), &before).unwrap();
    assert!(Store::open(&l.dir.join("store"), "station-s", Identity::from_seed(STATION), l.trust.clone()).is_err());
}

#[test]
fn rotation_continues_across_restarts_and_interrupted_seal_writes() {
    let mut l = lab("restart", 5);
    l.add(7); // segment 1 sealed, segment 2 active with 2 records
    l.reopen(5);
    l.add(6); // the active segment's hash state must survive the restart
    // a crash while writing a seal leaves a temporary file; it is discarded on open
    fs::write(l.dir.join("store/robots/probe-01/segments/.write.123.tmp"), b"partial seal").unwrap();
    l.reopen(5);
    l.add(1);
    let p = l.export("pkg");
    let r = verify::verify_package(&p, Some(&l.trust));
    assert!(r.all_pass() && r.robots["probe-01"].records == 14, "{}", r.text());
    // a sealed segment changed on the station's disk stops the store from starting
    let f = l.dir.join("store/robots/probe-01/segments/000001.jsonl");
    let mut b = fs::read(&f).unwrap();
    b[10] ^= 1;
    fs::write(&f, b).unwrap();
    assert!(Store::open(&l.dir.join("store"), "station-s", Identity::from_seed(STATION), l.trust.clone()).is_err());
}

#[test]
fn read_failures_and_unsupported_formats_never_produce_a_verified_report() {
    let mut l = lab("readfail", 4);
    l.add(8);
    let p = l.export("pkg");
    // a segment replaced by a directory: the file cannot be read
    let d = copy_pkg(&p, "dir");
    let f = segdir(&d).join(segment::segment_name(2));
    fs::remove_file(&f).unwrap();
    fs::create_dir(&f).unwrap();
    for opts in [VerifyOptions::default(), VerifyOptions::streaming()] {
        let r = verify::verify_package_with(&d, Some(&l.trust), &opts);
        assert_eq!(r.status, "failed", "{}", r.text());
        assert!(!r.all_pass());
    }
    // a future format is refused, not guessed at
    let fut = copy_pkg(&p, "future");
    let info = fut.join("bag-info.txt");
    fs::write(&info, fs::read_to_string(&info).unwrap().replace("Cursiv-Package-Version: 2", "Cursiv-Package-Version: 7")).unwrap();
    let r = verify::verify_package(&fut, Some(&l.trust));
    assert!(errors(&r).iter().any(|c| c == "unsupported_version") && r.status == "failed");
    // without a trust store nothing fails, but the report is "incomplete", never "verified"
    let r = verify::verify_package(&p, None);
    assert_eq!(r.status, "incomplete");
    assert!(!r.all_pass());
}

#[test]
fn the_plain_summary_says_what_went_wrong() {
    let mut l = lab("plain", 4);
    l.add(8);
    let p = l.export("pkg");
    let ok = verify::verify_package(&p, Some(&l.trust));
    assert!(ok.summary[0].starts_with("Verified: 8 record(s) from 1 robot(s)"), "{:?}", ok.summary);
    assert!(ok.summary.iter().any(|s| s.contains("SYNTHETIC")));
    let bad = copy_pkg(&p, "plain-bad");
    let f = segdir(&bad).join(segment::segment_name(1));
    let t = fs::read_to_string(&f).unwrap();
    let mut lines: Vec<String> = t.lines().map(String::from).collect();
    let mut env: Envelope = serde_json::from_str(&lines[0]).unwrap();
    env.payload = base64_encode(env.body_text().unwrap().replacen("\"value\":1", "\"value\":2", 1).as_bytes());
    lines[0] = serde_json::to_string(&env).unwrap();
    fs::write(&f, lines.join("\n") + "\n").unwrap();
    let r = verify::verify_package(&bad, Some(&l.trust));
    assert!(r.summary[0].starts_with("NOT VERIFIED"), "{:?}", r.summary);
    assert!(r.summary.iter().any(|s| s.contains("1 record(s) were changed after they were signed")), "{:?}", r.summary);
    let none = verify::verify_package(&p, None);
    assert!(none.summary[0].starts_with("Not fully verified") && none.summary.iter().any(|s| s.contains("No trust store")));
}
