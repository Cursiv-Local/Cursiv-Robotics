//! Property-based tests (proptest) and deterministic mutation fuzzing.
//!
//! The properties state what must hold for *every* input, not just the hand-picked cases in
//! `faults.rs`: parsers never panic, signatures bind every byte, Merkle roots commit to order
//! and content, unit conversions round-trip, and any single-byte change anywhere in a signed
//! package is detected (or provably harmless) and never crashes the verifier.
//! Mutation fuzzing is seeded, so a failure is reproducible from the case number it reports.

use cursiv_evidence::crypto::{sha256_hex, Envelope, Identity, CHECKPOINT_TYPE, RECORD_TYPE};
use cursiv_evidence::merkle;
use cursiv_evidence::model::*;
use cursiv_evidence::package::safe_rel;
use cursiv_evidence::store::{Outcome, Store};
use cursiv_evidence::trust::{TrustStore, TrustedKey};
use cursiv_evidence::{units, verify};
use proptest::prelude::*;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

fn tmp(name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("cursiv-props-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&p);
    fs::create_dir_all(&p).unwrap();
    p
}

fn tk(id: &Identity) -> TrustedKey {
    TrustedKey { key_id: id.key_id(), public_key: cursiv_evidence::crypto::public_b64(&id.public()), status: "active".into(), note: None, valid_from_seq: None, valid_until_seq: None }
}

fn obs(robot: &str, n: u64, value: f64) -> Observation {
    Observation {
        schema: OBSERVATION_SCHEMA.into(),
        observation_id: format!("{robot}-obs-{n:05}"),
        robot_id: robot.into(),
        mission_id: "props".into(),
        observation_type: "air_temperature".into(),
        synthetic: true,
        sensor: Sensor { sensor_id: format!("{robot}-s1"), sensor_type: "probe".into(), model: None, calibration: None },
        sensor_time: Some(format_utc(1_793_000_000.0 + n as f64 * 60.0)),
        time_source: TimeSource::Simulated,
        clock: None,
        location: None,
        measurement: Some(Measurement { value: Some(value), text: None, unit: "degC".into(), uncertainty: Some(Uncertainty { kind: "standard".into(), value: 0.2, coverage_k: None }) }),
        attachments: vec![],
        provenance: Provenance { source: "simulated".into(), software: "props-test".into(), software_version: "1".into(), derived_from: vec![] },
        processing: vec![],
        quality: None,
        correction: None,
        claim: None,
    }
}

/// One small, valid, signed package shared by the mutation tests (built once).
fn package() -> &'static (PathBuf, TrustStore) {
    static PKG: OnceLock<(PathBuf, TrustStore)> = OnceLock::new();
    PKG.get_or_init(|| {
        let dir = tmp("base");
        let robot = Identity::from_seed([5; 32]);
        let station = Identity::from_seed([6; 32]);
        let mut trust = TrustStore { format: "cursiv-trust-1".into(), ..Default::default() };
        trust.robots.insert("probe-01".into(), vec![tk(&robot)]);
        trust.stations.insert("station-p".into(), vec![tk(&station)]);
        let mut store = Store::open(&dir.join("store"), "station-p", Identity::from_seed([6; 32]), trust.clone()).unwrap();
        let mut hashes: Vec<String> = vec![];
        let mut envs = vec![];
        for n in 1..=6 {
            let rec = Record { schema: RECORD_SCHEMA.into(), robot_id: "probe-01".into(), seq: n, prev: hashes.last().cloned().unwrap_or_else(|| GENESIS.into()),
                               written_time: None, observation: obs("probe-01", n, 10.0 + n as f64) };
            let env = robot.sign_json(RECORD_TYPE, &rec);
            hashes.push(env.payload_hash());
            envs.push(env);
        }
        for o in store.ingest_batch(&envs).unwrap() {
            assert!(matches!(o, Outcome::Accepted { .. }), "{o:?}");
        }
        let cp = robot.sign_json(CHECKPOINT_TYPE, &Checkpoint { schema: CHECKPOINT_SCHEMA.into(), robot_id: "probe-01".into(), count: 6,
            head: hashes.last().unwrap().clone(), merkle_root: merkle::root(&hashes), signed_time: None });
        assert!(matches!(store.ingest_checkpoint(&cp), Outcome::Accepted { .. }));
        let pkg = dir.join("pkg");
        store.export(&pkg).unwrap();
        let r = verify::verify_package(&pkg, Some(&trust));
        assert!(r.all_pass(), "{}", r.text());
        (pkg, trust)
    })
}

fn files(root: &Path) -> Vec<PathBuf> {
    let mut out = vec![];
    let mut stack = vec![root.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in fs::read_dir(&d).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() { stack.push(p) } else { out.push(p) }
        }
    }
    out.sort();
    out
}

fn copy_tree(from: &Path, to: &Path) {
    for f in files(from) {
        let dest = to.join(f.strip_prefix(from).unwrap());
        fs::create_dir_all(dest.parent().unwrap()).unwrap();
        fs::copy(&f, dest).unwrap();
    }
}

/// Small deterministic PRNG (SplitMix64) so fuzz cases are reproducible without extra crates.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

fn verdict_strings(r: &verify::Report) -> [String; 5] {
    let v = &r.verdicts;
    [v.structure.clone(), v.integrity.clone(), v.authenticity.clone(), v.completeness.clone(), v.attachments.clone()]
}

/// Mutation fuzzing: flip, insert, delete or truncate bytes anywhere in a copy of a valid
/// package. The verifier must never panic, and every mutation of a byte under `data/` or of
/// `manifest.json` must fail at least one verdict. (Tag files outside the signed manifest,
/// such as bag-info.txt, may be changed harmlessly: they are not evidence.)
#[test]
fn mutated_packages_never_panic_and_evidence_changes_are_always_detected() {
    let (pkg, trust) = package();
    let all = files(pkg);
    let mut rng = Rng(0x5EED_0001);
    let cases = std::env::var("CURSIV_FUZZ_CASES").ok().and_then(|s| s.parse().ok()).unwrap_or(150);
    let work = tmp("mut");
    let mut detected = 0;
    for case in 0..cases {
        let dir = work.join(format!("c{case}"));
        copy_tree(pkg, &dir);
        let f = &all[rng.below(all.len())];
        let rel = f.strip_prefix(pkg).unwrap().to_path_buf();
        let target = dir.join(&rel);
        let mut bytes = fs::read(&target).unwrap();
        let op = rng.below(4);
        if bytes.is_empty() { bytes.push(b'x') }
        let at = rng.below(bytes.len());
        match op {
            0 => bytes[at] ^= 1 << rng.below(8),
            1 => bytes.insert(at, (rng.next() & 0xff) as u8),
            2 => { bytes.remove(at); }
            _ => bytes.truncate(at),
        }
        fs::write(&target, &bytes).unwrap();
        let r = std::panic::catch_unwind(|| verify::verify_package(&dir, Some(trust)));
        let r = r.unwrap_or_else(|_| panic!("verifier panicked: case {case}, {} op {op} at {at}", rel.display()));
        let evidence = rel.starts_with("data") || rel == Path::new("manifest.json");
        let original = fs::read(f).unwrap();
        if evidence && bytes != original {
            // The only harmless evidence edits: none. Every changed signed byte must be caught.
            assert!(!r.all_pass(), "undetected change: case {case}, {} op {op} at {at}\n{}", rel.display(), r.text());
            detected += 1;
        }
        let _ = fs::remove_dir_all(&dir);
    }
    assert!(detected > cases / 2, "mutations mostly hit evidence files ({detected}/{cases})");
}

/// Structural fuzz: delete, duplicate or swap whole files; the verifier must report, not crash.
#[test]
fn removed_or_swapped_files_are_reported_not_crashed_on() {
    let (pkg, trust) = package();
    let all: Vec<PathBuf> = files(pkg).into_iter().map(|f| f.strip_prefix(pkg).unwrap().to_path_buf()).collect();
    let work = tmp("files");
    for (i, rel) in all.iter().enumerate() {
        let dir = work.join(format!("rm{i}"));
        copy_tree(pkg, &dir);
        fs::remove_file(dir.join(rel)).unwrap();
        let r = verify::verify_package(&dir, Some(trust));
        if rel.starts_with("data") || rel == Path::new("manifest.json") || rel == Path::new("bagit.txt") {
            assert!(!r.all_pass(), "deleting {} went unnoticed", rel.display());
        }
        let _ = fs::remove_dir_all(&dir);
    }
    for (i, a) in all.iter().enumerate() {
        let b = &all[(i + 1) % all.len()];
        let dir = work.join(format!("sw{i}"));
        copy_tree(pkg, &dir);
        let (pa, pb) = (dir.join(a), dir.join(b));
        let (ba, bb) = (fs::read(&pa).unwrap(), fs::read(&pb).unwrap());
        fs::write(&pa, &bb).unwrap();
        fs::write(&pb, &ba).unwrap();
        let r = verify::verify_package(&dir, Some(trust));
        if ba != bb && (a.starts_with("data") || b.starts_with("data")) {
            assert!(!r.all_pass(), "swapping {} and {} went unnoticed", a.display(), b.display());
        }
        let _ = fs::remove_dir_all(&dir);
    }
    // a directory that is not a package at all
    let empty = work.join("empty");
    fs::create_dir_all(&empty).unwrap();
    assert_eq!(verify::verify_package(&empty, Some(trust)).verdicts.structure, "fail");
}

/// Inputs found by the property test (and their relatives), kept as fixed regression cases.
#[test]
fn non_canonical_paths_are_refused() {
    for bad in ["0/.", "./a", "a/./b", "a//b", "a/", "/a", "..", "a/../b", "a\\b", "c:x", ""] {
        assert!(!safe_rel(bad), "{bad:?} must be refused");
    }
    for good in ["a", "robots/r-1/segments/000001.jsonl", "blobs/sha256/ab", "a.b/c..d"] {
        assert!(safe_rel(good), "{good:?} must be accepted");
    }
}

/// Verification is a pure function of the bytes: running it twice gives the same verdicts.
#[test]
fn verification_is_deterministic() {
    let (pkg, trust) = package();
    let a = verify::verify_package(pkg, Some(trust));
    let b = verify::verify_package(pkg, Some(trust));
    assert_eq!(verdict_strings(&a), verdict_strings(&b));
    assert_eq!(a.findings.len(), b.findings.len());
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, failure_persistence: None, ..ProptestConfig::default() })]

    /// A signature binds the exact body and payload type: any change to either is rejected.
    #[test]
    fn envelope_signatures_bind_every_byte(seed in any::<[u8; 32]>(), body in ".{0,200}", flip in any::<usize>(), bit in 0u8..8) {
        let id = Identity::from_seed(seed);
        let env = id.sign_payload(RECORD_TYPE, &body);
        prop_assert!(env.verify_with(&id.public()));
        prop_assert_eq!(env.body_text().unwrap(), body.clone());
        let mut bytes = body.clone().into_bytes();
        if !bytes.is_empty() {
            let i = flip % bytes.len();
            bytes[i] ^= 1 << bit;
            let mut forged = env.clone();
            forged.payload = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &bytes);
            prop_assert!(!forged.verify_with(&id.public()));
        }
        let mut retyped = env.clone();
        retyped.payload_type = CHECKPOINT_TYPE.into();
        prop_assert!(!retyped.verify_with(&id.public()));
        let other = Identity::from_seed(seed.map(|b| b.wrapping_add(1)));
        prop_assert!(!env.verify_with(&other.public()));
    }

    /// Arbitrary JSON-ish text never panics the envelope parser or the record decoder.
    #[test]
    fn envelope_and_record_parsing_never_panic(s in "\\PC{0,300}") {
        if let Ok(env) = serde_json::from_str::<Envelope>(&s) {
            let _ = env.body_text();
            let _ = env.payload_hash();
        }
        let _ = serde_json::from_str::<Record>(&s);
        let wrapped = format!("{{\"payload\":\"{}\",\"payloadType\":\"{RECORD_TYPE}\",\"signatures\":[]}}", s.replace(['"', '\\'], ""));
        if let Ok(env) = serde_json::from_str::<Envelope>(&wrapped) {
            let _ = env.body_text();
        }
    }

    /// The store refuses garbage envelopes without panicking or accepting anything.
    #[test]
    fn store_refuses_arbitrary_envelopes(payload in "[A-Za-z0-9+/=]{0,120}", keyid in "[a-f0-9]{0,64}", sig in "[A-Za-z0-9+/=]{0,100}") {
        static STORE: OnceLock<std::sync::Mutex<Store>> = OnceLock::new();
        let store = STORE.get_or_init(|| {
            let mut trust = TrustStore { format: "cursiv-trust-1".into(), ..Default::default() };
            trust.robots.insert("probe-01".into(), vec![tk(&Identity::from_seed([5; 32]))]);
            std::sync::Mutex::new(Store::open(&tmp("garbage").join("store"), "station-g", Identity::from_seed([7; 32]), trust).unwrap())
        });
        let env = Envelope { payload, payload_type: RECORD_TYPE.into(), signatures: vec![cursiv_evidence::crypto::DsseSignature { keyid, sig }] };
        let mut s = store.lock().unwrap();
        for o in s.ingest_batch(std::slice::from_ref(&env)).unwrap() {
            prop_assert!(!matches!(o, Outcome::Accepted { .. }), "accepted garbage: {:?}", o);
        }
        let cp = s.ingest_checkpoint(&env);
        prop_assert!(!matches!(cp, Outcome::Accepted { .. }), "accepted a garbage checkpoint");
        prop_assert_eq!(s.robot_count("probe-01"), 0);
    }

    /// parse_utc never panics, and format → parse round-trips to the millisecond.
    #[test]
    fn utc_parsing_is_total_and_round_trips(s in "\\PC{0,40}", t in -2_000_000_000.0f64..8_000_000_000.0) {
        let _ = parse_utc(&s);
        let ms = (t * 1000.0).floor() / 1000.0;
        let back = parse_utc(&format_utc(ms)).unwrap();
        prop_assert!((back - ms).abs() < 1.5e-3, "{} -> {} -> {}", ms, format_utc(ms), back);
    }

    /// Timestamps that look almost valid are rejected, not misread.
    #[test]
    fn malformed_timestamps_are_rejected(y in 0u32..9999, mo in 13u32..99, d in 0u32..99) {
        let s = format!("{y:04}-{mo:02}-{d:02}T00:00:00Z");
        prop_assert!(parse_utc(&s).is_none());
        let (no_zone, offset) = (format!("{y:04}-01-01T00:00:00"), format!("{y:04}-01-01T00:00:00+01:00"));
        prop_assert!(parse_utc(&no_zone).is_none(), "no zone means no UTC");
        prop_assert!(parse_utc(&offset).is_none(), "offsets are refused, UTC only");
    }

    /// The Merkle root commits to every leaf and their order.
    #[test]
    fn merkle_root_commits_to_content_and_order(n in 1usize..40, i in any::<usize>(), j in any::<usize>()) {
        let hs: Vec<String> = (0..n).map(|k| sha256_hex(format!("leaf{k}").as_bytes())).collect();
        let r = merkle::root(&hs);
        prop_assert_eq!(&r, &merkle::root(&hs.clone()));
        let (i, j) = (i % n, j % n);
        if i != j {
            let mut sw = hs.clone();
            sw.swap(i, j);
            prop_assert_ne!(&r, &merkle::root(&sw));
        }
        let mut ch = hs.clone();
        ch[i] = sha256_hex(b"other");
        prop_assert_ne!(&r, &merkle::root(&ch));
        prop_assert_ne!(&r, &merkle::root(&hs[..n - 1]));
        let mut longer = hs.clone();
        longer.push(sha256_hex(b"extra"));
        prop_assert_ne!(&r, &merkle::root(&longer));
    }

    /// Package-relative paths can never escape the package, and each file has one canonical name.
    #[test]
    fn safe_paths_never_escape(s in "[a-zA-Z0-9./\\\\:_-]{0,40}") {
        if safe_rel(&s) {
            prop_assert!(!s.contains('\\') && !s.contains(':'));
            prop_assert!(s.split('/').all(|c| !c.is_empty() && c != ".." && c != "."), "{s}");
            prop_assert!(!Path::new(&s).is_absolute());
        }
    }

    /// Unit conversions are invertible and agree with their affine form.
    #[test]
    fn unit_conversions_round_trip(x in -1.0e6f64..1.0e6, a in 0usize..64, b in 0usize..64) {
        let ks = units::KNOWN;
        let (from, to) = (ks[a % ks.len()], ks[b % ks.len()]);
        if let Some(y) = units::convert(x, from, to) {
            let back = units::convert(y, to, from).expect("inverse exists when forward does");
            prop_assert!((back - x).abs() <= 1e-9 * x.abs().max(1.0), "{x} {from}->{to}->{from} = {back}");
            let (m, c) = units::affine(from, to).unwrap();
            prop_assert!((m * x + c - y).abs() <= 1e-9 * y.abs().max(1.0));
        }
        prop_assert_eq!(units::convert(x, from, from), Some(x));
    }
}
