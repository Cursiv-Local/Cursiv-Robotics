//! Throughput, latency and memory of the evidence core on *this* computer.
//!
//!     cargo run --release -p cursiv-evidence --example bench -- [records_per_robot] [robots] [out.json]
//!
//! It measures software on a desktop or cloud machine. It says nothing about a robot's CPU,
//! storage or radio: hardware numbers have to be measured on the hardware.

use cursiv_evidence::crypto::{public_b64, Identity, CHECKPOINT_TYPE, RECORD_TYPE};
use cursiv_evidence::merkle;
use cursiv_evidence::model::*;
use cursiv_evidence::science::{self, Profile};
use cursiv_evidence::store::{Outcome, Store};
use cursiv_evidence::trust::{TrustStore, TrustedKey};
use cursiv_evidence::verify;
use std::time::Instant;

fn peak_rss_kib() -> Option<u64> {
    // Linux only; elsewhere the field is reported as not measured rather than guessed.
    let s = std::fs::read_to_string("/proc/self/status").ok()?;
    s.lines().find(|l| l.starts_with("VmHWM:"))?.split_whitespace().nth(1)?.parse().ok()
}

fn tree_bytes(p: &std::path::Path) -> u64 {
    let mut n = 0;
    if let Ok(rd) = std::fs::read_dir(p) {
        for e in rd.flatten() {
            let m = e.metadata().unwrap();
            n += if m.is_dir() { tree_bytes(&e.path()) } else { m.len() };
        }
    }
    n
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let per: u64 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(10_000);
    let robots: u64 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(3);
    let out = args.get(3).cloned();
    // CURSIV_BENCH_DIR: where to build the store and package (needs about 2x the package size free)
    let base = std::env::var_os("CURSIV_BENCH_DIR").map(std::path::PathBuf::from).unwrap_or_else(std::env::temp_dir);
    let dir = base.join(format!("cursiv-bench-{}", std::process::id()));
    let science_max: u64 = std::env::var("CURSIV_BENCH_SCIENCE_MAX").ok().and_then(|v| v.parse().ok()).unwrap_or(200_000);
    let store_seg: u64 = std::env::var("CURSIV_BENCH_SEGMENT").ok().and_then(|v| v.parse().ok()).unwrap_or(cursiv_evidence::segment::DEFAULT_SEGMENT_RECORDS);
    let _ = std::fs::remove_dir_all(&dir);

    let keys: Vec<Identity> = (0..robots).map(|i| Identity::from_seed([i as u8 + 1; 32])).collect();
    let station = [200u8; 32];
    let mut trust = TrustStore { format: "cursiv-trust-1".into(), ..Default::default() };
    let tk = |id: &Identity| TrustedKey { key_id: id.key_id(), public_key: public_b64(&id.public()), status: "active".into(), note: None, valid_from_seq: None, valid_until_seq: None };
    for (i, k) in keys.iter().enumerate() {
        trust.robots.insert(format!("bench-{i:02}"), vec![tk(k)]);
    }
    trust.stations.insert("bench-station".into(), vec![tk(&Identity::from_seed(station))]);
    let trust_copy = trust.clone();
    let mut store = Store::open(&dir.join("store"), "bench-station", Identity::from_seed(station), trust.clone()).unwrap();
    store.set_segment_limits(cursiv_evidence::store::SegmentLimits { records: store_seg, bytes: cursiv_evidence::segment::DEFAULT_SEGMENT_BYTES });

    // 1-2. robots sign records and the station ingests them in batches of 100 (the agent's
    // default), with a robot checkpoint every 10,000 records. Generated in batches, so the
    // benchmark itself never holds the dataset in memory.
    let total = per * robots;
    let (mut sign_s, mut ingest_s) = (0.0f64, 0.0f64);
    let mut batch_lat = vec![];
    for (i, key) in keys.iter().enumerate() {
        let rid = format!("bench-{i:02}");
        let mut head = GENESIS.to_string();
        let mut frontier = merkle::Frontier::new();
        let mut n = 0u64;
        while n < per {
            let t = Instant::now();
            let mut envs = Vec::with_capacity(100);
            for _ in 0..100.min(per - n) {
                n += 1;
                let obs = Observation {
                    schema: OBSERVATION_SCHEMA.into(), observation_id: format!("{rid}-obs-{n:08}"), robot_id: rid.clone(), mission_id: "bench".into(),
                    observation_type: "air_temperature".into(), synthetic: true,
                    sensor: Sensor { sensor_id: format!("{rid}-t1"), sensor_type: "thermistor".into(), model: None,
                        calibration: Some(Calibration { calibrated_utc: Some("2026-10-01T00:00:00Z".into()), valid_until_utc: Some("2027-10-01T00:00:00Z".into()), reference: None, certificate_sha256: None }) },
                    sensor_time: Some(format_utc(1_793_000_000.0 + n as f64)), time_source: TimeSource::Simulated, clock: None,
                    location: Some(Location { lat: 45.0, lon: -122.0, alt_m: None, crs: "EPSG:4326".into(), horizontal_accuracy_m: Some(3.0), source: "simulated".into() }),
                    measurement: Some(Measurement { value: Some(15.0 + 0.5 * (n as f64 / 600.0).sin()), text: None, unit: "degC".into(),
                                                    uncertainty: Some(Uncertainty { kind: "standard".into(), value: 0.2, coverage_k: None }) }),
                    attachments: vec![], provenance: Provenance { source: "simulated".into(), software: "bench".into(), software_version: "1".into(), derived_from: vec![] },
                    processing: vec![], quality: None, correction: None, claim: None,
                };
                let rec = Record { schema: RECORD_SCHEMA.into(), robot_id: rid.clone(), seq: n, prev: head.clone(), written_time: None, observation: obs };
                let env = key.sign_json(RECORD_TYPE, &rec);
                head = env.payload_hash();
                frontier.push(&head);
                envs.push(env);
            }
            sign_s += t.elapsed().as_secs_f64();
            let b = Instant::now();
            for o in store.ingest_batch(&envs).unwrap() {
                assert!(matches!(o, Outcome::Accepted { .. }), "{o:?}");
            }
            if n % 10_000 == 0 || n == per {
                let cp = key.sign_json(CHECKPOINT_TYPE, &Checkpoint { schema: CHECKPOINT_SCHEMA.into(), robot_id: rid.clone(), count: n,
                    head: head.clone(), merkle_root: frontier.root(), signed_time: None });
                assert!(matches!(store.ingest_checkpoint(&cp), Outcome::Accepted { .. }));
            }
            let dt = b.elapsed().as_secs_f64();
            ingest_s += dt;
            batch_lat.push(dt * 1000.0);
        }
    }
    batch_lat.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let pct = |p: f64| batch_lat[((batch_lat.len() - 1) as f64 * p).round() as usize];

    // 3. export, 4. verify, 5. science checks, 6. reopen (crash recovery reads every log)
    let pkg = dir.join("pkg");
    let t = Instant::now();
    store.export(&pkg).unwrap();
    let export_s = t.elapsed().as_secs_f64();
    let t = Instant::now();
    let lean = verify::verify_package_with(&pkg, Some(&trust), &verify::VerifyOptions::streaming());
    let verify_s = t.elapsed().as_secs_f64();
    assert!(lean.all_pass(), "{}", lean.text());
    drop(lean);
    // science needs the records in memory; skipped above a size where that is impractical
    let (science_s, sci_counts) = if total <= science_max {
        let report = verify::verify_package(&pkg, Some(&trust));
        let t = Instant::now();
        let sci = science::validate(&report.records, &report.receipts, &Profile::survey_default());
        (Some(t.elapsed().as_secs_f64()), Some(sci.counts))
    } else {
        (None, None)
    };
    drop(store);
    let t = Instant::now();
    let reopened = Store::open(&dir.join("store"), "bench-station", Identity::from_seed(station), trust).unwrap();
    let reopen_s = t.elapsed().as_secs_f64();
    assert_eq!(reopened.robot_count("bench-00"), per);

    let result = serde_json::json!({
        "schema": "cursiv-bench-rust-1",
        "measured_on": format!("{} {} (software benchmark on this computer, not robot hardware)", std::env::consts::OS, std::env::consts::ARCH),
        "records": total, "robots": robots,
        "package_bytes": tree_bytes(&pkg),
        "sign_records_per_s": (total as f64 / sign_s).round(),
        "ingest_records_per_s": (total as f64 / ingest_s).round(),
        "ingest_batch100_ms": {"p50": pct(0.5), "p95": pct(0.95), "p99": pct(0.99), "max": pct(1.0)},
        "export_s": export_s, "verify_s": verify_s, "verify_records_per_s": (total as f64 / verify_s).round(),
        "science_s": science_s, "science_flags": sci_counts, "package_version": 2, "segment_records": store_seg, "reopen_s": reopen_s,
        "peak_rss_mib": peak_rss_kib().map(|k| (k as f64 / 1024.0 * 10.0).round() / 10.0),
    });
    let text = serde_json::to_string_pretty(&result).unwrap();
    println!("{text}");
    if let Some(o) = out {
        std::fs::write(o, text + "\n").unwrap();
    }
    if std::env::var_os("CURSIV_BENCH_KEEP").is_some() {
        std::fs::write(dir.join("trust.json"), serde_json::to_string_pretty(&trust_copy).unwrap()).unwrap();
        eprintln!("package kept at {}", pkg.display());
    } else {
        let _ = std::fs::remove_dir_all(&dir);
    }
}
