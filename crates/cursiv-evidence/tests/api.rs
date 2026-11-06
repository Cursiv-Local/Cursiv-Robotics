//! The stable API (v1) and the experimental converters, end to end.

use cursiv_evidence::api::{self, experimental, Error, Format, Mode, Status};
use cursiv_evidence::crypto::public_b64;
use cursiv_evidence::merkle;
use cursiv_evidence::model::*;
use cursiv_evidence::trust::{TrustStore, TrustedKey};
use std::path::{Path, PathBuf};

fn tmp(name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("cursiv-api-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn sample() -> (PathBuf, TrustStore) {
    let d = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/sample-package");
    (d.join("sample-buoy-1-package"), TrustStore::load(&d.join("trust.json")).unwrap())
}

#[test]
fn the_api_covers_ingest_checkpoint_export_and_verify() {
    let dir = tmp("flow");
    let robot = api::Identity::from_seed([3; 32]);
    let station = api::Identity::from_seed([4; 32]);
    let key = |id: &api::Identity| TrustedKey { key_id: id.key_id(), public_key: public_b64(&id.public()), status: "active".into(), note: None, valid_from_seq: None, valid_until_seq: None };
    let mut trust = TrustStore { format: "cursiv-trust-1".into(), ..Default::default() };
    trust.robots.insert("probe-01".into(), vec![key(&robot)]);
    trust.stations.insert("station-x".into(), vec![key(&api::Identity::from_seed([4; 32]))]);
    let mut store = api::open_store(&dir.join("store"), "station-x", station, trust.clone()).unwrap();
    let mut hashes: Vec<String> = vec![];
    let mut envs = vec![];
    for n in 1..=5u64 {
        let obs = Observation {
            schema: OBSERVATION_SCHEMA.into(), observation_id: format!("probe-01-{n}"), robot_id: "probe-01".into(), mission_id: "api".into(),
            observation_type: "water_temperature".into(), synthetic: true,
            sensor: Sensor { sensor_id: "probe-01-t".into(), sensor_type: "thermistor".into(), model: None, calibration: None },
            sensor_time: Some(format_utc(1_793_000_000.0 + n as f64)), time_source: TimeSource::Simulated, clock: None,
            location: Some(Location { lat: 45.0, lon: -124.0, alt_m: Some(-2.0), crs: "EPSG:4326".into(), horizontal_accuracy_m: Some(5.0), source: "simulated".into() }),
            measurement: Some(Measurement { value: Some(11.0 + n as f64 / 10.0), text: None, unit: "degC".into(),
                                            uncertainty: Some(Uncertainty { kind: "standard".into(), value: 0.1, coverage_k: None }) }),
            attachments: vec![], provenance: Provenance { source: "simulated".into(), software: "api-test".into(), software_version: "1".into(), derived_from: vec![] },
            processing: vec![], quality: None, correction: None, claim: None,
        };
        let rec = Record { schema: RECORD_SCHEMA.into(), robot_id: "probe-01".into(), seq: n, prev: hashes.last().cloned().unwrap_or_else(|| GENESIS.into()), written_time: None, observation: obs };
        let env = robot.sign_json(api::RECORD_TYPE, &rec);
        hashes.push(env.payload_hash());
        envs.push(env);
    }
    assert!(api::ingest(&mut store, &envs).unwrap().iter().all(|o| matches!(o, api::Outcome::Accepted { .. })));
    let cp = robot.sign_json(api::CHECKPOINT_TYPE, &Checkpoint { schema: CHECKPOINT_SCHEMA.into(), robot_id: "probe-01".into(), count: 5,
        head: hashes[4].clone(), merkle_root: merkle::root(&hashes), signed_time: None });
    api::checkpoint(&mut store, &cp).unwrap();
    // a checkpoint signed by an unenrolled key is a typed rejection, not a panic or a string
    let stranger = api::Identity::from_seed([9; 32]).sign_json(api::CHECKPOINT_TYPE, &Checkpoint { schema: CHECKPOINT_SCHEMA.into(), robot_id: "probe-01".into(), count: 5,
        head: hashes[4].clone(), merkle_root: merkle::root(&hashes), signed_time: None });
    assert!(matches!(api::checkpoint(&mut store, &stranger), Err(Error::Rejected { ref code, .. }) if code == "untrusted_key"));
    for (fmt, name) in [(Format::Segmented, "p2"), (Format::SingleFile, "p1")] {
        api::export(&mut store, &dir.join(name), fmt).unwrap();
        let v = api::verify(&dir.join(name), Some(&trust), Mode::Streaming);
        assert_eq!(v.status, Status::Verified, "{}", v.report.text());
        assert_eq!(v.report.package_version, if name == "p2" { 2 } else { 1 });
    }
    assert!(matches!(api::export(&mut store, &dir.join("p2"), Format::Segmented), Err(Error::Io(_))), "an existing destination is refused");
    assert_eq!(api::verify(&dir.join("p2"), None, Mode::Streaming).status, Status::Incomplete);
    let collected = api::verify(&dir.join("p2"), Some(&trust), Mode::Collect { max_records: 100 });
    let sta = experimental::to_sensorthings(&collected, "p2").unwrap();
    let obs = &sta["Things"][0]["Datastreams"][0]["Observations"];
    assert_eq!(obs.as_array().unwrap().len(), 5);
    assert_eq!(obs[0]["result"], 11.1);
    assert_eq!(obs[0]["FeatureOfInterest"]["feature"]["coordinates"], serde_json::json!([-124.0, 45.0, -2.0]));
    let unverified = api::verify(&dir.join("p2"), None, Mode::Collect { max_records: 100 });
    assert!(matches!(experimental::to_prov_json(&unverified, "p2"), Err(Error::NotVerified(Status::Incomplete))));
}

#[test]
fn prov_keeps_every_record_derivation_and_hash() {
    let (pkg, trust) = sample();
    let v = api::verify(&pkg, Some(&trust), Mode::Collect { max_records: 1_000_000 });
    assert_eq!(v.status, Status::Verified);
    let p = experimental::to_prov_json(&v, "sample").unwrap();
    let doc = &p["document"];
    let n = v.report.records.len();
    let obs_entities = doc["entity"].as_object().unwrap().keys().filter(|k| k.starts_with("cursiv:obs/")).count();
    assert_eq!(obs_entities, n, "one entity per record");
    let derived: usize = v.report.records.iter().map(|(r, _)| r.observation.provenance.derived_from.len()).sum();
    assert!(derived > 0);
    let derivations_from_inputs = doc["wasDerivedFrom"].as_object().unwrap().values().filter(|d| d.get("prov:activity").is_some()).count();
    assert_eq!(derivations_from_inputs, derived, "every derived_from link becomes a derivation");
    for (r, h) in &v.report.records {
        let e = &doc["entity"][format!("cursiv:obs/{}/{}", r.robot_id, r.observation.observation_id)];
        assert_eq!(e["cursiv:record_sha256"], serde_json::json!(h));
        assert_eq!(e["cursiv:synthetic"], serde_json::json!(r.observation.synthetic));
    }
    assert!(!p["losses"].as_array().unwrap().is_empty());
}

#[test]
fn sensorthings_entities_have_the_required_properties() {
    let (pkg, trust) = sample();
    let v = api::verify(&pkg, Some(&trust), Mode::Collect { max_records: 1_000_000 });
    let s = experimental::to_sensorthings(&v, "sample").unwrap();
    let has = |v: &serde_json::Value, keys: &[&str]| keys.iter().all(|k| v.get(*k).is_some());
    let mut total = 0;
    for t in s["Things"].as_array().unwrap() {
        assert!(has(t, &["name", "description"]));
        for l in t["Locations"].as_array().into_iter().flatten() {
            assert!(has(l, &["name", "description", "encodingType", "location"]));
        }
        for d in t["Datastreams"].as_array().unwrap() {
            assert!(has(d, &["name", "description", "unitOfMeasurement", "observationType", "Sensor", "ObservedProperty"]));
            assert!(has(&d["unitOfMeasurement"], &["name", "symbol", "definition"]));
            assert!(has(&d["Sensor"], &["name", "description", "encodingType", "metadata"]));
            assert!(has(&d["ObservedProperty"], &["name", "definition", "description"]));
            for o in d["Observations"].as_array().unwrap() {
                assert!(has(o, &["phenomenonTime", "resultTime", "result"]));
                assert!(o["parameters"]["record_sha256"].as_str().unwrap().len() == 64);
                total += 1;
            }
        }
    }
    let numeric = v.report.records.iter().filter(|(r, _)| r.observation.claim.is_none() && r.observation.measurement.as_ref().is_some_and(|m| m.value.is_some())).count();
    assert_eq!(total, numeric);
    assert_eq!(total as u64 + s["skipped"].as_u64().unwrap(), v.report.records.len() as u64, "every record is exported or counted as skipped");
}
