//! Rust quick start (stable API v1): sign, ingest, checkpoint, export, verify, convert.
//!
//!     cargo run --release -p cursiv-evidence --example quickstart
//!
//! Everything happens in a temporary folder with simulation keys; nothing leaves this computer.

use cursiv_evidence::api::{self, experimental, Format, Mode, Status};
use cursiv_evidence::crypto::public_b64;
use cursiv_evidence::merkle;
use cursiv_evidence::model::*;
use cursiv_evidence::trust::{TrustStore, TrustedKey};

fn main() -> Result<(), api::Error> {
    let dir = std::env::temp_dir().join(format!("cursiv-quickstart-{}", std::process::id()));
    let robot = api::Identity::generate();
    let station = api::Identity::generate();
    // The operator's trust store: which keys belong to which robot and station (never taken from packages).
    let entry = |id: &api::Identity| TrustedKey { key_id: id.key_id(), public_key: public_b64(&id.public()), status: "active".into(),
                                                  note: None, valid_from_seq: None, valid_until_seq: None };
    let mut trust = TrustStore { format: "cursiv-trust-1".into(), ..Default::default() };
    trust.robots.insert("buoy-01".into(), vec![entry(&robot)]);
    trust.stations.insert("station-a".into(), vec![entry(&station)]);
    let station_public = entry(&station);
    let mut store = api::open_store(&dir.join("store"), "station-a", station, trust.clone())?;

    // A robot signs observations into its own hash chain.
    let (mut hashes, mut batch) = (Vec::<String>::new(), Vec::new());
    for n in 1..=10u64 {
        let observation = Observation {
            schema: OBSERVATION_SCHEMA.into(), observation_id: format!("buoy-01-{n:04}"), robot_id: "buoy-01".into(), mission_id: "quickstart".into(),
            observation_type: "water_temperature".into(), synthetic: true,
            sensor: Sensor { sensor_id: "buoy-01-ctd".into(), sensor_type: "ctd".into(), model: None, calibration: None },
            sensor_time: Some(now_utc()), time_source: TimeSource::Simulated, clock: None, location: None,
            measurement: Some(Measurement { value: Some(12.0 + n as f64 * 0.01), text: None, unit: "degC".into(),
                                            uncertainty: Some(Uncertainty { kind: "standard".into(), value: 0.05, coverage_k: None }) }),
            attachments: vec![], provenance: Provenance { source: "simulated".into(), software: "quickstart".into(), software_version: "1".into(), derived_from: vec![] },
            processing: vec![], quality: None, correction: None, claim: None,
        };
        let record = Record { schema: RECORD_SCHEMA.into(), robot_id: "buoy-01".into(), seq: n,
                              prev: hashes.last().cloned().unwrap_or_else(|| GENESIS.into()), written_time: Some(now_utc()), observation };
        let env = robot.sign_json(api::RECORD_TYPE, &record);
        hashes.push(env.payload_hash());
        batch.push(env);
    }
    let outcomes = api::ingest(&mut store, &batch)?;
    println!("ingested: {} accepted", outcomes.iter().filter(|o| matches!(o, api::Outcome::Accepted { .. })).count());
    api::checkpoint(&mut store, &robot.sign_json(api::CHECKPOINT_TYPE, &Checkpoint {
        schema: CHECKPOINT_SCHEMA.into(), robot_id: "buoy-01".into(), count: 10, head: hashes[9].clone(),
        merkle_root: merkle::root(&hashes), signed_time: Some(now_utc()) }))?;

    let pkg = dir.join("package");
    api::export(&mut store, &pkg, Format::Segmented)?;
    let v = api::verify(&pkg, Some(&trust), Mode::Collect { max_records: 1_000 });
    println!("verification: {:?} ({} records)", v.status, v.report.robots["buoy-01"].records);
    assert_eq!(v.status, Status::Verified);
    let prov = experimental::to_prov_json(&v, "package")?;
    println!("PROV entities: {}", prov["document"]["entity"].as_object().map_or(0, |o| o.len()));
    println!("station key {} signed the package at {}", station_public.key_id, pkg.display());
    Ok(())
}
