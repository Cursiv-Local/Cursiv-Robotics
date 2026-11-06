//! Converters from a verified package to other data models. EXPERIMENTAL; mappings, not conformance.
//!
//! - [`to_prov_json`]: W3C PROV, serialised as PROV-JSON (W3C Member Submission 2013)
//! - [`to_sensorthings`]: the OGC SensorThings API (v1.1) data model as JSON entities, nested the
//!   way a deep insert would send them. Not a server and not posted to one.
//!
//! Both take the records the verifier collected (`Report::records`, which needs
//! `VerifyOptions { collect_records: true, .. }`). They refuse a report that is not verified or not
//! complete, unless `allow_unverified` is set, in which case the output says so. Provenance is
//! carried: record SHA-256 and seq, signer key id, processing steps, derivations, corrections and
//! interpretations. What a target model cannot represent is listed in the output under `losses` and
//! in docs/INTEROPERABILITY.md. Neither converter claims compliance: no conformance test suite was
//! run.

use crate::crypto::sha256_hex;
use crate::verify::Report;
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;

pub const PROV_LOSSES: &[&str] = &[
    "Signatures, hash chains, Merkle checkpoints and segment seals are not PROV concepts: record hashes and signer key ids are kept as attributes, but PROV consumers cannot check them. Verify the package itself.",
    "Measurement uncertainty, units and quality flags are plain attributes (cursiv:*), not a standard PROV vocabulary.",
    "Interpretations (findings) are entities with their supporting and contradicting evidence as qualified derivations; their epistemic label has no PROV equivalent.",
    "Attachment bytes are not embedded; attachments are entities named by their SHA-256.",
];

pub const STA_LOSSES: &[&str] = &[
    "Signatures, hash chains, checkpoints and seals have no SensorThings equivalent; record hashes are kept in Observation.parameters but cannot be checked by a SensorThings server.",
    "Observations without a numeric value (images, opaque ROS 2 messages, capture accounting) and interpretations are not exported; their count is listed under skipped.",
    "Uncertainty is kept in Observation.resultQuality (DQ-style JSON, not a standard SensorThings field).",
    "ObservedProperty.definition uses urn:cursiv:observation-type:<type>; no external vocabulary mapping is implied.",
    "Corrections: both the original and the correcting Observation are exported; the link is in parameters.corrects.",
    "Robot positions are exported per Observation (FeatureOfInterest), not as Thing HistoricalLocations.",
];

fn check(report: &Report, allow_unverified: bool) -> Result<(), String> {
    if !report.records_complete {
        return Err("the report does not hold every record (verify with collect_records and a high enough limit)".into());
    }
    if report.status != "verified" && !allow_unverified {
        return Err(format!("the package did not verify (status {}); refusing to convert unverified evidence", report.status));
    }
    Ok(())
}

fn obs_ref(robot: &str, id: &str) -> String {
    format!("cursiv:obs/{robot}/{id}")
}

/// "robot/id" or "id" (same robot) to a qualified name.
fn cited(default_robot: &str, c: &str) -> String {
    match c.split_once('/') {
        Some((r, id)) => obs_ref(r, id),
        None => obs_ref(default_robot, c),
    }
}

fn verification(report: &Report) -> Value {
    json!({"status": report.status, "verdicts": report.verdicts, "package_version": report.package_version, "verified_time": report.verified_time})
}

/// W3C PROV-JSON document for the package's records.
pub fn to_prov_json(report: &Report, package_name: &str, allow_unverified: bool) -> Result<Value, String> {
    check(report, allow_unverified)?;
    let mut entity = Map::new();
    let mut agent = Map::new();
    let mut activity = Map::new();
    let mut rel: BTreeMap<&str, Map<String, Value>> = BTreeMap::new();
    let mut n = 0u64;
    let mut add = |rel: &mut BTreeMap<&str, Map<String, Value>>, kind: &'static str, v: Value| {
        n += 1;
        rel.entry(kind).or_default().insert(format!("_:{kind}{n}"), v);
    };
    let pkg = format!("cursiv:package/{package_name}");
    entity.insert(pkg.clone(), json!({"prov:type": {"$": "prov:Collection", "type": "prov:QUALIFIED_NAME"}, "prov:label": package_name,
                                      "cursiv:verification": verification(report).to_string()}));
    for (rec, hash) in &report.records {
        let o = &rec.observation;
        let id = obs_ref(&rec.robot_id, &o.observation_id);
        let robot = format!("cursiv:robot/{}", rec.robot_id);
        let sensor = format!("cursiv:sensor/{}/{}", rec.robot_id, o.sensor.sensor_id);
        agent.entry(robot.clone()).or_insert(json!({"prov:type": {"$": "prov:SoftwareAgent", "type": "prov:QUALIFIED_NAME"}, "prov:label": rec.robot_id}));
        if !agent.contains_key(&sensor) {
            agent.insert(sensor.clone(), json!({"prov:label": o.sensor.sensor_id, "cursiv:sensor_type": o.sensor.sensor_type,
                                                "cursiv:calibration": serde_json::to_string(&o.sensor.calibration).unwrap()}));
            add(&mut rel, "actedOnBehalfOf", json!({"prov:delegate": sensor, "prov:responsible": robot}));
        }
        let mut e = Map::new();
        e.insert("prov:type".into(), json!({"$": if o.claim.is_some() { "cursiv:Interpretation" } else { "cursiv:Observation" }, "type": "prov:QUALIFIED_NAME"}));
        e.insert("cursiv:observation_type".into(), json!(o.observation_type));
        e.insert("cursiv:record_sha256".into(), json!(hash));
        e.insert("cursiv:record_seq".into(), json!(rec.seq));
        e.insert("cursiv:synthetic".into(), json!(o.synthetic));
        e.insert("cursiv:provenance_source".into(), json!(o.provenance.source));
        e.insert("cursiv:time_source".into(), json!(serde_json::to_value(&o.time_source).unwrap()));
        if let Some(m) = &o.measurement {
            if let Some(v) = m.value {
                e.insert("prov:value".into(), json!(v));
            }
            e.insert("cursiv:unit".into(), json!(m.unit));
            if let Some(u) = &m.uncertainty {
                e.insert("cursiv:uncertainty".into(), json!(format!("{} {}{}", u.kind, u.value, u.coverage_k.map(|k| format!(" (k={k})")).unwrap_or_default())));
            }
        }
        if let Some(q) = &o.quality {
            e.insert("cursiv:quality".into(), json!(q.flag));
        }
        if let Some(c) = &o.claim {
            e.insert("prov:label".into(), json!(c.statement));
            e.insert("cursiv:epistemic".into(), json!(c.epistemic));
            if !c.assumptions.is_empty() {
                e.insert("cursiv:assumptions".into(), json!(c.assumptions.join("; ")));
            }
        }
        if let Some(l) = &o.location {
            e.insert("prov:location".into(), json!(format!("POINT({} {})", l.lon, l.lat)));
        }
        entity.insert(id.clone(), Value::Object(e));
        add(&mut rel, "hadMember", json!({"prov:collection": pkg, "prov:entity": id}));
        // the activity that produced the record: sensing, computing or interpreting
        let act = format!("cursiv:activity/{}/{}", rec.robot_id, rec.seq);
        let mut a = Map::new();
        a.insert("prov:type".into(), json!({"$": format!("cursiv:{}", o.provenance.source), "type": "prov:QUALIFIED_NAME"}));
        if !o.processing.is_empty() {
            a.insert("cursiv:processing".into(), json!(serde_json::to_string(&o.processing).unwrap()));
        }
        activity.insert(act.clone(), Value::Object(a));
        let mut g = json!({"prov:entity": id, "prov:activity": act});
        if let Some(t) = &o.sensor_time {
            g["prov:time"] = json!(t);
        }
        add(&mut rel, "wasGeneratedBy", g);
        let author = match &o.claim {
            Some(c) => {
                let who = format!("cursiv:author/{}{}", c.author_kind, c.model.as_ref().map(|m| format!("/{}", &sha256_hex(m.as_bytes())[..12])).unwrap_or_default());
                agent.entry(who.clone()).or_insert(json!({"prov:label": c.model.clone().unwrap_or_else(|| c.author_kind.clone()), "cursiv:author_kind": c.author_kind}));
                who
            }
            None => sensor.clone(),
        };
        add(&mut rel, "wasAssociatedWith", json!({"prov:activity": act, "prov:agent": author}));
        add(&mut rel, "wasAttributedTo", json!({"prov:entity": id, "prov:agent": robot}));
        for d in &o.provenance.derived_from {
            add(&mut rel, "wasDerivedFrom", json!({"prov:generatedEntity": id, "prov:usedEntity": cited(&rec.robot_id, d), "prov:activity": act}));
            add(&mut rel, "used", json!({"prov:activity": act, "prov:entity": cited(&rec.robot_id, d)}));
        }
        if let Some(c) = &o.claim {
            for s in &c.supports {
                add(&mut rel, "wasDerivedFrom", json!({"prov:generatedEntity": id, "prov:usedEntity": cited(&rec.robot_id, s), "cursiv:role": "supports"}));
            }
            for s in &c.contradicts {
                add(&mut rel, "wasDerivedFrom", json!({"prov:generatedEntity": id, "prov:usedEntity": cited(&rec.robot_id, s), "cursiv:role": "contradicts"}));
            }
        }
        if let Some(c) = &o.correction {
            add(&mut rel, "wasDerivedFrom", json!({"prov:generatedEntity": id, "prov:usedEntity": obs_ref(&rec.robot_id, &c.corrects_observation_id),
                                                   "prov:type": {"$": "prov:Revision", "type": "prov:QUALIFIED_NAME"}, "cursiv:reason": c.reason}));
        }
        for at in &o.attachments {
            let b = format!("cursiv:blob/{}", at.sha256);
            entity.entry(b.clone()).or_insert(json!({"cursiv:media_type": at.media_type, "cursiv:size": at.size}));
            add(&mut rel, "wasDerivedFrom", json!({"prov:generatedEntity": id, "prov:usedEntity": b, "cursiv:role": at.role}));
        }
    }
    let mut doc = json!({
        "prefix": {"cursiv": "urn:cursiv:", "prov": "http://www.w3.org/ns/prov#", "xsd": "http://www.w3.org/2001/XMLSchema#"},
        "entity": entity, "agent": agent, "activity": activity,
    });
    for (k, v) in rel {
        doc[k] = Value::Object(v);
    }
    Ok(json!({"format": "PROV-JSON", "document": doc, "verification": verification(report), "losses": PROV_LOSSES}))
}

/// UCUM codes for the units this project uses (others: symbol only, definition null).
fn ucum(unit: &str) -> Option<&'static str> {
    Some(match unit {
        "degC" => "Cel", "K" => "K", "degF" => "[degF]", "%" => "%", "1" => "1", "hPa" => "hPa", "Pa" => "Pa", "kPa" => "kPa",
        "m" => "m", "cm" => "cm", "km" => "km", "m/s" => "m/s", "km/h" => "km/h", "mS/cm" => "mS/cm", "uS/cm" => "uS/cm",
        "mg/L" => "mg/L", "lx" => "lx", "uT" => "uT", "m/s2" => "m/s2", "deg" => "deg", "rad/s" => "rad/s", "Hz" => "Hz",
        "s" => "s", "V" => "V", "A" => "A", "W/m2" => "W/m2", "dbar" => "dbar",
        _ => return None,
    })
}

fn geo(loc: &crate::model::Location) -> Value {
    let mut c = vec![json!(loc.lon), json!(loc.lat)];
    if let Some(a) = loc.alt_m {
        c.push(json!(a));
    }
    json!({"type": "Point", "coordinates": c})
}

/// OGC SensorThings API v1.1 data model: Things (robots) with Datastreams (robot, sensor, type,
/// unit), each with its Sensor, ObservedProperty and Observations (with FeaturesOfInterest).
pub fn to_sensorthings(report: &Report, package_name: &str, allow_unverified: bool) -> Result<Value, String> {
    check(report, allow_unverified)?;
    // robot -> (Thing, datastreams keyed by (sensor, observation type, unit), last Location)
    type Streams = BTreeMap<(String, String, String), Vec<Value>>;
    let mut things: BTreeMap<String, (Value, Streams, Option<Value>)> = BTreeMap::new();
    let mut sensors: BTreeMap<(String, String), Value> = BTreeMap::new();
    let mut skipped = 0u64;
    for (rec, hash) in &report.records {
        let o = &rec.observation;
        let entry = things.entry(rec.robot_id.clone()).or_insert_with(|| (json!({
            "name": rec.robot_id, "description": format!("robot {} (Cursiv Robotics evidence package {package_name})", rec.robot_id),
            "properties": {"robot_id": rec.robot_id}}), BTreeMap::new(), None));
        if let Some(l) = &o.location {
            entry.2 = Some(json!({"name": format!("{} last position", rec.robot_id), "description": format!("from {} ({})", o.observation_id, l.source),
                                  "encodingType": "application/geo+json", "location": geo(l)}));
        }
        let Some(m) = &o.measurement else { skipped += 1; continue };
        let Some(v) = m.value else { skipped += 1; continue };
        if o.claim.is_some() {
            skipped += 1;
            continue;
        }
        sensors.entry((rec.robot_id.clone(), o.sensor.sensor_id.clone())).or_insert(json!({
            "name": o.sensor.sensor_id, "description": format!("{} on {}", o.sensor.sensor_type, rec.robot_id),
            "encodingType": "application/json",
            "metadata": serde_json::to_string(&json!({"sensor_type": o.sensor.sensor_type, "model": o.sensor.model, "calibration": o.sensor.calibration})).unwrap()}));
        let mut ob = json!({
            "phenomenonTime": o.sensor_time, "resultTime": rec.written_time, "result": v,
            "parameters": {"observation_id": o.observation_id, "record_seq": rec.seq, "record_sha256": hash, "synthetic": o.synthetic,
                           "time_source": o.time_source, "provenance_source": o.provenance.source,
                           "corrects": o.correction.as_ref().map(|c| c.corrects_observation_id.clone()),
                           "quality": o.quality.as_ref().map(|q| q.flag.clone())},
        });
        if let Some(u) = &m.uncertainty {
            ob["resultQuality"] = json!({"uncertainty": {"kind": u.kind, "value": u.value, "coverage_k": u.coverage_k, "unit": m.unit}});
        }
        if let Some(l) = &o.location {
            ob["FeatureOfInterest"] = json!({"name": format!("{} at {}", rec.robot_id, o.observation_id), "description": "position of the robot when it observed",
                                             "encodingType": "application/geo+json", "feature": geo(l)});
        }
        entry.1.entry((o.sensor.sensor_id.clone(), o.observation_type.clone(), m.unit.clone())).or_default().push(ob);
    }
    let things: Vec<Value> = things.into_iter().map(|(rid, (mut thing, streams, loc))| {
        let ds: Vec<Value> = streams.into_iter().map(|((sid, otype, unit), obs)| json!({
            "name": format!("{rid} {sid} {otype}"),
            "description": format!("{otype} from sensor {sid} of {rid}"),
            "observationType": "http://www.opengis.net/def/observationType/OGC-OM/2.0/OM_Measurement",
            "unitOfMeasurement": {"name": unit, "symbol": unit, "definition": ucum(&unit).map(|c| format!("http://unitsofmeasure.org/ucum.html#{c}"))},
            "Sensor": sensors[&(rid.clone(), sid.clone())],
            "ObservedProperty": {"name": otype, "definition": format!("urn:cursiv:observation-type:{otype}"), "description": format!("{otype} as recorded by Cursiv Robotics")},
            "Observations": obs,
        })).collect();
        thing["Datastreams"] = json!(ds);
        if let Some(l) = loc {
            thing["Locations"] = json!([l]);
        }
        thing
    }).collect();
    Ok(json!({"format": "OGC SensorThings API 1.1 data model (JSON, deep-insert shape)", "Things": things, "skipped": skipped,
              "verification": verification(report), "losses": STA_LOSSES}))
}
