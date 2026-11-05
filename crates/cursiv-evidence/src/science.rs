//! Scientific validation, separate from integrity and authenticity.
//!
//! Deterministic checks only: units, configured ranges, calibration, time
//! consistency, location, supporting evidence and cross-sensor agreement.
//! Each flag says what kind of knowledge it is:
//!   known     follows directly from the recorded values and the configured profile
//!   inferred  a conclusion drawn from several records (e.g. a drifting clock)
//!   assumed   rests on an assumption stated in the message (e.g. the station clock is right)
//!   unknown   the information needed to check was not recorded
//! A contradiction says two measurements disagree; it never says which one is right.

use crate::model::{parse_utc, Record};
use crate::store::Receipt;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TypeProfile {
    pub unit: String,
    pub min: Option<f64>,
    pub max: Option<f64>,
    #[serde(default)]
    pub requires_attachment: bool,
    /// Two observations of this type closer than these are expected to agree within uncertainty.
    pub compare_radius_m: Option<f64>,
    pub compare_window_s: Option<f64>,
    /// Expected sampling interval; a gap longer than 2.5x this between consecutive readings of
    /// one sensor is flagged as missing observations (scientific completeness, not cryptographic).
    #[serde(default)]
    pub expected_interval_s: Option<f64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Region {
    pub min_lat: f64,
    pub max_lat: f64,
    pub min_lon: f64,
    pub max_lon: f64,
}

fn yes() -> bool {
    true
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub name: String,
    pub types: BTreeMap<String, TypeProfile>,
    pub region: Option<Region>,
    /// Offset between sensor time and receipt time beyond which the clock is suspect.
    pub max_clock_offset_s: f64,
    /// Compare sensor clocks with station receipt times. Turn off for data imported after
    /// the fact (e.g. phone recordings), where receipt time says nothing about the sensor clock.
    #[serde(default = "yes")]
    pub check_clock_against_receipts: bool,
    /// Agreement threshold, in combined standard uncertainties.
    pub contradiction_sigma: f64,
}

impl Profile {
    /// The profile used by the simulation lab's survey missions.
    pub fn survey_default() -> Self {
        let t = |unit: &str, min: f64, max: f64, r: Option<f64>, w: Option<f64>| TypeProfile {
            unit: unit.into(), min: Some(min), max: Some(max), requires_attachment: false, compare_radius_m: r, compare_window_s: w,
            expected_interval_s: None,
        };
        let mut types = BTreeMap::new();
        types.insert("soil_moisture".into(), t("%", 0.0, 100.0, Some(25.0), Some(3600.0)));
        types.insert("soil_ph".into(), t("pH", 0.0, 14.0, Some(25.0), Some(86400.0)));
        types.insert("soil_temperature".into(), t("degC", -50.0, 80.0, Some(25.0), Some(1800.0)));
        types.insert("air_temperature".into(), t("degC", -90.0, 60.0, Some(200.0), Some(600.0)));
        types.insert("relative_humidity".into(), t("%", 0.0, 100.0, Some(200.0), Some(600.0)));
        types.insert("air_pressure".into(), t("hPa", 300.0, 1100.0, Some(500.0), Some(600.0)));
        types.insert("image".into(), TypeProfile { unit: "".into(), min: None, max: None, requires_attachment: true, compare_radius_m: None, compare_window_s: None, expected_interval_s: None });
        Profile { name: "survey-default-1".into(), types,
                  region: Some(Region { min_lat: 44.9, max_lat: 45.3, min_lon: -122.6, max_lon: -122.0 }),
                  max_clock_offset_s: 120.0, contradiction_sigma: 3.0, check_clock_against_receipts: true }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Flag {
    pub code: String,
    pub epistemic: String,
    pub message: String,
    pub robot_id: String,
    pub observation_ids: Vec<String>,
    /// Groups related flags (for contradictions: the observation type and the two sensors).
    pub group: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct ScienceReport {
    pub schema: String,
    pub profile: String,
    pub observations: usize,
    pub current_observations: usize,
    pub corrected: usize,
    pub flags: Vec<Flag>,
    pub counts: BTreeMap<String, usize>,
    pub statement: String,
}

fn haversine_m(a: (f64, f64), b: (f64, f64)) -> f64 {
    let r = 6_371_000.0;
    let (la1, lo1, la2, lo2) = (a.0.to_radians(), a.1.to_radians(), b.0.to_radians(), b.1.to_radians());
    let h = ((la2 - la1) / 2.0).sin().powi(2) + la1.cos() * la2.cos() * ((lo2 - lo1) / 2.0).sin().powi(2);
    2.0 * r * h.sqrt().asin()
}

/// Standard (1 sigma) uncertainty of a measurement, from its stated kind.
pub fn standard_u(m: &crate::model::Measurement) -> Option<f64> {
    let u = m.uncertainty.as_ref()?;
    Some(match u.kind.as_str() {
        "standard" => u.value,
        "expanded" => u.value / u.coverage_k.filter(|k| *k > 0.0).unwrap_or(2.0),
        // a +/- bound treated as a uniform distribution: sigma = a / sqrt(3)
        _ => u.value / 3f64.sqrt(),
    })
}

pub const MAX_PAIR_CHECKS: usize = 2_000_000;
pub const MAX_FLAGS_PER_GROUP: usize = 50;

pub fn validate(records: &[(Record, String)], receipts: &[Receipt], profile: &Profile) -> ScienceReport {
    let mut flags = Vec::new();
    let mut flag = |code: &str, epi: &str, msg: String, robot: &str, ids: Vec<String>| {
        flags.push(Flag { code: code.into(), epistemic: epi.into(), message: msg, robot_id: robot.into(), observation_ids: ids, group: String::new() });
    };
    let received: HashMap<(String, u64), f64> = receipts.iter()
        .filter_map(|r| Some(((r.robot_id.clone(), r.robot_seq), parse_utc(&r.received_time)?))).collect();
    let corrected: std::collections::HashSet<String> = records.iter()
        .filter_map(|(r, _)| r.observation.correction.as_ref().map(|c| format!("{}/{}", r.robot_id, c.corrects_observation_id))).collect();
    let current: Vec<&Record> = records.iter().map(|(r, _)| r)
        .filter(|r| !corrected.contains(&format!("{}/{}", r.robot_id, r.observation.observation_id)))
        // measured data only: derived results and findings are judged by `reasoning`, through their inputs
        .filter(|r| !matches!(r.observation.provenance.source.as_str(), "derived" | "interpretation")).collect();

    // per-record checks
    let mut last_time: HashMap<(String, String), (f64, String)> = HashMap::new();
    let mut seen_content: HashMap<(String, String, u64, String), String> = HashMap::new();
    let mut offsets: HashMap<String, Vec<(f64, f64, String)>> = HashMap::new();
    for r in &current {
        let o = &r.observation;
        let id = vec![o.observation_id.clone()];
        let prof = profile.types.get(&o.observation_type);
        if prof.is_none() {
            flag("type_unprofiled", "unknown", format!("no profile for observation type {:?}: range and unit not checked", o.observation_type), &r.robot_id, id.clone());
        }
        if let (Some(p), Some(m)) = (prof, &o.measurement) {
            // Range-check in the profile's unit; a convertible unit is converted (the record is not changed).
            let in_profile_unit = match m.value {
                Some(v) if p.unit.is_empty() || m.unit == p.unit => Some(v),
                Some(v) => match crate::units::convert(v, &m.unit, &p.unit) {
                    Some(c) => {
                        flag("unit_converted", "known", format!("{} recorded in {} was converted to {} for checking ({v} -> {c:.6})", o.observation_type, m.unit, p.unit, ), &r.robot_id, id.clone());
                        Some(c)
                    }
                    None => {
                        flag("unit_mismatch", "known", format!("{} recorded in {:?}; profile expects {:?} and there is no conversion", o.observation_type, m.unit, p.unit), &r.robot_id, id.clone());
                        None
                    }
                },
                None => None,
            };
            if let Some(v) = in_profile_unit {
                // tolerance for floating-point rounding in unit conversion (140 degF is exactly 60 degC)
                let eps = 1e-9 * v.abs().max(1.0);
                if p.min.is_some_and(|lo| v < lo - eps) || p.max.is_some_and(|hi| v > hi + eps) {
                    flag("out_of_range", "known", format!("{} = {v} {} is outside the profile range {:?}..{:?}", o.observation_type, p.unit, p.min, p.max), &r.robot_id, id.clone());
                }
            }
            if m.value.is_some() && m.uncertainty.is_none() {
                flag("uncertainty_unknown", "unknown", "no measurement uncertainty recorded; agreement with other sensors cannot be assessed".into(), &r.robot_id, id.clone());
            }
        }
        if let Some(p) = prof {
            if p.requires_attachment && o.attachments.is_empty() {
                flag("missing_supporting_evidence", "known", format!("{} observation has no attached raw evidence", o.observation_type), &r.robot_id, id.clone());
            }
        }
        if let Some(m) = &o.measurement {
            if !m.unit.is_empty() && !crate::units::known(&m.unit) {
                flag("unit_unrecognized", "unknown", format!("unit {:?} is not in the unit registry: conversions and unit checks are not possible", m.unit), &r.robot_id, id.clone());
            }
            // the same reading resubmitted under a new observation id (replay, double upload, buggy firmware)
            if let (Some(v), Some(st)) = (m.value, &o.sensor_time) {
                let key = (o.sensor.sensor_id.clone(), st.clone(), v.to_bits(), m.unit.clone());
                if let Some(first) = seen_content.get(&key) {
                    flag("duplicate_content", "known", format!("same sensor, time, value and unit as {first}, under a different observation id"), &r.robot_id,
                         vec![first.clone(), o.observation_id.clone()]);
                } else {
                    seen_content.insert(key, o.observation_id.clone());
                }
            }
        }
        let t = o.sensor_time.as_deref().and_then(parse_utc);
        if let (Some(st), Some(wt)) = (t, r.written_time.as_deref().and_then(parse_utc)) {
            if st > wt + 2.0 {
                flag("sensor_time_after_write", "known", format!("the reading's sensor time is {} after the robot wrote the record (inconsistent clocks)", human(st - wt)), &r.robot_id, id.clone());
            }
        }
        match &o.sensor.calibration {
            None => flag("calibration_unknown", "unknown", format!("calibration status of sensor {} was not recorded", o.sensor.sensor_id), &r.robot_id, id.clone()),
            Some(c) => {
                if let (Some(until), Some(t)) = (c.valid_until_utc.as_deref().and_then(parse_utc), t) {
                    if t > until {
                        flag("calibration_expired", "known", format!("sensor {} calibration expired {} before this measurement", o.sensor.sensor_id, human((t - until).abs())), &r.robot_id, id.clone());
                    }
                }
            }
        }
        match t {
            None => flag("sensor_time_unknown", "unknown", "the sensor gave no timestamp; only the receipt time is known".into(), &r.robot_id, id.clone()),
            Some(t) => {
                let key = (r.robot_id.clone(), o.sensor.sensor_id.clone());
                if let Some((prev, prev_id)) = last_time.get(&key) {
                    if let Some(exp) = prof.and_then(|p| p.expected_interval_s).filter(|e| *e > 0.0) {
                        if t - prev > 2.5 * exp {
                            let missing = ((t - prev) / exp).round() as i64 - 1;
                            flag("sampling_gap", "known", format!("{} between {prev_id} and this reading; at the expected {exp} s interval about {missing} reading(s) are missing",
                                                                   human(t - prev)), &r.robot_id, vec![prev_id.clone(), o.observation_id.clone()]);
                        }
                    }
                    if t < *prev {
                        flag("out_of_order_time", "known", format!("sensor time goes backwards by {} relative to {prev_id} (written earlier by the same sensor)", human(prev - t)), &r.robot_id, vec![prev_id.clone(), o.observation_id.clone()]);
                    }
                }
                last_time.insert(key, (t, o.observation_id.clone()));
                if let Some(rcv) = received.get(&(r.robot_id.clone(), r.seq)) {
                    offsets.entry(r.robot_id.clone()).or_default().push((t, rcv - t, o.observation_id.clone()));
                    if profile.check_clock_against_receipts && t - rcv > 5.0 {
                        flag("sensor_time_in_future", "assumed", format!("sensor time is {} after the station received it (assuming the station clock is correct)", human(t - rcv)), &r.robot_id, id.clone());
                    }
                }
            }
        }
        if let (Some(loc), Some(reg)) = (&o.location, &profile.region) {
            if loc.lat < reg.min_lat || loc.lat > reg.max_lat || loc.lon < reg.min_lon || loc.lon > reg.max_lon {
                flag("outside_mission_region", "known", format!("location {:.5},{:.5} is outside the mission region", loc.lat, loc.lon), &r.robot_id, id.clone());
            }
        } else if o.location.is_none() {
            flag("location_unknown", "unknown", "no location recorded".into(), &r.robot_id, id.clone());
        }
    }

    // clock drift: offset (receipt - sensor time) that grows steadily, beyond the configured limit.
    // Live delivery delay is only a few seconds; stored-and-forwarded records (offline) are excluded by
    // using the minimum offset per window, which tracks the clock rather than the link.
    if !profile.check_clock_against_receipts {
        offsets.clear();
    }
    for (robot, mut v) in offsets {
        v.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap());
        if v.len() < 6 {
            continue;
        }
        let k = v.len() / 3;
        let min_off = |s: &[(f64, f64, String)]| s.iter().map(|x| x.1).fold(f64::INFINITY, f64::min);
        let (first, last) = (min_off(&v[..k]), min_off(&v[v.len() - k..]));
        if (last - first).abs() > profile.max_clock_offset_s || last.abs() > profile.max_clock_offset_s && first.abs() <= profile.max_clock_offset_s {
            flag("clock_drift", "inferred", format!(
                "{robot}'s sensor clock appears to drift: its minimum lag behind the station went from {} to {} over the mission (assuming the station clock is correct)",
                signed(first), signed(last)), &robot, vec![v[0].2.clone(), v[v.len() - 1].2.clone()]);
        }
    }

    // cross-sensor agreement
    let mut by_type: BTreeMap<&str, Vec<&Record>> = BTreeMap::new();
    for r in &current {
        by_type.entry(r.observation.observation_type.as_str()).or_default().push(r);
    }
    let mut unassessable = 0usize;
    let mut contradictions: Vec<Flag> = Vec::new();
    // Bounded work and output: a dense or hostile package cannot exhaust time or memory.
    let mut checks = 0usize;
    let mut truncated = false;
    let mut per_group: HashMap<String, usize> = HashMap::new();
    let mut contradiction_total = 0usize;
    for (ty, mut rs) in by_type {
        let Some(p) = profile.types.get(ty) else { continue };
        let (Some(radius), Some(window)) = (p.compare_radius_m, p.compare_window_s) else { continue };
        rs.retain(|r| r.observation.sensor_time.as_deref().and_then(parse_utc).is_some()
            && r.observation.location.is_some() && r.observation.measurement.as_ref().and_then(|m| m.value).is_some());
        rs.sort_by(|a, b| parse_utc(a.observation.sensor_time.as_deref().unwrap()).partial_cmp(&parse_utc(b.observation.sensor_time.as_deref().unwrap())).unwrap());
        for i in 0..rs.len() {
            let a = &rs[i].observation;
            let ta = parse_utc(a.sensor_time.as_deref().unwrap()).unwrap();
            if truncated {
                break;
            }
            for b_rec in rs.iter().skip(i + 1) {
                checks += 1;
                if checks > MAX_PAIR_CHECKS {
                    truncated = true;
                    break;
                }
                let b = &b_rec.observation;
                let tb = parse_utc(b.sensor_time.as_deref().unwrap()).unwrap();
                if tb - ta > window {
                    break;
                }
                if a.sensor.sensor_id == b.sensor.sensor_id && a.robot_id == b.robot_id {
                    continue;
                }
                let (la, lb) = (a.location.as_ref().unwrap(), b.location.as_ref().unwrap());
                let d = haversine_m((la.lat, la.lon), (lb.lat, lb.lon));
                if d > radius {
                    continue;
                }
                let (ma, mb) = (a.measurement.as_ref().unwrap(), b.measurement.as_ref().unwrap());
                if ma.unit != mb.unit {
                    continue;
                }
                let diff = (ma.value.unwrap() - mb.value.unwrap()).abs();
                match (standard_u(ma), standard_u(mb)) {
                    (Some(ua), Some(ub)) => {
                        let combined = (ua * ua + ub * ub).sqrt();
                        if diff > profile.contradiction_sigma * combined {
                            let mut pair = [a.sensor.sensor_id.clone(), b.sensor.sensor_id.clone()];
                            pair.sort();
                            let group = format!("{ty}: {} vs {}", pair[0], pair[1]);
                            contradiction_total += 1;
                            let seen = per_group.entry(group.clone()).or_default();
                            *seen += 1;
                            if *seen > MAX_FLAGS_PER_GROUP {
                                continue;
                            }
                            contradictions.push(Flag { code: "contradiction".into(), epistemic: "known".into(),
                                message: format!(
                                "{ty}: {} ({}) and {} ({}) differ by {diff:.3} {}, more than {} combined standard uncertainties ({:.3}), {d:.0} m and {:.0} s apart. Which (if either) is correct is not determined.",
                                a.observation_id, a.robot_id, b.observation_id, b.robot_id, ma.unit, profile.contradiction_sigma, combined, (tb - ta)),
                                robot_id: a.robot_id.clone(), observation_ids: vec![a.observation_id.clone(), b.observation_id.clone()],
                                group });
                        }
                    }
                    _ => unassessable += 1,
                }
            }
        }
    }
    flags.extend(contradictions);
    if truncated {
        flags.push(Flag { code: "agreement_check_truncated".into(), epistemic: "unknown".into(),
            message: format!("cross-sensor agreement stopped after {MAX_PAIR_CHECKS} comparisons; later pairs were not checked"),
            robot_id: String::new(), observation_ids: vec![], group: String::new() });
    }
    if unassessable > 0 {
        flags.push(Flag { code: "agreement_unassessable".into(), epistemic: "unknown".into(),
            message: format!("{unassessable} nearby pair(s) could not be compared because an uncertainty was not recorded"),
            robot_id: String::new(), observation_ids: vec![], group: String::new() });
    }
    let mut counts = BTreeMap::new();
    for f in &flags {
        *counts.entry(f.code.clone()).or_insert(0) += 1;
    }
    if contradiction_total > 0 {
        // every disagreeing pair is counted; only the first few per sensor pair are listed
        counts.insert("contradiction".into(), contradiction_total);
    }
    ScienceReport {
        schema: "cursiv-science-report-1".into(),
        profile: profile.name.clone(),
        observations: records.len(),
        current_observations: current.len(),
        corrected: corrected.len(),
        flags,
        counts,
        statement: "Deterministic plausibility checks against the stated profile. They can show a value is out of range, inconsistent or unsupported; \
they cannot show a value is correct. No AI model was used.".into(),
    }
}

fn human(s: f64) -> String {
    if s >= 3600.0 { format!("{:.1} h", s / 3600.0) } else if s >= 60.0 { format!("{:.1} min", s / 60.0) } else { format!("{s:.1} s") }
}

fn signed(s: f64) -> String {
    format!("{}{}", if s < 0.0 { "-" } else { "+" }, human(s.abs()))
}
