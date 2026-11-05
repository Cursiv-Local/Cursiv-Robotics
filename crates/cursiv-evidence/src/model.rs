//! The common observation model and the record that carries it in a robot's log.
//!
//! Rules: unknown stays unknown (`null`/absent, never a guessed default); every
//! record says whether it is synthetic; integrity, authenticity, scientific
//! accuracy and sensor reliability are separate questions answered elsewhere.

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const OBSERVATION_SCHEMA: &str = "cursiv-observation-1";
pub const RECORD_SCHEMA: &str = "cursiv-record-1";
pub const CHECKPOINT_SCHEMA: &str = "cursiv-checkpoint-1";
pub const GENESIS: &str = "genesis";

/// Robot, mission and sensor ids double as directory names, so they are restricted.
pub fn valid_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_' || b == b'.')
        && !s.starts_with('.')
        && !s.contains("..")
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TimeSource {
    Gnss,
    Ntp,
    Ptp,
    RtcSynced,
    RtcUnsynced,
    MonotonicOnly,
    Simulated,
    Unknown,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ClockQuality {
    /// Estimated offset of the sensor clock from UTC, seconds; null = unknown.
    pub offset_estimate_s: Option<f64>,
    /// Stated maximum error of the sensor clock, seconds; null = unknown.
    pub max_error_s: Option<f64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Location {
    pub lat: f64,
    pub lon: f64,
    pub alt_m: Option<f64>,
    /// Coordinate reference system; this version accepts EPSG:4326 (WGS 84) only.
    pub crs: String,
    pub horizontal_accuracy_m: Option<f64>,
    /// How the position was obtained: gnss, rtk, dead_reckoning, survey, simulated, unknown.
    pub source: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Calibration {
    pub calibrated_utc: Option<String>,
    pub valid_until_utc: Option<String>,
    /// What it was calibrated against (standard, certificate, procedure).
    pub reference: Option<String>,
    pub certificate_sha256: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Sensor {
    pub sensor_id: String,
    pub sensor_type: String,
    pub model: Option<String>,
    /// null = calibration status unknown (never assumed calibrated).
    pub calibration: Option<Calibration>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Uncertainty {
    /// "standard" (1 sigma), "expanded" (k * sigma, see coverage_k) or "bound" (+/- maximum).
    pub kind: String,
    pub value: f64,
    pub coverage_k: Option<f64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Measurement {
    /// null when the observation has no numeric value (e.g. an image).
    pub value: Option<f64>,
    /// The value as the instrument reported it (keeps precision such as "12.40").
    pub text: Option<String>,
    pub unit: String,
    /// null = uncertainty unknown.
    pub uncertainty: Option<Uncertainty>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AttachmentRef {
    pub sha256: String,
    pub size: u64,
    pub media_type: String,
    /// raw, preview, calibration, context ...
    pub role: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ProcessingStep {
    pub step: String,
    pub software: String,
    pub version: String,
    pub parameters: Option<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Provenance {
    /// sensor, derived, manual, simulated
    pub source: String,
    pub software: String,
    pub software_version: String,
    /// observation_ids this observation was derived from.
    pub derived_from: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Quality {
    /// good | suspect | bad | unassessed. Means only what `basis` says; never a probability.
    pub flag: String,
    pub basis: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Correction {
    pub corrects_observation_id: String,
    pub reason: String,
}

/// An interpretation: a statement about the evidence, signed by whoever made it, citing the
/// observations it rests on. Recorded like any observation, so it is append-only and verifiable.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Claim {
    pub statement: String,
    /// known | inferred | assumed | unknown (see docs/ROBOTICS_ARCHITECTURE.md).
    pub epistemic: String,
    /// human | ai_model | software
    pub author_kind: String,
    /// Required for ai_model: the exact model identifier.
    pub model: Option<String>,
    /// observation_ids this statement rests on.
    pub supports: Vec<String>,
    /// observation_ids that count against it (must be cited, not hidden).
    pub contradicts: Vec<String>,
    /// Stated assumptions the statement depends on.
    pub assumptions: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub schema: String,
    pub observation_id: String,
    pub robot_id: String,
    pub mission_id: String,
    pub observation_type: String,
    /// True for simulated data. Required: there is no default.
    pub synthetic: bool,
    pub sensor: Sensor,
    /// Sensor clock time, RFC 3339 UTC ("...Z"); null = the sensor gave none.
    pub sensor_time: Option<String>,
    pub time_source: TimeSource,
    pub clock: Option<ClockQuality>,
    pub location: Option<Location>,
    pub measurement: Option<Measurement>,
    pub attachments: Vec<AttachmentRef>,
    pub provenance: Provenance,
    pub processing: Vec<ProcessingStep>,
    pub quality: Option<Quality>,
    pub correction: Option<Correction>,
    /// Present only on interpretations (observation_type "finding", provenance.source "interpretation").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim: Option<Claim>,
}

/// One entry in a robot's append-only log, signed by the robot.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub schema: String,
    pub robot_id: String,
    pub seq: u64,
    /// payload hash of the previous record, or "genesis".
    pub prev: String,
    /// Robot's own clock when the record was written (may be unsynced; see observation.time_source).
    pub written_time: Option<String>,
    pub observation: Observation,
}

/// A robot's signed statement about its own log: completeness and head.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    pub schema: String,
    pub robot_id: String,
    pub count: u64,
    pub head: String,
    pub merkle_root: String,
    pub signed_time: Option<String>,
}

fn finite(v: f64, what: &str, out: &mut Vec<String>) {
    if !v.is_finite() {
        out.push(format!("{what} is not a finite number"));
    }
}

impl Observation {
    /// Structural problems (not scientific ones). Empty = structurally valid.
    pub fn structural_problems(&self) -> Vec<String> {
        let mut p = Vec::new();
        if self.schema != OBSERVATION_SCHEMA {
            p.push(format!("unsupported observation schema {:?}", self.schema));
        }
        for (what, id) in [("observation_id", &self.observation_id), ("robot_id", &self.robot_id),
                           ("mission_id", &self.mission_id), ("sensor_id", &self.sensor.sensor_id)] {
            if !valid_id(id) {
                p.push(format!("{what} must be 1-64 of [a-z0-9._-]"));
            }
        }
        if self.observation_type.is_empty() || self.observation_type.len() > 64 {
            p.push("observation_type must be 1-64 characters".into());
        }
        if let Some(t) = &self.sensor_time {
            if parse_utc(t).is_none() {
                p.push("sensor_time must be RFC 3339 UTC (YYYY-MM-DDTHH:MM:SS[.fff]Z)".into());
            }
        }
        if let Some(loc) = &self.location {
            if loc.crs != "EPSG:4326" {
                p.push(format!("unsupported coordinate reference system {:?} (EPSG:4326 only)", loc.crs));
            }
            finite(loc.lat, "lat", &mut p);
            finite(loc.lon, "lon", &mut p);
            if !(-90.0..=90.0).contains(&loc.lat) || !(-180.0..=180.0).contains(&loc.lon) {
                p.push("location outside WGS 84 bounds".into());
            }
            if let Some(a) = loc.horizontal_accuracy_m {
                if !(a.is_finite() && a >= 0.0) {
                    p.push("horizontal_accuracy_m must be >= 0".into());
                }
            }
        }
        if let Some(m) = &self.measurement {
            if let Some(v) = m.value {
                finite(v, "measurement value", &mut p);
            }
            if let Some(u) = &m.uncertainty {
                if !matches!(u.kind.as_str(), "standard" | "expanded" | "bound") {
                    p.push("uncertainty.kind must be standard, expanded or bound".into());
                }
                if !(u.value.is_finite() && u.value >= 0.0) {
                    p.push("uncertainty.value must be >= 0".into());
                }
            }
        }
        for a in &self.attachments {
            if !crate::crypto::is_sha256_hex(&a.sha256) {
                p.push("attachment sha256 must be 64 lowercase hex characters".into());
            }
        }
        match self.provenance.source.as_str() {
            "simulated" if !self.synthetic => p.push("simulated observations must be marked synthetic".into()),
            "sensor" | "manual" if self.synthetic => p.push("sensor and manual observations cannot be marked synthetic".into()),
            "simulated" | "sensor" | "manual" | "derived" | "interpretation" => {}
            _ => p.push("provenance.source must be sensor, manual, simulated, derived or interpretation".into()),
        }
        // derived results and interpretations inherit "synthetic" from their inputs (checked by `reasoning`).
        match (&self.claim, self.provenance.source.as_str()) {
            (Some(c), "interpretation") => {
                if self.observation_type != "finding" || self.measurement.is_some() {
                    p.push("an interpretation is observation_type \"finding\" with no measurement".into());
                }
                if !matches!(c.epistemic.as_str(), "known" | "inferred" | "assumed" | "unknown") {
                    p.push("claim.epistemic must be known, inferred, assumed or unknown".into());
                }
                if !matches!(c.author_kind.as_str(), "human" | "ai_model" | "software") {
                    p.push("claim.author_kind must be human, ai_model or software".into());
                }
                if c.author_kind == "ai_model" && c.model.as_deref().is_none_or(|m| m.trim().is_empty()) {
                    p.push("an AI-authored claim must name the exact model".into());
                }
                if c.statement.trim().is_empty() || c.statement.len() > 4000 {
                    p.push("claim.statement must be 1-4000 characters".into());
                }
            }
            (None, "interpretation") => p.push("provenance.source \"interpretation\" requires a claim".into()),
            (Some(_), _) => p.push("a claim requires provenance.source \"interpretation\"".into()),
            (None, _) => {}
        }
        if let Some(q) = &self.quality {
            if !matches!(q.flag.as_str(), "good" | "suspect" | "bad" | "unassessed") {
                p.push("quality.flag must be good, suspect, bad or unassessed".into());
            }
        }
        if let Some(c) = &self.correction {
            if c.reason.trim().is_empty() {
                p.push("a correction needs a reason".into());
            }
            if c.corrects_observation_id == self.observation_id {
                p.push("an observation cannot correct itself".into());
            }
        }
        p
    }
}

/// Parse "YYYY-MM-DDTHH:MM:SS[.fraction]Z" to Unix seconds. UTC only, by design.
pub fn parse_utc(s: &str) -> Option<f64> {
    let b = s.as_bytes();
    if b.len() < 20 || *b.last()? != b'Z' || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[13] != b':' || b[16] != b':' {
        return None;
    }
    let num = |r: std::ops::Range<usize>| -> Option<i64> { s.get(r)?.parse().ok() };
    let (y, mo, d, h, mi, se) = (num(0..4)?, num(5..7)?, num(8..10)?, num(11..13)?, num(14..16)?, num(17..19)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || se > 60 {
        return None;
    }
    let mut frac = 0.0;
    let rest = &s[19..s.len() - 1];
    if !rest.is_empty() {
        let digits = rest.strip_prefix('.')?;
        if digits.is_empty() || digits.len() > 9 || !digits.bytes().all(|c| c.is_ascii_digit()) {
            return None;
        }
        frac = format!("0.{digits}").parse().ok()?;
    }
    // days from civil (Howard Hinnant)
    let y2 = if mo <= 2 { y - 1 } else { y };
    let era = y2.div_euclid(400);
    let yoe = y2 - era * 400;
    let mp = (mo + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    Some((days * 86400 + h * 3600 + mi * 60 + se) as f64 + frac)
}

pub fn format_utc(unix: f64) -> String {
    let secs = unix.floor() as i64;
    let millis = ((unix - secs as f64) * 1000.0).round().min(999.0) as i64;
    let days = secs.div_euclid(86400);
    let sod = secs.rem_euclid(86400);
    // civil from days
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{millis:03}Z", sod / 3600, (sod / 60) % 60, sod % 60)
}

pub fn now_utc() -> String {
    let d = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    format_utc(d.as_secs_f64())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utc_round_trip() {
        let t = parse_utc("2026-11-05T03:45:18.250Z").unwrap();
        assert_eq!(format_utc(t), "2026-11-05T03:45:18.250Z");
        assert_eq!(parse_utc("1970-01-01T00:00:00Z"), Some(0.0));
        assert!(parse_utc("2026-11-05T03:45:18+01:00").is_none());
        assert!(parse_utc("2026-13-05T03:45:18Z").is_none());
    }

    #[test]
    fn ids_are_path_safe() {
        assert!(valid_id("rover-01"));
        for bad in ["", "../x", "a/b", "Rover", ".hidden", "a..b", "a\\b"] {
            assert!(!valid_id(bad), "{bad}");
        }
    }
}
