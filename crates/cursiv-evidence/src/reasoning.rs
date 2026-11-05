//! Reproducible derivations and evidence-linked findings.
//!
//! This is what distinguishes a *scientific* evidence layer from a black-box recorder:
//! the verifier does not only check that records were not changed, it re-derives every
//! derived result from its cited inputs and checks every interpretation against the
//! observations it claims to rest on.
//!
//! Derivations: an observation with `provenance.source = "derived"` and a processing step
//! `{"step": "cursiv.derive", "parameters": {"op": ..., "params": {...}}}` over its ordered
//! `provenance.derived_from` inputs. Ops are deterministic (inputs summed in the cited order,
//! IEEE 754 f64): mean, median, min, max, sum, count, stddev (sample, n-1), linear (a*x+b,
//! one input), convert (unit conversion, one input). A derived observation without that step
//! is reported as *not reproducible*, never as verified.
//!
//! Findings: observations of type "finding" carrying a `claim`. Rules (each a flag):
//!   - every cited observation exists in the package;
//!   - a citation of a value that was later corrected is flagged (cite the correction);
//!   - "known" or "inferred" needs at least one supporting observation;
//!   - an AI model can never be the authority for a "known" statement;
//!   - a statement resting on flagged observations (out of range, contradiction...) is flagged;
//!   - anything derived from or about synthetic data must itself be marked synthetic.

use crate::model::{Observation, Record};
use crate::science::ScienceReport;
use serde::Serialize;
use std::collections::{BTreeMap, HashMap, HashSet};

pub const DERIVE_STEP: &str = "cursiv.derive";
const REL_TOL: f64 = 1e-9;

#[derive(Clone, Debug, Serialize)]
pub struct ReasoningFlag {
    pub code: String,
    /// error | warning | info
    pub severity: String,
    pub observation_id: String,
    pub robot_id: String,
    pub message: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct FindingSummary {
    pub observation_id: String,
    pub author: String,
    pub author_kind: String,
    pub model: Option<String>,
    pub epistemic: String,
    pub statement: String,
    pub supports: usize,
    pub contradicts: usize,
    pub assumptions: Vec<String>,
    /// well_supported | supported_with_caveats | unsupported | invalid
    pub status: String,
    pub synthetic: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct ReasoningReport {
    pub schema: String,
    pub derivations: BTreeMap<String, usize>,
    pub findings: Vec<FindingSummary>,
    pub flags: Vec<ReasoningFlag>,
    pub statement: String,
}

struct Ctx<'a> {
    by_id: HashMap<&'a str, Vec<&'a Record>>,
    corrected: HashSet<(&'a str, &'a str)>,
    flags: Vec<ReasoningFlag>,
}

impl<'a> Ctx<'a> {
    fn flag(&mut self, code: &str, severity: &str, r: &Record, msg: String) {
        self.flags.push(ReasoningFlag { code: code.into(), severity: severity.into(), observation_id: r.observation.observation_id.clone(),
                                        robot_id: r.robot_id.clone(), message: msg });
    }

    /// Resolve a cited id: "robot/observation_id" or a plain observation_id (must be unique).
    fn resolve(&self, id: &str) -> Result<&'a Record, String> {
        let (robot, oid) = id.split_once('/').map_or((None, id), |(r, o)| (Some(r), o));
        let hits: Vec<&&Record> = self.by_id.get(oid).map(|v| v.iter().filter(|r| robot.is_none_or(|x| x == r.robot_id)).collect()).unwrap_or_default();
        match hits.len() {
            0 => Err(format!("{id} is not in the package")),
            1 => Ok(hits[0]),
            _ => Err(format!("{id} is ambiguous (several robots used that id); cite it as robot/observation_id")),
        }
    }

    fn superseded(&self, r: &Record) -> bool {
        self.corrected.contains(&(r.robot_id.as_str(), r.observation.observation_id.as_str()))
    }
}

fn value(o: &Observation) -> Option<(f64, &str)> {
    let m = o.measurement.as_ref()?;
    Some((m.value?, m.unit.as_str()))
}

fn convert(x: f64, from: &str, to: &str) -> Option<f64> {
    crate::units::convert(x, from, to)
}

#[derive(Debug, PartialEq)]
pub enum Propagation {
    /// Propagated standard uncertainty.
    Value(f64),
    /// At least one input's uncertainty is unknown.
    InputUnknown,
    /// This operation has no propagation rule here (min, max, median, stddev, count).
    NoRule,
}

/// GUM first-order propagation for uncorrelated inputs.
pub fn propagate(op: &str, params: &serde_json::Value, units: &[&str], u: &[Option<f64>]) -> Propagation {
    if !matches!(op, "mean" | "sum" | "linear" | "convert") {
        return Propagation::NoRule;
    }
    if u.iter().any(|x| x.is_none()) || u.is_empty() {
        return Propagation::InputUnknown;
    }
    let us: Vec<f64> = u.iter().map(|x| x.unwrap()).collect();
    let rss = us.iter().fold(0.0, |a, x| a + x * x).sqrt();
    let v = match op {
        "mean" => Some(rss / us.len() as f64),
        "sum" => Some(rss),
        "linear" => params["a"].as_f64().map(|a| a.abs() * us[0]),
        _ => params["to"].as_str().and_then(|to| crate::units::affine(units[0], to)).map(|(a, _)| a.abs() * us[0]),
    };
    v.map_or(Propagation::NoRule, Propagation::Value)
}

/// Recompute a derivation. Ok((value, unit)) or Err(why it cannot be recomputed).
pub fn recompute(op: &str, params: &serde_json::Value, inputs: &[(f64, &str)]) -> Result<(f64, String), String> {
    if inputs.is_empty() {
        return Err("no inputs".into());
    }
    let unit = inputs[0].1;
    let same_unit = inputs.iter().all(|(_, u)| *u == unit);
    let xs: Vec<f64> = inputs.iter().map(|(v, _)| *v).collect();
    let n = xs.len() as f64;
    let need_same = || if same_unit { Ok(()) } else { Err("inputs have different units".to_string()) };
    let sum = || xs.iter().fold(0.0, |a, b| a + b);
    Ok(match op {
        "mean" => { need_same()?; (sum() / n, unit.into()) }
        "sum" => { need_same()?; (sum(), unit.into()) }
        "count" => (n, "1".into()),
        "min" => { need_same()?; (xs.iter().cloned().fold(f64::INFINITY, f64::min), unit.into()) }
        "max" => { need_same()?; (xs.iter().cloned().fold(f64::NEG_INFINITY, f64::max), unit.into()) }
        "median" => {
            need_same()?;
            let mut s = xs.clone();
            s.sort_by(|a, b| a.partial_cmp(b).unwrap());
            let k = s.len() / 2;
            (if s.len() % 2 == 1 { s[k] } else { (s[k - 1] + s[k]) / 2.0 }, unit.into())
        }
        "stddev" => {
            need_same()?;
            if xs.len() < 2 {
                return Err("stddev needs at least two inputs".into());
            }
            let m = sum() / n;
            let ss = xs.iter().fold(0.0, |a, x| a + (x - m) * (x - m));
            ((ss / (n - 1.0)).sqrt(), unit.into())
        }
        "linear" => {
            if xs.len() != 1 {
                return Err("linear takes exactly one input".into());
            }
            let a = params["a"].as_f64().ok_or("linear needs params.a")?;
            let b = params["b"].as_f64().ok_or("linear needs params.b")?;
            let u = params["unit"].as_str().unwrap_or(unit);
            (a * xs[0] + b, u.into())
        }
        "convert" => {
            if xs.len() != 1 {
                return Err("convert takes exactly one input".into());
            }
            let to = params["to"].as_str().ok_or("convert needs params.to")?;
            (convert(xs[0], unit, to).ok_or_else(|| format!("no conversion from {unit} to {to}"))?, to.into())
        }
        other => return Err(format!("unknown operation {other:?}")),
    })
}

pub fn analyse(records: &[(Record, String)], science: Option<&ScienceReport>) -> ReasoningReport {
    let mut by_id: HashMap<&str, Vec<&Record>> = HashMap::new();
    let mut corrected = HashSet::new();
    for (r, _) in records {
        by_id.entry(r.observation.observation_id.as_str()).or_default().push(r);
        if let Some(c) = &r.observation.correction {
            corrected.insert((r.robot_id.as_str(), c.corrects_observation_id.as_str()));
        }
    }
    let flagged: HashMap<&str, Vec<&str>> = science.map(|s| {
        let mut m: HashMap<&str, Vec<&str>> = HashMap::new();
        for f in &s.flags {
            if matches!(f.code.as_str(), "out_of_range" | "contradiction" | "calibration_expired" | "unit_mismatch" | "out_of_order_time" | "clock_drift") {
                for id in &f.observation_ids {
                    m.entry(id.as_str()).or_default().push(f.code.as_str());
                }
            }
        }
        m
    }).unwrap_or_default();
    // Flags follow derivations: a value derived from flagged inputs carries their flags, so a
    // finding citing a mean of contradictory readings is caveated like one citing the readings.
    let mut flagged: HashMap<&str, Vec<&str>> = flagged;
    let derived: Vec<&Record> = records.iter().map(|(r, _)| r).filter(|r| r.observation.provenance.source == "derived").collect();
    for _ in 0..derived.len().min(64) {
        let mut changed = false;
        for r in &derived {
            let mut inherited: Vec<&str> = Vec::new();
            for id in &r.observation.provenance.derived_from {
                let oid = id.split_once('/').map_or(id.as_str(), |(_, o)| o);
                if let Some(c) = flagged.get(oid) {
                    inherited.extend(c.iter().copied());
                }
            }
            if !inherited.is_empty() {
                let e = flagged.entry(r.observation.observation_id.as_str()).or_default();
                let before = e.len();
                for c in inherited {
                    if !e.contains(&c) {
                        e.push(c);
                    }
                }
                changed |= e.len() != before;
            }
        }
        if !changed {
            break;
        }
    }
    let mut cx = Ctx { by_id, corrected, flags: Vec::new() };
    let mut counts: BTreeMap<String, usize> = ["verified", "mismatch", "not_reproducible", "inputs_missing", "uncertainty_verified"].iter().map(|k| (k.to_string(), 0)).collect();
    let mut findings = Vec::new();

    for (r, _) in records {
        let o = &r.observation;
        if cx.superseded(r) {
            continue; // judged through its correction
        }
        // --- derivations
        if o.provenance.source == "derived" {
            let Some(step) = o.processing.iter().find(|p| p.step == DERIVE_STEP) else {
                *counts.get_mut("not_reproducible").unwrap() += 1;
                cx.flag("derivation_not_reproducible", "warning", r, "derived, but no cursiv.derive step states how: the value cannot be recomputed".into());
                continue;
            };
            let params = step.parameters.clone().unwrap_or_default();
            let op = params["op"].as_str().unwrap_or("").to_string();
            let mut inputs = Vec::new();
            let mut in_u: Vec<Option<f64>> = Vec::new();
            let mut missing = Vec::new();
            let mut synthetic_input = false;
            for id in &o.provenance.derived_from {
                match cx.resolve(id) {
                    Ok(inp) => {
                        synthetic_input |= inp.observation.synthetic;
                        if inp.robot_id == r.robot_id && inp.seq >= r.seq {
                            cx.flag("derivation_causality", "error", r, format!("input {id} was recorded after the result derived from it"));
                        }
                        if cx.superseded(inp) {
                            cx.flag("derivation_input_superseded", "warning", r, format!("input {id} was later corrected; the derivation uses the original value"));
                        }
                        match value(&inp.observation) {
                            Some(v) => {
                                inputs.push(v);
                                in_u.push(inp.observation.measurement.as_ref().and_then(crate::science::standard_u));
                            }
                            None => missing.push(format!("{id} has no numeric value")),
                        }
                    }
                    Err(e) => missing.push(e),
                }
            }
            if synthetic_input && !o.synthetic {
                cx.flag("synthetic_propagation", "error", r, "derived from synthetic data but not marked synthetic".into());
            }
            if !missing.is_empty() {
                *counts.get_mut("inputs_missing").unwrap() += 1;
                cx.flag("derivation_inputs_missing", "error", r, missing.join("; "));
                continue;
            }
            let recorded = value(o);
            match (recompute(&op, &params["params"], &inputs), recorded) {
                (Ok((v, unit)), Some((rv, ru))) => {
                    let close = (v - rv).abs() <= REL_TOL * v.abs().max(1.0);
                    if close && unit == ru {
                        *counts.get_mut("verified").unwrap() += 1;
                        let units: Vec<&str> = inputs.iter().map(|(_, u)| *u).collect();
                        let stated = o.measurement.as_ref().and_then(crate::science::standard_u);
                        match (propagate(&op, &params["params"], &units, &in_u), stated) {
                            (Propagation::Value(e), Some(su)) => {
                                if (e - su).abs() <= 1e-6 * e.abs().max(1e-12) {
                                    *counts.get_mut("uncertainty_verified").unwrap() += 1;
                                } else {
                                    cx.flag("uncertainty_mismatch", "error", r, format!(
                                        "stated standard uncertainty {su} {unit}; propagating the inputs' uncertainties (uncorrelated) gives {e:.6} {unit}"));
                                }
                            }
                            (Propagation::InputUnknown, Some(_)) => cx.flag("uncertainty_unsupported", "error", r,
                                "states an uncertainty although at least one input's uncertainty is unknown".into()),
                            (Propagation::NoRule, Some(_)) => cx.flag("uncertainty_unpropagated", "warning", r, format!(
                                "states an uncertainty for {op}, which has no propagation rule here; the record must say how it was obtained")),
                            (Propagation::Value(e), None) => cx.flag("uncertainty_not_stated", "info", r, format!(
                                "the inputs support a propagated standard uncertainty of {e:.6} {unit} (uncorrelated), but none is stated")),
                            _ => {}
                        }
                    } else {
                        *counts.get_mut("mismatch").unwrap() += 1;
                        cx.flag("derivation_mismatch", "error", r, format!("{op} of {} input(s) recomputes to {v} {unit}; the record says {rv} {ru}", inputs.len()));
                    }
                }
                (Err(e), _) => {
                    *counts.get_mut("not_reproducible").unwrap() += 1;
                    cx.flag("derivation_not_reproducible", "error", r, format!("cannot recompute: {e}"));
                }
                (_, None) => {
                    *counts.get_mut("mismatch").unwrap() += 1;
                    cx.flag("derivation_mismatch", "error", r, "the derived record has no numeric value".into());
                }
            }
        }
        // --- findings
        if let Some(c) = &o.claim {
            let before = cx.flags.len();
            let mut synthetic_input = false;
            let mut caveat = false;
            for (kind, ids) in [("supports", &c.supports), ("contradicts", &c.contradicts)] {
                for id in ids.iter() {
                    match cx.resolve(id) {
                        Err(e) => cx.flag("citation_missing", "error", r, format!("{kind}: {e}")),
                        Ok(inp) => {
                            synthetic_input |= inp.observation.synthetic;
                            if cx.superseded(inp) {
                                caveat = true;
                                cx.flag("citation_superseded", "warning", r, format!("{kind} {id}, which was later corrected; cite the correction"));
                            }
                            if kind == "supports" {
                                if let Some(codes) = flagged.get(inp.observation.observation_id.as_str()) {
                                    caveat = true;
                                    let mut c: Vec<&str> = codes.clone();
                                    c.sort();
                                    c.dedup();
                                    cx.flag("cites_flagged_observation", "warning", r, format!("rests on {id}, which the science checks flagged, directly or through its inputs ({})", c.join(", ")));
                                }
                            }
                        }
                    }
                }
            }
            if c.epistemic == "known" && c.author_kind == "ai_model" {
                cx.flag("ai_claim_marked_known", "error", r, "an AI model cannot be the authority for a \"known\" statement; label it inferred and cite the evidence".into());
            }
            if matches!(c.epistemic.as_str(), "known" | "inferred") && c.supports.is_empty() {
                cx.flag("unsupported_claim", "error", r, format!("a {} statement cites no supporting observation", c.epistemic));
            }
            if c.epistemic == "known" && !c.contradicts.is_empty() {
                caveat = true;
                cx.flag("known_despite_contradiction", "warning", r, "labelled known while citing contradicting observations".into());
            }
            if synthetic_input && !o.synthetic {
                cx.flag("synthetic_propagation", "error", r, "a statement about synthetic data is not marked synthetic".into());
            }
            let errors = cx.flags[before..].iter().any(|f| f.severity == "error");
            let status = if errors { "invalid" } else if c.supports.is_empty() { "unsupported" } else if caveat { "supported_with_caveats" } else { "well_supported" };
            findings.push(FindingSummary {
                observation_id: o.observation_id.clone(), author: r.robot_id.clone(), author_kind: c.author_kind.clone(), model: c.model.clone(),
                epistemic: c.epistemic.clone(), statement: c.statement.clone(), supports: c.supports.len(), contradicts: c.contradicts.len(),
                assumptions: c.assumptions.clone(), status: status.into(), synthetic: o.synthetic,
            });
        }
    }
    ReasoningReport {
        schema: "cursiv-reasoning-report-1".into(),
        derivations: counts,
        findings,
        flags: cx.flags,
        statement: "Derived values were recomputed from their cited inputs; findings were checked against the observations they cite. \
A well-supported finding is consistent with its evidence; it is not thereby true.".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ops_are_deterministic_and_unit_aware() {
        let v = [(1.0, "degC"), (2.0, "degC"), (4.0, "degC")];
        let p = serde_json::Value::Null;
        assert_eq!(recompute("mean", &p, &v).unwrap(), (7.0 / 3.0, "degC".into()));
        assert_eq!(recompute("median", &p, &v).unwrap().0, 2.0);
        assert!((recompute("stddev", &p, &v).unwrap().0 - 1.5275252316519468).abs() < 1e-15);
        assert_eq!(recompute("convert", &serde_json::json!({"to": "K"}), &[(20.0, "degC")]).unwrap(), (293.15, "K".into()));
        assert_eq!(recompute("linear", &serde_json::json!({"a": 1.02, "b": -0.3}), &[(10.0, "degC")]).unwrap().0, 1.02 * 10.0 - 0.3);
        assert!(recompute("mean", &p, &[(1.0, "degC"), (1.0, "K")]).is_err());
        assert!(recompute("convert", &serde_json::json!({"to": "hPa"}), &[(1.0, "degC")]).is_err());
        assert!(recompute("exec", &p, &v).is_err());
    }
}
