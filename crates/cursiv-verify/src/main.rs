//! cursiv-verify: independent verification. No service, no GUI, no AI model.
//!
//!   cursiv-verify package <dir> [--trust trust.json] [--json] [--science [--profile p.json]] [--report-md out.md]
//!   cursiv-verify cursiv-export <dir> [--key-id <id>] [--json]
//!
//! Exit status: 0 every verdict passes; 1 a verdict fails or is not established; 2 usage error;
//! 3 (with --science/--report-md) verification passes but a derived result or finding is invalid.

use cursiv_evidence::science::{self, Profile};
use cursiv_evidence::trust::TrustStore;
use cursiv_evidence::{legacy, reasoning, verify};
use std::path::PathBuf;
use std::process::ExitCode;

fn usage() -> ExitCode {
    eprintln!("usage:\n  cursiv-verify package <dir> [--trust trust.json] [--json] [--science [--profile p.json]] [--report-md out.md]\n  cursiv-verify cursiv-export <dir> [--key-id <id>] [--json]");
    ExitCode::from(2)
}

fn flag_value(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1).cloned())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() < 2 {
        return usage();
    }
    let dir = PathBuf::from(&args[1]);
    let json = args.iter().any(|a| a == "--json");
    match args[0].as_str() {
        "package" => {
            let trust = match flag_value(&args, "--trust").map(|p| TrustStore::load(p.as_ref())) {
                Some(Ok(t)) => Some(t),
                Some(Err(e)) => {
                    eprintln!("{e}");
                    return ExitCode::from(2);
                }
                None => None,
            };
            let profile = match flag_value(&args, "--profile") {
                None => Profile::survey_default(),
                Some(p) => match std::fs::read_to_string(&p).map_err(|e| e.to_string()).and_then(|t| serde_json::from_str::<Profile>(&t).map_err(|e| e.to_string())) {
                    Ok(pr) => pr,
                    Err(e) => {
                        eprintln!("profile {p}: {e}");
                        return ExitCode::from(2);
                    }
                },
            };
            let report = verify::verify_package(&dir, trust.as_ref());
            let sci = args.iter().any(|a| a == "--science" || a == "--report-md")
                .then(|| science::validate(&report.records, &report.receipts, &profile));
            let rsn = sci.as_ref().map(|s| reasoning::analyse(&report.records, Some(s)));
            if json {
                println!("{}", serde_json::to_string_pretty(&serde_json::json!({"verification": report, "science": sci, "reasoning": rsn})).unwrap());
            } else {
                print!("{}", report.text());
                if let Some(r) = &rsn {
                    println!("\nDerived results (recomputed from cited inputs): {:?}", r.derivations);
                    for f in &r.findings {
                        println!("  finding {} by {} ({}{}): {} [{}]", f.observation_id, f.author, f.author_kind,
                                 f.model.as_ref().map(|m| format!(", {m}")).unwrap_or_default(), f.epistemic, f.status);
                    }
                }
                if let Some(s) = &sci {
                    println!("\nScientific validation ({}; separate from integrity, no AI model):", s.profile);
                    for (k, n) in &s.counts {
                        println!("  {k}: {n}");
                    }
                }
            }
            if let Some(out) = flag_value(&args, "--report-md") {
                let md = render_markdown(&report, sci.as_ref().unwrap(), rsn.as_ref().unwrap());
                if let Err(e) = std::fs::write(&out, md) {
                    eprintln!("cannot write {out}: {e}");
                    return ExitCode::from(2);
                }
            }
            let reasoning_errors = rsn.as_ref().is_some_and(|r| r.flags.iter().any(|f| f.severity == "error"));
            if !report.all_pass() {
                ExitCode::from(1)
            } else if reasoning_errors {
                ExitCode::from(3) // records authentic and complete, but a derived result or finding is invalid
            } else {
                ExitCode::SUCCESS
            }
        }
        "cursiv-export" => {
            let r = legacy::verify_cursiv_export(&dir, flag_value(&args, "--key-id").as_deref());
            if json {
                println!("{}", serde_json::to_string_pretty(&r).unwrap());
            } else if r.problems.is_empty() {
                println!("Cursiv notebook export checks out: signed by key {} ({}); {} files unchanged; {} entries; log head entry {}.",
                         r.key_id,
                         match r.key_trusted { Some(true) => "the expected key", _ => "the key named in the export; who holds it is not established" },
                         r.files_checked, r.entries_exported.unwrap_or(0), r.log_head["seq"]);
            } else {
                println!("Cursiv notebook export does NOT check out:");
                for p in &r.problems {
                    println!("  - {p}");
                }
            }
            if r.problems.is_empty() && r.signature_valid { ExitCode::SUCCESS } else { ExitCode::from(1) }
        }
        _ => usage(),
    }
}

/// Final evidence report: verification verdicts, then scientific flags, with synthetic data labelled.
fn render_markdown(r: &verify::Report, s: &science::ScienceReport, rs: &reasoning::ReasoningReport) -> String {
    let v = &r.verdicts;
    let synthetic: u64 = r.robots.values().map(|x| x.synthetic_records).sum();
    let total: u64 = r.robots.values().map(|x| x.records).sum();
    let mut md = String::from("# Cursiv evidence report\n\n");
    if synthetic > 0 {
        md += &format!("> **SYNTHETIC DATA.** {synthetic} of {total} observations are simulated. Nothing in this report is real-world scientific evidence.\n\n");
    }
    md += &format!("Package: `{}`  \nVerified: {}  \nTrust store supplied: {}\n\n", r.package, r.verified_time, r.trust_store);
    md += "## 1. Verification (cryptographic, independent of the service)\n\n| Question | Verdict |\n|---|---|\n";
    for (k, val) in [("Structure", &v.structure), ("Integrity: nothing changed since signing", &v.integrity),
                     ("Authenticity: signed by trusted keys", &v.authenticity), ("Completeness: no records missing", &v.completeness),
                     ("Attachments present and unchanged", &v.attachments)] {
        md += &format!("| {k} | {val} |\n");
    }
    md += "\n| Robot | Records | Trusted checkpoint covers | Synthetic | Corrections |\n|---|---|---|---|---|\n";
    for (id, x) in &r.robots {
        md += &format!("| {id} | {} | {} | {} | {} |\n", x.records, x.trusted_checkpoint_count.map_or("none".into(), |c| c.to_string()), x.synthetic_records, x.corrections);
    }
    let problems: Vec<_> = r.findings.iter().filter(|f| f.severity != "info").collect();
    md += &format!("\n### Verification findings ({})\n\n", problems.len());
    if problems.is_empty() {
        md += "None.\n";
    }
    for f in problems.iter().take(100) {
        let at = f.robot_id.as_ref().map(|x| format!("{x}{}: ", f.seq.map(|q| format!(" #{q}")).unwrap_or_default())).unwrap_or_default();
        md += &format!("- **{}** `{}/{}` {at}{}\n", f.severity, f.area, f.code, f.message);
    }
    md += &format!("\n## 2. Scientific validation (deterministic, profile `{}`)\n\n{}\n\n", s.profile, s.statement);
    md += &format!("{} observations, {} current after {} correction(s).\n\n| Check | Count |\n|---|---|\n", s.observations, s.current_observations, s.corrected);
    for (k, n) in &s.counts {
        md += &format!("| {k} | {n} |\n");
    }
    md += "\n### Flags that need a scientist's attention\n\nEpistemic labels: **known** (follows from the recorded values), **inferred** (drawn from several records), **assumed** (rests on the stated assumption), **unknown** (not recorded).\n\n";
    let notable = ["contradiction", "agreement_check_truncated", "out_of_range", "clock_drift", "out_of_order_time", "calibration_expired",
                   "missing_supporting_evidence", "outside_mission_region", "sensor_time_in_future", "unit_mismatch"];
    let mut any = false;
    let mut groups: std::collections::BTreeMap<&str, Vec<&science::Flag>> = std::collections::BTreeMap::new();
    for f in s.flags.iter().filter(|f| f.code == "contradiction") {
        groups.entry(f.group.as_str()).or_default().push(f);
    }
    for (g, fs) in &groups {
        any = true;
        md += &format!("- *known* `contradiction` **{g}**: disagreeing pairs beyond the agreement threshold ({} listed; see the total under Check counts). Which sensor (if either) is right is not determined. Example: {}\n",
                       fs.len(), fs[0].message);
    }
    for f in s.flags.iter().filter(|f| f.code != "contradiction" && notable.contains(&f.code.as_str())).take(100) {
        any = true;
        md += &format!("- *{}* `{}` ({}): {}\n", f.epistemic, f.code, f.robot_id, f.message);
    }
    if !any {
        md += "None.\n";
    }
    md += "\n## 3. Derived results and findings\n\n";
    md += &format!("{}\n\nDerived values: {} recomputed and matching, {} mismatched, {} not reproducible, {} with missing inputs.\n\n",
                   rs.statement, rs.derivations["verified"], rs.derivations["mismatch"], rs.derivations["not_reproducible"], rs.derivations["inputs_missing"]);
    if rs.findings.is_empty() {
        md += "No findings were recorded.\n";
    } else {
        md += "| Finding | Author | Label | Evidence | Status |\n|---|---|---|---|---|\n";
        for f in &rs.findings {
            let who = match (&f.author_kind[..], &f.model) {
                ("ai_model", Some(m)) => format!("{} (AI: {m})", f.author),
                _ => format!("{} ({})", f.author, f.author_kind),
            };
            let tag = if f.synthetic { " *(synthetic)*" } else { "" };
            md += &format!("| {}{tag} | {who} | {} | {} supporting, {} contradicting{} | **{}** |\n", f.statement.replace('|', "\\|"), f.epistemic, f.supports, f.contradicts,
                           if f.assumptions.is_empty() { String::new() } else { format!("; assumes: {}", f.assumptions.join("; ")) }, f.status);
        }
    }
    let rflags: Vec<_> = rs.flags.iter().filter(|f| f.severity != "info").collect();
    if !rflags.is_empty() {
        md += "\n";
        for f in rflags.iter().take(100) {
            md += &format!("- **{}** `{}` ({} {}): {}\n", f.severity, f.code, f.robot_id, f.observation_id, f.message);
        }
    }
    md += "\n## 4. What this report does not show\n\n";
    for l in &r.limits {
        md += &format!("- {l}\n");
    }
    md += "- No conclusion about the survey area is drawn here. Any interpretation must cite the observations above and be labelled as an interpretation.\n";
    md
}
