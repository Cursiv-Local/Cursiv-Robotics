//! cursiv-verify: independent verification. No service, no GUI, no AI model.
//!
//!   cursiv-verify package <dir> [--trust trust.json] [--json] [--science [--profile p.json] [--max-records N]] [--report-md out.md]
//!   cursiv-verify segment <NNNNNN.jsonl> --trust trust.json [--json]
//!   cursiv-verify convert <dir> --to prov|sensorthings [--trust trust.json] [--out file.json] [--allow-unverified]
//!   cursiv-verify cursiv-export <dir> [--key-id <id>] [--json]
//!
//! Without --science the package is verified in bounded memory (records are streamed, not kept).
//! With --science, records are kept for the science and reasoning checks, up to --max-records
//! (default 2,000,000); beyond that those checks report "not_assessed" instead of running on part
//! of the data.
//!
//! Exit status: 0 every verdict passes; 1 a verdict fails or is not established; 2 usage error;
//! 3 (with --science/--report-md) verification passes but a derived result or finding is invalid.

use cursiv_evidence::science::{self, Profile};
use cursiv_evidence::trust::TrustStore;
use cursiv_evidence::{legacy, reasoning, verify};
use std::path::PathBuf;
use std::process::ExitCode;

fn usage() -> ExitCode {
    eprintln!("usage:\n  cursiv-verify package <dir> [--trust trust.json] [--json] [--science [--profile p.json] [--max-records N]] [--report-md out.md]\n  cursiv-verify segment <NNNNNN.jsonl> --trust trust.json [--json]\n  cursiv-verify convert <dir> --to prov|sensorthings [--trust trust.json] [--out file.json] [--allow-unverified]\n  cursiv-verify cursiv-export <dir> [--key-id <id>] [--json]");
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
            let want_science = args.iter().any(|a| a == "--science" || a == "--report-md");
            let opts = if want_science {
                let max = match flag_value(&args, "--max-records").map(|v| v.parse::<u64>()) {
                    None => verify::VerifyOptions::default().max_collected_records,
                    Some(Ok(n)) => n,
                    Some(Err(_)) => return usage(),
                };
                verify::VerifyOptions { collect_records: true, max_collected_records: max }
            } else {
                verify::VerifyOptions::streaming()
            };
            let report = verify::verify_package_with(&dir, trust.as_ref(), &opts);
            // Science on part of the data would look like science on all of it: refuse instead.
            let science_possible = want_science && report.records_complete;
            let sci = science_possible.then(|| science::validate(&report.records, &report.receipts, &profile));
            let rsn = sci.as_ref().map(|s| reasoning::analyse(&report.records, Some(s)));
            let not_assessed = (want_science && !science_possible).then(|| serde_json::json!({
                "status": "not_assessed",
                "reason": format!("the package has more than {} records; raise --max-records to run science and reasoning checks on all of them", opts.max_collected_records)}));
            if json {
                let sci_json = sci.as_ref().map(|s| serde_json::to_value(s).unwrap()).or(not_assessed.clone());
                let rsn_json = rsn.as_ref().map(|r| serde_json::to_value(r).unwrap()).or(not_assessed.clone());
                println!("{}", serde_json::to_string_pretty(&serde_json::json!({"verification": report, "science": sci_json, "reasoning": rsn_json})).unwrap());
            } else {
                print!("{}", report.text());
                if let Some(r) = &rsn {
                    println!("\nDerived results (recomputed from cited inputs): {:?}", r.derivations);
                    for f in &r.findings {
                        println!("  finding {} by {} ({}{}): {} [{}]", f.observation_id, f.author, f.author_kind,
                                 f.model.as_ref().map(|m| format!(", {m}")).unwrap_or_default(), f.epistemic, f.status);
                    }
                }
                if let Some(n) = &not_assessed {
                    println!("\nScientific validation: NOT ASSESSED ({})", n["reason"].as_str().unwrap_or(""));
                }
                if let Some(s) = &sci {
                    println!("\nScientific validation ({}; separate from integrity, no AI model):", s.profile);
                    for (k, n) in &s.counts {
                        println!("  {k}: {n}");
                    }
                }
            }
            if let Some(out) = flag_value(&args, "--report-md") {
                let (Some(sci), Some(rsn)) = (sci.as_ref(), rsn.as_ref()) else {
                    eprintln!("--report-md needs the science checks, which were not assessed (too many records; raise --max-records)");
                    return ExitCode::from(1);
                };
                let md = render_markdown(&report, sci, rsn);
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
        "convert" => {
            let trust = match flag_value(&args, "--trust").map(|p| TrustStore::load(p.as_ref())) {
                Some(Ok(t)) => Some(t),
                Some(Err(e)) => {
                    eprintln!("{e}");
                    return ExitCode::from(2);
                }
                None => None,
            };
            let allow = args.iter().any(|a| a == "--allow-unverified");
            let opts = verify::VerifyOptions { collect_records: true, max_collected_records: u64::MAX };
            let report = verify::verify_package_with(&dir, trust.as_ref(), &opts);
            let name = dir.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
            let out = match flag_value(&args, "--to").as_deref() {
                Some("prov") => cursiv_evidence::convert::to_prov_json(&report, &name, allow),
                Some("sensorthings") => cursiv_evidence::convert::to_sensorthings(&report, &name, allow),
                _ => return usage(),
            };
            match out {
                Err(e) => {
                    eprintln!("not converted: {e}");
                    ExitCode::from(1)
                }
                Ok(v) => {
                    let text = serde_json::to_string_pretty(&v).unwrap();
                    match flag_value(&args, "--out") {
                        Some(p) => {
                            if let Err(e) = std::fs::write(&p, text + "\n") {
                                eprintln!("cannot write {p}: {e}");
                                return ExitCode::from(2);
                            }
                            eprintln!("wrote {p} (verification status: {})", report.status);
                        }
                        None => println!("{text}"),
                    }
                    ExitCode::SUCCESS
                }
            }
        }
        "segment" => {
            let trust = match flag_value(&args, "--trust").map(|p| TrustStore::load(p.as_ref())) {
                Some(Ok(t)) => t,
                Some(Err(e)) => {
                    eprintln!("{e}");
                    return ExitCode::from(2);
                }
                None => {
                    eprintln!("segment verification needs --trust (the station and robot keys)");
                    return ExitCode::from(2);
                }
            };
            let seal_path = match dir.file_name().and_then(|n| n.to_str()).and_then(cursiv_evidence::segment::parse_name) {
                Some((n, false)) => dir.with_file_name(cursiv_evidence::segment::seal_name(n)),
                _ => {
                    eprintln!("expected a segment file named NNNNNN.jsonl");
                    return ExitCode::from(2);
                }
            };
            let env: Option<cursiv_evidence::crypto::Envelope> = std::fs::read_to_string(&seal_path).ok().and_then(|t| serde_json::from_str(&t).ok());
            let Some(env) = env else {
                eprintln!("cannot read the seal {}", seal_path.display());
                return ExitCode::from(1);
            };
            let seal = match cursiv_evidence::segment::decode(&env) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("{e}");
                    return ExitCode::from(1);
                }
            };
            // keys come from the operator's trust store, never from the files being checked
            let station_key = trust.station(&seal.station_id, env.keyid()).filter(|k| TrustStore::verdict(k, None) == cursiv_evidence::trust::KeyVerdict::Trusted);
            let robot_keys = trust.robots.get(&seal.robot_id).cloned().unwrap_or_default();
            let (Some(sk), Some(rk)) = (station_key, robot_keys.iter().find(|k| k.status == "active")) else {
                eprintln!("the trust store has no trusted key for station {} or robot {}", seal.station_id, seal.robot_id);
                return ExitCode::from(1);
            };
            let r = cursiv_evidence::segment::verify_segment(&dir, &env, &sk.public_key, &rk.public_key);
            if json {
                println!("{}", serde_json::to_string_pretty(&serde_json::json!({"segment": seal.segment, "robot_id": seal.robot_id,
                    "first_seq": seal.first_seq, "last_seq": seal.last_seq, "records": r.records, "problems": r.problems})).unwrap());
            } else if r.problems.is_empty() {
                println!("Segment {} of {} (records {}..{}) checks out against its seal; {} records verified.", seal.segment, seal.robot_id, seal.first_seq, seal.last_seq, r.records);
            } else {
                println!("Segment {} of {} does NOT check out:", seal.segment, seal.robot_id);
                for p in &r.problems {
                    println!("  - {p}");
                }
            }
            if r.problems.is_empty() { ExitCode::SUCCESS } else { ExitCode::from(1) }
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
