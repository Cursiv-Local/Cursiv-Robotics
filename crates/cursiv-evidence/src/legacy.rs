//! Verify an existing Cursiv desktop Field Notebook export (`signature.json`,
//! format `cursiv-export-1`, made by `cursiv_engine/core/fieldlog.py::sign_export`).
//!
//! Reimplements, independently of Cursiv's Python code, what `verify_export`
//! checks: the Ed25519 signature over the canonical JSON of the signed object
//! (Python `json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",",":"))`),
//! every listed file's SHA-256, and that no file was added. As in Cursiv, the
//! signature is checked against the key named in the envelope: that proves the
//! export was not changed after signing, not who signed it, unless the caller
//! supplies the expected key id (`expected_key_id`), e.g. one pinned by Cursiv's team sync.

use crate::crypto::{parse_public_b64, sha256_hex};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::{Signature, Verifier};
use serde::Serialize;
use std::fs;
use std::path::Path;

#[derive(Debug, Serialize)]
pub struct LegacyReport {
    pub signature_valid: bool,
    pub key_id: String,
    pub key_trusted: Option<bool>,
    pub files_checked: usize,
    pub problems: Vec<String>,
    pub log_head: serde_json::Value,
    pub entries_exported: Option<u64>,
}

/// Python-compatible canonical JSON for the value types Cursiv's export signature uses.
pub fn python_canonical(v: &serde_json::Value) -> String {
    // serde_json's default Map is a BTreeMap: keys sorted by code point, as Python's sort_keys.
    // Compact separators and raw (unescaped) non-ASCII match ensure_ascii=False.
    serde_json::to_string(v).expect("json")
}

pub fn verify_cursiv_export(dir: &Path, expected_key_id: Option<&str>) -> LegacyReport {
    let mut r = LegacyReport { signature_valid: false, key_id: String::new(), key_trusted: None, files_checked: 0,
                               problems: vec![], log_head: serde_json::Value::Null, entries_exported: None };
    let sig_path = dir.join("signature.json");
    let env: serde_json::Value = match fs::read_to_string(&sig_path).ok().and_then(|t| serde_json::from_str(&t).ok()) {
        Some(v) => v,
        None => {
            r.problems.push("signature.json is missing or unreadable: the export is not signed".into());
            return r;
        }
    };
    r.key_id = env["key_id"].as_str().unwrap_or("").to_string();
    let signed = &env["signed"];
    let ok = (|| -> Option<bool> {
        let pk = parse_public_b64(env["public_key"].as_str()?).ok()?;
        let sig = Signature::from_slice(&B64.decode(env["signature"].as_str()?).ok()?).ok()?;
        let kid = &sha256_hex(pk.as_bytes())[..16];
        Some(kid == r.key_id && pk.verify(python_canonical(signed).as_bytes(), &sig).is_ok())
    })().unwrap_or(false);
    r.signature_valid = ok;
    if !ok {
        r.problems.push("the signature does not match: signature.json was changed, or was not made by the key it names".into());
        return r;
    }
    if signed["format"] != "cursiv-export-1" {
        r.problems.push("not a Cursiv export signature (format)".into());
        return r;
    }
    r.key_trusted = expected_key_id.map(|k| k == r.key_id);
    if r.key_trusted == Some(false) {
        r.problems.push(format!("signed by key {}, not the expected key {}", r.key_id, expected_key_id.unwrap()));
    }
    r.log_head = signed["log_head"].clone();
    r.entries_exported = signed["entries_exported"].as_u64();
    let Some(files) = signed["files"].as_object() else {
        r.problems.push("signature lists no files".into());
        return r;
    };
    for (name, digest) in files {
        r.files_checked += 1;
        if !crate::package::safe_rel(name) {
            r.problems.push(format!("signature names an unsafe path {name:?}"));
            continue;
        }
        let p = dir.join(name);
        match fs::symlink_metadata(&p) {
            Err(_) => r.problems.push(format!("{name} is missing")),
            Ok(m) if !m.is_file() => r.problems.push(format!("{name} is not a regular file")),
            Ok(_) => {
                if fs::read(&p).map(|b| sha256_hex(&b)).ok().as_deref() != digest.as_str() {
                    r.problems.push(format!("{name} was changed after the export was signed"));
                }
            }
        }
    }
    if let Ok(rd) = fs::read_dir(dir) {
        for e in rd.flatten() {
            let n = e.file_name().to_string_lossy().to_string();
            if n != "signature.json" && !files.contains_key(&n) {
                r.problems.push(format!("{n} is not covered by the signature (added after the export was made)"));
            }
        }
    }
    r
}
