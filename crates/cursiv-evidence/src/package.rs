//! Evidence packages: a directory a third party can verify with `cursiv-verify`
//! alone, given the operator's trust store.
//!
//!   manifest.json                station-signed list of every other file (sha256, size)
//!   station-checkpoint.json      station-signed heads/Merkle roots of every robot log and the receipts
//!   robots/<id>/records.jsonl    robot-signed records, exactly as received
//!   robots/<id>/checkpoints.jsonl
//!   receipts.jsonl               when the station received each record
//!   blobs/sha256/<hex>           attachments
//!   keys/public-keys.json        keys seen in this package: informational, NEVER trusted from here
//!   README.txt

use crate::crypto::{public_b64, Envelope, Identity};
use crate::model;
use crate::store::{copy_hashed, Store};
use std::collections::BTreeMap;
use std::fs;
use std::io::BufRead;
use std::path::{Component, Path};

pub const MANIFEST_SCHEMA: &str = "cursiv-package-1";

/// A package-relative path that cannot escape the package.
pub fn safe_rel(name: &str) -> bool {
    let p = Path::new(name);
    !name.is_empty()
        && !name.contains('\\')
        && !name.contains(':')
        && p.components().all(|c| matches!(c, Component::Normal(_)))
}

pub(crate) fn export(store: &Store, dest: &Path, station: &Identity) -> Result<serde_json::Value, String> {
    if dest.exists() {
        return Err(format!("{} already exists; choose a new folder", dest.display()));
    }
    fs::create_dir_all(dest).map_err(|e| e.to_string())?;
    let root = store.root();
    let mut files: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    let mut keys: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    let mut add = |rel: String, src: &Path| -> Result<(), String> {
        let (sha, size) = copy_hashed(src, &dest.join(&rel))?;
        files.insert(rel, serde_json::json!({"sha256": sha, "size": size}));
        Ok(())
    };
    // Station checkpoint first, so it describes exactly the logs copied below.
    let cp = store.station_checkpoint();
    for e in fs::read_dir(root.join("robots")).map_err(|e| e.to_string())?.flatten() {
        let id = e.file_name().to_string_lossy().to_string();
        for name in ["records.jsonl", "checkpoints.jsonl"] {
            let src = e.path().join(name);
            if src.is_file() {
                add(format!("robots/{id}/{name}"), &src)?;
                let f = fs::File::open(&src).map_err(|e| e.to_string())?;
                for line in std::io::BufReader::new(f).lines().map_while(Result::ok) {
                    if let Ok(env) = serde_json::from_str::<Envelope>(&line) {
                        keys.entry(env.key_id.clone()).or_insert(serde_json::json!({"public_key": env.public_key, "seen_for": id}));
                    }
                }
            }
        }
    }
    if root.join("receipts.jsonl").is_file() {
        add("receipts.jsonl".into(), &root.join("receipts.jsonl"))?;
    }
    for e in fs::read_dir(root.join("blobs/sha256")).map_err(|e| e.to_string())?.flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        add(format!("blobs/sha256/{name}"), &e.path())?;
    }
    let cp_text = serde_json::to_string_pretty(&cp).unwrap();
    fs::write(dest.join("station-checkpoint.json"), &cp_text).map_err(|e| e.to_string())?;
    files.insert("station-checkpoint.json".into(), serde_json::json!({"sha256": crate::crypto::sha256_hex(cp_text.as_bytes()), "size": cp_text.len()}));
    keys.insert(station.key_id(), serde_json::json!({"public_key": public_b64(&station.public()), "seen_for": format!("station {}", store.station_id)}));
    let keys_text = serde_json::to_string_pretty(&serde_json::json!({
        "note": "Keys that appear in this package. Listing here establishes NOTHING about who holds them; verify against your own trust store.",
        "keys": keys}))
    .unwrap();
    fs::create_dir_all(dest.join("keys")).map_err(|e| e.to_string())?;
    fs::write(dest.join("keys/public-keys.json"), &keys_text).map_err(|e| e.to_string())?;
    files.insert("keys/public-keys.json".into(), serde_json::json!({"sha256": crate::crypto::sha256_hex(keys_text.as_bytes()), "size": keys_text.len()}));
    let readme = "Cursiv Robotics evidence package.\n\nVerify with: cursiv-verify package <this folder> --trust <your trust store>\n\
Integrity (nothing changed), authenticity (who signed) and scientific accuracy are separate questions;\n\
the verifier answers the first two. Observations marked synthetic are simulated, not real-world evidence.\n";
    fs::write(dest.join("README.txt"), readme).map_err(|e| e.to_string())?;
    files.insert("README.txt".into(), serde_json::json!({"sha256": crate::crypto::sha256_hex(readme.as_bytes()), "size": readme.len()}));
    let manifest = station.sign_json(&serde_json::json!({
        "schema": MANIFEST_SCHEMA,
        "station_id": store.station_id,
        "created_time": model::now_utc(),
        "files": files,
    }));
    fs::write(dest.join("manifest.json"), serde_json::to_string_pretty(&manifest).unwrap()).map_err(|e| e.to_string())?;
    Ok(serde_json::json!({"path": dest.display().to_string(), "files": files.len()}))
}
