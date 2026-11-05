//! Evidence packages are BagIt bags (RFC 8493), so any BagIt tool (e.g. bagit-python,
//! public domain) can check fixity, and `cursiv-verify` checks everything else, given the
//! operator's trust store.
//!
//!   bagit.txt, bag-info.txt, manifest-sha256.txt, tagmanifest-sha256.txt   BagIt tag files
//!   manifest.json                     station-signed DSSE list of every data/ file (sha256, size)
//!   data/station-checkpoint.json      station-signed heads/Merkle roots of every robot log and the receipts
//!   data/robots/<id>/records.jsonl    robot-signed records, exactly as received
//!   data/robots/<id>/checkpoints.jsonl
//!   data/receipts.jsonl               when the station received each record
//!   data/blobs/sha256/<hex>           attachments
//!   data/keys/public-keys.json        keys seen in this package: informational, NEVER trusted from here
//!   data/README.txt

use crate::crypto::{public_b64, Envelope, Identity};
use crate::model;
use crate::store::{copy_hashed, Store};
use std::collections::BTreeMap;
use std::fs;
use std::io::BufRead;
use std::path::{Component, Path};

pub const MANIFEST_SCHEMA: &str = "cursiv-package-1";
/// Package format written by default. Format 1 (one records.jsonl per robot) can still be
/// written for older verifiers and importers; the verifier reads both.
pub const PACKAGE_VERSION: u32 = 2;
pub const SUPPORTED_PACKAGE_VERSIONS: [u32; 2] = [1, 2];

#[derive(Clone, Copy, Debug)]
pub struct ExportOptions {
    /// 1 or 2
    pub format: u32,
}

impl Default for ExportOptions {
    fn default() -> Self {
        ExportOptions { format: PACKAGE_VERSION }
    }
}

/// A package-relative path that cannot escape the package.
pub fn safe_rel(name: &str) -> bool {
    let p = Path::new(name);
    !name.is_empty()
        && !name.contains('\\')
        && !name.contains(':')
        && p.components().all(|c| matches!(c, Component::Normal(_)))
}

/// Atomic: the package is built in a hidden sibling folder and renamed into place only when
/// complete, so an interrupted export never leaves a partial package under the final name.
pub(crate) fn export(store: &Store, dest: &Path, station: &Identity, opts: ExportOptions) -> Result<serde_json::Value, String> {
    if !SUPPORTED_PACKAGE_VERSIONS.contains(&opts.format) {
        return Err(format!("package format {} is not supported (1 or 2)", opts.format));
    }
    if dest.exists() {
        return Err(format!("{} already exists; choose a new folder", dest.display()));
    }
    let parent = dest.parent().ok_or("export path has no parent folder")?;
    fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    let name = dest.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
    let partial = crate::store::unique_tmp(parent, &format!(".partial-{name}"));
    let result = export_into(store, &partial, station, opts).and_then(|mut v| {
        fs::rename(&partial, dest).map_err(|e| format!("could not finish the export: {e}"))?;
        v["path"] = dest.display().to_string().into();
        Ok(v)
    });
    if result.is_err() {
        let _ = fs::remove_dir_all(&partial);
    }
    result
}

fn export_into(store: &Store, bag: &Path, station: &Identity, opts: ExportOptions) -> Result<serde_json::Value, String> {
    fs::create_dir_all(bag).map_err(|e| e.to_string())?;
    let dest = &bag.join("data");
    fs::create_dir_all(dest).map_err(|e| e.to_string())?;
    let root = store.root();
    let mut files: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    let mut keys: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    let add = |files: &mut BTreeMap<String, serde_json::Value>, rel: String, src: &Path| -> Result<(), String> {
        let (sha, size) = copy_hashed(src, &dest.join(&rel))?;
        files.insert(rel, serde_json::json!({"sha256": sha, "size": size}));
        Ok(())
    };
    // Station checkpoint first, so it describes exactly the logs copied below.
    let cp = store.station_checkpoint();
    for id in store.robot_ids() {
        let segs = store.segment_files(&id);
        if opts.format == 1 {
            // one records.jsonl: the segments concatenated, byte for byte
            let rel = format!("robots/{id}/records.jsonl");
            let (sha, size) = concat_hashed(&segs.iter().map(|(_, f, _)| f.clone()).collect::<Vec<_>>(), &dest.join(&rel))?;
            files.insert(rel, serde_json::json!({"sha256": sha, "size": size}));
        } else {
            for (n, f, seal) in &segs {
                let seal = seal.as_ref().ok_or(format!("{id} segment {n} is not sealed"))?;
                add(&mut files, format!("robots/{id}/segments/{}", crate::segment::segment_name(*n)), f)?;
                add(&mut files, format!("robots/{id}/segments/{}", crate::segment::seal_name(*n)), seal)?;
            }
        }
        let cps = root.join("robots").join(&id).join("checkpoints.jsonl");
        if cps.is_file() {
            add(&mut files, format!("robots/{id}/checkpoints.jsonl"), &cps)?;
            let f = fs::File::open(&cps).map_err(|e| e.to_string())?;
            for line in std::io::BufReader::new(f).lines().map_while(Result::ok) {
                if let Ok(env) = serde_json::from_str::<Envelope>(&line) {
                    if let Some(k) = store.trust().robot(&id, env.keyid()) {
                        keys.entry(k.key_id.clone()).or_insert(serde_json::json!({"public_key": k.public_key, "seen_for": id}));
                    }
                }
            }
        }
        // DSSE envelopes carry no public key: list the enrolled key for each keyid seen.
        for kid in store.robot_keyids(&id) {
            if let Some(k) = store.trust().robot(&id, &kid) {
                keys.entry(k.key_id.clone()).or_insert(serde_json::json!({"public_key": k.public_key, "seen_for": id}));
            }
        }
    }
    if root.join("receipts.jsonl").is_file() {
        add(&mut files, "receipts.jsonl".into(), &root.join("receipts.jsonl"))?;
    }
    for e in fs::read_dir(root.join("blobs/sha256")).map_err(|e| e.to_string())?.flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        add(&mut files, format!("blobs/sha256/{name}"), &e.path())?;
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
    let manifest = station.sign_json(crate::crypto::MANIFEST_TYPE, &serde_json::json!({
        "schema": MANIFEST_SCHEMA,
        "package_version": opts.format,
        "station_id": store.station_id,
        "created_time": model::now_utc(),
        "files": files,
    }));
    let w = |name: &str, text: &str| fs::write(bag.join(name), text).map_err(|e| e.to_string());
    w("manifest.json", &serde_json::to_string_pretty(&manifest).unwrap())?;
    // BagIt (RFC 8493) tag files.
    let mut bag_manifest = String::new();
    let mut octets = 0u64;
    for (rel, v) in &files {
        bag_manifest += &format!("{}  data/{rel}\n", v["sha256"].as_str().unwrap());
        octets += v["size"].as_u64().unwrap_or(0);
    }
    w("bagit.txt", "BagIt-Version: 1.0\nTag-File-Character-Encoding: UTF-8\n")?;
    w("bag-info.txt", &format!(
        "Bagging-Date: {}\nPayload-Oxum: {octets}.{}\nBag-Software-Agent: cursiv-evidence {}\nExternal-Identifier: {}\nCursiv-Package-Version: {}\n\
External-Description: Cursiv Robotics evidence package; verify with cursiv-verify (manifest.json is a DSSE envelope)\n",
        &model::now_utc()[..10], files.len(), env!("CARGO_PKG_VERSION"), store.station_id, opts.format))?;
    w("manifest-sha256.txt", &bag_manifest)?;
    let mut tags = String::new();
    for name in ["bagit.txt", "bag-info.txt", "manifest-sha256.txt", "manifest.json"] {
        tags += &format!("{}  {name}\n", crate::crypto::sha256_hex(&fs::read(bag.join(name)).map_err(|e| e.to_string())?));
    }
    w("tagmanifest-sha256.txt", &tags)?;
    Ok(serde_json::json!({"path": bag.display().to_string(), "files": files.len(), "format": "BagIt 1.0", "package_version": opts.format}))
}

/// Concatenate files into `dest`, returning (sha256, size).
fn concat_hashed(srcs: &[std::path::PathBuf], dest: &Path) -> Result<(String, u64), String> {
    use sha2::{Digest, Sha256};
    use std::io::{Read, Write};
    if let Some(d) = dest.parent() {
        fs::create_dir_all(d).map_err(|e| e.to_string())?;
    }
    let mut out = fs::File::create(dest).map_err(|e| e.to_string())?;
    let mut h = Sha256::new();
    let mut total = 0u64;
    let mut buf = vec![0u8; 256 * 1024];
    for src in srcs {
        let mut f = fs::File::open(src).map_err(|e| format!("{}: {e}", src.display()))?;
        loop {
            let n = f.read(&mut buf).map_err(|e| e.to_string())?;
            if n == 0 {
                break;
            }
            h.update(&buf[..n]);
            out.write_all(&buf[..n]).map_err(|e| e.to_string())?;
            total += n as u64;
        }
    }
    out.sync_all().map_err(|e| e.to_string())?;
    Ok((hex::encode(h.finalize()), total))
}
