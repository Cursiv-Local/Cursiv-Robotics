//! Hashing, Ed25519 identities and signed envelopes.
//!
//! Envelopes are DSSE (Dead Simple Signing Envelope, secure-systems-lab/dsse,
//! Apache-2.0; used by in-toto and Sigstore). The payload is base64 of the exact
//! body bytes, so a verifier never re-serializes JSON (no cross-language
//! canonical-JSON problem). Record hashes are SHA-256 of those body bytes.
//!
//! The design follows Cursiv's `core/devicekey.py` (an Ed25519 key per
//! installation, a short key id = first 16 hex chars of SHA-256(public key)),
//! with one deliberate difference: verifying an envelope against the public key
//! it carries only proves the payload was not changed since signing. It does
//! NOT say who signed. Authenticity needs a trust store (see `trust.rs`).

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::path::Path;

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// First 16 hex characters of SHA-256 over the raw 32-byte public key (as Cursiv does).
pub fn key_id(public: &VerifyingKey) -> String {
    sha256_hex(public.as_bytes())[..16].to_string()
}

pub fn public_b64(public: &VerifyingKey) -> String {
    B64.encode(public.as_bytes())
}

pub fn parse_public_b64(s: &str) -> Result<VerifyingKey, String> {
    let raw = B64.decode(s).map_err(|_| "public key is not base64".to_string())?;
    let arr: [u8; 32] = raw.try_into().map_err(|_| "public key is not 32 bytes".to_string())?;
    VerifyingKey::from_bytes(&arr).map_err(|_| "public key is not a valid Ed25519 point".to_string())
}

pub const RECORD_TYPE: &str = "application/vnd.cursiv.record.v1+json";
pub const CHECKPOINT_TYPE: &str = "application/vnd.cursiv.checkpoint.v1+json";
pub const STATION_CHECKPOINT_TYPE: &str = "application/vnd.cursiv.station-checkpoint.v1+json";
pub const MANIFEST_TYPE: &str = "application/vnd.cursiv.package-manifest.v1+json";

/// DSSE pre-authentication encoding (secure-systems-lab/dsse protocol.md, Apache-2.0):
/// "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body, LEN = ASCII decimal byte length.
pub fn pae(payload_type: &str, body: &[u8]) -> Vec<u8> {
    let mut out = format!("DSSEv1 {} {} {} ", payload_type.len(), payload_type, body.len()).into_bytes();
    out.extend_from_slice(body);
    out
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct DsseSignature {
    pub keyid: String,
    pub sig: String,
}

/// A DSSE envelope (the format in-toto and Sigstore use). `payload` is base64 of the exact
/// body bytes; signatures cover PAE(payloadType, body). DSSE carries no public key: who
/// signed is decided by looking `keyid` up in a trust store (keyid itself is unauthenticated).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Envelope {
    pub payload: String,
    #[serde(rename = "payloadType")]
    pub payload_type: String,
    pub signatures: Vec<DsseSignature>,
}

fn b64_decode(s: &str) -> Option<Vec<u8>> {
    use base64::engine::general_purpose::URL_SAFE;
    B64.decode(s).ok().or_else(|| URL_SAFE.decode(s).ok())
}

impl Envelope {
    pub fn body(&self) -> Option<Vec<u8>> {
        b64_decode(&self.payload)
    }

    /// The body as UTF-8 text (all Cursiv payloads are JSON).
    pub fn body_text(&self) -> Option<String> {
        String::from_utf8(self.body()?).ok()
    }

    /// SHA-256 of the exact body bytes: the record's identity in chains and Merkle trees.
    /// An undecodable payload hashes its base64 text, so it can still be named in reports.
    pub fn payload_hash(&self) -> String {
        sha256_hex(&self.body().unwrap_or_else(|| self.payload.clone().into_bytes()))
    }

    pub fn keyid(&self) -> &str {
        self.signatures.first().map(|s| s.keyid.as_str()).unwrap_or("")
    }

    /// True when some signature with this key's id verifies over PAE(type, body).
    /// Integrity relative to that key only; whether the key is trusted is a separate question.
    pub fn verify_with(&self, public: &VerifyingKey) -> bool {
        let Some(body) = self.body() else { return false };
        let msg = pae(&self.payload_type, &body);
        let kid = key_id(public);
        self.signatures.iter().filter(|s| s.keyid == kid).any(|s| {
            b64_decode(&s.sig).and_then(|raw| Signature::from_slice(&raw).ok())
                .is_some_and(|sig| public.verify_strict(&msg, &sig).is_ok())
        })
    }

    pub fn verify_with_b64(&self, public_b64: &str) -> bool {
        parse_public_b64(public_b64).is_ok_and(|pk| self.verify_with(&pk))
    }
}

/// A private signing identity. Never serialized into packages.
pub struct Identity {
    key: SigningKey,
}

impl Identity {
    pub fn generate() -> Self {
        let mut rng = rand_core::OsRng;
        Identity { key: SigningKey::generate(&mut rng) }
    }

    pub fn from_seed(seed: [u8; 32]) -> Self {
        Identity { key: SigningKey::from_bytes(&seed) }
    }

    pub fn public(&self) -> VerifyingKey {
        self.key.verifying_key()
    }

    pub fn key_id(&self) -> String {
        key_id(&self.public())
    }

    pub fn sign_payload(&self, payload_type: &str, body: &str) -> Envelope {
        let sig = self.key.sign(&pae(payload_type, body.as_bytes()));
        Envelope {
            payload: B64.encode(body.as_bytes()),
            payload_type: payload_type.into(),
            signatures: vec![DsseSignature { keyid: self.key_id(), sig: B64.encode(sig.to_bytes()) }],
        }
    }

    pub fn sign_json<T: Serialize>(&self, payload_type: &str, value: &T) -> Envelope {
        self.sign_payload(payload_type, &serde_json::to_string(value).expect("serializable payload"))
    }

    /// Key file: {"format":"cursiv-robotics-key-1","key_id","public_key","seed_b64"}.
    /// Written with owner-only permissions where the platform supports it.
    pub fn save(&self, path: &Path) -> Result<(), String> {
        let body = serde_json::json!({
            "format": "cursiv-robotics-key-1",
            "key_id": self.key_id(),
            "public_key": public_b64(&self.public()),
            "seed_b64": B64.encode(self.key.to_bytes()),
        });
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        }
        let tmp = path.with_extension("tmp");
        {
            let mut opts = fs::OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let mut f = opts.open(&tmp).map_err(|e| format!("cannot create key file: {e}"))?;
            f.write_all(body.to_string().as_bytes()).map_err(|e| e.to_string())?;
            f.sync_all().map_err(|e| e.to_string())?;
        }
        fs::rename(&tmp, path).map_err(|e| e.to_string())
    }

    pub fn load(path: &Path) -> Result<Self, String> {
        let text = fs::read_to_string(path).map_err(|e| format!("cannot read key file: {e}"))?;
        let v: serde_json::Value = serde_json::from_str(&text).map_err(|_| "key file is not JSON".to_string())?;
        if v["format"] != "cursiv-robotics-key-1" {
            return Err("not a cursiv-robotics key file".into());
        }
        let seed = B64
            .decode(v["seed_b64"].as_str().unwrap_or(""))
            .map_err(|_| "key seed is not base64".to_string())?;
        let seed: [u8; 32] = seed.try_into().map_err(|_| "key seed is not 32 bytes".to_string())?;
        let id = Identity::from_seed(seed);
        if v["key_id"].as_str() != Some(id.key_id().as_str()) {
            return Err("key file's key_id does not match its key".into());
        }
        Ok(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pae_matches_the_dsse_spec_example() {
        assert_eq!(pae("application/example", b"hello world"), b"DSSEv1 19 application/example 11 hello world".to_vec());
    }

    #[test]
    fn sign_verify_and_tamper() {
        let id = Identity::from_seed([7u8; 32]);
        let env = id.sign_payload(RECORD_TYPE, "{\"a\":1}");
        assert!(env.verify_with(&id.public()));
        let mut bad = env.clone();
        bad.payload = B64.encode(b"{\"a\":2}");
        assert!(!bad.verify_with(&id.public()));
        let mut retyped = env.clone();
        retyped.payload_type = CHECKPOINT_TYPE.into();
        assert!(!retyped.verify_with(&id.public()), "payloadType is signed: no cross-type replay");
        let other = Identity::from_seed([8u8; 32]);
        assert!(!env.verify_with(&other.public()));
        let mut relabelled = env;
        relabelled.signatures[0].keyid = other.key_id();
        assert!(!relabelled.verify_with(&other.public()), "keyid is unauthenticated and cannot transfer a signature");
    }
}
