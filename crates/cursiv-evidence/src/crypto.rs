//! Hashing, Ed25519 identities and signed envelopes.
//!
//! An envelope carries the *exact payload bytes* that were signed (as a JSON
//! string), so a verifier never has to re-serialize JSON identically to the
//! writer. Hashes and signatures are over those bytes. This avoids the
//! cross-language canonical-JSON problem (number formatting, key order).
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

/// A signed payload. `payload` is the exact UTF-8 JSON text that was signed.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub payload: String,
    pub key_id: String,
    pub public_key: String,
    pub signature: String,
}

impl Envelope {
    /// SHA-256 of the exact payload bytes: the record's identity in chains and Merkle trees.
    pub fn payload_hash(&self) -> String {
        sha256_hex(self.payload.as_bytes())
    }

    /// True when the signature matches the payload and the public key it names, and
    /// key_id is that key's id. Integrity only: says nothing about who holds the key.
    pub fn signature_valid(&self) -> bool {
        let Ok(pk) = parse_public_b64(&self.public_key) else { return false };
        if key_id(&pk) != self.key_id {
            return false;
        }
        let Ok(raw) = B64.decode(&self.signature) else { return false };
        let Ok(sig) = Signature::from_slice(&raw) else { return false };
        pk.verify_strict(self.payload.as_bytes(), &sig).is_ok()
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

    pub fn sign_payload(&self, payload: String) -> Envelope {
        let sig = self.key.sign(payload.as_bytes());
        Envelope {
            payload,
            key_id: self.key_id(),
            public_key: public_b64(&self.public()),
            signature: B64.encode(sig.to_bytes()),
        }
    }

    pub fn sign_json<T: Serialize>(&self, value: &T) -> Envelope {
        self.sign_payload(serde_json::to_string(value).expect("serializable payload"))
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
    fn sign_verify_and_tamper() {
        let id = Identity::from_seed([7u8; 32]);
        let env = id.sign_payload("{\"a\":1}".into());
        assert!(env.signature_valid());
        let mut bad = env.clone();
        bad.payload = "{\"a\":2}".into();
        assert!(!bad.signature_valid());
        let mut wrong_id = env.clone();
        wrong_id.key_id = "0000000000000000".into();
        assert!(!wrong_id.signature_valid());
        let other = Identity::from_seed([8u8; 32]);
        let mut swapped = env;
        swapped.public_key = public_b64(&other.public());
        swapped.key_id = other.key_id();
        assert!(!swapped.signature_valid());
    }
}
