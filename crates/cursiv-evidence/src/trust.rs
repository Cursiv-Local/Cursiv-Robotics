//! Trust store: which keys are allowed to speak for which robot or station.
//!
//! Supplied by the operator out of band (never taken from a package being
//! verified). A signature by a key that is not listed is "untrusted": the
//! payload may be internally consistent, but nothing establishes who wrote it.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TrustedKey {
    pub key_id: String,
    pub public_key: String,
    /// active | retired | revoked. Retired keys verify history; revoked keys verify nothing.
    pub status: String,
    pub note: Option<String>,
    /// For a rotated key: records with seq >= this were signed by this key.
    pub valid_from_seq: Option<u64>,
    /// For a retired key: records with seq > this must not be signed by it.
    pub valid_until_seq: Option<u64>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TrustStore {
    pub format: String,
    /// robot_id -> keys
    pub robots: BTreeMap<String, Vec<TrustedKey>>,
    /// station_id -> keys
    pub stations: BTreeMap<String, Vec<TrustedKey>>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyVerdict {
    Trusted,
    /// The key is known but not for this record (outside its seq window).
    OutOfWindow,
    Revoked,
    Unknown,
    /// No trust store was supplied: authenticity cannot be assessed.
    NoTrustStore,
}

impl TrustStore {
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("cannot read trust store: {e}"))?;
        let t: TrustStore = serde_json::from_str(&text).map_err(|e| format!("trust store is invalid: {e}"))?;
        if t.format != "cursiv-trust-1" {
            return Err("trust store format must be cursiv-trust-1".into());
        }
        Ok(t)
    }

    pub fn robot(&self, robot_id: &str, keyid: &str) -> Option<&TrustedKey> {
        self.robots.get(robot_id)?.iter().find(|k| k.key_id == keyid)
    }

    pub fn station(&self, station_id: &str, keyid: &str) -> Option<&TrustedKey> {
        self.stations.get(station_id)?.iter().find(|k| k.key_id == keyid)
    }

    /// Whether a listed key may sign record `seq` (None: not seq-bound, e.g. checkpoints).
    pub fn verdict(k: &TrustedKey, seq: Option<u64>) -> KeyVerdict {
        if k.status == "revoked" {
            return KeyVerdict::Revoked;
        }
        if let Some(s) = seq {
            if k.valid_from_seq.is_some_and(|f| s < f) || k.valid_until_seq.is_some_and(|u| s > u) {
                return KeyVerdict::OutOfWindow;
            }
        }
        if k.status == "active" || k.status == "retired" { KeyVerdict::Trusted } else { KeyVerdict::Unknown }
    }
}
