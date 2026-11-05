//! Merkle tree over record hashes (RFC 6962 style: 0x00 leaf / 0x01 node prefixes,
//! the largest power of two split). A checkpoint's root commits to every record
//! 1..=count in order, so a verifier can check a whole segment against one signature.

use sha2::{Digest, Sha256};

fn leaf(hash_hex: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0u8]);
    h.update(hash_hex.as_bytes());
    h.finalize().into()
}

fn node(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([1u8]);
    h.update(l);
    h.update(r);
    h.finalize().into()
}

fn root_of(leaves: &[[u8; 32]]) -> [u8; 32] {
    match leaves.len() {
        0 => Sha256::digest(b"").into(),
        1 => leaves[0],
        n => {
            let mut k = 1;
            while k * 2 < n {
                k *= 2;
            }
            node(&root_of(&leaves[..k]), &root_of(&leaves[k..]))
        }
    }
}

/// Root (hex) over the given record payload hashes, in order.
pub fn root(hashes: &[String]) -> String {
    let leaves: Vec<[u8; 32]> = hashes.iter().map(|h| leaf(h)).collect();
    hex::encode(root_of(&leaves))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_changes_with_any_leaf_or_order() {
        let hs: Vec<String> = (0..7).map(|i| format!("{i:064}")).collect();
        let r = root(&hs);
        let mut swapped = hs.clone();
        swapped.swap(2, 3);
        assert_ne!(r, root(&swapped));
        let mut changed = hs.clone();
        changed[6] = format!("{:064}", 9);
        assert_ne!(r, root(&changed));
        assert_ne!(r, root(&hs[..6]));
        assert_eq!(r, root(&hs));
    }
}
