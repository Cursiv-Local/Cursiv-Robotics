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

/// The RFC 6962 leaf hash of a record payload hash (hex), for [`Frontier::push_leaf`].
pub fn leaf_hash(hash_hex: &str) -> [u8; 32] {
    leaf(hash_hex)
}

/// Root (hex) over the given record payload hashes, in order.
pub fn root(hashes: &[String]) -> String {
    let leaves: Vec<[u8; 32]> = hashes.iter().map(|h| leaf(h)).collect();
    hex::encode(root_of(&leaves))
}

/// Incremental form of [`root`]: push leaves one at a time and ask for the root at any point,
/// in O(log n) memory. Gives exactly the same root as `root` over the same hashes
/// (property-tested), so a verifier can stream a multi-gigabyte log without holding it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Frontier {
    /// Perfect subtrees, largest first: (number of leaves, subtree hash).
    stack: Vec<(u64, [u8; 32])>,
    count: u64,
}

impl Frontier {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn count(&self) -> u64 {
        self.count
    }

    /// Add the next record payload hash (hex).
    pub fn push(&mut self, hash_hex: &str) {
        self.push_leaf(leaf(hash_hex));
    }

    /// Add a leaf already computed with [`leaf_hash`] (saves re-hashing when one record goes
    /// into several frontiers).
    pub fn push_leaf(&mut self, leaf: [u8; 32]) {
        let mut node_hash = leaf;
        let mut size = 1u64;
        while let Some(&(s, h)) = self.stack.last() {
            if s != size {
                break;
            }
            self.stack.pop();
            node_hash = node(&h, &node_hash);
            size *= 2;
        }
        self.stack.push((size, node_hash));
        self.count += 1;
    }

    /// Root (hex) over every leaf pushed so far.
    pub fn root(&self) -> String {
        let mut it = self.stack.iter().rev();
        let Some(&(_, mut acc)) = it.next() else {
            return hex::encode(Sha256::digest(b""));
        };
        for (_, h) in it {
            acc = node(h, &acc);
        }
        hex::encode(acc)
    }

    /// Serialisable state, so a store can resume a frontier without re-reading sealed segments.
    pub fn to_state(&self) -> serde_json::Value {
        serde_json::json!({"count": self.count, "nodes": self.stack.iter().map(|(s, h)| serde_json::json!([s, hex::encode(h)])).collect::<Vec<_>>()})
    }

    pub fn from_state(v: &serde_json::Value) -> Option<Self> {
        let count = v["count"].as_u64()?;
        let mut stack = Vec::new();
        for n in v["nodes"].as_array()? {
            let size = n[0].as_u64()?;
            let bytes = hex::decode(n[1].as_str()?).ok()?;
            stack.push((size, <[u8; 32]>::try_from(bytes.as_slice()).ok()?));
        }
        // sizes must be strictly decreasing powers of two that add up to count
        let ok = stack.iter().map(|(s, _)| *s).sum::<u64>() == count
            && stack.iter().all(|(s, _)| s.is_power_of_two())
            && stack.windows(2).all(|w| w[0].0 > w[1].0);
        ok.then_some(Frontier { stack, count })
    }
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

    #[test]
    fn frontier_matches_the_recursive_root_at_every_size() {
        let hs: Vec<String> = (0..300).map(|i| format!("{i:064}")).collect();
        let mut f = Frontier::new();
        assert_eq!(f.root(), root(&[]));
        for n in 1..=hs.len() {
            f.push(&hs[n - 1]);
            assert_eq!(f.root(), root(&hs[..n]), "size {n}");
            assert_eq!(Frontier::from_state(&f.to_state()).as_ref(), Some(&f));
        }
    }
}
