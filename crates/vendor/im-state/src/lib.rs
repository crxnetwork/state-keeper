//! smt2 (prefix-compacted keyed keccak tree) plus the two deterministic leaf-set → root builders.
//! KEY-BOUND. The registry stamps ONE constant value (`registry_leaf()`) at every present key; smt2's
//! `H_leaf = keccak(0x00‖key‖value)` folds the key in, so that constant can no longer alias across keys —
//! under the old positional hashing a single-entry registry rooted to the same bytes whatever its key.
#![forbid(unsafe_code)]
#![deny(missing_docs)]

/// Prefix-compacted keyed keccak tree — insert/delete/root/witness/fold/apply_step.
pub mod smt2;

use im_crypto::registry_leaf;

/// Fold account keys into the per-collateral registry (completeness) root.
pub fn credited_deposit_registry(keys: &[[u8; 32]]) -> [u8; 32] {
    let leaf = registry_leaf();
    let mut tree = smt2::Smt2::new();
    for k in keys {
        tree.insert(*k, leaf);
    }
    tree.root()
}

/// Reconstruct a per-collateral state root from `(aid, leaf)` entries.
pub fn prev_state_root(prev_leaves: &[([u8; 32], [u8; 32])]) -> [u8; 32] {
    let mut tree = smt2::Smt2::new();
    for (aid, leaf) in prev_leaves {
        tree.insert(*aid, *leaf);
    }
    tree.root()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn aid(seed: u8) -> [u8; 32] {
        let mut k = [0u8; 32];
        k[1] = seed;
        k[30] = seed.wrapping_mul(3);
        k
    }

    fn val(seed: u8) -> [u8; 32] {
        [seed | 0x80; 32]
    }

    #[test]
    fn registry_is_idempotent_under_duplicate_keys() {
        let once = credited_deposit_registry(&[aid(1), aid(2)]);
        let dup = credited_deposit_registry(&[aid(1), aid(2), aid(1), aid(2)]);
        assert_eq!(once, dup, "the membership marker is the same at every present key");
    }

    #[test]
    fn prev_state_root_binds_exact_balances() {
        let base = [(aid(1), val(1)), (aid(2), val(2))];
        let root = prev_state_root(&base);
        let mutated = [(aid(1), val(1)), (aid(2), [0x23u8; 32])];
        assert_ne!(root, prev_state_root(&mutated), "a forged balance changes the state root");
    }

    #[test]
    fn registry_leaf_constant_is_key_bound_under_compaction() {
        assert_ne!(
            credited_deposit_registry(&[aid(1)]),
            credited_deposit_registry(&[aid(2)]),
            "one constant value, two keys, two roots — the compaction unsoundness is closed"
        );
    }
}
