//! smt2 — prefix-compacted keyed keccak tree (JMT-style) over 256-bit keys.
//! CANONICAL FORM (mandatory). No internal node with two EMPTY children; no internal node whose subtree holds
//! exactly one leaf — such a subtree IS that leaf, at the highest level where its key prefix is unique. Root of
//! the empty map = EMPTY = bytes32(0). Leaf `H_leaf(k,v) = keccak(0x00‖k‖v)`; internal `H_node(l,r) =
//! keccak(0x01‖l‖r)`. The byte contract is mirrored by the Solidity verifier — see docs/smt-encoding-spec.md.
//! SORTED-UNIQUE PRECONDITION. `subtree_root` requires strictly-ascending unique keys, which the BTreeMap
//! guarantees. Duplicates break the pigeonhole termination argument and would drive `key_bit` past bit 255.
//! The guard is a plain `assert!`, not `debug_assert!`: the release profile strips debug assertions and the
//! host runs in release.
//! APPLY_STEP is the guest primitive and fails closed by panicking. The terminal must SAY what the caller
//! claims; the witness must fold to the running root (no stale paths); an `OtherLeaf` absence must share the
//! witness-depth prefix with the key, or absence could be forged. Insert splits on collision at the first
//! diverging bit. Delete promotes a lone sibling leaf upward to restore canonicality — hence `delete_kind`,
//! an unforgeable preimage of the first non-EMPTY sibling, which the domain tags make impossible to lie about.

use im_crypto::{smt2_leaf, smt2_node};
use im_types::{SmtTerminal, SiblingKind, SmtWitness};
use std::collections::BTreeMap;

/// The empty subtree at any height; also the root of the empty map.
pub const EMPTY: [u8; 32] = [0u8; 32];

/// Bit at position `i` (0 = MSB of `key[0]`); `true` descends right.
#[inline]
pub fn key_bit(key: &[u8; 32], i: usize) -> bool {
    (key[i / 8] >> (7 - (i % 8))) & 1 == 1
}

/// Host-side canonical map; the root is a pure function of the key⇒value map by construction.
pub struct Smt2 {
    leaves: BTreeMap<[u8; 32], [u8; 32]>,
}

impl Smt2 {
    /// A fresh empty map (root = EMPTY).
    pub fn new() -> Self {
        Smt2 { leaves: BTreeMap::new() }
    }

    /// Upsert `key ⇒ value`.
    pub fn insert(&mut self, key: [u8; 32], value: [u8; 32]) {
        self.leaves.insert(key, value);
    }

    /// Remove `key` (no-op if absent).
    pub fn remove(&mut self, key: &[u8; 32]) {
        self.leaves.remove(key);
    }

    /// The stored value at `key`, if present.
    pub fn get(&self, key: &[u8; 32]) -> Option<[u8; 32]> {
        self.leaves.get(key).copied()
    }

    /// Canonical root — a pure function of the map, computed structurally.
    pub fn root(&self) -> [u8; 32] {
        let entries: Vec<(&[u8; 32], &[u8; 32])> = self.leaves.iter().collect();
        subtree_root(&entries, 0)
    }
}

impl Default for Smt2 {
    fn default() -> Self {
        Self::new()
    }
}

/// Canonical root of the sorted `entries` viewed as a subtree at `depth`; keys MUST be ascending and unique.
pub fn subtree_root(entries: &[(&[u8; 32], &[u8; 32])], depth: usize) -> [u8; 32] {
    assert!(
        entries.windows(2).all(|w| w[0].0 < w[1].0),
        "subtree_root: entries must be sorted ascending by key with no duplicates"
    );
    match entries {
        [] => EMPTY,
        [(k, v)] => smt2_leaf(k, v),
        _ => {
            let split = entries.partition_point(|(k, _)| !key_bit(k, depth));
            smt2_node(&subtree_root(&entries[..split], depth + 1), &subtree_root(&entries[split..], depth + 1))
        }
    }
}

impl Smt2 {
    /// Build a map from `(key, value)` entries — `Smt2::new()` plus one insert per entry.
    pub fn from_leaves(entries: &[([u8; 32], [u8; 32])]) -> Smt2 {
        let mut t = Smt2::new();
        for (k, v) in entries {
            t.insert(*k, *v);
        }
        t
    }

    /// Witness `key` against the CURRENT tree (membership or absence), with `delete_kind` where a delete could need it.
    pub fn witness(&self, key: &[u8; 32]) -> SmtWitness {
        let entries: Vec<(&[u8; 32], &[u8; 32])> = self.leaves.iter().collect();
        let mut siblings_root_first: Vec<[u8; 32]> = Vec::new();
        let mut set: &[(&[u8; 32], &[u8; 32])] = &entries;
        let mut depth = 0usize;
        let terminal = loop {
            match set {
                [] => break SmtTerminal::Empty,
                [(k, v)] => {
                    break if *k == key {
                        SmtTerminal::Leaf(**v)
                    } else {
                        SmtTerminal::OtherLeaf(**k, **v)
                    }
                }
                _ => {
                    let split = set.partition_point(|(k, _)| !key_bit(k, depth));
                    let (kept, sib) = if key_bit(key, depth) {
                        (&set[split..], &set[..split])
                    } else {
                        (&set[..split], &set[split..])
                    };
                    siblings_root_first.push(subtree_root(sib, depth + 1));
                    set = kept;
                    depth += 1;
                }
            }
        };
        let siblings: Vec<[u8; 32]> = siblings_root_first.into_iter().rev().collect();
        let delete_kind = if matches!(terminal, SmtTerminal::Leaf(_)) {
            self.first_nonempty_sibling_kind(key, &siblings)
        } else {
            None
        };
        SmtWitness { key: *key, siblings, terminal, delete_kind }
    }

    /// Kind-proof for the FIRST non-EMPTY sibling above `key`'s leaf, if any.
    fn first_nonempty_sibling_kind(&self, key: &[u8; 32], siblings: &[[u8; 32]]) -> Option<SiblingKind> {
        let depth = siblings.len();
        let i = siblings.iter().position(|s| *s != EMPTY)?;
        let lvl = depth - 1 - i;
        let entries: Vec<(&[u8; 32], &[u8; 32])> = self
            .leaves
            .iter()
            .filter(|(k, _)| {
                (0..lvl).all(|b| key_bit(k, b) == key_bit(key, b)) && key_bit(k, lvl) != key_bit(key, lvl)
            })
            .collect();
        Some(match entries.as_slice() {
            [(k, v)] => SiblingKind::Leaf { key: **k, value: **v },
            many => {
                let split = many.partition_point(|(k, _)| !key_bit(k, lvl + 1));
                SiblingKind::Node {
                    left: subtree_root(&many[..split], lvl + 2),
                    right: subtree_root(&many[split..], lvl + 2),
                }
            }
        })
    }

    /// Witness `key`, then apply `key := new` (Some = upsert, None = delete); call in guest processing order.
    pub fn step(&mut self, key: [u8; 32], new: Option<[u8; 32]>) -> SmtWitness {
        let w = self.witness(&key);
        match new {
            Some(v) => self.insert(key, v),
            None => self.remove(&key),
        }
        w
    }
}

/// Fold `start` up through `w.siblings` along `w.key`'s bits; pure, no canonicality checks.
fn fold_up(w: &SmtWitness, start: [u8; 32]) -> [u8; 32] {
    let depth = w.siblings.len();
    let mut cur = start;
    for (i, sib) in w.siblings.iter().enumerate() {
        cur = if key_bit(&w.key, depth - 1 - i) { smt2_node(sib, &cur) } else { smt2_node(&cur, sib) };
    }
    cur
}

/// The terminal's start value, with the frozen absence checks.
fn terminal_start(w: &SmtWitness) -> [u8; 32] {
    match &w.terminal {
        SmtTerminal::Leaf(v) => smt2_leaf(&w.key, v),
        SmtTerminal::Empty => EMPTY,
        SmtTerminal::OtherLeaf(ok, ov) => {
            assert!(*ok != w.key, "smt2: OtherLeaf carries the witness's own key");
            let depth = w.siblings.len();
            assert!(
                (0..depth).all(|b| key_bit(ok, b) == key_bit(&w.key, b)),
                "smt2: OtherLeaf fails the diverging-key prefix check — absence would be forged"
            );
            smt2_leaf(ok, ov)
        }
    }
}

/// First bit index at which `a` and `b` differ. Panics if equal.
fn first_diverging_bit(a: &[u8; 32], b: &[u8; 32]) -> usize {
    (0..256).find(|i| key_bit(a, *i) != key_bit(b, *i)).expect("smt2: keys are identical")
}

/// Prove `old` at `w.key` under `running`, then return the root with `new` applied; panics on any inconsistency.
pub fn apply_step(
    running: [u8; 32],
    w: &SmtWitness,
    old: Option<[u8; 32]>,
    new: Option<[u8; 32]>,
) -> [u8; 32] {
    assert!(w.siblings.len() <= 256, "smt2: witness depth exceeds 256");
    match (&w.terminal, &old) {
        (SmtTerminal::Leaf(v), Some(o)) => assert!(v == o, "smt2: terminal leaf != claimed prior value"),
        (SmtTerminal::Empty, None) | (SmtTerminal::OtherLeaf(..), None) => {}
        _ => panic!("smt2: terminal kind contradicts the claimed prior presence"),
    }
    assert!(
        fold_up(w, terminal_start(w)) == running,
        "smt2: stale path — witness does not fold to the running root"
    );
    match (old, new) {
        (Some(_), Some(n)) => fold_up(w, smt2_leaf(&w.key, &n)),
        (None, Some(n)) => {
            let leaf = smt2_leaf(&w.key, &n);
            match &w.terminal {
                SmtTerminal::Empty => fold_up(w, leaf),
                SmtTerminal::OtherLeaf(ok, ov) => {
                    let depth = w.siblings.len();
                    let j = first_diverging_bit(&w.key, ok);
                    let other = smt2_leaf(ok, ov);
                    let mut cur = if key_bit(&w.key, j) {
                        smt2_node(&other, &leaf)
                    } else {
                        smt2_node(&leaf, &other)
                    };
                    for lvl in (depth..j).rev() {
                        cur = if key_bit(&w.key, lvl) { smt2_node(&EMPTY, &cur) } else { smt2_node(&cur, &EMPTY) };
                    }
                    fold_up(w, cur)
                }
                SmtTerminal::Leaf(_) => unreachable!("old-binding above rejects this"),
            }
        }
        (Some(_), None) => {
            let depth = w.siblings.len();
            match w.siblings.iter().position(|s| *s != EMPTY) {
                None => EMPTY,
                Some(i) => {
                    let s = w.siblings[i];
                    let kind = w
                        .delete_kind
                        .as_ref()
                        .expect("smt2: delete needs a delete_kind proof for the first non-EMPTY sibling");
                    match kind {
                        SiblingKind::Leaf { key: sk, value: sv } => {
                            assert!(
                                smt2_leaf(sk, sv) == s,
                                "smt2: delete_kind Leaf preimage does not hash to the sibling"
                            );
                            let mut cur = s;
                            let mut j = i + 1;
                            while j < depth && w.siblings[j] == EMPTY {
                                j += 1;
                            }
                            if j == depth {
                                return cur;
                            }
                            cur = if key_bit(&w.key, depth - 1 - j) {
                                smt2_node(&w.siblings[j], &cur)
                            } else {
                                smt2_node(&cur, &w.siblings[j])
                            };
                            for (idx, sib) in w.siblings.iter().enumerate().skip(j + 1) {
                                cur = if key_bit(&w.key, depth - 1 - idx) {
                                    smt2_node(sib, &cur)
                                } else {
                                    smt2_node(&cur, sib)
                                };
                            }
                            cur
                        }
                        SiblingKind::Node { left, right } => {
                            assert!(
                                smt2_node(left, right) == s,
                                "smt2: delete_kind Node preimage does not hash to the sibling"
                            );
                            let mut cur = EMPTY;
                            for (idx, sib) in w.siblings.iter().enumerate().skip(i) {
                                cur = if key_bit(&w.key, depth - 1 - idx) {
                                    smt2_node(sib, &cur)
                                } else {
                                    smt2_node(&cur, sib)
                                };
                            }
                            cur
                        }
                    }
                }
            }
        }
        (None, None) => panic!("smt2: a no-op step (absent → absent) is not a step"),
    }
}

/// Host/test convenience: apply `steps` to `prior` in order, returning the sequential witnesses and final root.
pub fn witness_sequence(
    prior: &[([u8; 32], [u8; 32])],
    steps: &[([u8; 32], Option<[u8; 32]>)],
) -> (Vec<SmtWitness>, [u8; 32]) {
    let mut t = Smt2::new();
    for (k, v) in prior {
        t.insert(*k, *v);
    }
    let ws = steps.iter().map(|(k, new)| t.step(*k, *new)).collect();
    (ws, t.root())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn key(seed: u8) -> [u8; 32] {
        let mut k = [seed; 32];
        k[0] = seed.wrapping_mul(31);
        k[31] = seed ^ 0xA5;
        k
    }
    fn val(seed: u8) -> [u8; 32] {
        [seed | 0x80; 32]
    }

    #[test]
    fn empty_map_roots_to_empty() {
        assert_eq!(Smt2::new().root(), EMPTY, "root of the empty map = bytes32(0)");
    }

    #[test]
    fn single_leaf_map_roots_to_the_leaf_node() {
        let mut t = Smt2::new();
        t.insert(key(1), val(1));
        assert_eq!(t.root(), smt2_leaf(&key(1), &val(1)), "one-entry map roots to H_leaf(key, value)");
    }

    #[test]
    fn two_leaves_split_at_first_diverging_bit() {
        let mut a = [0x22u8; 32];
        a[31] = 0xAA;
        let mut b = a;
        b[31] ^= 0x01;
        let mut t = Smt2::new();
        t.insert(a, val(1));
        t.insert(b, val(2));
        let mut cur = smt2_node(&smt2_leaf(&a, &val(1)), &smt2_leaf(&b, &val(2)));
        for lvl in (0..255).rev() {
            cur = if key_bit(&a, lvl) { smt2_node(&EMPTY, &cur) } else { smt2_node(&cur, &EMPTY) };
        }
        assert_eq!(t.root(), cur, "hand-folded 2-leaf tree matches");
    }

    #[test]
    fn delete_and_reinsert_restore_canonical_roots() {
        let mut t = Smt2::new();
        t.insert(key(1), val(1));
        let one = t.root();
        t.insert(key(2), val(2));
        t.remove(&key(2));
        assert_eq!(t.root(), one, "delete merges back to the single-leaf root (canonicality)");
        t.remove(&key(1));
        assert_eq!(t.root(), EMPTY, "deleting the last leaf restores EMPTY");
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(48))]

        #[test]
        fn root_is_a_pure_function_of_the_map(
            map in proptest::collection::hash_map(any::<[u8; 32]>(), any::<[u8; 32]>(), 0..8)
        ) {
            let entries: Vec<_> = map.into_iter().collect();
            let mut fwd = Smt2::new();
            for (k, v) in &entries { fwd.insert(*k, *v); }
            let mut rev = Smt2::new();
            for (k, v) in entries.iter().rev() { rev.insert(*k, *v); }
            prop_assert_eq!(fwd.root(), rev.root());
        }

        #[test]
        fn insert_then_delete_is_identity(
            map in proptest::collection::hash_map(any::<[u8; 32]>(), any::<[u8; 32]>(), 1..6),
            extra_k in any::<[u8; 32]>(),
            extra_v in any::<[u8; 32]>(),
        ) {
            prop_assume!(!map.contains_key(&extra_k));
            let mut t = Smt2::new();
            for (k, v) in &map { t.insert(*k, *v); }
            let before = t.root();
            t.insert(extra_k, extra_v);
            prop_assert_ne!(t.root(), before, "a new leaf must move the root");
            t.remove(&extra_k);
            prop_assert_eq!(t.root(), before, "delete must merge back to the canonical root");
        }
    }

    #[test]
    #[should_panic(expected = "sorted ascending")]
    fn subtree_root_rejects_unsorted_or_duplicate_entries() {
        let k = key(7);
        let v1 = val(1);
        let v2 = val(2);
        let entries: Vec<(&[u8; 32], &[u8; 32])> = vec![(&k, &v1), (&k, &v2)];
        let _ = subtree_root(&entries, 0);
    }

    #[test]
    fn witness_folds_to_root_for_present_and_absent_keys() {
        let mut t = Smt2::new();
        let entries = [(key(1), val(1)), (key(2), val(2)), (key(9), val(9))];
        for (k, v) in entries { t.insert(k, v); }
        let root = t.root();
        for (k, v) in entries {
            let w = t.witness(&k);
            assert!(matches!(w.terminal, SmtTerminal::Leaf(x) if x == v));
            assert_eq!(apply_step(root, &w, Some(v), Some(v)), root, "no-op step round-trips the root");
        }
        let absent = key(200);
        let w = t.witness(&absent);
        assert!(matches!(w.terminal, SmtTerminal::Empty | SmtTerminal::OtherLeaf(..)));
        let new_root = apply_step(root, &w, None, Some(val(7)));
        t.insert(absent, val(7));
        assert_eq!(new_root, t.root(), "insert via witness == host rebuild");
    }

    #[test]
    #[should_panic(expected = "stale")]
    fn stale_witness_is_rejected() {
        let mut t = Smt2::new();
        t.insert(key(1), val(1));
        t.insert(key(2), val(2));
        let w_stale = t.witness(&key(1));
        t.insert(key(3), val(3));
        let _ = apply_step(t.root(), &w_stale, Some(val(1)), Some(val(11)));
    }

    #[test]
    #[should_panic(expected = "diverging-key")]
    fn forged_absence_prefix_mismatch_is_rejected() {
        let mut ok = [0u8; 32];
        ok[0] = 0b1000_0000;
        let mut k = [0u8; 32];
        k[31] = 1;
        let w = SmtWitness {
            key: k,
            siblings: vec![[0x11; 32]],
            terminal: SmtTerminal::OtherLeaf(ok, [0x22; 32]),
            delete_kind: None,
        };
        let _ = apply_step([0x33; 32], &w, None, Some([0x44; 32]));
    }

    #[test]
    #[should_panic(expected = "own key")]
    fn other_leaf_equal_to_key_is_rejected() {
        let k = key(4);
        let w = SmtWitness {
            key: k,
            siblings: vec![],
            terminal: SmtTerminal::OtherLeaf(k, val(4)),
            delete_kind: None,
        };
        let _ = apply_step(smt2_leaf(&k, &val(4)), &w, None, Some(val(9)));
    }

    #[test]
    #[should_panic(expected = "depth")]
    fn witness_deeper_than_256_is_rejected() {
        let w = SmtWitness {
            key: key(1),
            siblings: vec![[0u8; 32]; 257],
            terminal: SmtTerminal::Empty,
            delete_kind: None,
        };
        let _ = apply_step([0x55; 32], &w, None, Some(val(1)));
    }

    #[test]
    #[should_panic(expected = "delete_kind")]
    fn delete_kind_preimage_must_match_the_sibling() {
        let mut t = Smt2::new();
        t.insert(key(1), val(1));
        t.insert(key(2), val(2));
        let mut w = t.step(key(1), None);
        w.delete_kind = Some(SiblingKind::Node { left: [9; 32], right: [9; 32] });
        let mut t2 = Smt2::new();
        t2.insert(key(1), val(1));
        t2.insert(key(2), val(2));
        let _ = apply_step(t2.root(), &w, Some(val(1)), None);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(48))]

        #[test]
        fn threaded_steps_track_the_host_tree(
            base in proptest::collection::hash_map(any::<[u8; 32]>(), any::<[u8; 32]>(), 0..6),
            ops in proptest::collection::vec((any::<[u8; 32]>(), proptest::option::of(any::<[u8; 32]>())), 1..8),
        ) {
            let mut host = Smt2::new();
            for (k, v) in &base { host.insert(*k, *v); }
            let mut running = host.root();
            for (k, new) in ops {
                let old = host.get(&k);
                if old.is_none() && new.is_none() { continue; }
                let w = host.step(k, new);
                running = apply_step(running, &w, old, new);
                prop_assert_eq!(running, host.root());
            }
        }
    }
}
