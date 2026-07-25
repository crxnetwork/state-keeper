//! keccak primitives plus the byte-exact ABI leaf/key encoders that must equal `LeafEncoding.sol`.
//! FROZEN. Every encoding is vkey-affecting and byte-mirrored by Solidity — a changed pad, field order, or
//! the `CRX/accountsRoot/v2` domain string breaks every prior proof. Layout is `abi.encode`: 32-byte words,
//! addresses left-padded, signed fields (`vmEquityUsd`, `side`) sign-extended over the high bytes. Leaves are
//! double-hashed `keccak(keccak(abi.encode(…)))` — the OZ guard against a second preimage.
//! DOMAINS. smt2 tags its nodes: leaf `keccak(0x00‖key‖value)`, internal `keccak(0x01‖l‖r)`. The tag stops an
//! internal node being presented as a leaf; the leaf tag binds the key to its value.
//! MERKLE. `positions_root` is OZ-shaped — parent `keccak(min‖max)`, odd node promoted, leaves sorted by
//! `terms_id` (the root binds the SET, not arrival order); the empty set roots to `bytes32(0)`. No money in
//! the tree: `account_leaf` = `{aid, vmEquityUsd, positionsRoot}`; collateral, IM and watermarks sit at the till.
#![forbid(unsafe_code)]
#![deny(missing_docs)]

use tiny_keccak::{Hasher, Keccak};

use im_types::PositionRecord;

/// `keccak256` over the concatenation of `parts`.
pub fn keccak(parts: &[&[u8]]) -> [u8; 32] {
    let mut k = Keccak::v256();
    for p in parts {
        k.update(p);
    }
    let mut out = [0u8; 32];
    k.finalize(&mut out);
    out
}

/// `keccak256(a ‖ b)` over two 32-byte words.
pub fn keccak_pair(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    keccak(&[&a[..], &b[..]])
}

/// smt2 leaf node `keccak256(0x00 ‖ key ‖ value)` — the key-binding wrapper over a frozen leaf value.
pub fn smt2_leaf(key: &[u8; 32], value: &[u8; 32]) -> [u8; 32] {
    keccak(&[&[0x00u8][..], &key[..], &value[..]])
}

/// smt2 internal node `keccak256(0x01 ‖ l ‖ r)`; directional.
pub fn smt2_node(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
    keccak(&[&[0x01u8][..], &l[..], &r[..]])
}

/// Single-address account key `keccak256(abi.encode(account_owner))`.
pub fn account_id_single(account_owner: [u8; 20]) -> [u8; 32] {
    let mut buf = [0u8; 32];
    buf[12..].copy_from_slice(&account_owner);
    keccak(&[&buf[..]])
}

/// Per-collateral account key `keccak256(abi.encode(token, account_owner))`.
pub fn account_id(token: [u8; 20], account_owner: [u8; 20]) -> [u8; 32] {
    let mut buf = [0u8; 64];
    buf[12..32].copy_from_slice(&token);
    buf[44..64].copy_from_slice(&account_owner);
    keccak(&[&buf[..]])
}

/// Double-hashed IM leaf `keccak(keccak(abi.encode(accountId, certifiedIm)))`.
pub fn im_leaf(aid: [u8; 32], certified_im: u128) -> [u8; 32] {
    let mut buf = [0u8; 64];
    buf[0..32].copy_from_slice(&aid);
    buf[48..64].copy_from_slice(&certified_im.to_be_bytes());
    let inner = keccak(&[&buf[..]]);
    keccak(&[&inner[..]])
}

/// Double-hashed Core 2.0 account leaf `{aid, vm_equity_usd, positions_root}`.
pub fn account_leaf(aid: [u8; 32], vm_equity_usd: i128, positions_root: [u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 96];

    buf[0..32].copy_from_slice(&aid);

    if vm_equity_usd < 0 {
        buf[32..48].fill(0xFF);
    }
    buf[48..64].copy_from_slice(&vm_equity_usd.to_be_bytes());

    buf[64..96].copy_from_slice(&positions_root);

    let inner = keccak(&[&buf[..]]);
    keccak(&[&inner[..]])
}

/// Domain-separation membership marker stamped at every present accounts-SMT key.
pub fn registry_leaf() -> [u8; 32] {
    keccak(&[b"CRX/accountsRoot/v2"])
}

/// Double-hashed 9-word position leaf.
pub fn position_leaf(b: &PositionRecord) -> [u8; 32] {
    let mut buf = [0u8; 288];

    buf[0..32].copy_from_slice(&b.terms_id);
    buf[44..64].copy_from_slice(&b.counterparty);
    buf[76..96].copy_from_slice(&b.oracle);
    buf[112..128].copy_from_slice(&b.notional.to_be_bytes());
    buf[144..160].copy_from_slice(&b.entry_rate.to_be_bytes());

    if b.side < 0 {
        buf[160..191].fill(0xFF);
    }
    buf[191] = b.side as u8;

    buf[216..224].copy_from_slice(&b.expiry.to_be_bytes());
    buf[240..256].copy_from_slice(&b.pushed_im.to_be_bytes());
    buf[256..288].copy_from_slice(&b.market_key);

    let inner = keccak(&[&buf[..]]);
    keccak(&[&inner[..]])
}

fn oz_hash_pair(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let (a, b) = if left <= right { (left, right) } else { (right, left) };
    keccak(&[&a[..], &b[..]])
}

/// OZ-compatible Merkle root over already-double-hashed leaves.
pub fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    debug_assert!(!leaves.is_empty(), "merkle_root on empty leaves");
    if leaves.len() == 1 {
        return leaves[0];
    }
    let mut current: Vec<[u8; 32]> = leaves.to_vec();
    while current.len() > 1 {
        let mut next = Vec::with_capacity((current.len() + 1) / 2);
        let mut i = 0;
        while i < current.len() {
            if i + 1 < current.len() {
                next.push(oz_hash_pair(current[i], current[i + 1]));
                i += 2;
            } else {
                next.push(current[i]);
                i += 1;
            }
        }
        current = next;
    }
    current[0]
}

/// OZ-compatible `positionsRoot` over the position leaves; empty set roots to `[0u8; 32]`.
pub fn positions_root(positions: &[PositionRecord]) -> [u8; 32] {
    if positions.is_empty() {
        return [0u8; 32];
    }
    let mut ordered: Vec<PositionRecord> = positions.to_vec();
    ordered.sort_by(|a, b| a.terms_id.cmp(&b.terms_id));
    let leaves: Vec<[u8; 32]> = ordered.iter().map(position_leaf).collect();
    merkle_root(&leaves)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const KECCAK_EMPTY: [u8; 32] = [
        0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03, 0xc0,
        0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85, 0xa4, 0x70,
    ];
    const KECCAK_ABC: [u8; 32] = [
        0x4e, 0x03, 0x65, 0x7a, 0xea, 0x45, 0xa9, 0x4f, 0xc7, 0xd4, 0x7b, 0xa8, 0x26, 0xc8, 0xd6, 0x67,
        0xc0, 0xd1, 0xe6, 0xe3, 0x3a, 0x64, 0xa0, 0x36, 0xec, 0x44, 0xf5, 0x8f, 0xa1, 0x2d, 0x6c, 0x45,
    ];

    fn sample_position(tag: u8) -> PositionRecord {
        PositionRecord {
            terms_id: [tag; 32],
            counterparty: [tag; 20],
            oracle: [tag.wrapping_add(1); 20],
            notional: 1_000 * (tag as u128 + 1),
            entry_rate: 1_234_567,
            side: if tag % 2 == 0 { 1 } else { -1 },
            expiry: 1_700_000_000 + tag as u64,
            pushed_im: 42,
            market_key: [tag.wrapping_add(2); 32],
        }
    }

    fn hex(bytes: [u8; 32]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn keccak_empty_known_answer() {
        assert_eq!(keccak(&[]), KECCAK_EMPTY, "keccak256 of no input");
        assert_eq!(keccak(&[b""]), KECCAK_EMPTY, "keccak256 of an empty slice is identical");
    }

    #[test]
    fn keccak_abc_known_answer() {
        assert_eq!(keccak(&[b"abc"]), KECCAK_ABC, "keccak256(\"abc\")");
    }

    #[test]
    fn keccak_concatenates_parts() {
        assert_eq!(keccak(&[b"ab", b"c"]), keccak(&[b"abc"]), "parts concatenate");
        assert_eq!(keccak(&[b"a", b"b", b"c"]), KECCAK_ABC, "three parts == abc");
    }

    /// Golden pin for owner `[0xAB; 20]` — a changed pad or word layout moves this digest.
    #[test]
    fn account_id_single_left_pads_the_owner() {
        assert_eq!(
            hex(account_id_single([0xAB; 20])),
            "fbf9dec37e25c45ae60799da9d3cd882ee00636c58f45888088dd90466d0974f",
            "pinned keccak256(abi.encode(owner))"
        );
    }

    /// Golden pin — the Rust `im_leaf` must equal the Solidity `_floor` leaf byte-for-byte.
    #[test]
    fn test_im_leaf_bytes_match_solidity() {
        let mut account_owner = [0u8; 20];
        account_owner[16] = 0xc0;
        account_owner[17] = 0xff;
        account_owner[18] = 0xee;
        account_owner[19] = 0x11;
        let aid = account_id_single(account_owner);
        let leaf = im_leaf(aid, 1_000_000u128);
        let expected_leaf: [u8; 32] = [
            0xbd, 0xd6, 0xa1, 0x23, 0xe2, 0x57, 0xe0, 0xbd,
            0x67, 0x4b, 0x2e, 0xb5, 0x3c, 0xe4, 0xca, 0x49,
            0x9a, 0xd2, 0x5b, 0x53, 0xd9, 0xcb, 0xd9, 0x90,
            0x4c, 0x53, 0x8e, 0xf2, 0xf9, 0x9d, 0x70, 0xd7,
        ];
        assert_eq!(leaf, expected_leaf, "Rust im_leaf MUST equal the Solidity _floor leaf byte-for-byte");
    }

    /// Golden pin plus the order-swap check — token and owner must stay in declaration order.
    #[test]
    fn account_id_encodes_token_then_owner() {
        let token = [0x11u8; 20];
        let owner = [0x22u8; 20];
        assert_ne!(account_id(token, owner), account_id(owner, token), "argument order is bound");
        assert_eq!(
            hex(account_id(token, owner)),
            "1bbe365357fe28ec15df954baa1b29fb309dd0e8a21208d768bce9ab1c0c4fd0",
            "pinned keccak256(abi.encode(token, owner))"
        );
    }

    /// Golden pin for a negative `vm_equity` leaf — dropping the 0xFF sign-fill moves this digest.
    #[test]
    fn account_leaf_sign_extends_negative_vm_equity() {
        let aid = [5u8; 32];
        let root = [6u8; 32];
        let neg = account_leaf(aid, -30, root);
        assert_ne!(account_leaf(aid, 30, root), neg, "sign of vm_equity changes the leaf");
        assert_ne!(neg, account_leaf(aid, -30, [7u8; 32]), "positions_root is bound");
        assert_eq!(
            hex(neg),
            "5456845e28b9ee1f9d24865b1f7ad3cd08b6d786f0b8c25a3694261cb5464e9b",
            "pinned digest for the sign-extended negative leaf"
        );
    }

    /// Golden pin for a short-side leaf — dropping the 0xFF sign-fill moves this digest.
    #[test]
    fn position_leaf_sign_extends_short_side() {
        let long = sample_position(0);
        let mut short = long;
        short.side = -1;
        assert_ne!(position_leaf(&long), position_leaf(&short), "the +1/−1 side is bound");
        assert_eq!(
            hex(position_leaf(&short)),
            "587c39a8e9fe0c9e83640cbfc645d21163b64f3f0f7427b025b7458408360849",
            "pinned digest for the sign-extended short leaf"
        );
    }

    /// Golden pin — a changed domain string or encoding breaks every prior registry proof.
    #[test]
    fn registry_leaf_is_the_frozen_domain_marker() {
        assert_eq!(
            hex(registry_leaf()),
            "9c5112afbff109dd8396b86179e84771d4ad9e3308158a335063d6b1b6bc73e6",
            "pinned keccak256(\"CRX/accountsRoot/v2\")"
        );
    }

    #[test]
    fn merkle_root_single_leaf_is_the_leaf() {
        let leaf = [9u8; 32];
        assert_eq!(merkle_root(&[leaf]), leaf, "a one-leaf tree roots to the leaf");
    }

    #[test]
    fn merkle_root_pair_is_order_independent() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        assert_eq!(merkle_root(&[a, b]), merkle_root(&[b, a]), "OZ hash pair is commutative");
    }

    /// Golden pin — a changed leaf tag or field order moves this digest.
    #[test]
    fn smt2_leaf_is_tag_00_over_key_and_value() {
        assert_eq!(
            hex(smt2_leaf(&[0x11; 32], &[0x22; 32])),
            "0cb3a67a36faf39b819f3cdce46a6f1e99beecd44ea7c264fbe76a900a067783",
            "pinned keccak256(0x00 ‖ key ‖ value)"
        );
    }

    /// Golden pin plus the left/right direction check.
    #[test]
    fn smt2_node_is_tag_01_over_children() {
        let l = [0x33u8; 32];
        let r = [0x44u8; 32];
        assert_ne!(smt2_node(&l, &r), smt2_node(&r, &l), "H_node is directional");
        assert_eq!(
            hex(smt2_node(&l, &r)),
            "ef4edb2522bbf5f46f019c89e8897abc222b6287fb145d20d55d69cf5dc7085d",
            "pinned keccak256(0x01 ‖ l ‖ r)"
        );
    }

    #[test]
    fn smt2_domains_never_collide() {
        let a = [0x55u8; 32];
        let b = [0x66u8; 32];
        assert_ne!(smt2_leaf(&a, &b), smt2_node(&a, &b), "0x00 vs 0x01 tag separates the domains");
        assert_ne!(smt2_leaf(&a, &b), [0u8; 32]);
        assert_ne!(smt2_node(&a, &b), [0u8; 32]);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]

        #[test]
        fn positions_root_is_permutation_invariant(tags in proptest::collection::hash_set(any::<u8>(), 1..6)) {
            let mut positions: Vec<PositionRecord> = tags.into_iter().map(sample_position).collect();
            let root = positions_root(&positions);
            positions.reverse();
            prop_assert_eq!(root, positions_root(&positions));
        }
    }
}
