//! The guest↔chain boundary: every hash and key here MUST equal its Solidity counterpart byte-for-byte —
//! `market_key`/`pair_tag_of`, the EIP-712 typehashes and struct hashes, the signing digest, the `entry_rate` read.
//! The `im-crypto` leaf (keccak + leaf/id encoders + OZ Merkle builders) re-exports flat through the crate root, so
//! one module audits the whole wire contract. Struct hashes are hand-packed `abi.encode`: word N occupies bytes
//! `[32N, 32N+32)`, each scalar right-aligned within its word. The typehash STRINGS are FROZEN WIRE — hashed into every
//! signature, so field lists and struct names move only in lockstep with `Rfq.sol`/`EIP712Lib`, and the consent digests
//! stay distinct so no signature minted for one purpose satisfies another.

use im_crypto::keccak;

/// Market-registry key `keccak256(abi.encode(instrument, pairTag))` — byte-identical to on-chain.
pub fn market_key(instrument: u8, pair_tag: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 64];
    buf[31] = instrument;
    buf[32..64].copy_from_slice(pair_tag);
    keccak(&[&buf[..]])
}

/// A position's pause key for the chain's `assetPaused` set, derived from the position's oracle.
pub fn pair_tag_of(oracle: &[u8; 20]) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[12..32].copy_from_slice(oracle);
    keccak(&[&word[..]])
}

fn terms_typehash() -> [u8; 32] {
    keccak(&[b"Terms(address partyA,address partyB,address oracle,bytes32 pairTag,uint256 quantity,uint16 imBpsA,uint16 imBpsB,uint16 mmPct,uint40 expiry,uint64 nonce,uint64 cureWindow,uint8 payoutPrefA,uint8 payoutPrefB,bytes data,uint8 instrument,int8 side)"])
}

/// Recompute position identity `Rfq.id(Terms 2.1)` — 17 words (typehash + 16 fields), byte-identical to on-chain.
#[allow(clippy::too_many_arguments)]
pub fn terms_id(
    party_a: &[u8; 20],
    party_b: &[u8; 20],
    oracle: &[u8; 20],
    pair_tag: &[u8; 32],
    quantity: u128,
    im_bps_a: u16,
    im_bps_b: u16,
    mm_pct: u16,
    expiry: u64,
    nonce: u64,
    cure_window: u64,
    payout_pref_a: u8,
    payout_pref_b: u8,
    data: &[u8],
    instrument: u8,
    side: i8,
) -> [u8; 32] {
    let mut buf = [0u8; 544];
    buf[0..32].copy_from_slice(&terms_typehash());
    buf[44..64].copy_from_slice(party_a);
    buf[76..96].copy_from_slice(party_b);
    buf[108..128].copy_from_slice(oracle);
    buf[128..160].copy_from_slice(pair_tag);
    buf[176..192].copy_from_slice(&quantity.to_be_bytes());
    buf[222..224].copy_from_slice(&im_bps_a.to_be_bytes());
    buf[254..256].copy_from_slice(&im_bps_b.to_be_bytes());
    buf[286..288].copy_from_slice(&mm_pct.to_be_bytes());
    buf[312..320].copy_from_slice(&expiry.to_be_bytes());
    buf[344..352].copy_from_slice(&nonce.to_be_bytes());
    buf[376..384].copy_from_slice(&cure_window.to_be_bytes());
    buf[415] = payout_pref_a;
    buf[447] = payout_pref_b;
    let data_hash = keccak(&[data]);
    buf[448..480].copy_from_slice(&data_hash);
    buf[511] = instrument;
    // word 16: int8 side — abi.encode sign-extends the high 31 bytes for a short (−1 = 0xFF..FF), same as
    // `im_crypto::position_leaf`'s int256 side encoding. Positive/zero: high bytes stay 0, low byte set.
    if side < 0 {
        buf[512..543].fill(0xFF);
    }
    buf[543] = side as u8;
    keccak(&[&buf[..]])
}

/// The EIP-712 signing digest: `keccak256("\x19\x01" ‖ domain_separator ‖ struct_hash)`.
pub fn eip712_digest(domain_separator: &[u8; 32], struct_hash: &[u8; 32]) -> [u8; 32] {
    keccak(&[&[0x19u8, 0x01u8], &domain_separator[..], &struct_hash[..]])
}

/// A position's bound `entry_rate` per on-chain `Crx._entryRate`: word 0 of signed `data`; `None` if it exceeds `u128`.
pub fn entry_rate_from_data(data: &[u8]) -> Option<u128> {
    if data.len() < 32 {
        return Some(0);
    }
    if data[..16].iter().any(|&x| x != 0) {
        return None;
    }
    let mut lo = [0u8; 16];
    lo.copy_from_slice(&data[16..32]);
    Some(u128::from_be_bytes(lo))
}

/// EIP-712 `FailoverConsent` typehash — the forced-closeout consent C signs; the struct name is frozen wire.
pub fn failover_consent_typehash() -> [u8; 32] {
    keccak(&[b"FailoverConsent(bytes32 oldId,address taker,bytes32 feedId,uint64 closeTime,uint128 cIm,uint128 spread,uint64 nonce,uint64 deadline)"])
}

/// `FailoverConsent` struct hash over `(oldId, taker, feedId, closeTime, cIm, spread, nonce, deadline)`.
#[allow(clippy::too_many_arguments)]
pub fn failover_consent_struct_hash(
    old_id: &[u8; 32],
    taker: &[u8; 20],
    feed_id: &[u8; 32],
    close_time: u64,
    c_im: u128,
    spread: u128,
    nonce: u64,
    deadline: u64,
) -> [u8; 32] {
    let mut buf = [0u8; 288];
    buf[0..32].copy_from_slice(&failover_consent_typehash());
    buf[32..64].copy_from_slice(old_id);
    buf[76..96].copy_from_slice(taker);
    buf[96..128].copy_from_slice(feed_id);
    buf[152..160].copy_from_slice(&close_time.to_be_bytes());
    buf[176..192].copy_from_slice(&c_im.to_be_bytes());
    buf[208..224].copy_from_slice(&spread.to_be_bytes());
    buf[248..256].copy_from_slice(&nonce.to_be_bytes());
    buf[280..288].copy_from_slice(&deadline.to_be_bytes());
    keccak(&[&buf[..]])
}

/// EIP-712 `NovationTakeover` typehash — C's voluntary consent, carrying a signed PRICE, never a feed id or close time.
pub fn novation_takeover_typehash() -> [u8; 32] {
    keccak(&[b"NovationTakeover(bytes32 oldId,address taker,uint128 transferPrice,uint16 cImBps,uint128 cIm,uint128 spread,uint64 nonce,uint64 deadline)"])
}

/// `NovationTakeover` struct hash over `(oldId, taker, transferPrice, cImBps, cIm, spread, nonce, deadline)`.
#[allow(clippy::too_many_arguments)]
pub fn novation_takeover_struct_hash(
    old_id: &[u8; 32],
    taker: &[u8; 20],
    transfer_price: u128,
    c_im_bps: u16,
    c_im: u128,
    spread: u128,
    nonce: u64,
    deadline: u64,
) -> [u8; 32] {
    let mut buf = [0u8; 288];
    buf[0..32].copy_from_slice(&novation_takeover_typehash());
    buf[32..64].copy_from_slice(old_id);
    buf[76..96].copy_from_slice(taker);
    buf[112..128].copy_from_slice(&transfer_price.to_be_bytes());
    buf[158..160].copy_from_slice(&c_im_bps.to_be_bytes());
    buf[176..192].copy_from_slice(&c_im.to_be_bytes());
    buf[208..224].copy_from_slice(&spread.to_be_bytes());
    buf[248..256].copy_from_slice(&nonce.to_be_bytes());
    buf[280..288].copy_from_slice(&deadline.to_be_bytes());
    keccak(&[&buf[..]])
}

/// EIP-712 `Closeout` typehash — the bilateral tear-up consent BOTH parties sign over the SAME digest (F2). A
/// distinct struct name from the three novation consents, so no unwind signature can ever authorize a novation
/// (and vice versa). FROZEN WIRE: byte-identical to `EIP712Lib.CLOSEOUT_TYPEHASH`, so it re-keys the vkey if touched.
pub fn closeout_typehash() -> [u8; 32] {
    keccak(&[b"Closeout(bytes32 positionId,uint128 closePrice,uint64 nonce,uint64 deadline)"])
}

/// `Closeout` struct hash over `(positionId, closePrice, nonce, deadline)` — the digest A and B both sign.
pub fn closeout_struct_hash(position_id: &[u8; 32], close_price: u128, nonce: u64, deadline: u64) -> [u8; 32] {
    let mut buf = [0u8; 160];
    buf[0..32].copy_from_slice(&closeout_typehash());
    buf[32..64].copy_from_slice(position_id);
    buf[80..96].copy_from_slice(&close_price.to_be_bytes());
    buf[120..128].copy_from_slice(&nonce.to_be_bytes());
    buf[152..160].copy_from_slice(&deadline.to_be_bytes());
    keccak(&[&buf[..]])
}

/// The bilateral-unwind authorization commitment (F2, discriminator `2`) — `keccak256(abi.encode(oldId, partyA,
/// partyB, closePrice, uint8(2), nonce, deadline))`, byte-identical to `Encode.unwindCommitment`. The `uint8(2)`
/// tag sits BETWEEN `closePrice` and `nonce` and keeps the image distinct from novation (`0`) and closeout (`1`).
/// `finalizeUnwinds` recomputes this on-chain from the surfaced [`crate::Unwind`] fields, so the guest surfaces
/// exactly the seven pre-images it hashes; this mirror re-derives them so the wire cannot drift silently.
pub fn unwind_commitment(
    old_id: &[u8; 32],
    party_a: &[u8; 20],
    party_b: &[u8; 20],
    close_price: u128,
    nonce: u64,
    deadline: u64,
) -> [u8; 32] {
    let mut buf = [0u8; 224];
    buf[0..32].copy_from_slice(old_id);
    buf[44..64].copy_from_slice(party_a);
    buf[76..96].copy_from_slice(party_b);
    buf[112..128].copy_from_slice(&close_price.to_be_bytes());
    buf[159] = 2;
    buf[184..192].copy_from_slice(&nonce.to_be_bytes());
    buf[216..224].copy_from_slice(&deadline.to_be_bytes());
    keccak(&[&buf[..]])
}

#[cfg(test)]
mod tests {
    use crate::test_util::*;
    use crate::*;

    #[test]
    fn terms_id_recompute_is_sensitive_to_economics() {
        let nb = a_new_position();
        let id0 = terms_id(&nb.party_a, &nb.party_b, &nb.oracle, &nb.pair_tag, nb.quantity,
            nb.im_bps_a, nb.im_bps_b, nb.mm_pct, nb.expiry, nb.nonce, nb.cure_window, nb.payout_pref_a, nb.payout_pref_b, &nb.data, nb.instrument, nb.side_a);
        assert_eq!(id0, nb.terms_id, "state_transition reproduces the claimed id");
        let id_bps = terms_id(&nb.party_a, &nb.party_b, &nb.oracle, &nb.pair_tag, nb.quantity,
            0, nb.im_bps_b, nb.mm_pct, nb.expiry, nb.nonce, nb.cure_window, nb.payout_pref_a, nb.payout_pref_b, &nb.data, nb.instrument, nb.side_a);
        assert_ne!(id_bps, nb.terms_id, "im_bps is bound into the id");
        let id_qty = terms_id(&nb.party_a, &nb.party_b, &nb.oracle, &nb.pair_tag, nb.quantity + 1,
            nb.im_bps_a, nb.im_bps_b, nb.mm_pct, nb.expiry, nb.nonce, nb.cure_window, nb.payout_pref_a, nb.payout_pref_b, &nb.data, nb.instrument, nb.side_a);
        assert_ne!(id_qty, nb.terms_id, "quantity is bound into the id");
        let id_data = terms_id(&nb.party_a, &nb.party_b, &nb.oracle, &nb.pair_tag, nb.quantity,
            nb.im_bps_a, nb.im_bps_b, nb.mm_pct, nb.expiry, nb.nonce, nb.cure_window, nb.payout_pref_a, nb.payout_pref_b, &nb_data_for_entry(1), nb.instrument, nb.side_a);
        assert_ne!(id_data, nb.terms_id, "entry rate (inside data) is bound into the id");
        let id_inst = terms_id(&nb.party_a, &nb.party_b, &nb.oracle, &nb.pair_tag, nb.quantity,
            nb.im_bps_a, nb.im_bps_b, nb.mm_pct, nb.expiry, nb.nonce, nb.cure_window, nb.payout_pref_a, nb.payout_pref_b, &nb.data, nb.instrument + 1, nb.side_a);
        assert_ne!(id_inst, nb.terms_id, "instrument is bound into the id");
        // F-2 (Terms 2.1): side is now a named typehash field — perturbing it must change the id.
        let id_side = terms_id(&nb.party_a, &nb.party_b, &nb.oracle, &nb.pair_tag, nb.quantity,
            nb.im_bps_a, nb.im_bps_b, nb.mm_pct, nb.expiry, nb.nonce, nb.cure_window, nb.payout_pref_a, nb.payout_pref_b, &nb.data, nb.instrument, -nb.side_a);
        assert_ne!(id_side, nb.terms_id, "side is bound into the id (Terms 2.1, F-2 close)");
        let id_pref = terms_id(&nb.party_a, &nb.party_b, &nb.oracle, &nb.pair_tag, nb.quantity,
            nb.im_bps_a, nb.im_bps_b, nb.mm_pct, nb.expiry, nb.nonce, nb.cure_window, nb.payout_pref_a + 1, nb.payout_pref_b, &nb.data, nb.instrument, nb.side_a);
        assert_ne!(id_pref, nb.terms_id, "payoutPrefA is bound into the id (Terms 2.0)");
    }

    #[test]
    fn closeout_struct_hash_is_field_sensitive() {
        let id = [0x11u8; 32];
        let base = closeout_struct_hash(&id, 44_000, 7, 1_700_001_000);
        assert_eq!(base, closeout_struct_hash(&id, 44_000, 7, 1_700_001_000), "deterministic");
        assert_ne!(base, closeout_struct_hash(&[0x12u8; 32], 44_000, 7, 1_700_001_000), "positionId bound");
        assert_ne!(base, closeout_struct_hash(&id, 44_001, 7, 1_700_001_000), "closePrice bound");
        assert_ne!(base, closeout_struct_hash(&id, 44_000, 8, 1_700_001_000), "nonce bound");
        assert_ne!(base, closeout_struct_hash(&id, 44_000, 7, 1_700_001_001), "deadline bound");
        assert_ne!(base, novation_takeover_typehash(), "distinct from the novation consents");
    }

    #[test]
    fn unwind_commitment_is_field_sensitive_and_tags_discriminator_2() {
        let id = [0xF6u8; 32];
        let a = [0xF7u8; 20];
        let b = [0xF8u8; 20];
        let base = unwind_commitment(&id, &a, &b, 44_000, 7, 1_700_001_000);
        assert_eq!(base, unwind_commitment(&id, &a, &b, 44_000, 7, 1_700_001_000), "deterministic");
        assert_ne!(base, unwind_commitment(&[0xF5u8; 32], &a, &b, 44_000, 7, 1_700_001_000), "oldId bound");
        assert_ne!(base, unwind_commitment(&id, &[0x00u8; 20], &b, 44_000, 7, 1_700_001_000), "partyA bound");
        assert_ne!(base, unwind_commitment(&id, &a, &[0x00u8; 20], 44_000, 7, 1_700_001_000), "partyB bound");
        assert_ne!(base, unwind_commitment(&id, &a, &b, 44_001, 7, 1_700_001_000), "closePrice bound");
        assert_ne!(base, unwind_commitment(&id, &a, &b, 44_000, 8, 1_700_001_000), "nonce bound");
        assert_ne!(base, unwind_commitment(&id, &a, &b, 44_000, 7, 1_700_001_001), "deadline bound");
        // A→B and B→A are distinct — the ordered parties are bound into the commitment.
        assert_ne!(base, unwind_commitment(&id, &b, &a, 44_000, 7, 1_700_001_000), "party order bound");
    }

    #[test]
    fn entry_rate_from_data_matches_contract_semantics() {
        assert_eq!(entry_rate_from_data(&[]), Some(0), "empty data ⇒ 0");
        assert_eq!(entry_rate_from_data(&[0u8; 16]), Some(0), "short data ⇒ 0");
        assert_eq!(entry_rate_from_data(&nb_data_for_entry(1_080_000)), Some(1_080_000), "first word");
        let mut big = vec![0u8; 32];
        big[0] = 0x01;
        assert_eq!(entry_rate_from_data(&big), None, "over-u128 first word ⇒ None");
    }
}
