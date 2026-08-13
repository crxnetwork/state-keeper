//! Shared test fixtures — reference positions, ISDA rosters, and EIP-712 signing helpers — used by the
//! per-module test suites. Compiled only under `cfg(test)`; the guest never sees this module.

use crate::*;

use k256::ecdsa::{signature::hazmat::PrehashSigner, RecoveryId, Signature as K256Sig, SigningKey};

/// Fixture seat IM, in bps — the RETIRED static protocol floor's old value (781), kept only so the
/// reference fixtures' pushed_im figures stay byte-stable. There is NO protocol minimum any more.
pub(crate) const TEST_SEAT_IM_BPS: u16 = 781;

pub(crate) fn empty_ri() -> RiskInputs {
    RiskInputs {
        unconsumed_settle_residual: None,
        positions: vec![],
        position_settlements: vec![],
        proven_twaps: vec![],
        proven_marks: vec![],
    }
}

pub(crate) fn hex_str(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

pub(crate) fn feed_for(oracle: [u8; 20]) -> [u8; 32] {
    let mut f = [0u8; 32];
    f[12..32].copy_from_slice(&oracle);
    f
}

pub(crate) fn rk(seed: u8) -> [u8; 32] {
    let mut k = [seed; 32];
    k[0] = seed.wrapping_mul(73).wrapping_add(5);
    k[11] = seed ^ 0x3C;
    k[31] = seed.wrapping_add(0x9E);
    k
}

pub(crate) fn reference_account_owner() -> [u8; 20] {
    let mut c = [0u8; 20];
    c[16] = 0xc0;
    c[17] = 0xff;
    c[18] = 0xee;
    c[19] = 0x11;
    c
}
pub(crate) fn reference_box0() -> PositionRecord {
    PositionRecord {
        terms_id: [0x11u8; 32],
        counterparty: { let mut a = [0u8; 20]; a[19] = 0xb0; a },
        oracle: { let mut a = [0u8; 20]; a[18] = 0x0e; a[19] = 0x71; a },
        notional: 1_000_000u128,
        entry_rate: 1_080_000u128,
        side: 1,
        expiry: 1_700_000_000u64,
        pushed_im: 70_000u128,
        market_key: [0xA0u8; 32],
    }
}
pub(crate) fn reference_box1() -> PositionRecord {
    PositionRecord {
        terms_id: [0x22u8; 32],
        counterparty: { let mut a = [0u8; 20]; a[19] = 0xb1; a },
        oracle: { let mut a = [0u8; 20]; a[18] = 0x0e; a[19] = 0x72; a },
        notional: 2_000_000u128,
        entry_rate: 990_000u128,
        side: -1,
        expiry: 1_700_086_400u64,
        pushed_im: 140_000u128,
        market_key: [0xB1u8; 32],
    }
}

pub(crate) fn fx_position(
    counterparty: [u8; 20],
    oracle: [u8; 20],
    pair: &[u8],
    notional_usd: u128,
    side: i8,
    terms_byte: u8,
) -> PositionRecord {
    const M: u128 = 1_000_000;
    let notional = notional_usd * M;
    PositionRecord {
        terms_id: [terms_byte; 32],
        counterparty,
        oracle,
        notional,
        entry_rate: 1_000_000,
        side,
        expiry: 2_000_000_000,
        pushed_im: im_for_side(notional, TEST_SEAT_IM_BPS),
        market_key: market_key(INSTRUMENT_NDF, &keccak(&[pair])),
    }
}

pub(crate) fn cop_position(notional_usd: u128, side: i8, terms_byte: u8) -> PositionRecord {
    fx_position([0xC0u8; 20], [0x3u8; 20], b"USD/COP", notional_usd, side, terms_byte)
}

pub(crate) fn brl_position(notional_usd: u128, side: i8, terms_byte: u8) -> PositionRecord {
    fx_position([0xC1u8; 20], [0x4u8; 20], b"USD/BRL", notional_usd, side, terms_byte)
}

/// The shared test scenario table: every fixture market gets a column; scenario 0 is a −10% shock across
/// the board, scenario 1 a +5% rally, the remaining 98 are quiet (sparse-empty). m = 1, so ES is
/// the single worst scenario: 10% of |net| for a long, 5% for a short.
pub(crate) fn test_table() -> ScenarioTable {
    let cols: Vec<[u8; 32]> = vec![
        market_key(INSTRUMENT_NDF, &keccak(&[b"USD/COP"])),
        market_key(INSTRUMENT_NDF, &keccak(&[b"USD/BRL"])),
        market_key(INSTRUMENT_NDF, &keccak(&[b"EUR/USD"])),
        market_key(INSTRUMENT_NDF, &keccak(&[b"USD/INR"])),
        market_key(INSTRUMENT_NDF, &[0x99u8; 32]),
        [0xA0u8; 32],
        [0xB1u8; 32],
        [0xC2u8; 32],
        [0u8; 32],
    ];
    let n = cols.len();
    let down: Vec<(u16, i128)> = (0..n).map(|c| (c as u16, -ONE_I / 10)).collect();
    let up: Vec<(u16, i128)> = (0..n).map(|c| (c as u16, ONE_I / 20)).collect();
    let mut rows = vec![down, up];
    rows.resize(100, vec![]);
    ScenarioTable { version: 1, k: 100, m: 1, market_keys: cols, rows }
}

pub(crate) fn nb_sk_a() -> SigningKey { SigningKey::from_bytes(&[0x11u8; 32].into()).unwrap() }
pub(crate) fn nb_sk_b() -> SigningKey { SigningKey::from_bytes(&[0x22u8; 32].into()).unwrap() }

pub(crate) fn nb_eth_addr(sk: &SigningKey) -> [u8; 20] {
    let pt = sk.verifying_key().to_encoded_point(false);
    let h = keccak(&[&pt.as_bytes()[1..]]);
    let mut a = [0u8; 20];
    a.copy_from_slice(&h[12..]);
    a
}

pub(crate) fn new_party_a() -> [u8; 20] { nb_eth_addr(&nb_sk_a()) }
pub(crate) fn new_party_b() -> [u8; 20] { nb_eth_addr(&nb_sk_b()) }
pub(crate) fn nb_domain() -> [u8; 32] { [0x5Cu8; 32] }

pub(crate) fn nb_sign(sk: &SigningKey, digest: &[u8; 32]) -> Vec<u8> {
    let (sig, rid): (K256Sig, RecoveryId) = sk.sign_prehash(digest).expect("sign");
    let b = sig.to_bytes();
    let mut out = Vec::with_capacity(65);
    out.extend_from_slice(&b[..64]);
    out.push(rid.to_byte());
    out
}

pub(crate) fn nb_data_for_entry(entry_rate: u128) -> Vec<u8> {
    let mut d = vec![0u8; 32];
    d[16..32].copy_from_slice(&entry_rate.to_be_bytes());
    d
}

/// The reference dual-sig new position (Core 2.1 Terms), partyA long (`side_a = 1`).
pub(crate) fn a_new_position() -> NewPosition {
    signed_new_position(1)
}

/// Build a fully-signed `NewPosition` for a given `side_a`, threading it into `terms_id` (Terms 2.1) so the
/// recomputed id matches the signed one. Lets a test exercise both polar sides AND a non-polar side that is
/// genuinely signed into the id (so the id-recompute passes and the polarity floor is what fires).
pub(crate) fn signed_new_position(side_a: i8) -> NewPosition {
    let party_a = new_party_a();
    let party_b = new_party_b();
    let oracle = { let mut a = [0u8; 20]; a[18] = 0x0e; a[19] = 0x71; a };
    let quantity = 1_000_000u128;
    let entry_rate = 1_080_000u128;
    let expiry = 1_700_000_000u64;
    let im_bps_a = 800u16;
    let im_bps_b = 900u16;
    let pair_tag = [0x99u8; 32];
    let mm_pct = 5_000u16;
    let nonce = 7u64;
    let cure_window = 3_600u64;
    let (payout_pref_a, payout_pref_b) = (0u8, 0u8);
    let data = nb_data_for_entry(entry_rate);
    let instrument = 1u8;
    let terms_id = terms_id(
        &party_a, &party_b, &oracle, &pair_tag, quantity,
        im_bps_a, im_bps_b, mm_pct, expiry, nonce, cure_window,
        payout_pref_a, payout_pref_b, &data, instrument, side_a,
    );
    let domain_separator = nb_domain();
    let digest = eip712_digest(&domain_separator, &terms_id);
    let sig_a = nb_sign(&nb_sk_a(), &digest);
    let sig_b = nb_sign(&nb_sk_b(), &digest);
    NewPosition {
        terms_id, party_a, party_b, oracle, quantity, entry_rate, side_a, expiry,
        im_bps_a, im_bps_b, instrument, pair_tag, mm_pct, nonce, cure_window,
        payout_pref_a, payout_pref_b, data, sig_a, sig_b, domain_separator,
    }
}

pub(crate) fn nov_party_a() -> [u8; 20] {
    let mut a = [0u8; 20];
    a[19] = 0xAA;
    a
}
pub(crate) fn nov_sk_c() -> k256::ecdsa::SigningKey {
    k256::ecdsa::SigningKey::from_bytes(&[0xCCu8; 32].into()).unwrap()
}
pub(crate) fn nov_party_c() -> [u8; 20] {
    nov_eth_addr_of(&nov_sk_c())
}
pub(crate) fn nov_eth_addr_of(sk: &k256::ecdsa::SigningKey) -> [u8; 20] {
    let pt = sk.verifying_key().to_encoded_point(false);
    let h = keccak(&[&pt.as_bytes()[1..]]);
    let mut a = [0u8; 20];
    a.copy_from_slice(&h[12..]);
    a
}
pub(crate) fn nov_domain() -> [u8; 32] { [0x5Cu8; 32] }

/// Build a signed VOLUNTARY witness (Core 2.0: no leaf money; C signs the price it funds).
pub(crate) fn nov_w(a_position: PositionRecord, mark: u128, c_im: u128, spread: u128) -> NovationWitness {
    let mut w = NovationWitness {
        a_position, mark, c_im,
        party_a: nov_party_a(), party_c: nov_party_c(),
        kind: NovationKind::Voluntary,
        transfer_price: mark, spread, c_im_bps: 800, nonce: 0, deadline: 1_700_000_900,
        domain_separator: nov_domain(), sig_c: Vec::new(),
    };
    nov_sign_c(&mut w);
    w
}

/// A FORCED witness carries no signed maker quote (default handoff).
pub(crate) fn nov_w_forced(a_position: PositionRecord, mark: u128, c_im: u128) -> NovationWitness {
    NovationWitness {
        a_position, mark, c_im,
        party_a: nov_party_a(), party_c: nov_party_c(),
        kind: NovationKind::Forced,
        transfer_price: 0, spread: 0, c_im_bps: 0, nonce: 0, deadline: 0,
        domain_separator: [0u8; 32], sig_c: Vec::new(),
    }
}

pub(crate) fn nov_sign_c(w: &mut NovationWitness) {
    use k256::ecdsa::{signature::hazmat::PrehashSigner, RecoveryId, Signature as K256Sig};
    let consent = novation_takeover_struct_hash(
        &w.a_position.terms_id, &w.party_c, w.transfer_price, w.c_im_bps, w.c_im, w.spread, w.nonce, w.deadline,
    );
    let digest = eip712_digest(&w.domain_separator, &consent);
    let (sig, rid): (K256Sig, RecoveryId) = nov_sk_c().sign_prehash(&digest).expect("sign");
    let b = sig.to_bytes();
    let mut out = Vec::with_capacity(65);
    out.extend_from_slice(&b[..64]);
    out.push(rid.to_byte());
    w.sig_c = out;
}

pub(crate) fn nov_valid_witness() -> NovationWitness {
    nov_w(reference_box0(), 1_050_000, 60_000, 0)
}

pub(crate) fn nov_entry_for(w: &NovationWitness) -> Novation {
    transfer_as_close(w).entry.expect("the honest valid witness must produce an entry")
}

pub(crate) fn nov_entry_literal(w: &NovationWitness) -> Novation {
    Novation {
        old_id: w.a_position.terms_id,
        new_id: novation_new_id(&w.a_position.terms_id, &w.party_c),
        party_a: w.party_a,
        party_b: w.a_position.counterparty,
        party_c: w.party_c,
        c_im: w.c_im,
        forced: 0,
        transfer_price: w.transfer_price,
        spread: w.spread,
        nonce: w.nonce,
        deadline: w.deadline,
    }
}

/// Sign the `Closeout` digest over `(old_id, close_price, nonce, deadline)` with `sk` under `domain`.
pub(crate) fn unwind_sign(
    sk: &SigningKey,
    domain: &[u8; 32],
    old_id: &[u8; 32],
    close_price: u128,
    nonce: u64,
    deadline: u64,
) -> Vec<u8> {
    let struct_hash = closeout_struct_hash(old_id, close_price, nonce, deadline);
    let digest = eip712_digest(domain, &struct_hash);
    nb_sign(sk, &digest)
}

/// A valid bilateral-unwind witness: A = `nb_sk_a` (leaf owner), B = `nb_sk_b` (A's counterparty), both signing
/// the SAME `Closeout` digest over `a_position` at `close_price`. `a_position.counterparty` is forced to B.
pub(crate) fn unwind_valid_witness(a_position: PositionRecord, close_price: u128) -> UnwindWitness {
    let party_a = new_party_a();
    let party_b = new_party_b();
    let a_position = PositionRecord { counterparty: party_b, ..a_position };
    let nonce = 7u64;
    let deadline = 1_700_001_000u64;
    let domain_separator = nb_domain();
    let sig_a = unwind_sign(&nb_sk_a(), &domain_separator, &a_position.terms_id, close_price, nonce, deadline);
    let sig_b = unwind_sign(&nb_sk_b(), &domain_separator, &a_position.terms_id, close_price, nonce, deadline);
    UnwindWitness { a_position, close_price, party_a, party_b, nonce, deadline, domain_separator, sig_a, sig_b }
}

pub(crate) fn fo_sk_c() -> SigningKey {
    SigningKey::from_bytes(&[0x33u8; 32].into()).unwrap()
}
pub(crate) fn closeout_novation_party_c() -> [u8; 20] {
    nb_eth_addr(&fo_sk_c())
}

pub(crate) fn fo_valid_witness() -> CloseoutNovationWitness {
    let party_a = new_party_a();
    let party_b = new_party_b();
    let party_c = closeout_novation_party_c();
    let oracle = { let mut a = [0u8; 20]; a[18] = 0x0e; a[19] = 0x71; a };
    let quantity = 1_000_000u128;
    let entry_rate = 1_080_000u128;
    let expiry = 1_700_000_000u64;
    let im_bps_a = 800u16;
    let im_bps_b = 900u16;
    let pair_tag = [0x99u8; 32];
    let mm_pct = 5_000u16;
    let terms_nonce = 7u64;
    let cure_window = 3_600u64;
    let (payout_pref_a, payout_pref_b) = (0u8, 0u8);
    let data = nb_data_for_entry(entry_rate);

    let terms_id = terms_id(
        &party_a, &party_b, &oracle, &pair_tag, quantity, im_bps_a, im_bps_b, mm_pct,
        expiry, terms_nonce, cure_window, payout_pref_a, payout_pref_b, &data, 1u8, 1,
    );
    let notional = gross_notional(quantity, entry_rate);
    let pushed_im = im_for_side(notional, im_bps_a);

    let a_position = PositionRecord {
        terms_id,
        counterparty: party_b,
        oracle,
        notional,
        entry_rate,
        side: 1,
        expiry,
        pushed_im,
        market_key: [0u8; 32],
    };

    let c_im = 90_000u128;
    let spread = 50_000u128;
    let m_a_authorized = 96_400u128;

    let domain_separator = nb_domain();
    let feed_id = feed_for(oracle);
    let close_time = 1_700_000_500u64;
    let nonce = 0u64;
    let deadline = 1_700_000_900u64;
    let proven_twap = ProvenTwap { feed_id, close_time, settle_price: 1_000_000, expo: -6 };

    let consent = failover_consent_struct_hash(&terms_id, &party_c, &feed_id, close_time, c_im, spread, nonce, deadline);
    let digest = eip712_digest(&domain_separator, &consent);
    let sig_c = nb_sign(&fo_sk_c(), &digest);

    CloseoutNovationWitness {
        a_position,
        proven_twap,
        c_im,
        spread,
        party_a,
        party_c,
        sig_c,
        nonce,
        deadline,
        domain_separator,
        m_a_authorized,
        pair_tag,
        quantity,
        im_bps_a,
        im_bps_b,
        mm_pct,
        terms_nonce,
        cure_window,
        payout_pref_a,
        payout_pref_b,
        data,
        instrument: 1u8,
    }
}

pub(crate) fn fo_resign(w: &mut CloseoutNovationWitness) {
    let consent = failover_consent_struct_hash(
        &w.a_position.terms_id, &w.party_c, &w.proven_twap.feed_id, w.proven_twap.close_time, w.c_im,
        w.spread, w.nonce, w.deadline,
    );
    let digest = eip712_digest(&w.domain_separator, &consent);
    w.sig_c = nb_sign(&fo_sk_c(), &digest);
}
