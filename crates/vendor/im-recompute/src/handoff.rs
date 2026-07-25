//! The A→C close lifecycle (Core 2.0) — NO money in the tree. Both close paths MOVE A's leg to C (terms verbatim, id
//! re-derived `keccak256(old_id ‖ party_c)`, `pushed_im = c_im`) and EMIT the cash as `Settlement`s; solvency and IM
//! coverage are enforced ON-CHAIN. B is untouched, so the A↔B P&L is SURFACED as a claim. A FORCED close carries no
//! signed maker quote: no consent, no maker cash, tail zeroed.

use serde::{Serialize, Deserialize};
use crate::signed_price;
use crate::{PositionRecord, NovationWitness, Novation, NovationKind, CloseoutNovationWitness, CloseoutNovation,
    Settlement, keccak, gross_notional,
    novation_takeover_struct_hash, failover_consent_struct_hash,
    eip712_digest, closeout_novation_spread_within_best_exec, feed_id_oracle,
    settle_native_to_1e6, position_vm, terms_id, entry_rate_from_data};

/// Why a novation rejected — atomic, nothing moved.
#[derive(Clone, Copy, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub enum NovationReject {
    /// Handoff mark is zero — no priceable leg.
    QuoteBelowMark,
}

/// Proof result of one `transfer_as_close`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransferAsCloseResult {
    /// A (outgoing) — leg closed.
    pub party_a: [u8; 20],
    /// C (incoming maker) — inherits the leg.
    pub party_c: [u8; 20],
    /// The position C now holds (`new_id`, terms copied from A's leg, `pushed_im = c_im`).
    pub c_moved: PositionRecord,
    /// Signed A↔B P&L at the mark (A's side).
    pub pnl: i128,
    /// A↔C cash: the funded mark (voluntary) and the maker spread.
    pub settlements: Vec<Settlement>,
    /// Voluntary vs forced (carried for indexers).
    pub kind: NovationKind,
    /// `None` on success; `Some(reason)` on atomic reject.
    pub reject: Option<NovationReject>,
    /// The `Novation` public-values entry (`None` on reject).
    pub entry: Option<Novation>,
}

fn zero_position() -> PositionRecord {
    PositionRecord {
        terms_id: [0u8; 32],
        counterparty: [0u8; 20],
        oracle: [0u8; 20],
        notional: 0,
        entry_rate: 0,
        side: 0,
        expiry: 0,
        pushed_im: 0,
        market_key: [0u8; 32],
    }
}

/// Voluntary, maker-funded novation: C's signed `transfer_price` MUST equal the witness mark, so a raw keeper mark is forbidden and C's cash — never the pool — funds the handoff, which is what stops an in-the-money novation minting.
pub fn transfer_as_close(w: &NovationWitness) -> TransferAsCloseResult {
    let a_position = &w.a_position;
    let old_id = a_position.terms_id;
    let (party_a, party_c, kind) = (w.party_a, w.party_c, w.kind);

    let reject_with = |reason: NovationReject| TransferAsCloseResult {
        party_a,
        party_c,
        c_moved: zero_position(),
        pnl: 0,
        settlements: Vec::new(),
        kind,
        reject: Some(reason),
        entry: None,
    };

    if matches!(kind, NovationKind::Voluntary) {
        assert_eq!(
            w.mark, w.transfer_price,
            "novation: witness mark != C's signed transferPrice — a raw keeper mark is forbidden (voluntary funded price)"
        );
        let consent_hash = novation_takeover_struct_hash(
            &old_id, &party_c, w.transfer_price, w.c_im_bps, w.c_im, w.spread, w.nonce, w.deadline,
        );
        let digest = eip712_digest(&w.domain_separator, &consent_hash);
        assert_eq!(
            signed_price::recover_eth_signer(&digest, &w.sig_c),
            party_c,
            "novation: NovationTakeover does not recover partyC — forged/missing C consent (price/cIm/spread/nonce/domain)"
        );
    }

    if w.mark == 0 {
        return reject_with(NovationReject::QuoteBelowMark);
    }

    let pnl = position_vm(a_position.entry_rate, w.mark, a_position.notional, a_position.side);

    let mut settlements: Vec<Settlement> = Vec::new();
    if matches!(kind, NovationKind::Voluntary) {
        if pnl > 0 {
            settlements.push(Settlement { payer: party_c, payee: party_a, usd: pnl as u128, id: old_id });
        } else if pnl < 0 {
            settlements.push(Settlement { payer: party_a, payee: party_c, usd: pnl.unsigned_abs(), id: old_id });
        }
        if w.spread > 0 {
            settlements.push(Settlement { payer: party_a, payee: party_c, usd: w.spread, id: old_id });
        }
    }

    let new_id = novation_new_id(&old_id, &party_c);
    let c_moved = moved_position(a_position, new_id, w.c_im);

    let (t_price, t_spread, t_nonce, t_deadline) = match kind {
        NovationKind::Voluntary => (w.transfer_price, w.spread, w.nonce, w.deadline),
        NovationKind::Forced => (0, 0, 0, 0),
    };
    let entry = Novation {
        old_id,
        new_id,
        party_a,
        party_b: a_position.counterparty,
        party_c,
        c_im: w.c_im,
        forced: match kind {
            NovationKind::Voluntary => 0,
            NovationKind::Forced => 1,
        },
        transfer_price: t_price,
        spread: t_spread,
        nonce: t_nonce,
        deadline: t_deadline,
    };

    TransferAsCloseResult {
        party_a,
        party_c,
        c_moved,
        pnl,
        settlements,
        kind,
        reject: None,
        entry: Some(entry),
    }
}

/// Build C's inherited position — A's terms verbatim, id re-derived. `pub(crate)` so `state_transition` rebuilds the moved leaf from A's REAL committed position, never from the free witness.
pub(crate) fn moved_position(a_position: &PositionRecord, new_id: [u8; 32], c_im: u128) -> PositionRecord {
    PositionRecord {
        terms_id: new_id,
        counterparty: a_position.counterparty,
        oracle: a_position.oracle,
        notional: a_position.notional,
        entry_rate: a_position.entry_rate,
        side: a_position.side,
        expiry: a_position.expiry,
        pushed_im: c_im,
        market_key: a_position.market_key,
    }
}

/// Re-derived id for the inherited position: `keccak256(old_id ‖ party_c)` — binds the moved leg to maker C.
pub fn novation_new_id(old_id: &[u8; 32], party_c: &[u8; 20]) -> [u8; 32] {
    keccak(&[&old_id[..], &party_c[..]])
}

/// Does committed `entry` arise from a sound `transfer_as_close` over the witness?
pub fn novation_entry_valid(witness: &NovationWitness, committed: &Novation) -> bool {
    transfer_as_close(witness).entry.as_ref() == Some(committed)
}

/// Proof result of one `closeout_novation_close`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CloseoutNovationResult {
    /// A (defaulting) — leg closed.
    pub party_a: [u8; 20],
    /// C (inheriting maker).
    pub party_c: [u8; 20],
    /// The position C now holds (`new_id`, terms copied from A's leg, `pushed_im = c_im`).
    pub c_moved: PositionRecord,
    /// Signed A↔B P&L at the proven mark — surfaced as a claim (no in-tree A leaf to absorb it).
    pub pnl: i128,
    /// The uncovered spread the default fund owes C: named in USD, unclamped, since only A's realized GAIN is provably funding.
    pub shortfall: u128,
    /// A→C cash: the part of the spread A's realized gain demonstrably funds (`spread − shortfall`).
    pub settlements: Vec<Settlement>,
    /// The committed public-values entry.
    pub entry: CloseoutNovation,
}

/// Forced default close at the proven TWAP: re-bind A's economics and oracle, recover C's consent, best-exec-bound the A→C spread against keeper price-gouging, and name the uncovered remainder as `shortfall`. C's IM is whatever C signed, required only to be positive (no static floor — pure scenario-ES margin); the fold's scenario-ES `imRequirements` re-price C's post-handoff book and the chain cover-checks C at consume.
pub fn closeout_novation_close(w: &CloseoutNovationWitness) -> CloseoutNovationResult {
    let a_position = &w.a_position;
    let old_id = a_position.terms_id;

    let mark = settle_native_to_1e6(w.proven_twap.settle_price, w.proven_twap.expo);
    assert!(
        feed_id_oracle(&w.proven_twap.feed_id) == a_position.oracle,
        "closeout_novation: proven-TWAP feed_id does not bind A's position oracle (A2/V-02)"
    );

    let recomputed = terms_id(
        &w.party_a,
        &a_position.counterparty,
        &a_position.oracle,
        &w.pair_tag,
        w.quantity,
        w.im_bps_a,
        w.im_bps_b,
        w.mm_pct,
        a_position.expiry,
        w.terms_nonce,
        w.cure_window,
        w.payout_pref_a,
        w.payout_pref_b,
        &w.data,
        w.instrument,
        // Terms 2.1: `a_position.side` is A's committed (GS-03-bound) side; the existing recompute already
        // pins `w.party_a` == original Terms.partyA, so A's seat side == the signed Terms.side. Threading it
        // keeps the id byte-exact and binds side on the handoff path too.
        a_position.side,
    );
    assert_eq!(
        recomputed, old_id,
        "closeout_novation: recomputed terms_id != a_position.terms_id — forged position economics (A1)"
    );
    let bound_entry =
        entry_rate_from_data(&w.data).expect("closeout_novation: entry-rate word exceeds u128 — unrepresentable");
    assert_eq!(bound_entry, a_position.entry_rate, "closeout_novation: entry_rate != first word of signed data (A1)");
    assert_eq!(
        gross_notional(w.quantity, a_position.entry_rate),
        a_position.notional,
        "closeout_novation: gross_notional(quantity, entry_rate) != a_position.notional (A1)"
    );

    let consent_hash = failover_consent_struct_hash(
        &old_id,
        &w.party_c,
        &w.proven_twap.feed_id,
        w.proven_twap.close_time,
        w.c_im,
        w.spread,
        w.nonce,
        w.deadline,
    );
    let digest = eip712_digest(&w.domain_separator, &consent_hash);
    assert_eq!(
        signed_price::recover_eth_signer(&digest, &w.sig_c),
        w.party_c,
        "closeout_novation: FailoverConsent does not recover partyC — forged C consent/spread/cIm/nonce/domain (A5)"
    );

    // No static c_im floor (pure scenario-ES margin): C posts exactly the IM it SIGNED in the
    // FailoverConsent, and this fold's scenario-ES imRequirements re-price C's post-handoff book —
    // the on-chain cover-check (`NovationCoverageShort`) is what keeps an unfunded C out. The one
    // structural check mirrors the open path's zero-IM rejection: an inherited seat may not carry a
    // ZERO seat lock. This is a degenerate-seat guard, not an economic floor.
    assert!(w.c_im > 0, "closeout_novation: c_im must be positive — a zero-IM inherited seat is degenerate");

    let pnl = position_vm(a_position.entry_rate, mark, a_position.notional, a_position.side);

    assert!(
        closeout_novation_spread_within_best_exec(w.spread, pnl, a_position.notional),
        "closeout_novation: spread exceeds the best-execution bound — keeper price-gouge of the defaulter (OT-04)"
    );
    let a_realized_gain = if pnl > 0 { pnl as u128 } else { 0 };
    let from_a = w.spread.min(a_realized_gain);
    let shortfall = w.spread - from_a;
    let a_residual = a_realized_gain - from_a;
    let mut settlements: Vec<Settlement> = Vec::new();
    if from_a > 0 {
        settlements.push(Settlement { payer: w.party_a, payee: w.party_c, usd: from_a, id: old_id });
    }

    let new_id = novation_new_id(&old_id, &w.party_c);
    let c_moved = moved_position(a_position, new_id, w.c_im);

    let entry = CloseoutNovation {
        old_id,
        new_id,
        party_a: w.party_a,
        party_b: a_position.counterparty,
        party_c: w.party_c,
        feed_id: w.proven_twap.feed_id,
        close_time: w.proven_twap.close_time,
        handoff_mark: w.proven_twap.settle_price as i128,
        spread: w.spread,
        c_im: w.c_im,
        a_residual,
        shortfall,
        nonce: w.nonce,
        domain_separator: w.domain_separator,
        m_a_authorized: w.m_a_authorized,
    };

    CloseoutNovationResult {
        party_a: w.party_a,
        party_c: w.party_c,
        c_moved,
        pnl,
        shortfall,
        settlements,
        entry,
    }
}

/// Does committed `entry` arise from a sound `closeout_novation_close` over the witness?
pub fn closeout_novation_entry_valid(witness: &CloseoutNovationWitness, committed: &CloseoutNovation) -> bool {
    closeout_novation_close(witness).entry == *committed
}

#[cfg(test)]
mod tests {
    use crate::test_util::*;
    use crate::*;

    #[test]
    fn transfer_as_close_conserves_and_bounds_b() {
        let a_position = reference_box0();
        let b = a_position.counterparty;
        let party_a = nov_party_a();
        let party_c = nov_party_c();
        let mark: u128 = 1_050_000;
        let c_im: u128 = 60_000;

        let r = transfer_as_close(&nov_w(a_position, mark, c_im, 0));

        assert!(r.reject.is_none(), "voluntary novation must not reject");
        assert!(r.entry.is_some(), "a successful novation surfaces a public-values entry");

        let pnl = position_vm(a_position.entry_rate, mark, a_position.notional, a_position.side);
        assert_eq!(pnl, -27_777, "the long A loses 27_777 at the below-entry mark (H-2 base-size, entry 1.08)");
        assert_eq!(r.pnl, pnl, "the result carries A's absorbed P&L");

        assert_eq!(r.settlements.len(), 1, "one A↔C cash leg (the mark loss); no spread");
        assert_eq!(r.settlements[0].payer, party_a, "A pays C for the below-entry seat it hands over");
        assert_eq!(r.settlements[0].payee, party_c);
        assert_eq!(r.settlements[0].usd, 27_777, "the mark loss is the A→C cash");
        assert_eq!(r.settlements[0].id, a_position.terms_id, "cash is tagged with A's old position id");

        let new_id = novation_new_id(&a_position.terms_id, &party_c);
        assert_eq!(r.c_moved.terms_id, new_id, "the inherited position gets a fresh id");
        assert_ne!(r.c_moved.terms_id, a_position.terms_id, "new id != old id");
        assert_eq!(r.c_moved.pushed_im, c_im, "C posts c_im on the inherited seat");
        assert_eq!(r.c_moved.counterparty, b, "B is the position's matched counterparty (UNTOUCHED)");

        let e = r.entry.unwrap();
        assert_eq!(e.old_id, a_position.terms_id);
        assert_eq!(e.new_id, new_id);
        assert_eq!(e.party_a, party_a, "A is the outgoing leaf owner");
        assert_eq!(e.party_b, b, "B is the position's matched counterparty (UNTOUCHED)");
        assert_eq!(e.party_c, party_c, "C is the inheriting maker");
        assert_eq!(e.c_im, c_im);
        assert_eq!(e.forced, 0, "voluntary path ⇒ forced flag 0");
    }

    #[test]
    fn transfer_as_close_forced_default_path() {
        let a_position = reference_box0();
        let mark: u128 = 1_060_000;
        let c_im: u128 = 50_000;

        let r = transfer_as_close(&nov_w_forced(a_position, mark, c_im));

        assert!(r.reject.is_none(), "the forced default path does not reject");
        let e = r.entry.expect("forced novation surfaces an entry");
        assert_eq!(e.forced, 1, "forced/default path ⇒ forced flag 1");
        let pnl = position_vm(a_position.entry_rate, mark, a_position.notional, a_position.side);
        assert_eq!(r.pnl, pnl, "the P&L is surfaced (resolved on-chain — no maker cash emitted)");
        assert!(r.settlements.is_empty(), "FORCED: no signed maker quote ⇒ no A↔C cash emitted here");
        assert_eq!(r.c_moved.pushed_im, c_im, "C's IM on the inherited seat");
    }

    #[test]
    fn gs02_valid_conserved_novation_passes_in_guest_check() {
        let w = nov_valid_witness();
        let committed = nov_entry_for(&w);
        assert!(novation_entry_valid(&w, &committed), "GS-02: a conserved, in-bounds novation MUST pass the in-guest validation");
        assert_eq!(committed.c_im, 60_000, "the committed C IM is the conserved figure");
        assert_eq!(committed.party_a, nov_party_a());
        assert_eq!(committed.party_c, nov_party_c());
        assert_eq!(committed.party_b, reference_box0().counterparty, "B is the position's matched counterparty");
        assert_eq!(committed.forced, 0, "voluntary path ⇒ forced flag 0");
    }

    #[test]
    fn gs02_unconserved_minted_c_im_is_rejected_in_guest() {
        let w = nov_valid_witness();
        let mut forged = nov_entry_for(&w);
        forged.c_im = 1_000_000;
        assert!(!novation_entry_valid(&w, &forged), "GS-02: an UNCONSERVED novation (minted C IM) MUST be rejected");
    }

    #[test]
    fn gs02_forged_party_is_rejected_in_guest() {
        let w = nov_valid_witness();
        let mut forged = nov_entry_for(&w);
        forged.party_c = { let mut a = [0u8; 20]; a[19] = 0xee; a };
        assert!(!novation_entry_valid(&w, &forged), "GS-02: a novation re-pointed to an unfunded party MUST be rejected");
    }

    #[test]
    fn gs02_quote_below_mark_breach_is_rejected_in_guest() {
        let mut w = nov_valid_witness();
        w.mark = 0;
        w.transfer_price = 0;
        nov_sign_c(&mut w);
        let plausible = nov_entry_literal(&w);
        assert!(!novation_entry_valid(&w, &plausible), "GS-02: a QuoteBelowMark-breaching novation MUST be rejected");
        let r = transfer_as_close(&w);
        assert_eq!(r.reject, Some(NovationReject::QuoteBelowMark), "the close rejected for QuoteBelowMark");
        assert!(r.entry.is_none(), "a no-loss breach surfaces NO committable entry");
    }

    #[test]
    fn closeout_novation_happy_conserves_and_names_shortfall() {
        let w = fo_valid_witness();
        let r = closeout_novation_close(&w);
        assert_eq!(r.pnl, -80_000, "A absorbs the proven mark loss (H-2 base-size: 1_080_000·−80_000/1_080_000)");
        assert_eq!(r.shortfall, 50_000, "A realized no gain ⇒ the full spread is the named USD shortfall");
        assert!(r.settlements.is_empty(), "A funds none of the spread from a losing leg ⇒ no A→C cash");
        assert_eq!(r.entry.shortfall, 50_000);
        assert_eq!(r.entry.a_residual, 0, "no realized gain left after funding its (zero) share");
        assert_eq!(r.entry.spread, 50_000, "the signed maker spread is surfaced");
        assert_eq!(r.entry.party_a, new_party_a());
        assert_eq!(r.entry.party_b, new_party_b(), "B is the staying counterparty — UNTOUCHED");
        assert_eq!(r.entry.party_c, closeout_novation_party_c());
        assert_eq!(r.entry.handoff_mark, 1_000_000, "handoff mark == the proven TWAP native price");
        assert_eq!(r.entry.c_im, 90_000);
        assert_eq!(r.entry.old_id, w.a_position.terms_id);
        assert_eq!(r.entry.new_id, novation_new_id(&w.a_position.terms_id, &closeout_novation_party_c()));
        assert_eq!(r.entry.m_a_authorized, 96_400, "A's authorized snapshot is carried verbatim");
        assert_eq!(r.c_moved.pushed_im, 90_000, "C posts its own IM on the inherited seat");
        assert!(closeout_novation_entry_valid(&w, &r.entry), "the honest entry re-derives");
    }

    #[test]
    fn closeout_novation_close_rejects_each_forgery() {
        let cases: &[(&str, bool, fn(&mut CloseoutNovationWitness))] = &[
            ("does not bind A's position oracle", false, |w| { w.proven_twap.feed_id[31] ^= 0xFF; }),
            // Sham-C guard: a validly SIGNED c_im of zero (resigned so the signature holds) still
            // panics — no zero-IM seat enters by forced handoff, matching the open path's semantics.
            ("c_im must be positive", true, |w| { w.c_im = 0; }),
            ("best-execution bound", true, |w| { w.spread = 200_000; }),
            ("does not recover partyC", false, |w| { w.nonce = 999; }),
            ("does not recover partyC", false, |w| { w.domain_separator = [0xABu8; 32]; }),
        ];
        for &(expected, resign, mutate) in cases {
            let mut w = fo_valid_witness();
            mutate(&mut w);
            if resign { fo_resign(&mut w); }
            let err = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| closeout_novation_close(&w)))
                .expect_err(&format!("closeout_novation_close must panic for: {expected}"));
            let msg = err.downcast_ref::<String>().map(String::as_str)
                .or_else(|| err.downcast_ref::<&str>().copied()).unwrap_or("");
            assert!(msg.contains(expected), "panic message {msg:?} must contain {expected:?}");
        }
    }

    #[test]
    fn closeout_novation_entry_valid_rejects_forged_entry() {
        let w = fo_valid_witness();
        let mut forged = closeout_novation_close(&w).entry;
        forged.shortfall += 1;
        assert!(!closeout_novation_entry_valid(&w, &forged), "a forged entry cannot be reproduced");
    }

    #[test]
    fn closeout_novation_expo_neg5_rescales_mark_to_1e6() {
        let mut w = fo_valid_witness();
        w.proven_twap.settle_price = 100_000;
        w.proven_twap.expo = -5;
        fo_resign(&mut w);
        let r = closeout_novation_close(&w);
        assert_eq!(r.pnl, -80_000, "rescaled mark 1_000_000 reproduces the expo=-6 pnl");
        assert_eq!(r.shortfall, 50_000, "rescaled mark ⇒ identical conservation as expo=-6");
        assert_eq!(r.entry.handoff_mark, 100_000, "handoff_mark is the raw native price for the on-chain re-assert");
        let buggy_pnl = position_vm(w.a_position.entry_rate, 100_000, w.a_position.notional, w.a_position.side);
        assert_eq!(buggy_pnl, -980_000, "raw 100_000 mark is 10×+ off — the bug this fix kills");
        assert_ne!(r.pnl, buggy_pnl, "rescaled and raw marks diverge 10×");
    }
}
