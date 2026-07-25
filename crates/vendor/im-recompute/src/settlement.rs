//! Proven-price rail: turn a proven Pyth price into a realized residual, and fold cumulative VM from proven hourly
//! marks. Prices arrive Pyth-native and rescale to the 1e6 position scale; the freshness windows live in `constants`.
//! Both fold paths assert at most ONE proven price per binding key — per position for settles, per pair for marks — so
//! the price a position takes cannot depend on the host's ordering of two same-key inputs. VM is cumulative FROM ENTRY
//! (the immutable open rate), never a between-mark delta, and sums saturating with no ISDA correlation; an unmarked
//! pair contributes nothing, while `assert_marks_complete` separately forbids leaving a live priced position unmarked.
//! `settle_native_to_1e6` fails closed outside a generous FX exponent envelope rather than silently mis-scale to 0 or
//! `u128::MAX` — defence in depth behind the on-chain `twapExpo` re-assert, which is the binding gate.

use crate::{PositionRecord, ProvenTwap, ProvenMark, PositionSettlement, ConsumedTwap, ConsumedMark,
    assert_unique_position_twaps, assert_unique_proven_marks,
    COLLATERAL_DECIMALS, BPS_DENOM, MARK_MAX_AGE_SECS, CLOSEOUT_NOVATION_MARK_MAX_AGE_SECS,
    SPREAD_BEST_EXEC_K, SPREAD_BEST_EXEC_FLOOR_BPS, im_for_side, position_vm};

/// The proof's `feed_id` reduced to the position's 20-byte oracle (low 20 bytes).
pub fn feed_id_oracle(feed_id: &[u8; 32]) -> [u8; 20] {
    let mut o = [0u8; 20];
    o.copy_from_slice(&feed_id[12..32]);
    o
}

/// Proven-price binding: true iff `feed_id[12..] == oracle && close_time == expiry` — the guest half of the chain's bind.
pub fn position_twap_binding_ok(b: &PositionRecord, proven: &ProvenTwap) -> bool {
    feed_id_oracle(&proven.feed_id) == b.oracle && b.expiry == proven.close_time
}

/// Rescale a Pyth-native settle price to the 1e6 position scale; an out-of-envelope exponent panics.
pub fn settle_native_to_1e6(settle_native: u128, expo: i32) -> u128 {
    let p: i32 = COLLATERAL_DECIMALS + expo;
    assert!(
        p >= -12 && p <= 24,
        "settle_native_to_1e6: price exponent out of FX envelope — fail-closed"
    );
    if p >= 0 {
        settle_native.saturating_mul(10u128.saturating_pow(p as u32))
    } else {
        match 10u128.checked_pow((-p) as u32) {
            Some(d) => settle_native / d,
            None => 0,
        }
    }
}

/// The `PositionSettlement` a proven TWAP realizes — `Some` only when the TWAP binds the position.
pub fn position_settlement_from_twap(b: &PositionRecord, proven: &ProvenTwap) -> Option<PositionSettlement> {
    if !position_twap_binding_ok(b, proven) {
        return None;
    }
    let settle_1e6 = settle_native_to_1e6(proven.settle_price, proven.expo);
    Some(PositionSettlement {
        terms_id: b.terms_id,
        vm_realized: position_vm(b.entry_rate, settle_1e6, b.notional, b.side),
    })
}

/// Per-position settlements for a book, plus the `ConsumedTwap`s the chain re-asserts.
pub fn position_settlements_from_twaps(
    positions: &[PositionRecord],
    proven_twaps: &[ProvenTwap],
) -> (Vec<PositionSettlement>, Vec<ConsumedTwap>) {
    assert_unique_position_twaps(proven_twaps);
    let mut settlements: Vec<PositionSettlement> = Vec::new();
    let mut consumed: Vec<ConsumedTwap> = Vec::new();
    for b in positions {
        if let Some(p) = proven_twaps.iter().find(|p| position_twap_binding_ok(b, p)) {
            settlements.push(position_settlement_from_twap(b, p).expect("binding-ok position must settle"));
            consumed.push(ConsumedTwap {
                feed_id: p.feed_id,
                close_time: p.close_time,
                twap: p.settle_price as i128,
                expo: p.expo,
            });
        }
    }
    (settlements, consumed)
}

/// Guest freshness half for a proven hourly mark: not in the future, not older than `MARK_MAX_AGE_SECS`.
pub fn mark_fresh(mark_time: u64, proof_time: u64) -> bool {
    mark_time <= proof_time && proof_time.saturating_sub(mark_time) <= MARK_MAX_AGE_SECS
}

/// A mark binds a position iff its feed id reduces to the position's oracle — a pair match, with no `close_time` clause.
pub fn mark_binds_position(b: &PositionRecord, mark: &ProvenMark) -> bool {
    feed_id_oracle(&mark.feed_id) == b.oracle
}

/// One account's cumulative-since-entry VM from proven hourly marks, plus the `ConsumedMark`s the chain re-asserts.
pub fn account_vm_from_marks(
    positions: &[PositionRecord],
    proven_marks: &[ProvenMark],
) -> (i128, Vec<ConsumedMark>) {
    assert_unique_proven_marks(proven_marks);
    let mut vm: i128 = 0;
    let mut consumed: Vec<ConsumedMark> = Vec::new();
    for b in positions {
        if let Some(m) = proven_marks.iter().find(|m| mark_binds_position(b, m)) {
            let mark_1e6 = settle_native_to_1e6(m.price, m.expo);
            vm = vm.saturating_add(position_vm(b.entry_rate, mark_1e6, b.notional, b.side));
            consumed.push(ConsumedMark {
                feed_id: m.feed_id,
                mark_time: m.mark_time,
                price: m.price as i128,
                expo: m.expo,
            });
        }
    }
    (vm, consumed)
}

/// Guest freshness half for the handoff mark: not stale, and NOT in the future — the chain re-asserts only the stale half.
pub fn closeout_novation_mark_fresh(close_time: u64, proof_time: u64) -> bool {
    close_time <= proof_time && proof_time.saturating_sub(close_time) <= CLOSEOUT_NOVATION_MARK_MAX_AGE_SECS
}

/// Best-exec bound (proven-mark-derived, NOT a keeper buffer): `spread ≤ K·|pnl| + floor_bps of notional`.
pub fn closeout_novation_spread_within_best_exec(spread: u128, pnl: i128, notional: u128) -> bool {
    let pnl_abs = pnl.unsigned_abs();
    let max_spread = im_for_side(notional, SPREAD_BEST_EXEC_FLOOR_BPS)
        .saturating_add(SPREAD_BEST_EXEC_K.saturating_mul(pnl_abs));
    spread <= max_spread
}

/// A position's MAINTENANCE-margin bps: `ceil(im_bps · mm_pct / 1e4)` (`mm_pct` is MM as a % of IM, 1e4 = 100%).
pub fn mm_bps_from(im_bps: u16, mm_pct: u16) -> u16 {
    let prod = (im_bps as u128).saturating_mul(mm_pct as u128);
    let bps = prod.saturating_add(BPS_DENOM - 1) / BPS_DENOM;
    bps.min(u16::MAX as u128) as u16
}

#[cfg(test)]
mod tests {
    use crate::test_util::*;
    use crate::*;

    #[test]
    #[should_panic(expected = "out of FX envelope")]
    fn settle_native_out_of_envelope_fails_closed() {
        let _ = settle_native_to_1e6(1_100_000, -100);
    }

    #[test]
    fn m02_expo_rescales_only_the_settle_price() {
        assert_eq!(settle_native_to_1e6(1_100_000, -6), 1_100_000);
        assert_eq!(settle_native_to_1e6(110_000, -5), 1_100_000);
        assert_eq!(settle_native_to_1e6(110_000_000, -8), 1_100_000);
        assert_eq!(settle_native_to_1e6(1, 0), 1_000_000);
        let b0 = reference_box0();
        let proven = ProvenTwap { feed_id: feed_for(b0.oracle), close_time: b0.expiry, settle_price: 110_000, expo: -5 };
        let s = position_settlement_from_twap(&b0, &proven).expect("bound");
        assert_eq!(s.vm_realized, 18_518, "residual derived from the expo-rescaled settle price");
        let (_, consumed) = position_settlements_from_twaps(&[b0], &[proven]);
        assert_eq!(consumed[0].twap, 110_000, "ConsumedTwap.twap is the NATIVE price (== boundTwap)");
        assert_eq!(consumed[0].expo, -5, "ConsumedTwap.expo is surfaced for the on-chain twapExpo assert");
    }

    #[test]
    fn proven_twap_binding_rejects_wrong_feed_or_close() {
        let b0 = reference_box0();
        let good = ProvenTwap { feed_id: feed_for(b0.oracle), close_time: b0.expiry, settle_price: 1_100_000, expo: -6 };
        assert!(position_twap_binding_ok(&b0, &good), "matching feed_id+close_time binds");
        let s = position_settlement_from_twap(&b0, &good).expect("a bound price yields a settlement");
        assert_eq!(s.terms_id, b0.terms_id);
        assert_eq!(s.vm_realized, 18_518, "the residual is DERIVED from the proven price (H-2 base-size)");
        let wrong_feed = ProvenTwap { feed_id: feed_for(reference_box1().oracle), close_time: b0.expiry, settle_price: 1_100_000, expo: -6 };
        assert!(!position_twap_binding_ok(&b0, &wrong_feed), "a price for the WRONG pair must not bind");
        assert!(position_settlement_from_twap(&b0, &wrong_feed).is_none(), "wrong feed ⇒ no settlement");
        let wrong_close = ProvenTwap { feed_id: feed_for(b0.oracle), close_time: b0.expiry + 1, settle_price: 1_100_000, expo: -6 };
        assert!(!position_twap_binding_ok(&b0, &wrong_close), "a price for the WRONG close must not bind");
        assert!(position_settlement_from_twap(&b0, &wrong_close).is_none(), "wrong close ⇒ no settlement");
    }

    #[test]
    fn position_settlements_from_twaps_derives_only_bound_positions() {
        let b0 = reference_box0();
        let b1 = reference_box1();
        let positions = [b0, b1];
        let proven = [ProvenTwap { feed_id: feed_for(b0.oracle), close_time: b0.expiry, settle_price: 1_100_000, expo: -6 }];
        let (settlements, consumed) = position_settlements_from_twaps(&positions, &proven);
        assert_eq!(settlements.len(), 1, "only the position with a bound price settles");
        assert_eq!(settlements[0].terms_id, b0.terms_id, "b0 settled");
        assert_eq!(settlements[0].vm_realized, 18_518, "residual DERIVED from the proven price (H-2 base-size)");
        assert!(!settlements.iter().any(|s| s.terms_id == b1.terms_id), "b1 has no proven price ⇒ no settle");
        assert_eq!(consumed.len(), 1, "one consumed price for the one settled position");
        assert_eq!(consumed[0].feed_id, feed_for(b0.oracle), "consumed feed_id is the proven one");
        assert_eq!(consumed[0].close_time, b0.expiry, "consumed close_time is the position's expiry");
        assert_eq!(consumed[0].twap, 1_100_000, "consumed twap is the proven price the chain bound");
        let r = resolve_account(reference_account_owner(), &positions, &settlements, 0, &[], 0, &test_table());
        assert!(r.positions_live && r.surviving.len() == 1, "b1 stays live, b0 retired");
        assert_eq!(r.surviving[0].terms_id, b1.terms_id, "the un-priced position b1 survives");
    }

    #[test]
    #[should_panic(expected = "same position-binding key")]
    fn f1_two_same_binding_different_priced_twaps_rejected() {
        let b0 = reference_box0();
        let positions = [b0];
        let cheap = ProvenTwap { feed_id: feed_for(b0.oracle), close_time: b0.expiry, settle_price: 900_000, expo: -6 };
        let dear  = ProvenTwap { feed_id: feed_for(b0.oracle), close_time: b0.expiry, settle_price: 1_300_000, expo: -6 };
        let _ = position_settlements_from_twaps(&positions, &[cheap, dear]);
    }

    #[test]
    fn f1_single_and_distinct_key_twaps_accepted() {
        let b0 = reference_box0();
        let b1 = reference_box1();
        let one = [ProvenTwap { feed_id: feed_for(b0.oracle), close_time: b0.expiry, settle_price: 1_100_000, expo: -6 }];
        let (settlements, consumed) = position_settlements_from_twaps(&[b0, b1], &one);
        assert_eq!(settlements.len(), 1, "single binding TWAP still settles its one position");
        assert_eq!(consumed.len(), 1, "one consumed price surfaced");
        assert_ne!(b0.oracle, b1.oracle, "fixture positions carry distinct oracles");
        let two_distinct = [
            ProvenTwap { feed_id: feed_for(b0.oracle), close_time: b0.expiry, settle_price: 1_100_000, expo: -6 },
            ProvenTwap { feed_id: feed_for(b1.oracle), close_time: b1.expiry, settle_price: 980_000, expo: -6 },
        ];
        assert_unique_position_twaps(&two_distinct);
        let two_distinct_close = [
            ProvenTwap { feed_id: feed_for(b0.oracle), close_time: b0.expiry, settle_price: 1_100_000, expo: -6 },
            ProvenTwap { feed_id: feed_for(b0.oracle), close_time: b0.expiry + 1, settle_price: 1_100_000, expo: -6 },
        ];
        assert_unique_position_twaps(&two_distinct_close);
        assert_unique_position_twaps(&[]);
    }

    #[test]
    #[should_panic(expected = "two hourly marks for the same pair")]
    fn gap1_cherry_pick_via_account_vm_from_marks_rejected() {
        let b0 = reference_box0();
        let cheap = ProvenMark { feed_id: feed_for(b0.oracle), mark_time: 1_700_000_000, price: 900_000, expo: -6 };
        let dear = ProvenMark { feed_id: feed_for(b0.oracle), mark_time: 1_700_003_600, price: 1_300_000, expo: -6 };
        let _ = account_vm_from_marks(&[b0], &[cheap, dear]);
    }

    #[test]
    fn gap1_distinct_pair_marks_and_empty_accepted() {
        let b0 = reference_box0();
        let b1 = reference_box1();
        assert_ne!(b0.oracle, b1.oracle, "fixture positions carry distinct oracles");
        let two_pairs = [
            ProvenMark { feed_id: feed_for(b0.oracle), mark_time: 1_700_000_000, price: 1_020_000, expo: -6 },
            ProvenMark { feed_id: feed_for(b1.oracle), mark_time: 1_700_000_000, price: 980_000, expo: -6 },
        ];
        assert_unique_proven_marks(&two_pairs);
        assert_unique_proven_marks(&[]);
        let (_vm, consumed) = account_vm_from_marks(&[b0, b1], &two_pairs);
        assert_eq!(consumed.len(), 2, "two distinct pairs ⇒ two consumed marks, no false reject");
    }

    #[test]
    fn gs05_trusted_position_settlements_cannot_move_value() {
        let b0 = reference_box0();
        let positions = [b0];
        let (settlements, consumed) = position_settlements_from_twaps(&positions, &[]);
        assert!(settlements.is_empty(), "no proven price ⇒ no settlement");
        assert!(consumed.is_empty(), "no proven price ⇒ no ConsumedTwap");
        let r = resolve_account(reference_account_owner(), &positions, &settlements, 0, &[], 0, &test_table());
        assert_eq!(r.outcome, ResolveOutcome::NoOp, "no proven price ⇒ no settle ⇒ NoOp");
        assert!(r.settlements.is_empty(), "the trusted residual never lands as cash");
        assert!(r.positions_live && r.surviving.len() == 1, "the position stays live, unsettled");
    }

    #[test]
    fn closeout_novation_mark_fresh_bounds_close_time() {
        let proof_time = 1_700_000_500u64;
        assert!(closeout_novation_mark_fresh(proof_time, proof_time), "same-instant mark is fresh");
        assert!(closeout_novation_mark_fresh(proof_time - CLOSEOUT_NOVATION_MARK_MAX_AGE_SECS, proof_time),
            "a mark exactly CLOSEOUT_NOVATION_MARK_MAX_AGE_SECS old is still fresh (inclusive edge)");
        assert!(!closeout_novation_mark_fresh(proof_time - CLOSEOUT_NOVATION_MARK_MAX_AGE_SECS - 1, proof_time),
            "one second past the window is STALE — rejected");
        assert!(!closeout_novation_mark_fresh(proof_time + 1, proof_time), "a future close_time is rejected (settle-parity)");
    }
}
