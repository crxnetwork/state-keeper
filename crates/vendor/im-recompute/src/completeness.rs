//! The fail-closed valves — every soundness invariant that makes the proof UNSATISFIABLE rather than let a host
//! under-margin. They check what the chain cannot: it re-asserts surfaced entries, never the position set behind them.
//!
//! Settlement. Every settle flows per-position through a proven TWAP; a trusted whole-account residual is
//! rejected outright. Every DUE un-paused position must bind a proven TWAP.
//!
//! Marking. All-or-nothing: it is a marking epoch iff any account carries a proven mark, and then EVERY live
//! un-paused position must bind one — else a keeper marks the winners and withholds a loser's mark to skew the
//! cumulative VM. A non-marking epoch re-marks nothing and carries the prior VM verbatim.
//!
//! Pause. A paused pair exempts a position from settling (always) and from marking (on a marking epoch), but
//! `paused_pairs` is a pure host input, so the exemption must COST an on-chain proof: every exempted position is
//! surfaced as a `PausedHold`, count-equal to the skips, and `applyState` re-asserts `markets[key].paused`. A
//! forged pause reverts on-chain; a genuine one stays exempt.
//!
//! Surfaces. `opened_position_ids` must equal the processed new-position set EXACTLY — nothing withheld, none
//! fabricated — else a signed-but-never-opened position folds in. Novation-created positions are correctly absent.
//! (The per-market ISDA-selector surface died with the ρ-form: the scenario table binds through ONE recomputed
//! `scenario_root` the chain re-asserts, so no per-position surface is needed.)
//!
//! Order-independence. At most one proven TWAP per `(oracle, close_time)`, at most one hourly mark per pair, and
//! unique `terms_id` per position set — a duplicate would let host iteration order pick the favorable price.

use crate::{PositionRecord, RiskInputs, ProvenTwap, ProvenMark, PausedHold, NewPosition,
    feed_id_oracle, pair_tag_of, positions_root, position_twap_binding_ok, mark_binds_position};

/// Reject a trusted whole-account `unconsumed_settle_residual` credit — an unproven keeper residual.
pub fn assert_no_trusted_settle(ri: &RiskInputs) {
    assert!(
        ri.unconsumed_settle_residual.is_none(),
        "state_transition: trusted whole-account settle_residual is removed (C-02) — settle per-position via a proven TWAP"
    );
}

/// Settlement completeness: every DUE un-paused position must bind a proven TWAP; a due paused one is surfaced as a `PausedHold`.
pub fn assert_due_boxes_have_proven_twap(
    positions: &[PositionRecord],
    proven_twaps: &[ProvenTwap],
    paused: &[[u8; 32]],
    proof_time: u64,
) -> Vec<PausedHold> {
    let mut holds: Vec<PausedHold> = Vec::new();
    for b in positions {
        if b.expiry > proof_time {
            continue;
        }
        if paused.contains(&pair_tag_of(&b.oracle)) {
            holds.push(PausedHold { market_key: b.market_key, position_id: b.terms_id });
            continue;
        }
        assert!(
            proven_twaps.iter().any(|p| position_twap_binding_ok(b, p)),
            "settlement-completeness: a due position has no binding proven TWAP (GS-05)"
        );
    }
    holds
}

/// Mark completeness: on a marking epoch every live un-paused position must bind a proven mark; each live position exempted on pause grounds is returned as a `PausedHold`.
pub fn assert_marks_complete(
    positions: &[PositionRecord],
    proven_marks: &[ProvenMark],
    paused: &[[u8; 32]],
    proof_time: u64,
    marking_epoch: bool,
) -> Vec<PausedHold> {
    let mut live_paused_holds: Vec<PausedHold> = Vec::new();
    if !marking_epoch {
        return live_paused_holds;
    }
    for b in positions {
        if b.expiry <= proof_time {
            continue;
        }
        if paused.contains(&pair_tag_of(&b.oracle)) {
            live_paused_holds.push(PausedHold { market_key: b.market_key, position_id: b.terms_id });
            continue;
        }
        assert!(
            proven_marks.iter().any(|m| mark_binds_position(b, m)),
            "mark-completeness: on a marking epoch, a live position on an un-paused pair has no binding proven mark \
             — a keeper cannot mark the winners and withhold a loser's mark to skew the cumulative VM (V-01 mark sibling)"
        );
    }
    live_paused_holds
}

/// Pause completeness: every position exempted on pause grounds is surfaced as a `PausedHold`, and the surface is count-equal to the skips.
pub fn assert_paused_holds_complete(
    positions: &[PositionRecord],
    paused: &[[u8; 32]],
    proof_time: u64,
    paused_holds: &[PausedHold],
    marking_epoch: bool,
) {
    let mut expected: usize = 0;
    for b in positions {
        let position_paused = paused.contains(&pair_tag_of(&b.oracle));
        if !position_paused {
            continue;
        }
        let held = if b.expiry <= proof_time { true } else { marking_epoch };
        if held {
            expected += 1;
            assert!(
                paused_holds
                    .iter()
                    .any(|h| h.market_key == b.market_key && h.position_id == b.terms_id),
                "settlement-pause completeness: a position skipped on pause grounds has no PausedHold surface entry (V-01 / GAP-2)"
            );
        }
    }
    assert_eq!(
        paused_holds.len(),
        expected,
        "settlement-pause completeness: pausedHolds count != paused-skip count (V-01 / GAP-2 count-equality)"
    );
}

/// Opened-set completeness: the surfaced `opened` ids must be EXACTLY the processed new positions — none withheld, none fabricated.
pub fn assert_opened_position_ids_complete(new_positions: &[NewPosition], opened: &[[u8; 32]]) {
    assert_surface_is_processed_set(
        new_positions,
        opened,
        |_| true,
        "opened-position-ids: a surfaced id is not a processed new position in a rebuilt lane — a fabricated \
         or un-rebuilt-lane id must never be surfaced (openedPositionIds over-surface)",
        "opened-position-ids: a processed new position is missing from openedPositionIds — its on-chain \
         open mark would never be re-checked, so a phantom box could fold unbound (Road 2 phantom-box hole)",
    );
}

fn assert_surface_is_processed_set(
    new_positions: &[NewPosition],
    surfaced: &[[u8; 32]],
    include: fn(&NewPosition) -> bool,
    over_surface_msg: &str,
    under_surface_msg: &str,
) {
    let mut expected: Vec<[u8; 32]> = new_positions
        .iter()
        .filter(|nb| include(nb))
        .map(|nb| nb.terms_id)
        .collect();
    expected.sort_unstable();
    expected.dedup();
    for sid in surfaced {
        assert!(expected.binary_search(sid).is_ok(), "{}", over_surface_msg);
    }
    for eid in &expected {
        assert!(surfaced.binary_search(eid).is_ok(), "{}", under_surface_msg);
    }
}

/// A position set MUST carry unique `terms_id`. Panics (fail-closed) on any duplicate.
pub fn assert_unique_terms_id(positions: &[PositionRecord]) {
    let mut ids: Vec<[u8; 32]> = positions.iter().map(|b| b.terms_id).collect();
    ids.sort();
    for w in ids.windows(2) {
        assert!(
            w[0] != w[1],
            "position set carries a duplicate terms_id — RA-1 order-invariance / no-double-settle violated"
        );
    }
}

/// A `proven_twaps` set must carry at most one price per position-binding key `(oracle, close_time)`.
pub fn assert_unique_position_twaps(proven_twaps: &[ProvenTwap]) {
    let mut keys: Vec<([u8; 20], u64)> = proven_twaps
        .iter()
        .map(|p| (feed_id_oracle(&p.feed_id), p.close_time))
        .collect();
    keys.sort();
    for w in keys.windows(2) {
        assert!(
            w[0] != w[1],
            "proven_twaps carries two prices for the same position-binding key (oracle, close_time) — a host \
             could pick the favorable settle; margin must bind at most one proven price per position (F-1 fail-closed)"
        );
    }
}

/// A `proven_marks` set must carry at most one hourly mark per pair — a mark binds by ORACLE ALONE, so a duplicate would let host order cherry-pick the favorable hour.
pub fn assert_unique_proven_marks(proven_marks: &[ProvenMark]) {
    let mut keys: Vec<[u8; 20]> = proven_marks
        .iter()
        .map(|m| feed_id_oracle(&m.feed_id))
        .collect();
    keys.sort();
    for w in keys.windows(2) {
        assert!(
            w[0] != w[1],
            "proven_marks carries two hourly marks for the same pair — a keeper could cherry-pick the \
             favorable hour via host iteration order; margin must bind at most one mark per pair (GAP-1 fail-closed)"
        );
    }
}

/// Per-position binding predicate: do the supplied positions open the committed `positions_root`?
pub fn positions_open_root(positions: &[PositionRecord], committed_root: &[u8; 32]) -> bool {
    assert_unique_terms_id(positions);
    positions_root(positions) == *committed_root
}

#[cfg(test)]
mod tests {
    use crate::test_util::*;
    use crate::*;

    #[test]
    fn gs03_fabricated_position_fails_positions_binding() {
        let honest = vec![reference_box0(), reference_box1()];
        let committed_pr = positions_root(&honest);
        let forged_dropped = vec![reference_box0()];
        assert!(!positions_open_root(&forged_dropped, &committed_pr), "GS-03: an OMITTED position MUST NOT open positions_root");
        let forged_added = vec![reference_box0(), reference_box1(), PositionRecord { terms_id: [0x99u8; 32], ..reference_box0() }];
        assert!(!positions_open_root(&forged_added, &committed_pr), "GS-03: an ADDED phantom position MUST NOT open positions_root");
        let forged_mutated = vec![reference_box0(), PositionRecord { notional: 1u128, ..reference_box1() }];
        assert!(!positions_open_root(&forged_mutated, &committed_pr), "GS-03: a MUTATED position field MUST NOT open positions_root");
        assert!(positions_open_root(&honest, &committed_pr), "the honest position set opens positions_root");
    }

    #[test]
    fn gs03_empty_boxes_with_real_positions_fails_binding() {
        let committed_pr = positions_root(&[reference_box0(), reference_box1()]);
        assert_ne!(committed_pr, [0u8; 32], "an account with real positions has a non-zero positions_root");
        let empty: Vec<PositionRecord> = Vec::new();
        assert_eq!(positions_root(&empty), [0u8; 32], "empty positions hash to the zero sentinel");
        assert!(!positions_open_root(&empty, &committed_pr), "GS-03: empty positions MUST NOT open a non-zero positions_root");
    }

    #[test]
    fn gs03_empty_boxes_with_empty_leaf_passes_binding() {
        let empty_leaf_root = [0u8; 32];
        let empty_positions: Vec<PositionRecord> = Vec::new();
        assert!(positions_open_root(&empty_positions, &empty_leaf_root), "GS-03: a genuinely-empty leaf MUST pass the total binding");
        let positions = vec![reference_box0(), reference_box1()];
        let committed_pr = positions_root(&positions);
        assert!(positions_open_root(&positions, &committed_pr), "a non-zero root with matching positions passes");
        assert!(!positions_open_root(&positions, &empty_leaf_root), "positions against an empty-leaf root are rejected");
    }

    #[test]
    fn test_positions_root_order_invariant() {
        let b_lo = PositionRecord { terms_id: [0x11u8; 32], ..reference_box0() };
        let b_mid = PositionRecord { terms_id: [0x55u8; 32], ..reference_box1() };
        let b_hi = PositionRecord {
            terms_id: [0x99u8; 32],
            counterparty: { let mut a = [0u8; 20]; a[19] = 0xb2; a },
            oracle: { let mut a = [0u8; 20]; a[18] = 0x0e; a[19] = 0x73; a },
            notional: 3_000_000u128,
            entry_rate: 1_010_000u128,
            side: 1,
            expiry: 1_700_172_800u64,
            pushed_im: 210_000u128,
            market_key: [0xC2u8; 32],
        };
        let canonical = positions_root(&[b_lo, b_mid, b_hi]);
        println!("canonical_3box_positions_root = 0x{}", hex_str(&canonical));
        let canonical_3box: [u8; 32] = [
            0xc9, 0xfa, 0xb3, 0xfc, 0xcf, 0x6b, 0x66, 0x05,
            0x88, 0x9b, 0x2b, 0xb4, 0x97, 0xf6, 0xe5, 0x12,
            0x70, 0xeb, 0xae, 0x59, 0xc2, 0x6b, 0x4f, 0x4a,
            0xbc, 0x11, 0x63, 0x79, 0x20, 0x19, 0xff, 0x2d,
        ];
        assert_eq!(canonical, canonical_3box, "canonical 3-position root must match the pinned cross-language value");
        let perms = [
            [b_lo, b_mid, b_hi], [b_lo, b_hi, b_mid], [b_mid, b_lo, b_hi],
            [b_mid, b_hi, b_lo], [b_hi, b_lo, b_mid], [b_hi, b_mid, b_lo],
        ];
        for (i, p) in perms.iter().enumerate() {
            assert_eq!(positions_root(p), canonical, "permutation {i} must produce the SAME positions_root");
        }
        let positional_inorder = merkle_root(&[position_leaf(&b_lo), position_leaf(&b_mid), position_leaf(&b_hi)]);
        let positional_shuffled = merkle_root(&[position_leaf(&b_hi), position_leaf(&b_lo), position_leaf(&b_mid)]);
        assert_ne!(positional_inorder, positional_shuffled, "a positional (unsorted) 3-leaf tree DOES diverge on reorder");
        assert_eq!(canonical, positional_inorder, "canonical root == positional root of the terms_id-sorted leaves");
        let b0 = reference_box0();
        let b1 = reference_box1();
        assert_eq!(positions_root(&[b0, b1]), positions_root(&[b1, b0]), "the 2-position reference vector root is order-invariant");
    }

    #[test]
    #[should_panic(expected = "duplicate terms_id")]
    fn positions_open_root_rejects_duplicate() {
        let dup = PositionRecord { counterparty: { let mut a = [0u8; 20]; a[19] = 0xcc; a }, ..reference_box0() };
        let _ = positions_open_root(&[reference_box0(), dup], &[0u8; 32]);
    }

    #[test]
    fn test_completeness_fold_set_equality_is_total() {
        let mut keys = vec![rk(1), rk(2), rk(3), rk(4), rk(5)];
        keys.sort();
        keys.dedup();
        assert_eq!(keys.len(), 5, "fixture keys must be distinct");
        let accounts_root = credited_deposit_registry(&keys);
        assert_eq!(credited_deposit_registry(&keys), accounts_root, "the same key set must reproduce the root");
        for drop_idx in 0..keys.len() {
            let mut subset = keys.clone();
            subset.remove(drop_idx);
            assert_ne!(credited_deposit_registry(&subset), accounts_root, "omitting key {drop_idx} must break reproduction");
        }
        let mut superset = keys.clone();
        superset.push(rk(99));
        superset.sort();
        assert_ne!(credited_deposit_registry(&superset), accounts_root, "a phantom key must break reproduction");
        assert_ne!(registry_leaf(), crate::smt2::EMPTY, "a present key must store a non-empty value");
        assert_eq!(registry_leaf(), keccak(&[b"CRX/accountsRoot/v2"]), "registry_leaf is pinned");
        let mut reversed = keys.clone();
        reversed.reverse();
        assert_eq!(credited_deposit_registry(&reversed), accounts_root, "registry root is order-independent");
        assert_eq!(credited_deposit_registry(&[]), crate::smt2::EMPTY, "empty registry == empty SMT root");
    }

    #[test]
    fn test_completeness_fold_prune_on_empty_deletes_key() {
        let mut keys = vec![rk(10), rk(20), rk(30)];
        keys.sort();
        let accounts_root_prev = credited_deposit_registry(&keys);
        let pruned = rk(20);
        let remaining: Vec<[u8; 32]> = keys.iter().copied().filter(|k| *k != pruned).collect();
        assert_eq!(remaining.len(), 2, "one account pruned ⇒ two remaining");
        let accounts_root_new = credited_deposit_registry(&remaining);
        assert_ne!(accounts_root_new, accounts_root_prev, "pruning an empty account must move the registry root");
        let mut rebuilt = crate::smt2::Smt2::new();
        let leaf = registry_leaf();
        for s in &remaining { rebuilt.insert(*s, leaf); }
        let mut cleared = crate::smt2::Smt2::new();
        for k in &keys { cleared.insert(*k, leaf); }
        cleared.remove(&pruned);
        assert_eq!(rebuilt.root(), accounts_root_new, "remaining rebuild matches credited_deposit_registry");
        assert_eq!(cleared.root(), accounts_root_new, "deleting the pruned key == rebuilding over remaining");
        assert_eq!(credited_deposit_registry(&keys), accounts_root_prev, "the prior set still reproduces accountsRootPrev");
    }

    #[test]
    #[should_panic(expected = "settlement-completeness")]
    fn gs05_due_position_without_proven_twap_panics() {
        let b0 = reference_box0();
        let positions = [b0];
        assert_due_boxes_have_proven_twap(&positions, &[], &[], b0.expiry);
    }

    #[test]
    fn gs05_completeness_exemptions_do_not_panic() {
        let b0 = reference_box0();
        let positions = [b0];
        let proven = [ProvenTwap { feed_id: feed_for(b0.oracle), close_time: b0.expiry, settle_price: 1_100_000, expo: -6 }];
        assert_due_boxes_have_proven_twap(&positions, &proven, &[], b0.expiry);
        let paused = [pair_tag_of(&b0.oracle)];
        assert_due_boxes_have_proven_twap(&positions, &[], &paused, b0.expiry);
        assert_due_boxes_have_proven_twap(&positions, &[], &[], b0.expiry - 1);
        assert_due_boxes_have_proven_twap(&positions, &[], &[], 0);
    }

    #[test]
    fn kpause_one_paused_hold_per_held_due_position() {
        let b0 = reference_box0();
        let b1 = reference_box1();
        let positions = [b0, b1];
        let paused = [pair_tag_of(&b0.oracle)];
        let proven = [ProvenTwap { feed_id: feed_for(b1.oracle), close_time: b1.expiry, settle_price: 980_000, expo: -6 }];
        let holds = assert_due_boxes_have_proven_twap(&positions, &proven, &paused, b1.expiry);
        assert_eq!(holds.len(), 1, "exactly one PausedHold — the one DUE position on the paused pair");
        assert_eq!(holds[0].market_key, b0.market_key, "the hold carries the held position's market_key");
        assert_eq!(holds[0].position_id, b0.terms_id, "the hold carries the held position's terms_id");
        let holds_not_due = assert_due_boxes_have_proven_twap(&[b0], &[], &paused, b0.expiry - 1);
        assert!(holds_not_due.is_empty(), "a not-yet-due position on a paused pair is not a held surface entry");
    }

    #[test]
    #[should_panic(expected = "no PausedHold surface entry")]
    fn kpause_completeness_panics_on_missing_surface_entry() {
        let b0 = reference_box0();
        let paused = [pair_tag_of(&b0.oracle)];
        assert_paused_holds_complete(&[b0], &paused, b0.expiry, &[], false);
    }

    #[test]
    #[should_panic(expected = "count != paused-skip count")]
    fn kpause_completeness_panics_on_padded_surface() {
        let b0 = reference_box0();
        let b1 = reference_box1();
        let paused = [pair_tag_of(&b0.oracle)];
        let padded = [
            PausedHold { market_key: b0.market_key, position_id: b0.terms_id },
            PausedHold { market_key: b1.market_key, position_id: b1.terms_id },
        ];
        assert_paused_holds_complete(&[b0], &paused, b0.expiry, &padded, false);
    }

    #[test]
    fn kpause_completeness_accepts_exact_cover() {
        let b0 = reference_box0();
        let b1 = reference_box1();
        let paused = [pair_tag_of(&b0.oracle)];
        let surfaced = [PausedHold { market_key: b0.market_key, position_id: b0.terms_id }];
        assert_paused_holds_complete(&[b0, b1], &paused, b1.expiry, &surfaced, false);
    }

    #[test]
    fn gap2_marks_complete_surfaces_hold_for_live_paused_position() {
        let b0 = reference_box0();
        let proof_time = b0.expiry - 1;
        let paused = [pair_tag_of(&b0.oracle)];
        let holds = assert_marks_complete(&[b0], &[], &paused, proof_time, true);
        assert_eq!(holds.len(), 1, "one hold for the one live position exempted on pause grounds");
        assert_eq!(holds[0].market_key, b0.market_key, "hold carries the live position's market_key");
        assert_eq!(holds[0].position_id, b0.terms_id, "hold carries the live position's identity");
        assert_paused_holds_complete(&[b0], &paused, proof_time, &holds, true);
    }

    #[test]
    #[should_panic(expected = "no PausedHold surface entry")]
    fn gap2_live_paused_position_without_hold_is_rejected() {
        let b0 = reference_box0();
        let proof_time = b0.expiry - 1;
        let paused = [pair_tag_of(&b0.oracle)];
        assert_paused_holds_complete(&[b0], &paused, proof_time, &[], true);
    }

    #[test]
    fn gap2_live_paused_position_not_required_off_marking_epoch() {
        let b0 = reference_box0();
        let proof_time = b0.expiry - 1;
        let paused = [pair_tag_of(&b0.oracle)];
        let holds = assert_marks_complete(&[b0], &[], &paused, proof_time, false);
        assert!(holds.is_empty(), "no marking epoch ⇒ no live-pause hold surfaced");
        assert_paused_holds_complete(&[b0], &paused, proof_time, &[], false);
    }

    #[test]
    fn gap2_due_and_live_paused_boxes_both_surface_holds_on_marking_epoch() {
        let b0 = reference_box0();
        let mut bx_live = reference_box0();
        bx_live.terms_id = [0x33u8; 32];
        bx_live.expiry = b0.expiry + 100_000;
        let proof_time = b0.expiry;
        let paused = [pair_tag_of(&b0.oracle)];
        let due_holds = assert_due_boxes_have_proven_twap(&[b0, bx_live], &[], &paused, proof_time);
        assert_eq!(due_holds.len(), 1, "one due hold — b0 only (bx_live is live)");
        let live_holds = assert_marks_complete(&[b0, bx_live], &[], &paused, proof_time, true);
        assert_eq!(live_holds.len(), 1, "one live hold — bx_live only (b0 is due)");
        let mut all = due_holds;
        all.extend(live_holds);
        assert_paused_holds_complete(&[b0, bx_live], &paused, proof_time, &all, true);
    }

    #[test]
    fn opened_position_ids_accepts_exact_cover() {
        let nb = a_new_position();
        assert!(!nb.sig_a.is_empty(), "Core 2.0 opens are always dual-sig (both sigs present)");
        let opened = [nb.terms_id];
        assert_opened_position_ids_complete(&[nb], &opened);
    }

    #[test]
    #[should_panic(expected = "openedPositionIds over-surface")]
    fn opened_position_ids_panics_on_over_surface() {
        let nb = a_new_position();
        let fabricated = [0xEEu8; 32];
        let opened = [nb.terms_id, fabricated];
        assert_opened_position_ids_complete(&[nb], &opened);
    }

    #[test]
    #[should_panic(expected = "phantom-box hole")]
    fn opened_position_ids_panics_on_withheld_id() {
        let nb = a_new_position();
        let opened: [[u8; 32]; 0] = [];
        assert_opened_position_ids_complete(&[nb], &opened);
    }

    #[test]
    #[should_panic(expected = "trusted whole-account settle_residual is removed")]
    fn c02_assert_no_trusted_settle_panics_on_some() {
        let ri = RiskInputs { unconsumed_settle_residual: Some(1_000_000), ..empty_ri() };
        assert_no_trusted_settle(&ri);
    }
}
