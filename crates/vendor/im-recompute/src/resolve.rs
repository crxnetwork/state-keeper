//! Core 2.0 per-account resolve — NO money in the tree. Split the book into SETTLING (named in `settlements_in`, pair not
//! `paused`; a paused pair is HELD, never force-settled) and SURVIVING, then EMIT realized cash as `Settlement` and per-cp
//! IM as `ImRequirement`. Survivors re-root in canonical `terms_id` order and carry the cumulative VM; solvency is
//! enforced ON-CHAIN, so ordinary settlement names no `DefaultRecord`. `openLock` mirrors every trade into TWO records
//! sharing one `terms_id`, one per party's book, and BOTH settle — so the inter-party residual is emitted from EXACTLY
//! ONE seat: the LOSER's, the payer. It must be the loser's, because a settling leg RELEASES its IM — a debit deferred to
//! the winner's later fold would let the loser shed margin and withdraw before it lands. The residual is GROSS, so the
//! pair conserves (loser out = gross, winner in = gross).

use crate::{PositionRecord, PositionSettlement, DefaultRecord, ScenarioTable,
    Settlement, ImRequirement, assert_unique_terms_id, positions_root, pair_tag_of,
    im_requirements_for};

/// The per-account lifecycle delta the proof emits; mirrors on-chain re-emitted events.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResolveOutcome {
    /// Σ pushedIM == K: nothing moved.
    NoOp,
    /// Σ pushedIM > K: netting refund — excess locked → free.
    Released,
    /// Σ pushedIM < K, free covered the shortfall — topped up to K.
    ToppedUp,
    /// Σ pushedIM < K, free could NOT cover — position unwound (free reject).
    Rejected,
    /// Position past expiry — residual realized into free, position retired.
    Settled,
    /// Some positions settled, some live: the settling ones retire, the rest re-root. Account NOT wound down.
    SettledPerPosition,
    /// Per-position loss exceeded free: the uncovered amount is named as a `DefaultRecord` and the position retires.
    Defaulted,
}

/// Resolved state of one account: the fold inputs for a fresh account leaf, plus the cash / IM / fee records the chain re-emits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountResolve {
    /// New cumulative VM carried into the leaf (survivors only; 0 on a full wind-down).
    pub vm_equity: i128,
    /// Survivors' `positions_root` (`[0u8;32]` when none survive).
    pub positions_root: [u8; 32],
    /// Any position survives? false ⇒ account wound down this fold.
    pub positions_live: bool,
    /// Survivors — settling positions removed, paused holds kept — in canonical `terms_id` order.
    pub surviving: Vec<PositionRecord>,
    /// Realized cash: the GROSS inter-party residual, emitted ONCE from the LOSER's seat.
    pub settlements: Vec<Settlement>,
    /// Per-counterparty IM claims over the survivors.
    pub im_requirements: Vec<ImRequirement>,
    /// Named under-margin claims. Empty in ordinary settlement — on-chain coverage and the grace gate decide cuts.
    pub defaults: Vec<DefaultRecord>,
    /// The lifecycle outcome the chain re-emits.
    pub outcome: ResolveOutcome,
}

/// Resolve `owner`'s book for the fold; an empty (or wholly paused) `settlements_in` is the live no-settle branch.
#[allow(clippy::too_many_arguments)]
pub fn resolve_account(
    owner: [u8; 20],
    positions: &[PositionRecord],
    settlements_in: &[PositionSettlement],
    new_vm: i128,
    paused: &[[u8; 32]],
    proof_time: u64,
    table: &ScenarioTable,
) -> AccountResolve {
    let _ = proof_time;
    assert_unique_terms_id(positions);

    let mut settlements: Vec<Settlement> = Vec::new();
    let mut surviving: Vec<PositionRecord> = Vec::with_capacity(positions.len());
    let mut settled_count: usize = 0;

    for p in positions {
        let position_paused = paused.contains(&pair_tag_of(&p.oracle));
        let settle = if position_paused {
            None
        } else {
            settlements_in.iter().find(|s| s.terms_id == p.terms_id)
        };
        match settle {
            Some(s) => {
                if s.vm_realized < 0 {
                    settlements.push(Settlement { payer: owner, payee: p.counterparty, usd: s.vm_realized.unsigned_abs(), id: p.terms_id });
                }
                settled_count += 1;
            }
            None => surviving.push(*p),
        }
    }

    surviving.sort_by(|a, b| a.terms_id.cmp(&b.terms_id));
    let positions_live = !surviving.is_empty();
    let positions_root = positions_root(&surviving);
    let im_requirements = im_requirements_for(owner, &surviving, table);
    let vm_equity = if positions_live { new_vm } else { 0 };

    let outcome = if settled_count == 0 {
        ResolveOutcome::NoOp
    } else if positions_live {
        ResolveOutcome::SettledPerPosition
    } else {
        ResolveOutcome::Settled
    };

    AccountResolve {
        vm_equity,
        positions_root,
        positions_live,
        surviving,
        settlements,
        im_requirements,
        defaults: Vec::new(),
        outcome,
    }
}

/// Thin live no-settle convenience — equivalent to `resolve_account` with an empty `settlements_in`.
pub fn resolve_no_settle(
    owner: [u8; 20],
    positions: &[PositionRecord],
    new_vm: i128,
    table: &ScenarioTable,
) -> AccountResolve {
    resolve_account(owner, positions, &[], new_vm, &[], 0, table)
}

#[cfg(test)]
mod tests {
    use crate::test_util::*;
    use crate::*;

    #[test]
    fn resolve_account_settles_and_emits_cash() {
        let b0 = reference_box0();
        let b1 = reference_box1();
        let owner = reference_account_owner();
        let settlements_in = [PositionSettlement { terms_id: b0.terms_id, vm_realized: -30_000 }];
        let r = resolve_account(owner, &[b0, b1], &settlements_in, 0, &[], 0, &test_table());
        assert_eq!(r.outcome, ResolveOutcome::SettledPerPosition, "a partial settle stays live");
        assert!(r.positions_live);
        assert_eq!(r.surviving.len(), 1, "only b0 retired");
        assert_eq!(r.surviving[0].terms_id, b1.terms_id, "b1 survives");
        assert_eq!(r.positions_root, positions_root(&[b1]), "survivors re-root over the remaining");
        assert_eq!(r.settlements.len(), 1, "one gross-residual settlement, no fee");
        assert_eq!(r.settlements[0].payer, owner, "the loser (owner) pays its own debit");
        assert_eq!(r.settlements[0].payee, b0.counterparty, "the counterparty (winner) is the payee");
        assert_eq!(r.settlements[0].usd, 30_000);
        assert!(r.defaults.is_empty(), "ordinary settlement names no default (coverage is on-chain)");
    }

    #[test]
    fn resolve_account_no_settle_is_noop_and_conserves() {
        let b0 = reference_box0();
        let b1 = reference_box1();
        let owner = reference_account_owner();
        let r = resolve_account(owner, &[b0, b1], &[], 500, &[], 0, &test_table());
        assert_eq!(r.outcome, ResolveOutcome::NoOp, "no settlement ⇒ NoOp");
        assert!(r.settlements.is_empty(), "no realized cash emitted");
        assert_eq!(r.vm_equity, 500, "the supplied new VM carries into the leaf");
        assert_eq!(r.surviving.len(), 2, "every position survives");
        assert_eq!(r.im_requirements.len(), 2, "one ImRequirement per counterparty netting set");
    }

    #[test]
    fn resolve_account_paused_position_is_held_not_settled() {
        let b0 = reference_box0();
        let b1 = reference_box1();
        let owner = reference_account_owner();
        let paused = [pair_tag_of(&b0.oracle)];
        let settlements_in = [PositionSettlement { terms_id: b0.terms_id, vm_realized: 30_000 }];
        let r = resolve_account(owner, &[b0, b1], &settlements_in, 0, &paused, 0, &test_table());
        assert!(r.surviving.iter().any(|b| b.terms_id == b0.terms_id), "the paused position is held, not retired");
        assert_eq!(r.surviving.len(), 2, "both positions survive");
        assert!(r.settlements.is_empty(), "a held paused position realizes no cash");
        assert_eq!(r.outcome, ResolveOutcome::NoOp, "nothing settled ⇒ NoOp");
    }
}
