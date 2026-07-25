//! The guest's whole-book state transition as a pure, testable function — no `sp1_zkvm` dependency.
//!
//! Core 2.0: the circuit computes risk, the chain holds money. ONE USD tree keyed by `account_id_single(owner)`;
//! the leaf is `{aid, vm_equity_usd, positions_root}` and holds no money. Each fold emits `settlements` (USD the
//! till pays), `im_requirements` (per-cp IM claims the till coverage-compares) and `defaults` (under-margin
//! claims the grace gate rules on). Deposits, watermarks and conservation live on-chain. `overflow-checks = true`.
//!
//! The fold, in order: gate the clock and the handoff-witness counts; rebuild each touched account's prior leaf
//! and bind its positions to the committed `positions_root`; run the `openLock` pre-pass; resolve each account
//! (settle due positions on proven TWAPs, re-mark VM from proven marks, emit cash and IM claims); move the A→C
//! handoffs; take per-cp IM over the FINAL books; fold both trees; canonicalize and prove the bind surfaces.
//!
//! Bindings. Touched accounts are strictly ascending by aid, no duplicate; `proof_now` must be ≥ every consumed
//! mark's publish time. Every new position and every handoff consent is signed under the proof's pinned EIP-712
//! domain, so a signature from another deployment cannot be replayed. A handoff rebuilds the moved leaf from A's
//! REAL committed position (the witness must equal it), so a prover cannot forge the economics C inherits.

use crate::{
    account_id_single, account_leaf, account_vm_from_marks, apply_new_boxes_to_book,
    assert_due_boxes_have_proven_twap, assert_marks_complete, assert_no_trusted_settle,
    assert_opened_position_ids_complete, assert_paused_holds_complete,
    closeout_novation_close, closeout_novation_entry_valid,
    closeout_novation_mark_fresh, im_requirements_for, keccak_pair, mark_fresh,
    moved_position, novation_entry_valid, pair_tag_of, position_settlements_from_twaps, positions_open_root,
    positions_root, registry_leaf, resolve_account, smt2, transfer_as_close, unwind_entry_valid,
    unwind_settlements_for_account, Account, BookOpenOutcome, CloseoutNovation, CloseoutNovationWitness,
    ConsumedMark, ConsumedTwap, DefaultRecord, ImRequirement, NewPosition, Novation,
    NovationWitness, PausedHold, PositionRecord, PositionSettlement, ResolveOutcome, RiskInputs, Roots,
    ScenarioTable, Settlement, Unwind, UnwindWitness,
};

/// Everything the state_transition reads, filled from stdin in a fixed read order (Core 2.0 — one book).
pub struct StateTransitionInputs {
    /// The single USD book: `(root_prev, accounts_root_prev, touched)` — touched strictly ascending by aid.
    pub book: crate::TouchedBook,
    /// Oracle-pinned marks (used only for the `proof_now >= max(publish_time)` gate).
    pub marks: Vec<crate::Mark>,
    /// Paused pairTag set.
    pub paused_pairs: Vec<[u8; 32]>,
    /// transferAsClose moves, surfaced verbatim.
    pub novations: Vec<Novation>,
    /// Newly-Bound positions (the openLock pre-pass).
    pub new_positions: Vec<NewPosition>,
    /// transferAsClose witnesses, one per committed novation in the same order.
    pub novation_witnesses: Vec<NovationWitness>,
    /// Default-closeout A→C handoffs, surfaced verbatim.
    pub closeout_novations: Vec<CloseoutNovation>,
    /// closeout_novation_close witnesses, one per committed closeout_novation in the same order.
    pub closeout_novation_witnesses: Vec<CloseoutNovationWitness>,
    /// The bound proof clock; in-guest MUST be >= max(mark.publish_time).
    pub proof_now: u64,
    /// The proof's pinned EIP-712 domain separator; every new position's Terms must be signed under it.
    pub domain_separator: [u8; 32],
    /// The scenario-table witness; the guest validates it and recomputes its keccak commitment, which the
    /// chain re-asserts against the owner-published `scenarioRoot`.
    pub scenario_table: ScenarioTable,
    /// F2 bilateral unwinds, surfaced verbatim as the 15th public-values row.
    pub unwinds: Vec<Unwind>,
    /// `unwind_close` witnesses, one per committed unwind in the same order.
    pub unwind_witnesses: Vec<UnwindWitness>,
}

/// Everything the state_transition commits, mapped 1:1 onto the sol! PublicValuesStruct (15 rows).
pub struct StateTransitionOutputs {
    /// The single USD tree's root advance.
    pub roots: Roots,
    /// Named under-margin claims (grace-gated on-chain).
    pub defaults: Vec<DefaultRecord>,
    /// Proven prices consumed by per-position settles.
    pub consumed_twaps: Vec<ConsumedTwap>,
    /// transferAsClose moves surfaced verbatim.
    pub novations: Vec<Novation>,
    /// Validated default-closeout A→C handoffs.
    pub closeout_novations: Vec<CloseoutNovation>,
    /// keccak-chain of ordered per-account outcomes plus rejected opens.
    pub events_commitment: [u8; 32],
    /// The bound proof clock (equals input proof_now).
    pub committed_now: u64,
    /// The proof's pinned EIP-712 domain (equals input domain_separator).
    pub committed_domain: [u8; 32],
    /// One entry per due/live position skipped on PAUSE grounds, sorted canonically.
    pub paused_holds: Vec<PausedHold>,
    /// The keccak commitment of the scenario table the guest margined with, recomputed IN-GUEST from the raw
    /// witness bytes and re-asserted on-chain against the owner-published root (public values row 10).
    pub scenario_root: [u8; 32],
    /// The deduped proven hourly marks consumed this epoch, re-asserted against the `boundTwap` rail.
    pub consumed_marks: Vec<ConsumedMark>,
    /// The `terms_id` of every new position folded this epoch; re-asserted on-chain against `opened[id]`.
    pub opened_position_ids: Vec<[u8; 32]>,
    /// Per touched netting set: `position_im_floor(acct's positions facing cp)` — scenario-ES with the seat floor.
    pub im_requirements: Vec<ImRequirement>,
    /// Netted USD cash obligations due this fold, paid at the till.
    pub settlements: Vec<Settlement>,
    /// F2 bilateral unwinds surfaced verbatim (the 15th public-values row); `finalizeUnwinds` recomputes and
    /// consumes each single-use `unwindAuth` commitment from these fields.
    pub unwinds: Vec<Unwind>,
}

const OUTCOME_TAG_REJECTED: u8 = 3;

fn outcome_tag(o: ResolveOutcome) -> u8 {
    match o {
        ResolveOutcome::NoOp => 0,
        ResolveOutcome::Released => 1,
        ResolveOutcome::ToppedUp => 2,
        ResolveOutcome::Rejected => 3,
        ResolveOutcome::Settled => 4,
        ResolveOutcome::SettledPerPosition => 5,
        ResolveOutcome::Defaulted => 6,
    }
}

struct AccountPost {
    aid: [u8; 32],
    owner: [u8; 20],
    positions: Vec<PositionRecord>,
    vm: i128,
    prior_leaf: Option<[u8; 32]>,
}

/// Full whole-book state transition over the single USD tree.
pub fn state_transition(inputs: StateTransitionInputs) -> StateTransitionOutputs {
    let StateTransitionInputs {
        book,
        marks,
        paused_pairs,
        novations,
        new_positions,
        novation_witnesses,
        closeout_novations,
        closeout_novation_witnesses,
        proof_now,
        domain_separator,
        scenario_table,
        unwinds,
        unwind_witnesses,
    } = inputs;

    // Validate the scenario table ONCE (fail-closed on any malformed field) and recompute its commitment —
    // the chain re-asserts this root against the owner-published one, so a prover cannot margin off a table
    // the owner never published.
    let scenario_root = scenario_table.scenario_root();

    let (root_prev, accounts_root_prev, touched) = book;

    assert_eq!(
        novation_witnesses.len(),
        novations.len(),
        "state_transition: one transferAsClose witness required per committed novation (GS-02)"
    );
    assert_eq!(
        closeout_novation_witnesses.len(),
        closeout_novations.len(),
        "state_transition: one closeout_novation_close witness required per committed closeout_novation (GS-02)"
    );
    assert_eq!(
        unwind_witnesses.len(),
        unwinds.len(),
        "state_transition: one unwind_close witness required per committed unwind (GS-02)"
    );

    let proof_time: u64 = proof_now;
    let latest_publish_time: u64 = marks.iter().map(|m| m.publish_time).max().unwrap_or(0);
    assert!(
        proof_time >= latest_publish_time,
        "state_transition: proof_now must be >= every consumed mark publish_time"
    );

    let marking_epoch: bool = touched.iter().any(|ta| !ta.risk.proven_marks.is_empty());

    for nb in &new_positions {
        assert_eq!(
            nb.domain_separator, domain_separator,
            "state_transition: new position domain_separator != the proof's pinned deployment domain (N-01)"
        );
    }

    let mut events_commitment: [u8; 32] = [0u8; 32];
    let mut defaults: Vec<DefaultRecord> = Vec::new();
    let mut settlements: Vec<Settlement> = Vec::new();
    let mut consumed_twaps: Vec<ConsumedTwap> = Vec::new();
    let mut consumed_marks: Vec<ConsumedMark> = Vec::new();
    let mut paused_holds: Vec<PausedHold> = Vec::new();
    let mut opened_position_ids: Vec<[u8; 32]> = Vec::new();
    let mut all_positions_for_completeness: Vec<PositionRecord> = Vec::new();

    let mut prev_key: Option<[u8; 32]> = None;
    let mut priors: Vec<Option<[u8; 32]>> = Vec::with_capacity(touched.len());
    for ta in touched.iter() {
        let (a, ri) = (&ta.account, &ta.risk);
        let aid = account_id_single(a.account_owner);
        if let Some(p) = prev_key {
            assert!(aid > p, "state_transition: touched accounts must be strictly ascending by aid, no dup");
        }
        prev_key = Some(aid);
        assert!(ta.state_witness.key == aid, "state_transition: state witness key != aid");
        if let Some(rw) = &ta.registry_witness {
            assert!(rw.key == aid, "state_transition: registry witness key != aid");
        }

        let present = matches!(ta.state_witness.terminal, im_types::SmtTerminal::Leaf(_));
        if !present {
            assert!(
                a.vm_equity == 0 && a.prev_vm_equity == 0 && a.positions_root == [0u8; 32],
                "state_transition: an absent touched account must carry all-default prior fields"
            );
            assert!(
                ri.positions.is_empty() && ri.proven_twaps.is_empty() && ri.proven_marks.is_empty(),
                "state_transition: an absent touched account must carry an empty risk witness"
            );
        }
        assert!(
            positions_open_root(&ri.positions, &a.positions_root),
            "state_transition: supplied positions do not reproduce the account's positionsRoot (GS-03)"
        );
        paused_holds.extend(assert_due_boxes_have_proven_twap(
            &ri.positions, &ri.proven_twaps, &paused_pairs, proof_time,
        ));
        all_positions_for_completeness.extend(ri.positions.iter().copied());
        priors.push(present.then(|| account_leaf(aid, a.prev_vm_equity, a.positions_root)));
    }

    let mut accounts: Vec<(Account, RiskInputs)> =
        touched.iter().map(|ta| (ta.account.clone(), ta.risk.clone())).collect();
    let BookOpenOutcome { rejected: rejected_opens, opened } =
        apply_new_boxes_to_book(&mut accounts, &new_positions, proof_time);
    opened_position_ids.extend(opened);

    // F2 bilateral unwind — validate each committed tear-up against its dual-sig witness, bind the domain, and
    // assert the torn-up leaf actually exists (== the witness) in A's committed book (invariant #6: no unwinding an
    // absent/closed leaf). The per-seat settlements are injected into `resolve_account` below; the set-emptying
    // IM-zero rows are emitted once the FINAL books are known.
    for (entry, witness) in unwinds.iter().zip(unwind_witnesses.iter()) {
        assert_eq!(
            witness.domain_separator, domain_separator,
            "state_transition: unwind consent domain != the proof's pinned domain (guest-crypto-4)"
        );
        assert!(
            unwind_entry_valid(witness, entry),
            "state_transition: committed unwind is not a sound bilateral unwind_close (GS-02)"
        );
        let ai = accounts
            .iter()
            .position(|(a, _)| a.account_owner == entry.party_a)
            .expect("unwind: A is not a touched account");
        let src = accounts[ai]
            .1
            .positions
            .iter()
            .find(|b| b.terms_id == entry.old_id)
            .copied()
            .expect("unwind: A does not hold old_id in its committed book (GS-03) — cannot unwind an absent/closed leaf");
        assert_eq!(
            witness.a_position, src,
            "unwind: witness a_position != A's committed leaf for old_id — forged unwind economics (guest-crypto-4)"
        );
        // Two-endpoint requirement, symmetric to the novation handoff (`apply_handoff_move` demands BOTH A and C be
        // touched): party_b's MIRROR seat of `old_id` must be a touched account in this SAME fold too. Without it a
        // prover folds `touched=[A], unwinds=[{X,A,B}]` — A's seat retires but B's identical-`terms_id` mirror stays
        // LIVE in B's unchanged leaf, while the emptied-set loop still zeroes `imRequired[B][A]` → B withdraws all
        // collateral off a still-live position. Forcing B into the fold makes `unwind_settlements_for_account` retire
        // B's seat and emit its side symmetrically. Matched-principal holds only if BOTH seats leave together.
        let bi = accounts
            .iter()
            .position(|(a, _)| a.account_owner == entry.party_b)
            .expect("unwind: B is not a touched account — the mirror seat must be folded in the same epoch");
        let mirror = accounts[bi]
            .1
            .positions
            .iter()
            .find(|b| b.terms_id == entry.old_id)
            .copied()
            .expect("unwind: B does not hold old_id in its committed book (GS-03) — the mirror seat must retire with A's");
        assert_eq!(
            mirror.counterparty, entry.party_a,
            "unwind: B's mirror seat for old_id does not face A — not a genuine bilateral mirror (guest-crypto-4)"
        );
    }

    let mut posts: Vec<AccountPost> = Vec::with_capacity(accounts.len());
    for ((a, ri), prior) in accounts.iter().zip(priors.iter()) {
        let aid = account_id_single(a.account_owner);

        assert_no_trusted_settle(ri);

        let (mut position_settlements, lane_consumed): (Vec<PositionSettlement>, Vec<ConsumedTwap>) =
            position_settlements_from_twaps(&ri.positions, &ri.proven_twaps);
        consumed_twaps.extend(lane_consumed.iter().copied());
        // F2: inject the symmetric unwind settlement for any seat this account holds of a torn-up position — from
        // THAT seat's own side — so `resolve_account` retires the leaf and emits the loser→winner residual once.
        position_settlements.extend(unwind_settlements_for_account(&ri.positions, &unwinds));

        for m in &ri.proven_marks {
            assert!(
                mark_fresh(m.mark_time, proof_time),
                "state_transition: proven-mark mark_time stale/future beyond the mark window"
            );
        }
        paused_holds.extend(assert_marks_complete(
            &ri.positions, &ri.proven_marks, &paused_pairs, proof_time, marking_epoch,
        ));

        let survivors_for_vm: Vec<PositionRecord> = ri
            .positions
            .iter()
            .copied()
            .filter(|b| {
                let paused = paused_pairs.contains(&pair_tag_of(&b.oracle));
                paused || !position_settlements.iter().any(|s| s.terms_id == b.terms_id)
            })
            .collect();
        let (new_vm, consumed) = if marking_epoch {
            account_vm_from_marks(&survivors_for_vm, &ri.proven_marks)
        } else {
            (a.prev_vm_equity, Vec::new())
        };
        consumed_marks.extend(consumed.into_iter());

        let r = resolve_account(
            a.account_owner,
            &ri.positions,
            &position_settlements,
            new_vm,
            &paused_pairs,
            proof_time,
            &scenario_table,
        );
        defaults.extend(r.defaults.iter().copied());
        settlements.extend(r.settlements.iter().copied());

        let mut ev = [0u8; 32];
        ev[0] = outcome_tag(r.outcome);
        ev[1..].copy_from_slice(&aid[..31]);
        events_commitment = keccak_pair(&events_commitment, &ev);

        posts.push(AccountPost {
            aid,
            owner: a.account_owner,
            positions: r.surviving,
            vm: r.vm_equity,
            prior_leaf: *prior,
        });
    }

    for (entry, witness) in novations.iter().zip(novation_witnesses.iter()) {
        assert_eq!(
            witness.domain_separator, domain_separator,
            "state_transition: voluntary novation consent domain != the proof's pinned domain (guest-crypto-2)"
        );
        assert!(
            novation_entry_valid(witness, entry),
            "state_transition: committed novation is not a conserved, in-bounds transferAsClose (GS-02)"
        );
        let r = transfer_as_close(witness);
        assert!(r.reject.is_none(), "state_transition: committed novation rejected in-guest");
        settlements.extend(r.settlements.iter().copied());
        apply_handoff_move(
            &mut posts, r.party_a, r.party_c, entry.old_id, entry.new_id, entry.c_im, &witness.a_position,
        );
    }

    for (entry, witness) in closeout_novations.iter().zip(closeout_novation_witnesses.iter()) {
        assert_eq!(
            witness.domain_separator, domain_separator,
            "state_transition: closeout novation consent domain != the proof's pinned domain (guest-crypto-3)"
        );
        assert!(
            closeout_novation_entry_valid(witness, entry),
            "state_transition: committed closeout_novation is not a sound closeout_novation_close (GS-02)"
        );
        assert!(
            closeout_novation_mark_fresh(witness.proven_twap.close_time, proof_time),
            "state_transition: closeout_novation handoff mark close_time stale beyond the window (M-freshness)"
        );
        let r = closeout_novation_close(witness);
        settlements.extend(r.settlements.iter().copied());
        consumed_twaps.push(ConsumedTwap {
            feed_id: witness.proven_twap.feed_id,
            close_time: witness.proven_twap.close_time,
            twap: witness.proven_twap.settle_price as i128,
            expo: witness.proven_twap.expo,
        });
        apply_handoff_move(
            &mut posts, r.party_a, r.party_c, entry.old_id, entry.new_id, entry.c_im, &witness.a_position,
        );
    }

    let mut im_requirements: Vec<ImRequirement> = Vec::new();
    for p in &posts {
        im_requirements.extend(im_requirements_for(p.owner, &p.positions, &scenario_table));
    }

    // ★ Release IM on a set-emptying unwind (spec invariant #3 — the margin-return correctness gate). On-chain,
    // `_writeReqsAndCompare` only OVERWRITES emitted rows; it never zeroes an emptied set. So when an unwind retires
    // the LAST position in an (A,B) netting set, no (A,B) row is emitted above → `imRequired[A][B]/[B][A]` stays
    // stale-positive → `withdraw` reverts forever and the margin never returns. Fix: emit an explicit zero-valued
    // row for BOTH directions of every set an unwind has emptied. Guarded on the FINAL books, so a set that still
    // holds another live position is NOT zeroed (the NovationPartialMultiPos lesson), and a positive row already
    // written by `im_requirements_for` is never double-emitted.
    for u in &unwinds {
        for (owner, cp) in [(u.party_a, u.party_b), (u.party_b, u.party_a)] {
            let owner_still_faces_cp = posts
                .iter()
                .find(|p| p.owner == owner)
                .map(|p| p.positions.iter().any(|b| b.counterparty == cp))
                .unwrap_or(false);
            let already_emitted = im_requirements.iter().any(|r| r.acct == owner && r.cp == cp);
            if !owner_still_faces_cp && !already_emitted {
                im_requirements.push(ImRequirement { acct: owner, cp, usd: 0 });
            }
        }
    }

    let mut state_running: [u8; 32] = root_prev;
    let mut registry_running: [u8; 32] = accounts_root_prev;
    let reg_leaf = registry_leaf();

    for (p, ta) in posts.iter().zip(touched.iter()) {
        debug_assert_eq!(ta.state_witness.key, p.aid, "staging order drifted from the touched order");
        let final_present = !p.positions.is_empty();
        let was_present = p.prior_leaf.is_some();

        let new_leaf = final_present.then(|| {
            account_leaf(p.aid, p.vm, positions_root(&p.positions))
        });
        state_running = smt2::apply_step(state_running, &ta.state_witness, p.prior_leaf, new_leaf);

        match (was_present, final_present) {
            (true, true) | (false, false) => assert!(
                ta.registry_witness.is_none(),
                "state_transition: registry witness supplied for a membership-preserving touch"
            ),
            (false, true) => {
                let rw = ta.registry_witness.as_ref()
                    .expect("state_transition: inserting account needs a registry witness");
                registry_running = smt2::apply_step(registry_running, rw, None, Some(reg_leaf));
            }
            (true, false) => {
                let rw = ta.registry_witness.as_ref()
                    .expect("state_transition: pruning account needs a registry witness");
                registry_running = smt2::apply_step(registry_running, rw, Some(reg_leaf), None);
            }
        }
    }

    for terms_id in &rejected_opens {
        let mut ev = [0u8; 32];
        ev[0] = OUTCOME_TAG_REJECTED;
        ev[1..].copy_from_slice(&terms_id[..31]);
        events_commitment = keccak_pair(&events_commitment, &ev);
    }

    paused_holds.sort_by(|a, b| (a.market_key, a.position_id).cmp(&(b.market_key, b.position_id)));
    assert_paused_holds_complete(&all_positions_for_completeness, &paused_pairs, proof_time, &paused_holds, marking_epoch);

    consumed_marks.sort_by(|a, b| (a.feed_id, a.mark_time).cmp(&(b.feed_id, b.mark_time)));
    consumed_marks.dedup();

    opened_position_ids.sort();
    opened_position_ids.dedup();
    assert_opened_position_ids_complete(&new_positions, &opened_position_ids);

    im_requirements.sort_by(|a, b| (a.acct, a.cp).cmp(&(b.acct, b.cp)));

    StateTransitionOutputs {
        roots: Roots {
            root_prev,
            root_new: state_running,
            accounts_root_prev,
            accounts_root_new: registry_running,
        },
        defaults,
        consumed_twaps,
        novations,
        closeout_novations,
        events_commitment,
        committed_now: proof_time,
        committed_domain: domain_separator,
        paused_holds,
        scenario_root,
        consumed_marks,
        opened_position_ids,
        im_requirements,
        settlements,
        unwinds,
    }
}

/// Move a novated position A→C in the post rows: drop `old_id` from A, push the rebuilt leaf onto C.
fn apply_handoff_move(
    posts: &mut [AccountPost],
    party_a: [u8; 20],
    party_c: [u8; 20],
    old_id: [u8; 32],
    new_id: [u8; 32],
    c_im: u128,
    a_position: &PositionRecord,
) {
    assert!(party_a != party_c, "handoff: A and C must be distinct accounts");
    let ai = posts.iter().position(|p| p.owner == party_a).expect("handoff: A not a touched account");
    let src = posts[ai]
        .positions
        .iter()
        .find(|b| b.terms_id == old_id)
        .copied()
        .expect("handoff: A does not hold old_id in its committed book (GS-03) (guest-crypto-1)");
    assert_eq!(
        *a_position, src,
        "handoff: witness a_position != A's committed leaf for old_id — forged handoff economics (guest-crypto-1)"
    );
    let before = posts[ai].positions.len();
    posts[ai].positions.retain(|b| b.terms_id != old_id);
    assert_eq!(
        posts[ai].positions.len(),
        before - 1,
        "handoff: retain removed != 1 leaf (guest-crypto-1)"
    );
    let c_moved = moved_position(&src, new_id, c_im);
    let ci = posts.iter().position(|p| p.owner == party_c).expect("handoff: C not a touched account");
    posts[ci].positions.push(c_moved);
}

#[cfg(test)]
mod tests {
    use crate::test_util::*;
    use crate::*;

    fn pos(terms: u8, cp: [u8; 20], oracle: [u8; 20], pair: &[u8], notional_usd: u128, side: i8) -> PositionRecord {
        const M: u128 = 1_000_000;
        PositionRecord {
            terms_id: [terms; 32],
            counterparty: cp,
            oracle,
            notional: notional_usd * M,
            entry_rate: 1_000_000,
            side,
            expiry: 2_000_000_000,
            pushed_im: 0,
            market_key: market_key(INSTRUMENT_NDF, &keccak(&[pair])),
        }
    }

    /// End-to-end IM parity: the whole-book engine must reproduce the kernel's per-party IM to the cent, and its emitted root must equal a host recomputation over the survivors.
    #[test]
    fn golden_state_transition_reproduces_kernel_im_to_the_cent() {
        let owner_a: [u8; 20] = { let mut a = [0u8; 20]; a[19] = 0xA1; a };
        let owner_b: [u8; 20] = { let mut a = [0u8; 20]; a[19] = 0xB2; a };
        let cop_oracle: [u8; 20] = [0x03u8; 20];
        let brl_oracle: [u8; 20] = [0x04u8; 20];

        let a_positions = vec![
            pos(0x01, owner_b, cop_oracle, b"USD/COP", 500_000_000, 1),
            pos(0x02, owner_b, brl_oracle, b"USD/BRL", 200_000_000, 1),
        ];
        let b_positions = vec![
            pos(0x03, owner_a, cop_oracle, b"USD/COP", 500_000_000, -1),
            pos(0x04, owner_a, brl_oracle, b"USD/BRL", 200_000_000, -1),
        ];
        let table = test_table();

        const M: u128 = 1_000_000;
        let expected_a = position_im_floor(&a_positions, &table);
        let expected_b = position_im_floor(&b_positions, &table);
        // A is long $700M gross: the worst scenario is the −10% shock ⇒ $70M. B mirrors short: worst is the
        // +5% rally ⇒ $35M. Scenario-ES margin is ASYMMETRIC per side of the same matched trade.
        assert_eq!(expected_a, 70_000_000 * M, "A's expected kernel IM = 10% of the $700M long");
        assert_eq!(expected_b, 35_000_000 * M, "B's expected kernel IM = 5% of the $700M short");

        let mut accts: Vec<([u8; 20], Vec<PositionRecord>)> =
            vec![(owner_a, a_positions.clone()), (owner_b, b_positions.clone())];
        accts.sort_by_key(|(o, _)| account_id_single(*o));

        let leaves: Vec<([u8; 32], [u8; 32])> = accts
            .iter()
            .map(|(o, p)| {
                let aid = account_id_single(*o);
                (aid, account_leaf(aid, 0, positions_root(p)))
            })
            .collect();
        let steps: Vec<([u8; 32], Option<[u8; 32]>)> = leaves.iter().map(|(k, v)| (*k, Some(*v))).collect();
        let (witnesses, root_prev) = smt2::witness_sequence(&leaves, &steps);

        let sorted_aids: Vec<[u8; 32]> = accts.iter().map(|(o, _)| account_id_single(*o)).collect();
        let accounts_root_prev = credited_deposit_registry(&sorted_aids);

        let touched: Vec<TouchedAccount> = accts
            .iter()
            .zip(witnesses.iter())
            .map(|((o, p), w)| TouchedAccount {
                account: Account {
                    account_owner: *o,
                    positions_root: positions_root(p),
                    ..Default::default()
                },
                risk: RiskInputs { positions: p.clone(), ..empty_ri() },
                state_witness: w.clone(),
                registry_witness: None,
            })
            .collect();

        let out = state_transition(StateTransitionInputs {
            book: (root_prev, accounts_root_prev, touched),
            marks: vec![],
            paused_pairs: vec![],
            novations: vec![],
            new_positions: vec![],
            novation_witnesses: vec![],
            closeout_novations: vec![],
            closeout_novation_witnesses: vec![],
            proof_now: 1_700_000_000,
            domain_separator: [0x5Cu8; 32],
            scenario_table: table.clone(),
            unwinds: vec![],
            unwind_witnesses: vec![],
        });

        assert_eq!(out.im_requirements.len(), 2, "one ImRequirement per touched netting set (A↔B, B↔A)");
        let got_a = out.im_requirements.iter().find(|r| r.acct == owner_a && r.cp == owner_b)
            .expect("A's netting-set requirement is emitted").usd;
        let got_b = out.im_requirements.iter().find(|r| r.acct == owner_b && r.cp == owner_a)
            .expect("B's netting-set requirement is emitted").usd;

        println!("GOLDEN IM PARITY (6-dp USD):");
        println!("  party A  expected = {expected_a}  actual = {got_a}  {}", if got_a == expected_a { "PASS" } else { "FAIL" });
        println!("  party B  expected = {expected_b}  actual = {got_b}  {}", if got_b == expected_b { "PASS" } else { "FAIL" });

        assert_eq!(got_a, expected_a, "A: emitted imRequirement.usd must reproduce the kernel position_im_floor to the cent");
        assert_eq!(got_b, expected_b, "B: emitted imRequirement.usd must reproduce the kernel position_im_floor to the cent");

        assert!(out.settlements.is_empty(), "a quiet no-settle epoch moves no cash");
        assert!(out.defaults.is_empty(), "no under-margin claim on a solvent, unsettled book");
        assert_eq!(out.committed_now, 1_700_000_000, "the proof clock is bound through");

        let mut host = smt2::Smt2::new();
        for (o, p) in &accts {
            let aid = account_id_single(*o);
            host.insert(aid, account_leaf(aid, 0, positions_root(p)));
        }
        assert_eq!(out.roots.root_new, host.root(),
            "guest-emitted root_new must equal the host recomputation of the new USD tree over the survivors");
        assert_eq!(out.roots.root_new, root_prev,
            "a quiet epoch (VM unmoved, survivors unchanged) leaves the state root byte-identical — self-consistent");
        assert_eq!(out.roots.accounts_root_new, accounts_root_prev,
            "no membership change ⇒ the registry root is carried through unchanged");
    }

    /// Build a membership-preserving touched book from `(owner, initial_positions, surviving_positions)` triples —
    /// every leaf present before and after (so `registry_witness` is `None`, no pruning). Because the fold CHANGES
    /// leaf values (positions retire), the state witnesses must be the SEQUENTIAL witnesses for the actual
    /// prior→new transition — captured as each leaf updates — so a later leaf's siblings carry the earlier leaf's
    /// NEW hash. `root_prev` is the INITIAL tree root; the VM stays 0 (non-marking, prev_vm 0), so the predicted
    /// new leaf `account_leaf(aid, 0, positions_root(surviving))` matches what `resolve_account` will build.
    #[allow(clippy::type_complexity)]
    fn build_book(
        accts: &[([u8; 20], Vec<PositionRecord>, Vec<PositionRecord>)],
    ) -> ([u8; 32], [u8; 32], Vec<TouchedAccount>) {
        let mut accts = accts.to_vec();
        accts.sort_by_key(|(o, _, _)| account_id_single(*o));

        let initial_leaves: Vec<([u8; 32], [u8; 32])> = accts
            .iter()
            .map(|(o, init, _)| {
                let aid = account_id_single(*o);
                (aid, account_leaf(aid, 0, positions_root(init)))
            })
            .collect();
        let steps: Vec<([u8; 32], Option<[u8; 32]>)> = accts
            .iter()
            .map(|(o, _, surv)| {
                let aid = account_id_single(*o);
                (aid, Some(account_leaf(aid, 0, positions_root(surv))))
            })
            .collect();
        let (witnesses, _root_after) = smt2::witness_sequence(&initial_leaves, &steps);

        let mut t = smt2::Smt2::new();
        for (k, v) in &initial_leaves {
            t.insert(*k, *v);
        }
        let root_prev = t.root();

        let sorted_aids: Vec<[u8; 32]> = accts.iter().map(|(o, _, _)| account_id_single(*o)).collect();
        let accounts_root_prev = credited_deposit_registry(&sorted_aids);
        let touched: Vec<TouchedAccount> = accts
            .iter()
            .zip(witnesses.iter())
            .map(|((o, init, _), w)| TouchedAccount {
                account: Account {
                    account_owner: *o,
                    positions_root: positions_root(init),
                    ..Default::default()
                },
                risk: RiskInputs { positions: init.clone(), ..empty_ri() },
                state_witness: w.clone(),
                registry_witness: None,
            })
            .collect();
        (root_prev, accounts_root_prev, touched)
    }

    fn im_row(out: &StateTransitionOutputs, acct: [u8; 20], cp: [u8; 20]) -> Vec<u128> {
        out.im_requirements.iter().filter(|r| r.acct == acct && r.cp == cp).map(|r| r.usd).collect()
    }

    /// The headline: an unwind that empties the (A,B) set retires BOTH mirrored seats, emits ONE loser→winner
    /// residual, and — the margin-return fix — emits zero-valued `imRequired[A][B]` AND `[B][A]` rows so the till
    /// clears the stale requirement. A and B each keep a surviving position facing C, so both leaves stay live.
    #[test]
    fn unwind_empties_ab_set_retires_both_and_emits_zero_im_rows() {
        let a = new_party_a();
        let b = new_party_b();
        let c = { let mut x = [0u8; 20]; x[19] = 0xCC; x };
        let oracle_ab = [0x03u8; 20];
        let oracle_ac = [0x04u8; 20];
        let oracle_bc = [0x05u8; 20];

        let a_ab = pos(0x01, b, oracle_ab, b"USD/COP", 100_000_000, 1);
        let a_ac = pos(0x02, c, oracle_ac, b"USD/BRL", 50_000_000, 1);
        let b_ab = pos(0x01, a, oracle_ab, b"USD/COP", 100_000_000, -1);
        let b_bc = pos(0x03, c, oracle_bc, b"USD/INR", 40_000_000, 1);

        let (root_prev, accounts_root_prev, touched) = build_book(&[
            (a, vec![a_ab, a_ac], vec![a_ac]),
            (b, vec![b_ab, b_bc], vec![b_bc]),
        ]);

        let w = unwind_valid_witness(a_ab, 900_000);
        let entry = unwind_close(&w);

        let out = state_transition(StateTransitionInputs {
            book: (root_prev, accounts_root_prev, touched),
            marks: vec![],
            paused_pairs: vec![],
            novations: vec![],
            new_positions: vec![],
            novation_witnesses: vec![],
            closeout_novations: vec![],
            closeout_novation_witnesses: vec![],
            proof_now: 1_700_000_000,
            domain_separator: nb_domain(),
            scenario_table: test_table(),
            unwinds: vec![entry],
            unwind_witnesses: vec![w],
        });

        // ONE inter-party residual, loser (A) → winner (B), at the signed close price.
        let vm_a = position_vm(1_000_000, 900_000, a_ab.notional, 1);
        assert!(vm_a < 0, "the long A loses on the 0.90 tear-up");
        assert_eq!(out.settlements.len(), 1, "exactly one loser→winner residual (winner's seat emits none)");
        assert_eq!(out.settlements[0].payer, a, "the loser A pays");
        assert_eq!(out.settlements[0].payee, b, "the winner B receives");
        assert_eq!(out.settlements[0].usd, vm_a.unsigned_abs(), "the residual is |A's realized VM|");
        assert_eq!(out.settlements[0].id, a_ab.terms_id, "tagged with the torn-up id");

        // ★ MARGIN-RETURN FIX: the emptied (A,B) set is zeroed in BOTH directions.
        assert_eq!(im_row(&out, a, b), vec![0u128], "imRequired[A][B] zeroed — the emptied set releases");
        assert_eq!(im_row(&out, b, a), vec![0u128], "imRequired[B][A] zeroed — the emptied set releases");
        // Surviving sets against C stay margined (positive), never zeroed.
        assert_eq!(im_row(&out, a, c).len(), 1, "A→C row survives");
        assert!(im_row(&out, a, c)[0] > 0, "A still margins its live C position");
        assert!(im_row(&out, b, c)[0] > 0, "B still margins its live C position");

        // Both seats left the tree; both leaves stayed live (each keeps a C position).
        assert_eq!(out.unwinds, vec![entry], "the unwind is surfaced verbatim as the 17th row");
        assert_ne!(out.roots.root_new, root_prev, "retiring both AB seats advances the state root");
        assert_eq!(out.roots.accounts_root_new, accounts_root_prev, "no leaf pruned ⇒ registry unchanged");
    }

    /// The NovationPartialMultiPos guard: when A and B still hold ANOTHER live position facing each other, the
    /// unwind must NOT zero their set — the surviving position keeps `imRequired[A][B]` positive.
    #[test]
    fn unwind_partial_set_does_not_zero_surviving_im() {
        let a = new_party_a();
        let b = new_party_b();
        let oracle = [0x03u8; 20];

        let a1 = pos(0x01, b, oracle, b"USD/COP", 100_000_000, 1);
        let a2 = pos(0x02, b, oracle, b"USD/COP", 50_000_000, 1);
        let b1 = pos(0x01, a, oracle, b"USD/COP", 100_000_000, -1);
        let b2 = pos(0x02, a, oracle, b"USD/COP", 50_000_000, -1);

        let (root_prev, accounts_root_prev, touched) = build_book(&[
            (a, vec![a1, a2], vec![a2]),
            (b, vec![b1, b2], vec![b2]),
        ]);

        let w = unwind_valid_witness(a1, 900_000);
        let entry = unwind_close(&w);

        let out = state_transition(StateTransitionInputs {
            book: (root_prev, accounts_root_prev, touched),
            marks: vec![],
            paused_pairs: vec![],
            novations: vec![],
            new_positions: vec![],
            novation_witnesses: vec![],
            closeout_novations: vec![],
            closeout_novation_witnesses: vec![],
            proof_now: 1_700_000_000,
            domain_separator: nb_domain(),
            scenario_table: test_table(),
            unwinds: vec![entry],
            unwind_witnesses: vec![w],
        });

        // EXACTLY one A→B row, and it is POSITIVE — no spurious zero, no double row.
        let ab = im_row(&out, a, b);
        assert_eq!(ab.len(), 1, "exactly one A→B row — the surviving position, no injected zero");
        assert!(ab[0] > 0, "the surviving a2 keeps A→B margined — NOT zeroed");
        let ba = im_row(&out, b, a);
        assert_eq!(ba.len(), 1, "exactly one B→A row");
        assert!(ba[0] > 0, "the surviving b2 keeps B→A margined — NOT zeroed");

        // Still one loser→winner residual for the single torn-up leg.
        assert_eq!(out.settlements.len(), 1, "one residual for the one unwound leg");
        assert_eq!(out.settlements[0].id, a1.terms_id, "tagged with the torn-up leg's id");
    }

    /// SOUNDNESS BLOCKER (the party_b-touched fix): a SINGLE-SIDED unwind — only A is a touched account, B's mirror
    /// seat is left untouched and LIVE — must be REJECTED. Otherwise A's seat retires while B's identical-`terms_id`
    /// seat survives in B's unchanged leaf, yet the emptied-set loop still emits `imRequired[B][A]=0` → B could
    /// withdraw all its collateral off a still-live position. The guest now forces B's mirror seat into the fold.
    #[test]
    #[should_panic(expected = "B is not a touched account")]
    fn unwind_single_sided_without_b_touched_is_rejected() {
        let a = new_party_a();
        let b = new_party_b();
        let c = { let mut x = [0u8; 20]; x[19] = 0xCC; x };
        let oracle_ab = [0x03u8; 20];
        let oracle_ac = [0x04u8; 20];

        // A holds the AB seat (to be torn up) plus a C position so A's leaf stays live. B is NOT in the touched book.
        let a_ab = pos(0x01, b, oracle_ab, b"USD/COP", 100_000_000, 1);
        let a_ac = pos(0x02, c, oracle_ac, b"USD/BRL", 50_000_000, 1);

        let (root_prev, accounts_root_prev, touched) = build_book(&[(a, vec![a_ab, a_ac], vec![a_ac])]);

        let w = unwind_valid_witness(a_ab, 900_000);
        let entry = unwind_close(&w);

        let _ = state_transition(StateTransitionInputs {
            book: (root_prev, accounts_root_prev, touched),
            marks: vec![],
            paused_pairs: vec![],
            novations: vec![],
            new_positions: vec![],
            novation_witnesses: vec![],
            closeout_novations: vec![],
            closeout_novation_witnesses: vec![],
            proof_now: 1_700_000_000,
            domain_separator: nb_domain(),
            scenario_table: test_table(),
            unwinds: vec![entry],
            unwind_witnesses: vec![w],
        });
    }

    #[test]
    #[should_panic(expected = "committed unwind is not a sound")]
    fn unwind_forged_entry_price_is_rejected_in_state_transition() {
        let a = new_party_a();
        let b = new_party_b();
        let oracle = [0x03u8; 20];
        let a1 = pos(0x01, b, oracle, b"USD/COP", 100_000_000, 1);
        let b1 = pos(0x01, a, oracle, b"USD/COP", 100_000_000, -1);
        let (root_prev, accounts_root_prev, touched) =
            build_book(&[(a, vec![a1], vec![]), (b, vec![b1], vec![])]);
        let w = unwind_valid_witness(a1, 900_000);
        let mut entry = unwind_close(&w);
        entry.close_price = 950_000; // a price nobody signed
        let _ = state_transition(StateTransitionInputs {
            book: (root_prev, accounts_root_prev, touched),
            marks: vec![],
            paused_pairs: vec![],
            novations: vec![],
            new_positions: vec![],
            novation_witnesses: vec![],
            closeout_novations: vec![],
            closeout_novation_witnesses: vec![],
            proof_now: 1_700_000_000,
            domain_separator: nb_domain(),
            scenario_table: test_table(),
            unwinds: vec![entry],
            unwind_witnesses: vec![w],
        });
    }
}
