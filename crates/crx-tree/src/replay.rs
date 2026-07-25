//! The replay: fold the chain's own history through the vendored engine and carry the
//! account state forward, epoch by epoch.
//!
//! Each historical fold's inputs are fully recoverable: `openedPositionIds` names the
//! opens it consumed, `consumedMarks`/`consumedTwaps` name the prices, `proofTime` and
//! `domainSeparator` pin the clock and the domain, and the scenario table is the
//! committed artifact whose keccak the fold's `scenarioRoot` re-asserts. Fed the same
//! inputs, the same pure functions produce the same tree — and the recomputed
//! `root_new` is asserted against the fold's own committed roots at every step.

use std::collections::BTreeMap;

use anyhow::{anyhow, bail, Result};
use im_recompute as sr;
use im_types as st;

use crate::scan::{ChainHistory, FoldRecord, OpenRecord};

/// One account's carried state — exactly what the committed leaf binds:
/// the cumulative VM and the open position set.
#[derive(Clone, Default)]
pub struct AccountState {
    pub owner: [u8; 20],
    pub vm_equity: i128,
    pub positions: Vec<st::PositionRecord>,
}

/// The rebuilt tree: every account keyed by `account_id_single(owner)`.
#[derive(Clone, Default)]
pub struct TreeState {
    pub accounts: BTreeMap<[u8; 32], AccountState>,
}

impl TreeState {
    /// The committed leaves, ascending by aid.
    pub fn leaves(&self) -> Vec<([u8; 32], [u8; 32])> {
        self.accounts
            .iter()
            .map(|(aid, a)| {
                (*aid, sr::account_leaf(*aid, a.vm_equity, sr::positions_root(&a.positions)))
            })
            .collect()
    }

    /// The state root — the smt2 fold of the committed leaves.
    pub fn root(&self) -> [u8; 32] {
        im_state::smt2::Smt2::from_leaves(&self.leaves()).root()
    }

    /// The account-registry root over the present key set.
    pub fn accounts_root(&self) -> [u8; 32] {
        let keys: Vec<[u8; 32]> = self.accounts.keys().copied().collect();
        im_state::credited_deposit_registry(&keys)
    }
}

/// Map a chain-recovered open onto the guest's `NewPosition` input. The entry rate is
/// the signed `Terms.data` word 0 (the on-chain 1e6-scaled rate); the domain separator
/// is stamped by the caller (the guest asserts it equals the proof's pinned domain).
pub fn open_to_new_position(o: &OpenRecord, domain_separator: [u8; 32]) -> Result<st::NewPosition> {
    let t = &o.terms;
    let quantity = u128::try_from(t.quantity).map_err(|_| anyhow!("quantity exceeds u128"))?;
    if t.data.len() < 32 {
        bail!("open 0x{}: Terms.data shorter than one word", hex::encode(o.id));
    }
    let entry_rate = u128::from_be_bytes(t.data[16..32].try_into().expect("16 bytes"));
    if t.data[0..16].iter().any(|&b| b != 0) {
        bail!("open 0x{}: entry-rate word exceeds u128", hex::encode(o.id));
    }
    Ok(st::NewPosition {
        terms_id: o.id,
        party_a: t.partyA.into_array(),
        party_b: t.partyB.into_array(),
        oracle: t.oracle.into_array(),
        quantity,
        entry_rate,
        side_a: t.side,
        expiry: u64::try_from(t.expiry).unwrap_or(0),
        im_bps_a: t.imBpsA,
        im_bps_b: t.imBpsB,
        instrument: t.instrument,
        pair_tag: t.pairTag.0,
        mm_pct: t.mmPct,
        nonce: t.nonce,
        cure_window: t.cureWindow,
        payout_pref_a: t.payoutPrefA,
        payout_pref_b: t.payoutPrefB,
        data: t.data.to_vec(),
        sig_a: o.sig_a.clone(),
        sig_b: o.sig_b.clone(),
        domain_separator,
    })
}

/// The inputs of one epoch, however sourced — a historical fold's recovered inputs, or
/// the next epoch's fresh ones.
pub struct EpochInputs {
    pub new_positions: Vec<st::NewPosition>,
    /// Per-feed proven hourly marks this epoch consumes (deduped, one per feed).
    pub proven_marks: Vec<st::ProvenMark>,
    /// Per-feed proven settle prices this epoch consumes.
    pub proven_twaps: Vec<st::ProvenTwap>,
    pub paused_pairs: Vec<[u8; 32]>,
    pub proof_now: u64,
    pub domain_separator: [u8; 32],
}

/// One resolved epoch: the post state, and the per-account rows the frame builder reuses.
pub struct EpochOutcome {
    pub post: TreeState,
    /// Touched aids ascending, with each post leaf (`None` = pruned/never present).
    pub steps: Vec<([u8; 32], Option<[u8; 32]>)>,
    /// The prior rows fed to the engine, in the same touched order.
    pub prior_rows: Vec<(st::Account, st::RiskInputs)>,
    /// Ids of the new positions the open pre-pass processed (opened ++ rejected).
    pub processed_open_ids: Vec<[u8; 32]>,
}

/// Resolve one epoch over `prior`: the same Stage-3 pipeline the guest runs —
/// openLock pre-pass, per-account settle/re-mark/resolve — carried onto a fresh
/// `TreeState`. Touches every present account plus every open party; an extra
/// touch whose leaf ends unchanged is harmless (the guest's own rule).
pub fn resolve_epoch(
    prior: &TreeState,
    inputs: &EpochInputs,
    table: &sr::ScenarioTable,
) -> Result<EpochOutcome> {
    use std::collections::BTreeSet;

    // The touched set: every present account + both parties of every new position.
    let mut touched: BTreeSet<[u8; 32]> = prior.accounts.keys().copied().collect();
    let mut owners: BTreeMap<[u8; 32], [u8; 20]> =
        prior.accounts.iter().map(|(k, v)| (*k, v.owner)).collect();
    for np in &inputs.new_positions {
        for owner in [np.party_a, np.party_b] {
            let aid = sr::account_id_single(owner);
            touched.insert(aid);
            owners.insert(aid, owner);
        }
    }
    let touched: Vec<[u8; 32]> = touched.into_iter().collect();

    // Prior rows in touched order: the committed leaf fields + the per-account risk
    // witness (positions, and the epoch's marks/twaps that bind to them).
    let mut rows: Vec<(st::Account, st::RiskInputs)> = Vec::with_capacity(touched.len());
    for aid in &touched {
        let (account, risk) = match prior.accounts.get(aid) {
            Some(a) => {
                let positions_root = sr::positions_root(&a.positions);
                let marks: Vec<st::ProvenMark> = inputs
                    .proven_marks
                    .iter()
                    .copied()
                    .filter(|m| a.positions.iter().any(|b| sr::mark_binds_position(b, m)))
                    .collect();
                let twaps: Vec<st::ProvenTwap> = inputs
                    .proven_twaps
                    .iter()
                    .copied()
                    .filter(|tw| {
                        a.positions.iter().any(|b| {
                            sr::feed_id_oracle(&tw.feed_id) == b.oracle && b.expiry == tw.close_time
                        })
                    })
                    .collect();
                (
                    st::Account {
                        account_owner: a.owner,
                        positions: Vec::new(),
                        vm_equity: a.vm_equity,
                        prev_vm_equity: a.vm_equity,
                        positions_root,
                    },
                    st::RiskInputs {
                        unconsumed_settle_residual: None,
                        positions: a.positions.clone(),
                        position_settlements: Vec::new(),
                        proven_twaps: twaps,
                        proven_marks: marks,
                    },
                )
            }
            None => (
                st::Account {
                    account_owner: owners[aid],
                    ..Default::default()
                },
                st::RiskInputs {
                    unconsumed_settle_residual: None,
                    positions: Vec::new(),
                    position_settlements: Vec::new(),
                    proven_twaps: Vec::new(),
                    proven_marks: Vec::new(),
                },
            ),
        };
        rows.push((account, risk));
    }

    // Whole-epoch marking gate: any touched account carries a proven hourly mark.
    let marking_epoch = rows.iter().any(|(_, ri)| !ri.proven_marks.is_empty());

    // The PRIOR rows, before the open pre-pass mutates them — the frame builder feeds
    // these to the guest, which re-runs the pre-pass itself.
    let prior_rows = rows.clone();

    // Stage 3b: the openLock pre-pass — authenticate, surface, push both mirrored records.
    let outcome = sr::apply_new_boxes_to_book(&mut rows, &inputs.new_positions, inputs.proof_now);
    let mut processed: Vec<[u8; 32]> = outcome.opened.clone();
    processed.extend(outcome.rejected.iter().copied());

    // Stage 3c: per-account resolve, in touched order.
    let mut post = TreeState::default();
    let mut steps: Vec<([u8; 32], Option<[u8; 32]>)> = Vec::with_capacity(touched.len());
    for (idx, aid) in touched.iter().enumerate() {
        let (a, ri) = &rows[idx];

        let (position_settlements, _consumed) =
            sr::position_settlements_from_twaps(&ri.positions, &ri.proven_twaps);

        let survivors_for_vm: Vec<st::PositionRecord> = ri
            .positions
            .iter()
            .copied()
            .filter(|b| {
                let paused = inputs.paused_pairs.contains(&sr::pair_tag_of(&b.oracle));
                paused || !position_settlements.iter().any(|s| s.terms_id == b.terms_id)
            })
            .collect();
        let (new_vm, _) = if marking_epoch {
            sr::account_vm_from_marks(&survivors_for_vm, &ri.proven_marks)
        } else {
            (a.prev_vm_equity, Vec::new())
        };

        let r = sr::resolve_account(
            a.account_owner,
            &ri.positions,
            &position_settlements,
            new_vm,
            &inputs.paused_pairs,
            inputs.proof_now,
            table,
        );

        if r.positions_live {
            let leaf = sr::account_leaf(*aid, r.vm_equity, sr::positions_root(&r.surviving));
            steps.push((*aid, Some(leaf)));
            post.accounts.insert(
                *aid,
                AccountState { owner: a.account_owner, vm_equity: r.vm_equity, positions: r.surviving },
            );
        } else {
            steps.push((*aid, None));
        }
    }

    Ok(EpochOutcome { post, steps, prior_rows, processed_open_ids: processed })
}

/// Rebuild the whole tree from the chain history: start empty, replay every fold,
/// assert the recomputed roots equal each fold's committed roots.
pub fn rebuild(history: &ChainHistory, table: &sr::ScenarioTable) -> Result<TreeState> {
    let mut state = TreeState::default();
    let opens_by_id: BTreeMap<[u8; 32], &OpenRecord> =
        history.opens.iter().map(|o| (o.id, o)).collect();

    for (i, fold) in history.folds.iter().enumerate() {
        let n = i + 1;
        let inputs = fold_inputs(fold, &opens_by_id, history)?;
        if table.scenario_root() != fold.pv.scenario_root {
            bail!(
                "fold {n}: committed scenarioRoot 0x{} differs from the local table's 0x{} — \
                 the table artifact does not match this generation",
                hex::encode(fold.pv.scenario_root),
                hex::encode(table.scenario_root())
            );
        }

        let root_prev = state.root();
        if root_prev != fold.pv.roots.root_prev {
            bail!(
                "fold {n} (block {}): replayed prior root 0x{} != committed rootPrev 0x{}",
                fold.block,
                hex::encode(root_prev),
                hex::encode(fold.pv.roots.root_prev)
            );
        }

        let outcome = resolve_epoch(&state, &inputs, table)?;

        // The open pre-pass must have processed exactly the ids the fold surfaced.
        let mut got = outcome.processed_open_ids.clone();
        let mut want = fold.pv.opened_position_ids.clone();
        got.sort_unstable();
        want.sort_unstable();
        if got != want {
            bail!("fold {n}: replayed open set diverges from the committed openedPositionIds");
        }

        let root_new = outcome.post.root();
        let accounts_root_new = outcome.post.accounts_root();
        if root_new != fold.pv.roots.root_new {
            bail!(
                "fold {n} (block {}): replayed root 0x{} != committed rootNew 0x{}",
                fold.block,
                hex::encode(root_new),
                hex::encode(fold.pv.roots.root_new)
            );
        }
        if accounts_root_new != fold.pv.roots.accounts_root_new {
            bail!(
                "fold {n}: replayed accountsRoot 0x{} != committed 0x{}",
                hex::encode(accounts_root_new),
                hex::encode(fold.pv.roots.accounts_root_new)
            );
        }
        state = outcome.post;
    }
    Ok(state)
}

/// Recover one historical fold's epoch inputs from its committed public values.
fn fold_inputs(
    fold: &FoldRecord,
    opens_by_id: &BTreeMap<[u8; 32], &OpenRecord>,
    history: &ChainHistory,
) -> Result<EpochInputs> {
    if !fold.pv.novations.is_empty() || fold.pv.closeout_novations_len > 0 || fold.pv.unwinds_len > 0 {
        bail!(
            "fold at block {} carries novations/closeouts/unwinds — this replay does not model them yet",
            fold.block
        );
    }

    let mut new_positions = Vec::with_capacity(fold.pv.opened_position_ids.len());
    for id in &fold.pv.opened_position_ids {
        let open = opens_by_id.get(id).ok_or_else(|| {
            anyhow!(
                "fold at block {} consumed open 0x{} with no TermsOpened record",
                fold.block,
                hex::encode(id)
            )
        })?;
        new_positions.push(open_to_new_position(open, fold.pv.domain_separator)?);
    }

    let proven_marks: Vec<st::ProvenMark> = fold
        .pv
        .consumed_marks
        .iter()
        .map(|m| {
            Ok(st::ProvenMark {
                feed_id: m.feed_id,
                mark_time: m.mark_time,
                price: u128::try_from(m.price).map_err(|_| anyhow!("negative consumed mark"))?,
                expo: m.expo,
            })
        })
        .collect::<Result<_>>()?;

    let proven_twaps: Vec<st::ProvenTwap> = fold
        .pv
        .consumed_twaps
        .iter()
        .map(|t| {
            Ok(st::ProvenTwap {
                feed_id: t.feed_id,
                close_time: t.close_time,
                settle_price: u128::try_from(t.twap).map_err(|_| anyhow!("negative consumed twap"))?,
                expo: t.expo,
            })
        })
        .collect::<Result<_>>()?;

    Ok(EpochInputs {
        new_positions,
        proven_marks,
        proven_twaps,
        paused_pairs: history.paused_pairs_at(fold.block.saturating_sub(1)),
        proof_now: fold.pv.proof_time,
        domain_separator: fold.pv.domain_separator,
    })
}
