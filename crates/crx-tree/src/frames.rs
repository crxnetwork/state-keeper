//! The 13-frame guest stdin for one advance — the exact read order of the scenario-ES
//! guest (`sp1_zkvm::io::read::<T>()` deserialises positionally under bincode):
//!
//!   0  book                : TouchedBook = (root_prev, accounts_root_prev, Vec<TouchedAccount>)
//!   1  marks               : Vec<Mark>            (proof-clock gate only; empty here)
//!   2  paused_pairs        : Vec<[u8;32]>
//!   3  novations           : Vec<Novation>        (EMPTY on this path)
//!   4  new_positions       : Vec<NewPosition>
//!   5  novation_witnesses  : Vec<NovationWitness> (EMPTY)
//!   6  closeout_novations          : Vec<CloseoutNovation>        (EMPTY)
//!   7  closeout_novation_witnesses : Vec<CloseoutNovationWitness> (EMPTY)
//!   8  proof_now           : u64
//!   9  domain_separator    : [u8;32]
//!   10 scenario_table      : ScenarioTable (keccak-committed as PV row 10)
//!   11 unwinds             : Vec<Unwind>          (EMPTY)
//!   12 unwind_witnesses    : Vec<UnwindWitness>   (EMPTY)

use anyhow::{bail, Result};
use im_recompute as sr;
use im_types as st;

use crate::replay::{resolve_epoch, EpochInputs, TreeState};

/// The assembled advance: the 13 encoded frames plus the predicted advance.
pub struct AdvanceFrames {
    pub frames: Vec<Vec<u8>>,
    pub predicted_root: [u8; 32],
    pub predicted_accounts_root: [u8; 32],
    pub root_prev: [u8; 32],
}

/// Build the 13 frames for one epoch over `state`. `state.root()` must equal the root
/// the chain holds (the caller has already diffed it) — it becomes the CAS target.
pub fn build_advance_frames(
    state: &TreeState,
    inputs: &EpochInputs,
    table: &sr::ScenarioTable,
    chain_accounts_root: [u8; 32],
) -> Result<AdvanceFrames> {
    // Fail-closed table gate: validate + commit BEFORE any prediction.
    let _root = table.scenario_root();

    let prior = state.leaves();
    let root_prev = im_state::smt2::Smt2::from_leaves(&prior).root();
    let prior_keys: std::collections::BTreeSet<[u8; 32]> =
        prior.iter().map(|(k, _)| *k).collect();

    let outcome = resolve_epoch(state, inputs, table)?;

    // Step the state + registry trees sequentially, one witness per touched path.
    // An absent-and-finally-absent account is dropped — a `None → None` step the guest
    // rejects as a no-op.
    let mut smt = im_state::smt2::Smt2::from_leaves(&prior);
    let reg_leaf = sr::registry_leaf();
    let mut registry = im_state::smt2::Smt2::new();
    for k in prior_keys.iter() {
        registry.insert(*k, reg_leaf);
    }
    if registry.root() != chain_accounts_root {
        bail!(
            "prior registry root 0x{} != chain accountsRoot 0x{} — the account set drifted",
            hex::encode(registry.root()),
            hex::encode(chain_accounts_root)
        );
    }

    let mut touched_accounts: Vec<st::TouchedAccount> = Vec::new();
    for ((aid, post), (account, risk)) in outcome.steps.iter().zip(outcome.prior_rows.iter()) {
        let was_present = prior_keys.contains(aid);
        let final_present = post.is_some();
        if !was_present && !final_present {
            continue;
        }
        let state_witness = smt.step(*aid, *post);
        let registry_witness = match (was_present, final_present) {
            (false, true) => Some(registry.step(*aid, Some(reg_leaf))),
            (true, false) => Some(registry.step(*aid, None)),
            _ => None,
        };
        touched_accounts.push(st::TouchedAccount {
            account: account.clone(),
            risk: risk.clone(),
            state_witness,
            registry_witness,
        });
    }

    let predicted_root = smt.root();
    let predicted_accounts_root = registry.root();
    let book: st::TouchedBook = (root_prev, chain_accounts_root, touched_accounts);

    let marks: Vec<st::Mark> = Vec::new();
    let novations: Vec<st::Novation> = Vec::new();
    let novation_witnesses: Vec<st::NovationWitness> = Vec::new();
    let closeout_novations: Vec<st::CloseoutNovation> = Vec::new();
    let closeout_witnesses: Vec<st::CloseoutNovationWitness> = Vec::new();
    let unwinds: Vec<st::Unwind> = Vec::new();
    let unwind_witnesses: Vec<st::UnwindWitness> = Vec::new();

    let frames = vec![
        enc(&book)?,
        enc(&marks)?,
        enc(&inputs.paused_pairs)?,
        enc(&novations)?,
        enc(&inputs.new_positions)?,
        enc(&novation_witnesses)?,
        enc(&closeout_novations)?,
        enc(&closeout_witnesses)?,
        enc(&inputs.proof_now)?,
        enc(&inputs.domain_separator)?,
        enc(table)?,
        enc(&unwinds)?,
        enc(&unwind_witnesses)?,
    ];

    Ok(AdvanceFrames { frames, predicted_root, predicted_accounts_root, root_prev })
}

fn enc<T: serde::Serialize>(val: &T) -> Result<Vec<u8>> {
    // sp1_zkvm::io::read::<T>() deserialises with bincode; this encoder MUST stay
    // byte-compatible with the guest's read calls.
    bincode::serialize(val).map_err(|e| anyhow::anyhow!("bincode: {e}"))
}
