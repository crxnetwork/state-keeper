//! crx-tree — rebuild the CRX state tree purely from on-chain events, and assemble the
//! next epoch's guest input from the rebuilt state.
//!
//! The tree is key-addressed (one leaf per account, `account_id_single(owner)`), the
//! leaf commits only `{aid, vm_equity, positions_root}`, and every input a fold ever
//! consumed is on the chain: the signed Terms in `TermsOpened` + `openLock` calldata,
//! the fold's public values in `applyState` calldata, the proven prices in `TwapBound`.
//! Replaying those inputs through the vendored engine — the same pure functions the
//! proven guest ELF runs — reproduces the exact root the contract holds.

pub mod events;
pub mod frames;
pub mod pv;
pub mod replay;
pub mod scan;

pub use im_recompute as engine;
pub use im_types as guest_types;

use anyhow::Result;

/// Load and validate the committed scenario-table artifact (bincode `ScenarioTable`).
/// Returns the table and its keccak commitment — the value the chain's owner-published
/// `scenarioRoot` must equal, or no proof built on this table can ever be accepted.
pub fn load_scenario_table(path: &std::path::Path) -> Result<(im_recompute::ScenarioTable, [u8; 32])> {
    let bytes = std::fs::read(path)
        .map_err(|e| anyhow::anyhow!("read scenario table {}: {e}", path.display()))?;
    let table: im_recompute::ScenarioTable = bincode::deserialize(&bytes)
        .map_err(|e| anyhow::anyhow!("bincode-deserialize ScenarioTable from {}: {e}", path.display()))?;
    // `scenario_root()` validates the table (fail-closed on any structural defect), then commits.
    let root = table.scenario_root();
    Ok((table, root))
}
