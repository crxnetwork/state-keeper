//! crx-tree — rebuild the CRX state tree purely from on-chain events and assemble the next
//! epoch's guest input. One leaf per account: `{aid, vm_equity, positions_root}`.

#![forbid(unsafe_code)]
#![deny(clippy::arithmetic_side_effects)]

pub mod events;
pub mod frames;
pub mod pv;
pub mod replay;
pub mod scan;

pub use crxvm as engine;
pub use im_types as guest_types;

use anyhow::Result;

/// Load the committed scenario-table artifact and its keccak commitment — must equal the
/// on-chain `scenarioRoot` or no proof built on it can be accepted.
pub fn load_scenario_table(path: &std::path::Path) -> Result<(crxvm::ScenarioTable, [u8; 32])> {
    let bytes = std::fs::read(path)
        .map_err(|e| anyhow::anyhow!("read scenario table {}: {e}", path.display()))?;
    let table: crxvm::ScenarioTable = bincode::deserialize(&bytes)
        .map_err(|e| anyhow::anyhow!("bincode-deserialize ScenarioTable from {}: {e}", path.display()))?;
    // scenario_root() validates fail-closed, then commits.
    let root = table.scenario_root();
    Ok((table, root))
}
