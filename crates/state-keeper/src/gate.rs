//! Every refusal the keeper answers, as a NAMED variant — the name is the diagnosis,
//! the message names the fix. Message strings are FROZEN output surface.
//! enforced by: gate_messages_are_frozen

use thiserror::Error;

/// Pre-flight and parity refusals, one variant per operator-fixable condition.
#[derive(Debug, Error)]
pub enum Gate {
    /// Fix: ship the scenario-table artifact of THIS generation, or repin chains.json.
    #[error("scenario table root mismatch: data/scenario-table.bin commits 0x{local}, chains.json pins 0x{pinned} — the core would reject every proof built on this table")]
    TableArtifactNotThisGeneration { local: String, pinned: String },
    /// Fix: rebuild against the generation the core answers, or repoint chains.json.
    #[error("the core answers a DIFFERENT vkey than this build is pinned to — do not advance")]
    VerifyVkeyDrift,
    /// Fix: replace data/scenario-table.bin with the on-chain generation's artifact.
    #[error("the committed scenario table does not match the on-chain scenarioRoot")]
    VerifyScenarioRootDrift,
    /// Fix: export PRIVATE_KEY (or put it in `.env`).
    #[error("PRIVATE_KEY is not set — the advance signs a real transaction")]
    PrivateKeyUnset,
    /// Fix: this build proves a different generation than the core verifies.
    #[error("core vkey 0x{chain} != pinned {pinned} — wrong generation, refusing")]
    AdvanceWrongGeneration { chain: String, pinned: String },
    /// Fix: replace data/scenario-table.bin with the on-chain generation's artifact.
    #[error("scenario table does not match the on-chain scenarioRoot — refusing to prove")]
    AdvanceScenarioRootDrift,
    /// The replayed event fold and the chain disagree — investigate before trusting either.
    #[error("REBUILD MISMATCH: the replayed tree does not reproduce the on-chain root")]
    RebuildRootMismatch,
    /// The replayed account registry and the chain disagree.
    #[error("REBUILD MISMATCH: the replayed registry does not reproduce the on-chain accountsRoot")]
    RebuildRegistryMismatch,
    /// Fix: replace data/scenario-table.bin with the on-chain generation's artifact.
    #[error("scenario table mismatch against the on-chain scenarioRoot")]
    RebuildScenarioRootMismatch,
}

#[cfg(test)]
mod tests {
    use super::Gate;

    /// The runtime strings are part of the observable surface — a variant may gain
    /// precision only by conscious edit of BOTH the format string and this record.
    #[test]
    fn gate_messages_are_frozen() {
        let cases: Vec<(Gate, &str)> = vec![
            (
                Gate::TableArtifactNotThisGeneration { local: "aa".into(), pinned: "bb".into() },
                "scenario table root mismatch: data/scenario-table.bin commits 0xaa, chains.json pins 0xbb — the core would reject every proof built on this table",
            ),
            (
                Gate::VerifyVkeyDrift,
                "the core answers a DIFFERENT vkey than this build is pinned to — do not advance",
            ),
            (
                Gate::VerifyScenarioRootDrift,
                "the committed scenario table does not match the on-chain scenarioRoot",
            ),
            (
                Gate::PrivateKeyUnset,
                "PRIVATE_KEY is not set — the advance signs a real transaction",
            ),
            (
                Gate::AdvanceWrongGeneration { chain: "cc".into(), pinned: "0xdd".into() },
                "core vkey 0xcc != pinned 0xdd — wrong generation, refusing",
            ),
            (
                Gate::AdvanceScenarioRootDrift,
                "scenario table does not match the on-chain scenarioRoot — refusing to prove",
            ),
            (
                Gate::RebuildRootMismatch,
                "REBUILD MISMATCH: the replayed tree does not reproduce the on-chain root",
            ),
            (
                Gate::RebuildRegistryMismatch,
                "REBUILD MISMATCH: the replayed registry does not reproduce the on-chain accountsRoot",
            ),
            (
                Gate::RebuildScenarioRootMismatch,
                "scenario table mismatch against the on-chain scenarioRoot",
            ),
        ];
        for (gate, want) in cases {
            assert_eq!(gate.to_string(), want);
        }
    }
}
