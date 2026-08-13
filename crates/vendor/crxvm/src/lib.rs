//! crxvm — the zk-IM margin / settlement / lifecycle orchestrator. Deterministic, fail-closed; the
//! committed public-values struct is the proof's only output.
//!
//! The pipeline is the module order, so the crate root reads top-to-bottom as the proof: every touched account's
//! prior leaf is rebuilt from bound witnesses and its positions bound to the committed `positions_root`; the
//! `openLock` pre-pass locks IM on both seats of a new position; resolve settles due positions from proven TWAPs,
//! re-marks VM from proven marks and re-floors IM; the A→C handoffs close and re-bind seats; the new roots are
//! recomputed and committed. Submodules re-export FLAT — consumers import `crx_im::{…}`, never a module path.
//!
//! Core 2.0 holds no money: the circuit computes risk, the chain holds the collateral, and conservation
//! (`Σwithdrawn ≤ Σdeposited`, per token) is enforced on-chain at the till. Built with `overflow-checks = true`;
//! the authoritative arithmetic rationale is on the `constants` module header.
#![forbid(unsafe_code)]
#![deny(missing_docs)]

/// Every vkey-affecting scalar (scales, bps floors, freshness bounds, the instrument tag) in one block.
mod constants;
pub use constants::*;

/// The guest↔chain boundary: keccak/leaf/id encoders + the EIP-712 typehashes/struct-hashes + `market_key`.
mod encoding;
pub use encoding::*;

/// The scenario-matrix ES99 kernel: the `ScenarioTable` witness, its keccak commitment, `party_scenario_es`.
mod scenario;
pub use scenario::*;

/// Margin as applied to positions: `position_vm`, the scenario-ES `position_im_floor`, per-cp requirements.
mod margin;
pub use margin::*;

/// The proven-price rail: TWAP binding, per-position settle, fees, mark freshness, cumulative VM from marks.
mod settlement;
pub use settlement::*;

/// The two resolvers + their result types: the plain lane and the per-position lane (Seam-1 fail-closed).
mod resolve;
pub use resolve::*;

/// The `openLock` pre-pass: lock IM for a newly-bound position on both seats, or reject a seat that can't fund.
mod open_lock;
pub use open_lock::*;

/// The A→C lifecycle: novation + closeout_novation close-and-rebind, their binding predicates, and the re-floors.
mod handoff;
pub use handoff::*;

/// F2 bilateral unwind: dual-sig `Closeout` validation, the committed entry, and the per-seat settlement injection.
mod unwind;
pub use unwind::*;

/// The fail-closed valves: every soundness invariant that makes an under-margining proof unsatisfiable.
mod completeness;
pub use completeness::*;

/// Keyed SMT + tree reconstructors, re-exported so guest and host build the roots through this crate.
pub use im_state::{credited_deposit_registry, prev_state_root};
pub use im_state::smt2;

/// Signed-price-in-proof (model B): verify an oracle's secp256k1-signed price in-circuit.
pub mod signed_price;

/// The full state_transition — pure, testable; the guest is a thin I/O shell over it.
pub mod state_transition;
pub use state_transition::{state_transition, StateTransitionInputs, StateTransitionOutputs};

/// Flat re-export of the four pure leaf crates: calibration, types, ISDA math, keccak/crypto.
pub use im_calibration::*;
pub use im_types::*;
pub use im_math::*;
pub use im_crypto::*;

/// Shared test fixtures (reference positions, ISDA rosters, signing helpers) for the per-module test suites.
#[cfg(test)]
mod test_util;
