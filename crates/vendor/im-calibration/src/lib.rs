//! Scenario-ES calibration: the fixed-point scale constants and the two scenario-table bounds.
//! The ISDA IM v2.8 ρ-form calibration (risk weights, correlations, concentration thresholds, the currency
//! classifier and the `uint8` selector wire) was DELETED in the scenario-matrix ES99 migration — margin now
//! derives from a published scenario table (`im-recompute::scenario`), not from an ISDA quadratic form.
//! Every constant here is vkey-affecting; do not retune blind. Returns and bounds are 1e18 fixed-point.
#![forbid(unsafe_code)]
#![deny(missing_docs)]

/// 1.0 in the 1e18 fixed-point scale (unsigned).
pub const ONE:   u128 = 1_000_000_000_000_000_000;
/// 1.0 in the 1e18 fixed-point scale (signed).
pub const ONE_I: i128 = 1_000_000_000_000_000_000;

/// Scenario-return magnitude ceiling, 1e18 = 100%: a table row asserting a move beyond ±100% is malformed
/// and fails closed (panic = unsatisfiable proof), never clamped.
pub const RET_MAX_1E18: i128 = 1_000_000_000_000_000_000;

/// Conservative adverse return (43.3%, 1e18) applied to EVERY scenario's loss for a held market the published
/// table does not list — an un-listed market can only RAISE margin, never lower it.
pub const FALLBACK_RET_1E18: i128 = 433_000_000_000_000_000;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scenario_bounds_are_scaled_and_ordered() {
        assert_eq!(ONE as i128, ONE_I, "the signed and unsigned scales agree");
        assert_eq!(RET_MAX_1E18, ONE_I, "the return ceiling is exactly 100%");
        assert!(FALLBACK_RET_1E18 > 0 && FALLBACK_RET_1E18 < RET_MAX_1E18, "the fallback is a real, sub-ceiling adverse return");
        assert_eq!(FALLBACK_RET_1E18, 433_000_000_000_000_000, "fallback pinned at 43.3%");
    }
}
