//! Margin over bound positions: realized residual (`position_vm`), the per-party scenario-ES floor, and the
//! per-counterparty requirement rows. The scenario-matrix ES99 kernel is `scenario::party_scenario_es`; this
//! module is its application to a party's book. The ISDA ρ-form kernels (`im_full`, the FX-delta quadratic
//! form, the concentration floor) were DELETED in the scenario-ES migration.
//!
//! Units. Notionals, pushed IM and every returned margin are 1e6 collateral minor; scenario returns are 1e18.
//!
//! Fail-closed. The scenario table is validated (and its root recomputed) once per fold in `state_transition`;
//! a malformed table panics — an unsatisfiable proof beats a silently wrong margin.

use crate::{party_scenario_es, PositionRecord, ScenarioTable, FALLBACK_RET_1E18};

/// Per-position realized residual from a proven price: `side · notional · (settle − entry) / entry`.
pub fn position_vm(entry_rate: u128, settle_price: u128, notional: u128, side: i8) -> i128 {
    if entry_rate == 0 {
        return 0;
    }
    let move_mag: u128 = settle_price.abs_diff(entry_rate);
    let move_neg: bool = settle_price < entry_rate;
    let mag: u128 = notional.saturating_mul(move_mag) / entry_rate;
    let neg = move_neg ^ (side < 0);
    let mag_i = mag.min(i128::MAX as u128) as i128;
    if neg { mag_i.saturating_neg() } else { mag_i }
}

/// Soundness floor: the party's scenario-ES ([`party_scenario_es`] at the calibrated
/// [`FALLBACK_RET_1E18`]), never below the collateral locked at open (`Σ pushed_im`, each seat the
/// party-SIGNED `im_bps` — there is no static minimum; margin is pure scenario-ES). The all-gains ES
/// clamps to 0 BEFORE this max — the signed seat floor still applies.
pub fn position_im_floor(positions: &[PositionRecord], table: &ScenarioTable) -> u128 {
    let seat_floor = positions
        .iter()
        .fold(0u128, |acc, b| acc.saturating_add(b.pushed_im));
    party_scenario_es(positions, table, FALLBACK_RET_1E18).max(seat_floor)
}

/// One `ImRequirement` per distinct counterparty — `usd = position_im_floor(positions facing cp)`, sorted by cp.
pub fn im_requirements_for(
    acct: [u8; 20],
    positions: &[crate::PositionRecord],
    table: &ScenarioTable,
) -> Vec<crate::ImRequirement> {
    let mut cps: Vec<[u8; 20]> = Vec::new();
    for b in positions {
        if !cps.contains(&b.counterparty) {
            cps.push(b.counterparty);
        }
    }
    cps.sort_unstable();
    cps.into_iter()
        .map(|cp| {
            let sub: Vec<PositionRecord> =
                positions.iter().copied().filter(|b| b.counterparty == cp).collect();
            crate::ImRequirement { acct, cp, usd: position_im_floor(&sub, table) }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::test_util::*;
    use crate::*;

    #[test]
    fn c01_position_im_floor_sums_pushed_im() {
        let t = test_table();
        assert_eq!(position_im_floor(&[], &t), 0, "no positions ⇒ zero floor");
        let b0 = reference_box0();
        let b1 = reference_box1();
        let one = position_im_floor(&[b0], &t);
        assert!(one >= b0.pushed_im, "one-position party: floor ≥ its pushed_im");
        let two = position_im_floor(&[b0, b1], &t);
        assert!(
            two >= b0.pushed_im + b1.pushed_im,
            "two-position party: floor ≥ Σ pushed_im (the seat lock never releases below par)"
        );
    }

    #[test]
    fn netting_release_offsetting_book_margins_to_net_es() {
        // Pure scenario-ES margin (the static MIN_IM_BPS floor was REMOVED): a fully-offsetting
        // same-market same-counterparty book nets to ZERO, its scenario ES is zero, and with
        // near-zero party-signed seat IM the margin is ≈ 0 BY DESIGN — bilateral netting released.
        let t = test_table();
        let mut long = cop_position(100_000_000, 1, 0x51);
        let mut short = cop_position(100_000_000, -1, 0x52);
        // The parties signed a near-zero im_bps (1 unit per seat; exactly 0 IM rejects at open as degenerate).
        long.pushed_im = 1;
        short.pushed_im = 1;
        assert_eq!(
            party_scenario_es(&[long, short], &t, FALLBACK_RET_1E18), 0,
            "fully-offsetting book: ES of the NET (zero) position is zero"
        );
        assert_eq!(
            position_im_floor(&[long, short], &t), 2,
            "margin = max(net ES = 0, Σ signed seat IM = 2 minor units) ≈ 0 — the netting release is intentional"
        );
        // The standalone legs still margin in full — only the OFFSET is released.
        assert!(
            position_im_floor(std::slice::from_ref(&long), &t) >= 10_000_000_000_000,
            "one naked $100M leg still carries its full 10% worst-scenario ES"
        );
    }

    #[test]
    fn im_requirements_split_per_counterparty_and_sort() {
        let t = test_table();
        let b0 = reference_box0();
        let b1 = reference_box1();
        let acct = reference_account_owner();
        let reqs = im_requirements_for(acct, &[b0, b1], &t);
        assert_eq!(reqs.len(), 2, "one row per distinct counterparty");
        assert!(reqs[0].cp < reqs[1].cp, "rows sorted ascending by cp");
        assert_eq!(reqs[0].usd, position_im_floor(&[b0], &t), "each row is the floor over that netting set alone");
        assert_eq!(reqs[1].usd, position_im_floor(&[b1], &t), "each row is the floor over that netting set alone");
        for r in &reqs {
            assert_eq!(r.acct, acct, "every row carries the account");
        }
    }

    #[test]
    fn per_party_asymmetry_same_position_different_inventory() {
        let t = test_table();
        let a_positions = [cop_position(1_000_000_000, 1, 0xA1)];
        let b_positions = [cop_position(1_000_000_000, -1, 0xB1), cop_position(800_000_000, 1, 0xB2)];
        let k_a = party_scenario_es(&a_positions, &t, FALLBACK_RET_1E18);
        let k_b = party_scenario_es(&b_positions, &t, FALLBACK_RET_1E18);
        assert_ne!(k_a, k_b, "per-party inventory ES is asymmetric");
        assert!(k_a > k_b, "the concentrated $1B seat pays more than the $200M-net book");
        assert_eq!(
            k_b,
            party_scenario_es(&[cop_position(200_000_000, -1, 0x21)], &t, FALLBACK_RET_1E18),
            "B's two seats margin on their NET short $200M"
        );
    }

    #[test]
    fn position_residual_long_short_signs() {
        let b0 = reference_box0();
        assert_eq!(position_vm(b0.entry_rate, 1_100_000, b0.notional, b0.side), 18_518);
        assert_eq!(position_vm(b0.entry_rate, 1_050_000, b0.notional, b0.side), -27_777);
        let b1 = reference_box1();
        assert_eq!(position_vm(b1.entry_rate, 1_000_000, b1.notional, b1.side), -20_202);
        assert_eq!(position_vm(b1.entry_rate, 980_000, b1.notional, b1.side), 20_202);
        assert_eq!(position_vm(b0.entry_rate, b0.entry_rate, b0.notional, b0.side), 0);
        assert_eq!(position_vm(b1.entry_rate, b1.entry_rate, b1.notional, b1.side), 0);
        assert_eq!(position_vm(150_000_000, 151_500_000, 150_000_000, 1), 1_500_000);
        assert_ne!(position_vm(150_000_000, 151_500_000, 150_000_000, 1), 225_000_000);
        assert_eq!(position_vm(0, 1_100_000, 1_000_000, 1), 0);
    }

    #[test]
    fn position_vm_huge_notional_keeps_correct_sign() {
        let entry_rate: u128 = 1;
        let settle_price: u128 = 3;
        let notional: u128 = (i128::MAX as u128) + 10;
        let side: i8 = 1;
        let move_ = (settle_price as i128) - (entry_rate as i128);
        let old_style = (notional as i128).saturating_mul(move_).saturating_div(entry_rate as i128);
        assert!(old_style < 0, "documents the old sign-flip bug (as-i128 wrap turns a win negative)");
        assert!(position_vm(entry_rate, settle_price, notional, side) > 0, "long gains on an up-move — sign correct");
        assert!(position_vm(entry_rate, settle_price, notional, -1) < 0, "short loses on the same up-move");
    }
}
