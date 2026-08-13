//! Scenario-matrix ES99 margin kernel — the clean-break replacement for the ISDA IM ρ-form.
//!
//! The witness is a published `ScenarioTable` of K historical 2-day stressed returns per market; the guest
//! recomputes its keccak commitment (`scenario_root`) from the raw witness bytes and surfaces it as public
//! values row 10, so the chain re-asserts the prover used EXACTLY the owner-published table. Margin per
//! netting set is Expected Shortfall: net the book per `market_key` (stage 1, unchanged from the ρ-form
//! kernel), price every scenario's P&L over the netted factors, and average the worst `m` scenario losses,
//! rounded UP. The tail count `m` is CARRIED BY THE TABLE (not derived as ceil(K/100)): the published set is
//! tail-enriched by set-cover reduction from a larger pool, so the pool's own tail count ships with it.
//!
//! Rounding is DIRECTED, never neutral: a loss-increasing contribution folds /ONE with ceil, a
//! loss-decreasing one with floor, the final ES divide is ceil — every rounding error over-margins.
//!
//! Fail-closed. Every malformed-table condition PANICS (an unsatisfiable proof beats a silently wrong
//! margin): zero K, row-count mismatch, out-of-range or non-ascending column indices, a |return| above
//! `RET_MAX_1E18`, duplicate market keys. Nothing is clamped. A held market the table does not list adds
//! `ceil(FALLBACK_RET_1E18 × |net| / ONE)` to EVERY scenario's loss — always adverse.

use serde::{Deserialize, Serialize};

use crate::{keccak, PositionRecord, U256, ONE, RET_MAX_1E18};

/// The scenario-table witness the host supplies and the guest commits to.
///
/// Rows are SPARSE: `rows[s]` lists only the non-zero returns of scenario `s` as `(col_idx, return_1e18)`
/// pairs, strictly ascending by `col_idx`; an omitted column IS a zero return (sparse ≡ dense-zero).
/// `market_keys[col_idx]` names the market a column prices; returns are signed 1e18 fractions of notional
/// (positive = the priced rate moved UP).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScenarioTable {
    /// Publisher version counter (strictly increasing on-chain; bound into the root).
    pub version: u32,
    /// Number of scenarios K.
    pub k: u32,
    /// ES tail count: the number of worst losses averaged. Published WITH the table (the reduced set is
    /// tail-enriched, so deriving ceil(K/100) from the shipped K would over-state ES); 0 < m ≤ k.
    pub m: u32,
    /// One market key per column, no duplicates.
    pub market_keys: Vec<[u8; 32]>,
    /// K sparse rows of `(col_idx, return_1e18)`, strictly ascending `col_idx` per row.
    pub rows: Vec<Vec<(u16, i128)>>,
}

impl ScenarioTable {
    /// Assert every structural invariant; panic = unsatisfiable proof (fail-closed, NEVER clamp).
    pub fn validate(&self) {
        assert!(self.k > 0, "scenario-table: k must be > 0 — an empty table margins nothing (fail-closed)");
        assert!(
            self.m > 0 && self.m <= self.k,
            "scenario-table: tail count m must satisfy 0 < m <= k (fail-closed)"
        );
        assert_eq!(
            self.rows.len(),
            self.k as usize,
            "scenario-table: rows.len() != k — a truncated or padded table is malformed (fail-closed)"
        );
        assert!(
            self.market_keys.len() <= (u16::MAX as usize) + 1,
            "scenario-table: more market columns than u16 col_idx can address (fail-closed)"
        );
        for (i, a) in self.market_keys.iter().enumerate() {
            for b in self.market_keys.iter().skip(i + 1) {
                assert!(a != b, "scenario-table: duplicate market_key — one market must price through ONE column (fail-closed)");
            }
        }
        for row in &self.rows {
            let mut prev: Option<u16> = None;
            for &(col, ret) in row {
                assert!(
                    (col as usize) < self.market_keys.len(),
                    "scenario-table: col_idx out of range — a row references a column no market_key names (fail-closed)"
                );
                if let Some(p) = prev {
                    assert!(
                        col > p,
                        "scenario-table: row col_idx not strictly ascending — a duplicate or shuffled column would \
                         make the sparse encoding ambiguous (fail-closed)"
                    );
                }
                prev = Some(col);
                assert!(
                    ret.unsigned_abs() <= RET_MAX_1E18.unsigned_abs(),
                    "scenario-table: |return| exceeds RET_MAX_1E18 (100%) — a super-unitary return is malformed (fail-closed)"
                );
            }
        }
    }

    /// The canonical commitment preimage. Byte layout (all integers big-endian, fixed width):
    ///
    /// ```text
    /// version      : u32  BE                        (4 bytes)
    /// k            : u32  BE                        (4 bytes)
    /// m            : u32  BE (ES tail count)        (4 bytes)
    /// n            : u32  BE = market_keys.len()    (4 bytes)
    /// market_keys  : n × 32 raw bytes
    /// per row, K times:
    ///   len        : u32  BE = row.len()            (4 bytes)
    ///   per entry:  col_idx u16 BE (2 bytes) ‖ return_1e18 i128 BE two's-complement (16 bytes)
    /// ```
    ///
    /// Every field is length-prefixed fixed-width, so the encoding is prefix-free and injective: two
    /// distinct tables can never share a preimage.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let entries: usize = self.rows.iter().map(|r| r.len()).sum();
        let mut out = Vec::with_capacity(16 + 32 * self.market_keys.len() + 4 * self.rows.len() + 18 * entries);
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(&self.k.to_be_bytes());
        out.extend_from_slice(&self.m.to_be_bytes());
        out.extend_from_slice(&(self.market_keys.len() as u32).to_be_bytes());
        for mk in &self.market_keys {
            out.extend_from_slice(mk);
        }
        for row in &self.rows {
            out.extend_from_slice(&(row.len() as u32).to_be_bytes());
            for &(col, ret) in row {
                out.extend_from_slice(&col.to_be_bytes());
                out.extend_from_slice(&ret.to_be_bytes());
            }
        }
        out
    }

    /// Validate, then keccak the canonical bytes — the in-guest recomputed commitment the chain re-asserts.
    pub fn scenario_root(&self) -> [u8; 32] {
        self.validate();
        keccak(&[&self.canonical_bytes()])
    }
}

/// Stage 1 (kept verbatim from the ρ-form kernel): net a party's positions into per-market signed factors
/// (long − short per `market_key`), 1e6 minor units.
fn net_by_market(positions: &[PositionRecord]) -> Vec<([u8; 32], i128)> {
    let mut factors: Vec<([u8; 32], i128)> = Vec::new();
    for b in positions {
        // No `as i128` cast: a u128 notional above 2^127−1 would wrap into a phantom negative and flip a
        // long into a short. Build the signed net through the checked unsigned adders instead — a short of
        // exactly 2^127 (i128::MIN) stays representable, anything larger fails closed.
        assert!(
            b.side == 1 || b.side == -1,
            "net_by_market: side must be exactly +1 or -1 (polarity floor)"
        );
        let signed: i128 = if b.side == 1 {
            0i128
                .checked_add_unsigned(b.notional)
                .expect("net_by_market: long notional exceeds i128::MAX — fail-closed")
        } else {
            0i128
                .checked_sub_unsigned(b.notional)
                .expect("net_by_market: short notional exceeds |i128::MIN| — fail-closed")
        };
        match factors.iter_mut().find(|(mk, _)| *mk == b.market_key) {
            Some((_, net)) => {
                *net = net
                    .checked_add(signed)
                    .expect("net_by_market: net accumulation overflow");
            }
            None => factors.push((b.market_key, signed)),
        }
    }
    factors
}

/// One scenario's signed loss, 1e6 minor: `neg == true` is a GAIN (loss < 0).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SignedLoss {
    neg: bool,
    mag: u128,
}

/// Value order: gains < losses, larger loss = larger value.
fn loss_cmp(a: SignedLoss, b: SignedLoss) -> core::cmp::Ordering {
    use core::cmp::Ordering;
    match (a.neg, b.neg) {
        (false, true) => Ordering::Greater,
        (true, false) => Ordering::Less,
        (false, false) => a.mag.cmp(&b.mag),
        (true, true) => b.mag.cmp(&a.mag),
    }
}

/// Convert a split-sign U256 pair into a `SignedLoss`, failing closed if the magnitude exceeds u128.
fn signed_loss(pos: U256, neg: U256) -> SignedLoss {
    let (n, d) = if neg.le(pos) { (false, pos.sub(neg)) } else { (true, neg.sub(pos)) };
    assert_eq!(d.hi, 0, "party_scenario_es: scenario loss magnitude exceeds u128 — fail-closed");
    SignedLoss { neg: n, mag: d.lo }
}

/// Per-party scenario-ES margin over the party's OWN netted book, 1e6 minor units.
///
/// The caller must supply a VALIDATED table (`state_transition` validates once via [`ScenarioTable::scenario_root`]);
/// the two structural asserts kept here are the ones iteration itself depends on.
///
/// Per scenario `s` the loss is `−Σ_j r_{s,j}·n_j` (positive = the party loses): each leg's magnitude is the
/// EXACT 256-bit product `|net_1e6| × |ret_1e18|` folded `/ONE` with DIRECTED rounding — ceil when the leg
/// increases the loss, floor when it decreases it — accumulated in split-sign U256 pos/neg registers. A held
/// market the table does not list adds `ceil(fallback_ret × |net| / ONE)` to EVERY scenario's loss.
///
/// ES: `m` is the TABLE'S tail count (validated 0 < m ≤ k); sort losses descending with ascending
/// scenario-index tie-break (deterministic), sum the worst `m` in split U256, and return `ceil(sum / m)`.
/// A non-positive tail sum returns 0 — an all-gains book owes no initial margin (the seat floor
/// `Σ pushed_im` still applies at `position_im_floor`).
///
/// OVERFLOW BOUND. `|net_1e6| < 2^127` (i128 magnitude) and `|ret_1e18| ≤ RET_MAX_1E18 = 1e18 < 2^60`, so a
/// leg product is `< 2^187 ≪ 2^256` — `U256::mul` is exact. Post-`/ONE` a leg is `< 2^127`; a book nets to
/// ≤ 24 live factors, so each split accumulator stays `< 24·2^127 < 2^132 ≪ 2^256`. The only narrowing back
/// to u128 (per-scenario loss, final IM) is asserted, never truncated.
pub fn party_scenario_es(positions: &[PositionRecord], table: &ScenarioTable, fallback_ret: i128) -> u128 {
    assert!(table.k > 0, "party_scenario_es: k must be > 0 (fail-closed)");
    assert_eq!(
        table.rows.len(),
        table.k as usize,
        "party_scenario_es: rows.len() != k (fail-closed)"
    );
    assert!(
        table.m > 0 && table.m <= table.k,
        "party_scenario_es: tail count m must satisfy 0 < m <= k (fail-closed)"
    );
    assert!(fallback_ret > 0, "party_scenario_es: fallback_ret must be a positive adverse return (fail-closed)");

    let factors = net_by_market(positions);
    if factors.is_empty() {
        return 0;
    }

    // (|net|, net<0, table column) per netted factor; None = unlisted → the adverse fallback.
    let mut legs: Vec<(u128, bool, Option<u16>)> = Vec::with_capacity(factors.len());
    let mut fallback_base = U256::ZERO;
    for (mk, net) in &factors {
        let net_abs = net.unsigned_abs();
        let col = table.market_keys.iter().position(|k| k == mk);
        match col {
            Some(c) => legs.push((net_abs, *net < 0, Some(c as u16))),
            None => {
                // Unlisted held market: a constant adverse loss in EVERY scenario, rounded UP per market.
                fallback_base = fallback_base
                    .add(U256::mul(net_abs, fallback_ret.unsigned_abs()).div_u128_ceil(ONE));
            }
        }
    }

    let mut losses: Vec<SignedLoss> = Vec::with_capacity(table.k as usize);
    for row in &table.rows {
        let mut pos = fallback_base;
        let mut neg = U256::ZERO;
        for &(net_abs, net_neg, col) in &legs {
            let Some(col) = col else { continue };
            if net_abs == 0 {
                continue;
            }
            let Ok(i) = row.binary_search_by_key(&col, |&(c, _)| c) else { continue };
            let ret = row[i].1;
            if ret == 0 {
                continue;
            }
            let prod = U256::mul(net_abs, ret.unsigned_abs());
            // loss = −r·n: the leg RAISES the loss iff sign(r) != sign(n).
            if (ret < 0) != net_neg {
                pos = pos.add(prod.div_u128_ceil(ONE));
            } else {
                neg = neg.add(prod.div_u128(ONE));
            }
        }
        losses.push(signed_loss(pos, neg));
    }

    // Deterministic selection: descending loss, ascending scenario index on exact ties.
    let mut order: Vec<usize> = (0..losses.len()).collect();
    order.sort_by(|&a, &b| loss_cmp(losses[b], losses[a]).then(a.cmp(&b)));

    let m = table.m as usize;
    let mut tail_pos = U256::ZERO;
    let mut tail_neg = U256::ZERO;
    for &i in order.iter().take(m) {
        let l = losses[i];
        if l.neg {
            tail_neg = tail_neg.add(U256 { hi: 0, lo: l.mag });
        } else {
            tail_pos = tail_pos.add(U256 { hi: 0, lo: l.mag });
        }
    }
    if tail_pos.le(tail_neg) {
        // Non-positive expected shortfall: the tail is all gains — the book owes no scenario IM.
        return 0;
    }
    let im = tail_pos.sub(tail_neg).div_u128_ceil(m as u128);
    assert_eq!(im.hi, 0, "party_scenario_es: ES exceeds u128 — fail-closed");
    im.lo
}

/// One market key's signed leg in the binding scenario's loss, 1e6 minor.
///
/// `neg == false` = the leg RAISED the loss (adverse, ceil-rounded); `neg == true` = it REDUCED the
/// loss (a gain, floor-rounded). The signed sum `Σ(mag where !neg) − Σ(mag where neg)` over all
/// contributions equals the binding scenario's total loss (`tail[0]`), so the attribution reconciles
/// exactly against the ES the kernel margins on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MarketContribution {
    /// The market key this netted leg prices through.
    pub market_key: [u8; 32],
    /// `false` = raised the loss (adverse); `true` = reduced it (a gain).
    pub neg: bool,
    /// Magnitude of the leg's directed-rounded contribution to the binding scenario, 1e6 minor.
    pub mag: u128,
}

/// One tail scenario: its table-row index and its signed loss (`neg == true` = a net gain).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TailScenario {
    /// Scenario index into `table.rows`.
    pub scenario: u32,
    /// `true` = the scenario is a net gain (loss < 0).
    pub neg: bool,
    /// Loss magnitude, 1e6 minor.
    pub mag: u128,
}

/// The attribution companion to [`party_scenario_es`].
///
/// `im` is IDENTICAL to `party_scenario_es(same inputs)`; the rest is the CME-style decomposition:
/// the binding scenario (the worst / first-in-tail), the worst-`m` tail, and the per-market-key leg
/// AT the binding scenario. HOST-ONLY — the guest never calls it, so `party_scenario_es` is left
/// byte-for-byte unchanged and the proven kernel / vkey is untouched.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScenarioBreakdown {
    /// Identical to `party_scenario_es(positions, table, fallback_ret)`.
    pub im: u128,
    /// The worst (first-in-tail) scenario index — the CME "binding scenario".
    pub binding_scenario: u32,
    /// The worst `m` scenarios, worst-first (ascending index on exact ties).
    pub tail: Vec<TailScenario>,
    /// Per netted market key, its signed leg in the binding scenario's loss.
    pub contributions: Vec<MarketContribution>,
}

/// Attribution companion to [`party_scenario_es`]: the SAME ES `im`, plus the binding scenario, the
/// worst-`m` tail, and the per-market-key contribution at the binding scenario. Reuses the identical
/// loss math — every rounding decision matches the kernel — so `breakdown.im == party_scenario_es(..)`
/// on every input, and the signed contribution sum reconciles to the binding scenario's loss.
pub fn party_scenario_es_breakdown(
    positions: &[PositionRecord],
    table: &ScenarioTable,
    fallback_ret: i128,
) -> ScenarioBreakdown {
    assert!(table.k > 0, "party_scenario_es_breakdown: k must be > 0 (fail-closed)");
    assert_eq!(
        table.rows.len(),
        table.k as usize,
        "party_scenario_es_breakdown: rows.len() != k (fail-closed)"
    );
    assert!(
        table.m > 0 && table.m <= table.k,
        "party_scenario_es_breakdown: tail count m must satisfy 0 < m <= k (fail-closed)"
    );
    assert!(
        fallback_ret > 0,
        "party_scenario_es_breakdown: fallback_ret must be a positive adverse return (fail-closed)"
    );

    let factors = net_by_market(positions);
    if factors.is_empty() {
        return ScenarioBreakdown { im: 0, binding_scenario: 0, tail: Vec::new(), contributions: Vec::new() };
    }

    // (|net|, net<0, table column, market_key) per netted factor; None = unlisted → the adverse fallback.
    let mut legs: Vec<(u128, bool, Option<u16>, [u8; 32])> = Vec::with_capacity(factors.len());
    let mut fallback_base = U256::ZERO;
    for (mk, net) in &factors {
        let net_abs = net.unsigned_abs();
        let col = table.market_keys.iter().position(|k| k == mk);
        match col {
            Some(c) => legs.push((net_abs, *net < 0, Some(c as u16), *mk)),
            None => {
                fallback_base = fallback_base
                    .add(U256::mul(net_abs, fallback_ret.unsigned_abs()).div_u128_ceil(ONE));
                legs.push((net_abs, *net < 0, None, *mk));
            }
        }
    }

    // Per-scenario loss — the SAME directed-rounded accumulation as `party_scenario_es`.
    let mut losses: Vec<SignedLoss> = Vec::with_capacity(table.k as usize);
    for row in &table.rows {
        let mut pos = fallback_base;
        let mut neg = U256::ZERO;
        for &(net_abs, net_neg, col, _mk) in &legs {
            let Some(col) = col else { continue };
            if net_abs == 0 {
                continue;
            }
            let Ok(i) = row.binary_search_by_key(&col, |&(c, _)| c) else { continue };
            let ret = row[i].1;
            if ret == 0 {
                continue;
            }
            let prod = U256::mul(net_abs, ret.unsigned_abs());
            if (ret < 0) != net_neg {
                pos = pos.add(prod.div_u128_ceil(ONE));
            } else {
                neg = neg.add(prod.div_u128(ONE));
            }
        }
        losses.push(signed_loss(pos, neg));
    }

    let mut order: Vec<usize> = (0..losses.len()).collect();
    order.sort_by(|&a, &b| loss_cmp(losses[b], losses[a]).then(a.cmp(&b)));

    let m = table.m as usize;
    let mut tail_pos = U256::ZERO;
    let mut tail_neg = U256::ZERO;
    let mut tail: Vec<TailScenario> = Vec::with_capacity(m);
    for &i in order.iter().take(m) {
        let l = losses[i];
        tail.push(TailScenario { scenario: i as u32, neg: l.neg, mag: l.mag });
        if l.neg {
            tail_neg = tail_neg.add(U256 { hi: 0, lo: l.mag });
        } else {
            tail_pos = tail_pos.add(U256 { hi: 0, lo: l.mag });
        }
    }
    let im = if tail_pos.le(tail_neg) {
        0
    } else {
        let v = tail_pos.sub(tail_neg).div_u128_ceil(m as u128);
        assert_eq!(v.hi, 0, "party_scenario_es_breakdown: ES exceeds u128 — fail-closed");
        v.lo
    };

    // Per-market contribution at the binding scenario (order[0], the worst loss).
    let binding = order[0];
    let brow = &table.rows[binding];
    let mut contributions: Vec<MarketContribution> = Vec::with_capacity(legs.len());
    for &(net_abs, net_neg, col, mk) in &legs {
        if net_abs == 0 {
            contributions.push(MarketContribution { market_key: mk, neg: false, mag: 0 });
            continue;
        }
        match col {
            // Unlisted held market: the constant adverse fallback that rode every scenario's loss.
            None => {
                let v = U256::mul(net_abs, fallback_ret.unsigned_abs()).div_u128_ceil(ONE);
                assert_eq!(v.hi, 0, "party_scenario_es_breakdown: fallback leg exceeds u128 — fail-closed");
                contributions.push(MarketContribution { market_key: mk, neg: false, mag: v.lo });
            }
            Some(col) => {
                let ret = brow.binary_search_by_key(&col, |&(c, _)| c).ok().map(|i| brow[i].1).unwrap_or(0);
                if ret == 0 {
                    contributions.push(MarketContribution { market_key: mk, neg: false, mag: 0 });
                    continue;
                }
                let prod = U256::mul(net_abs, ret.unsigned_abs());
                if (ret < 0) != net_neg {
                    let v = prod.div_u128_ceil(ONE);
                    assert_eq!(v.hi, 0, "party_scenario_es_breakdown: adverse leg exceeds u128 — fail-closed");
                    contributions.push(MarketContribution { market_key: mk, neg: false, mag: v.lo });
                } else {
                    let v = prod.div_u128(ONE);
                    assert_eq!(v.hi, 0, "party_scenario_es_breakdown: gain leg exceeds u128 — fail-closed");
                    contributions.push(MarketContribution { market_key: mk, neg: true, mag: v.lo });
                }
            }
        }
    }

    ScenarioBreakdown { im, binding_scenario: binding as u32, tail, contributions }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::*;
    use crate::{position_im_floor, FALLBACK_RET_1E18, ONE_I};

    const M: u128 = 1_000_000;

    fn one_col_table_m(mk: [u8; 32], rets: &[i128], m: u32) -> ScenarioTable {
        ScenarioTable {
            version: 1,
            k: rets.len() as u32,
            m,
            market_keys: vec![mk],
            rows: rets.iter().map(|&r| if r == 0 { vec![] } else { vec![(0u16, r)] }).collect(),
        }
    }

    fn one_col_table(mk: [u8; 32], rets: &[i128]) -> ScenarioTable {
        one_col_table_m(mk, rets, 1)
    }

    // ── validation asserts, one test per invariant ─────────────────────────────────────────────────

    #[test]
    #[should_panic(expected = "k must be > 0")]
    fn validate_rejects_zero_k() {
        ScenarioTable { version: 1, k: 0, m: 1, market_keys: vec![], rows: vec![] }.validate();
    }

    #[test]
    #[should_panic(expected = "rows.len() != k")]
    fn validate_rejects_row_count_mismatch() {
        ScenarioTable { version: 1, k: 2, m: 1, market_keys: vec![[1u8; 32]], rows: vec![vec![]] }.validate();
    }

    #[test]
    #[should_panic(expected = "col_idx out of range")]
    fn validate_rejects_out_of_range_col() {
        ScenarioTable { version: 1, k: 1, m: 1, market_keys: vec![[1u8; 32]], rows: vec![vec![(1, ONE_I / 10)]] }.validate();
    }

    #[test]
    #[should_panic(expected = "not strictly ascending")]
    fn validate_rejects_non_ascending_cols() {
        ScenarioTable {
            version: 1,
            k: 1,
            m: 1,
            market_keys: vec![[1u8; 32], [2u8; 32]],
            rows: vec![vec![(1, ONE_I / 10), (0, ONE_I / 20)]],
        }
        .validate();
    }

    #[test]
    #[should_panic(expected = "not strictly ascending")]
    fn validate_rejects_duplicate_col_in_row() {
        ScenarioTable {
            version: 1,
            k: 1,
            m: 1,
            market_keys: vec![[1u8; 32], [2u8; 32]],
            rows: vec![vec![(0, ONE_I / 10), (0, ONE_I / 20)]],
        }
        .validate();
    }

    #[test]
    #[should_panic(expected = "exceeds RET_MAX_1E18")]
    fn validate_rejects_super_unitary_return() {
        ScenarioTable { version: 1, k: 1, m: 1, market_keys: vec![[1u8; 32]], rows: vec![vec![(0, RET_MAX_1E18 + 1)]] }
            .validate();
    }

    #[test]
    #[should_panic(expected = "exceeds RET_MAX_1E18")]
    fn validate_rejects_super_unitary_negative_return() {
        ScenarioTable { version: 1, k: 1, m: 1, market_keys: vec![[1u8; 32]], rows: vec![vec![(0, -(RET_MAX_1E18 + 1))]] }
            .validate();
    }

    #[test]
    #[should_panic(expected = "duplicate market_key")]
    fn validate_rejects_duplicate_market_keys() {
        ScenarioTable { version: 1, k: 1, m: 1, market_keys: vec![[1u8; 32], [1u8; 32]], rows: vec![vec![]] }.validate();
    }

    #[test]
    #[should_panic(expected = "tail count m")]
    fn validate_rejects_zero_m() {
        ScenarioTable { version: 1, k: 1, m: 0, market_keys: vec![[1u8; 32]], rows: vec![vec![]] }.validate();
    }

    #[test]
    #[should_panic(expected = "tail count m")]
    fn validate_rejects_m_above_k() {
        ScenarioTable { version: 1, k: 1, m: 2, market_keys: vec![[1u8; 32]], rows: vec![vec![]] }.validate();
    }

    #[test]
    fn validate_accepts_the_test_table() {
        test_table().validate();
        let _ = test_table().scenario_root();
    }

    // ── the commitment ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn scenario_root_is_stable_and_field_sensitive() {
        let t = test_table();
        let root = t.scenario_root();
        assert_eq!(root, t.clone().scenario_root(), "the root is deterministic");
        let mut v = t.clone();
        v.version += 1;
        assert_ne!(v.scenario_root(), root, "version moves the root");
        let mut r = t.clone();
        r.rows[0] = vec![(0, ONE_I / 1000)];
        assert_ne!(r.scenario_root(), root, "a single return moves the root");
        let mut k = t.clone();
        k.market_keys.reverse();
        assert_ne!(k.scenario_root(), root, "column order moves the root");
        let mut m = t.clone();
        m.m += 1;
        assert_ne!(m.scenario_root(), root, "the tail count moves the root");
    }

    #[test]
    fn canonical_bytes_layout_is_the_documented_one() {
        let t = ScenarioTable {
            version: 7,
            k: 2,
            m: 2,
            market_keys: vec![[0xABu8; 32]],
            rows: vec![vec![(0u16, 3i128)], vec![]],
        };
        let mut expect = Vec::new();
        expect.extend_from_slice(&7u32.to_be_bytes());
        expect.extend_from_slice(&2u32.to_be_bytes());
        expect.extend_from_slice(&2u32.to_be_bytes());
        expect.extend_from_slice(&1u32.to_be_bytes());
        expect.extend_from_slice(&[0xABu8; 32]);
        expect.extend_from_slice(&1u32.to_be_bytes());
        expect.extend_from_slice(&0u16.to_be_bytes());
        expect.extend_from_slice(&3i128.to_be_bytes());
        expect.extend_from_slice(&0u32.to_be_bytes());
        assert_eq!(t.canonical_bytes(), expect, "byte layout matches the doc comment");
    }

    // ── the kernel ─────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn empty_book_is_zero() {
        assert_eq!(party_scenario_es(&[], &test_table(), FALLBACK_RET_1E18), 0, "no positions ⇒ no scenario IM");
    }

    #[test]
    fn single_long_worst_scenario_prices_exactly() {
        // $100M long COP; scenarios: −10%, −5%, +2% (a long loses when the rate FALLS).
        let bx = cop_position(100_000_000, 1, 0x01);
        let t = one_col_table(bx.market_key, &[-ONE_I / 10, -ONE_I / 20, ONE_I / 50]);
        let es = party_scenario_es(&[bx], &t, FALLBACK_RET_1E18);
        // m=1 ⇒ ES = worst loss = 10% × $100M = $10M (exact — no rounding residue).
        assert_eq!(es, 10_000_000 * M, "worst-1 ES prices the −10% scenario on the $100M long");
    }

    #[test]
    fn short_side_flips_the_adverse_scenario() {
        let bx = cop_position(100_000_000, -1, 0x01);
        let t = one_col_table(bx.market_key, &[-ONE_I / 10, ONE_I / 20]);
        // The short loses when the rate RISES: worst is +5% ⇒ $5M.
        assert_eq!(party_scenario_es(&[bx], &t, FALLBACK_RET_1E18), 5_000_000 * M, "the short's worst is the up-move");
    }

    #[test]
    fn sparse_equals_dense_zero() {
        let bx = cop_position(50_000_000, 1, 0x01);
        let other_mk = [0x5Au8; 32];
        let sparse = ScenarioTable {
            version: 1,
            k: 3,
            m: 1,
            market_keys: vec![bx.market_key, other_mk],
            rows: vec![vec![(0, -ONE_I / 10)], vec![], vec![(1, ONE_I / 4)]],
        };
        let dense = ScenarioTable {
            version: 1,
            k: 3,
            m: 1,
            market_keys: vec![bx.market_key, other_mk],
            rows: vec![
                vec![(0, -ONE_I / 10), (1, 0)],
                vec![(0, 0), (1, 0)],
                vec![(0, 0), (1, ONE_I / 4)],
            ],
        };
        assert_eq!(
            party_scenario_es(&[bx], &sparse, FALLBACK_RET_1E18),
            party_scenario_es(&[bx], &dense, FALLBACK_RET_1E18),
            "an omitted column IS a zero return — sparse ≡ dense"
        );
    }

    #[test]
    fn netting_offsets_before_pricing() {
        // +$500M and −$300M COP net to +$200M before any scenario prices.
        let t = one_col_table(cop_position(1, 1, 0x00).market_key, &[-ONE_I / 10, ONE_I / 100]);
        let netted = party_scenario_es(
            &[cop_position(500_000_000, 1, 0x51), cop_position(300_000_000, -1, 0x31)],
            &t,
            FALLBACK_RET_1E18,
        );
        let direct = party_scenario_es(&[cop_position(200_000_000, 1, 0x21)], &t, FALLBACK_RET_1E18);
        assert_eq!(netted, direct, "stage-1 netting: offsetting seats margin on their NET");
        assert_eq!(direct, 20_000_000 * M, "10% of the $200M net");
    }

    #[test]
    fn cross_market_scenario_loss_nets_within_a_scenario() {
        // Long $100M COP, short $100M BRL; scenario: both rates fall 10% ⇒ COP loses $10M, BRL gains $10M ⇒ 0.
        let cop = cop_position(100_000_000, 1, 0x01);
        let brl = brl_position(100_000_000, -1, 0x02);
        let t = ScenarioTable {
            version: 1,
            k: 2,
            m: 1,
            market_keys: vec![cop.market_key, brl.market_key],
            rows: vec![vec![(0, -ONE_I / 10), (1, -ONE_I / 10)], vec![(0, -ONE_I / 20)]],
        };
        // Scenario 0 nets to 0; scenario 1: COP −5% ⇒ $5M loss, BRL unmoved. Worst-1 = $5M.
        assert_eq!(party_scenario_es(&[cop, brl], &t, FALLBACK_RET_1E18), 5_000_000 * M, "the hedged scenario nets to zero; the unhedged one binds");
    }

    #[test]
    fn all_gains_book_owes_zero() {
        // Long book, every scenario is an up-move: every "loss" is a gain ⇒ ES = 0.
        let bx = cop_position(100_000_000, 1, 0x01);
        let t = one_col_table(bx.market_key, &[ONE_I / 10, ONE_I / 20, ONE_I / 100]);
        assert_eq!(party_scenario_es(&[bx], &t, FALLBACK_RET_1E18), 0, "an all-gains tail owes nothing");
    }

    #[test]
    fn fallback_adds_adverse_loss_to_every_scenario() {
        // A held market the table does not list: every scenario carries ceil(43.3% × |net|).
        let bx = cop_position(100_000_000, 1, 0x01);
        let unrelated = [0x9Du8; 32];
        let t = one_col_table(unrelated, &[ONE_I / 10, -ONE_I / 10]);
        let es = party_scenario_es(&[bx], &t, FALLBACK_RET_1E18);
        assert_eq!(es, 43_300_000 * M, "the unlisted $100M long margins at the 43.3% fallback in every scenario");
        // The fallback rides ON TOP of listed-scenario losses for other legs.
        let listed = brl_position(100_000_000, 1, 0x02);
        let t2 = one_col_table(listed.market_key, &[-ONE_I / 10, ONE_I / 100]);
        let es2 = party_scenario_es(&[bx, listed], &t2, FALLBACK_RET_1E18);
        assert_eq!(es2, (43_300_000 + 10_000_000) * M, "fallback + the listed leg's worst scenario stack");
    }

    #[test]
    fn tie_break_and_permutation_are_deterministic() {
        // Two scenarios with EXACTLY equal losses; m=2 picks both regardless of index order.
        let bx = cop_position(100_000_000, 1, 0x01);
        let mut rets = vec![0i128; 200];
        rets[7] = -ONE_I / 10;
        rets[123] = -ONE_I / 10;
        let t = one_col_table_m(bx.market_key, &rets, 2);
        let es = party_scenario_es(&[bx], &t, FALLBACK_RET_1E18);
        assert_eq!(es, 10_000_000 * M, "ES over the two tied worst scenarios = the tied loss");
        // Permute the scenario order: the multiset of losses is unchanged, so ES is invariant.
        let mut rets_p = vec![0i128; 200];
        rets_p[0] = -ONE_I / 10;
        rets_p[199] = -ONE_I / 10;
        let tp = one_col_table_m(bx.market_key, &rets_p, 2);
        assert_eq!(party_scenario_es(&[bx], &tp, FALLBACK_RET_1E18), es, "scenario permutation invariance");
    }

    #[test]
    fn es_average_rounds_up() {
        // m=2 from the table; worst two losses $3 and $2 minor ⇒ ES = ceil(5/2) = 3.
        let bx = PositionRecord { notional: 100, ..cop_position(0, 1, 0x01) };
        let mut rets = vec![0i128; 200];
        rets[0] = -(ONE_I * 3) / 100; // 3% of 100 minor = 3
        rets[1] = -(ONE_I * 2) / 100; // 2
        let t = one_col_table_m(bx.market_key, &rets, 2);
        assert_eq!(party_scenario_es(&[bx], &t, FALLBACK_RET_1E18), 3, "ceil((3+2)/2) = 3 — the ES divide rounds UP");
    }

    #[test]
    fn directed_rounding_ceils_the_loss_leg() {
        // net = 3 minor, ret = −1/3 (loss leg): exact loss 0.999… ⇒ ceil to 1, never floor to 0.
        let bx = PositionRecord { notional: 3, ..cop_position(0, 1, 0x01) };
        let third = ONE_I / 3;
        let t = one_col_table(bx.market_key, &[-third]);
        assert_eq!(party_scenario_es(&[bx], &t, FALLBACK_RET_1E18), 1, "a fractional loss rounds UP (over-margin)");
        // The same magnitude as a GAIN floors to 0 — the gain is never over-credited.
        let t_gain_only = one_col_table(bx.market_key, &[third, -third]);
        // worst-1 is still the loss scenario; the gain scenario is not selected — ES unchanged.
        assert_eq!(party_scenario_es(&[bx], &t_gain_only, FALLBACK_RET_1E18), 1, "gains never dilute the worst-loss tail");
    }

    #[test]
    fn seat_floor_dominates_via_position_im_floor() {
        let bx = cop_position(100_000_000, 1, 0x01);
        // Tiny scenario losses: ES ≪ pushed_im ⇒ the seat floor binds.
        let t = one_col_table(bx.market_key, &[-ONE_I / 1_000_000]);
        let es = party_scenario_es(&[bx], &t, FALLBACK_RET_1E18);
        assert!(es < bx.pushed_im, "the fixture's ES is genuinely below the seat lock");
        assert_eq!(position_im_floor(&[bx], &t), bx.pushed_im, "position_im_floor = max(ES, Σ pushed_im) — the seat floor verbatim");
        // Big scenario loss: ES > pushed_im ⇒ the ES binds.
        let t_big = one_col_table(bx.market_key, &[-ONE_I / 2]);
        let es_big = party_scenario_es(&[bx], &t_big, FALLBACK_RET_1E18);
        assert!(es_big > bx.pushed_im, "the −50% scenario beats the 781bps seat lock");
        assert_eq!(position_im_floor(&[bx], &t_big), es_big, "the scenario ES binds when it exceeds the seat floor");
    }

    #[test]
    fn zero_net_listed_market_contributes_nothing() {
        let long = cop_position(100_000_000, 1, 0x01);
        let short = cop_position(100_000_000, -1, 0x02);
        let t = one_col_table(long.market_key, &[-ONE_I / 10]);
        assert_eq!(party_scenario_es(&[long, short], &t, FALLBACK_RET_1E18), 0, "a flat net prices to zero in every scenario");
    }

    // ── the attribution breakdown ────────────────────────────────────────────────────────────────────

    /// Signed reconstruction of a scenario's loss from a contribution set: Σ(!neg) − Σ(neg).
    fn signed_sum(contribs: &[MarketContribution]) -> i128 {
        let mut acc: i128 = 0;
        for c in contribs {
            let m = c.mag as i128;
            if c.neg {
                acc -= m;
            } else {
                acc += m;
            }
        }
        acc
    }

    /// The signed value of a tail entry (positive = a loss, negative = a gain).
    fn signed_of(t: TailScenario) -> i128 {
        if t.neg { -(t.mag as i128) } else { t.mag as i128 }
    }

    #[test]
    fn breakdown_im_matches_party_scenario_es_across_fixtures() {
        let cop = cop_position(100_000_000, 1, 0x01);
        let short = cop_position(100_000_000, -1, 0x01);
        let brl = brl_position(100_000_000, -1, 0x02);
        let cases: Vec<(Vec<PositionRecord>, ScenarioTable)> = vec![
            (vec![cop], one_col_table(cop.market_key, &[-ONE_I / 10, -ONE_I / 20, ONE_I / 50])),
            (vec![short], one_col_table(short.market_key, &[-ONE_I / 10, ONE_I / 20])),
            (vec![cop], one_col_table(cop.market_key, &[ONE_I / 10, ONE_I / 20, ONE_I / 100])), // all-gains ⇒ 0
            (
                vec![cop, brl],
                ScenarioTable {
                    version: 1,
                    k: 2,
                    m: 1,
                    market_keys: vec![cop.market_key, brl.market_key],
                    rows: vec![vec![(0, -ONE_I / 10), (1, -ONE_I / 10)], vec![(0, -ONE_I / 20)]],
                },
            ),
            // Unlisted held market ⇒ the fallback rides every scenario.
            (vec![cop], one_col_table([0x9Du8; 32], &[ONE_I / 10, -ONE_I / 10])),
        ];
        for (i, (positions, table)) in cases.iter().enumerate() {
            let want = party_scenario_es(positions, table, FALLBACK_RET_1E18);
            let bd = party_scenario_es_breakdown(positions, table, FALLBACK_RET_1E18);
            assert_eq!(bd.im, want, "case {i}: breakdown.im must equal party_scenario_es");
        }
    }

    #[test]
    fn binding_scenario_is_the_argmax_loss() {
        // Worst loss is the −10% at index 0 for a long.
        let bx = cop_position(100_000_000, 1, 0x01);
        let t = one_col_table(bx.market_key, &[-ONE_I / 10, -ONE_I / 20, ONE_I / 50]);
        let bd = party_scenario_es_breakdown(&[bx], &t, FALLBACK_RET_1E18);
        assert_eq!(bd.binding_scenario, 0, "the −10% scenario binds the long");
        assert_eq!(bd.tail.len(), 1, "m=1 ⇒ a one-scenario tail");
        assert_eq!(bd.tail[0].scenario, bd.binding_scenario, "the tail head IS the binding scenario");

        // A short: worst is the up-move, placed at index 2 here.
        let sx = cop_position(100_000_000, -1, 0x01);
        let ts = one_col_table(sx.market_key, &[-ONE_I / 10, ONE_I / 100, ONE_I / 20]);
        let bds = party_scenario_es_breakdown(&[sx], &ts, FALLBACK_RET_1E18);
        assert_eq!(bds.binding_scenario, 2, "the short's worst is the +5% at index 2");

        // Cross-check the argmax property directly against the kernel's own ordering: no scenario
        // outranks the binding one (recompute losses through the private helpers).
        let factors = net_by_market(&[bx]);
        let col = t.market_keys.iter().position(|k| *k == factors[0].0).unwrap() as u16;
        let net = factors[0].1;
        let mut worst = 0usize;
        let mut worst_loss = SignedLoss { neg: true, mag: u128::MAX };
        for (s, row) in t.rows.iter().enumerate() {
            let mut pos = U256::ZERO;
            let mut neg = U256::ZERO;
            if let Ok(i) = row.binary_search_by_key(&col, |&(c, _)| c) {
                let ret = row[i].1;
                let prod = U256::mul(net.unsigned_abs(), ret.unsigned_abs());
                if (ret < 0) != (net < 0) { pos = pos.add(prod.div_u128_ceil(ONE)); }
                else { neg = neg.add(prod.div_u128(ONE)); }
            }
            let l = signed_loss(pos, neg);
            if loss_cmp(l, worst_loss) == core::cmp::Ordering::Greater { worst_loss = l; worst = s; }
        }
        assert_eq!(bd.binding_scenario as usize, worst, "binding_scenario is the argmax over scenario losses");
    }

    #[test]
    fn contributions_reconcile_to_the_binding_loss() {
        // Multi-market book: long $100M COP, short $80M BRL; two scenarios.
        let cop = cop_position(100_000_000, 1, 0x01);
        let brl = brl_position(80_000_000, -1, 0x02);
        let t = ScenarioTable {
            version: 1,
            k: 2,
            m: 1,
            market_keys: vec![cop.market_key, brl.market_key],
            rows: vec![
                vec![(0, -ONE_I / 10), (1, ONE_I / 20)], // COP −10% (long loses), BRL +5% (short loses)
                vec![(0, ONE_I / 100)],                  // COP +1% (long gains), BRL flat
            ],
        };
        let bd = party_scenario_es_breakdown(&[cop, brl], &t, FALLBACK_RET_1E18);
        // Both legs are adverse in scenario 0 ⇒ it binds. Contributions must sum to that loss.
        assert_eq!(bd.binding_scenario, 0);
        assert_eq!(signed_sum(&bd.contributions), signed_of(bd.tail[0]), "Σ signed contributions = binding scenario loss");
        // One contribution per netted market key.
        assert_eq!(bd.contributions.len(), 2, "one leg per market key");
        // Both legs raised the loss in scenario 0.
        assert!(bd.contributions.iter().all(|c| !c.neg), "every leg is adverse in the binding scenario");
    }

    #[test]
    fn contributions_reconcile_with_a_gain_leg_and_fallback() {
        // A book that mixes an adverse listed leg, a gain listed leg, and an unlisted fallback leg.
        let cop = cop_position(100_000_000, 1, 0x01); // listed, will lose
        let brl = brl_position(100_000_000, 1, 0x02); // listed, will gain in the binding scenario
        let orphan = PositionRecord { market_key: [0x9Du8; 32], ..cop_position(50_000_000, 1, 0x03) }; // unlisted
        let t = ScenarioTable {
            version: 1,
            k: 1,
            m: 1,
            market_keys: vec![cop.market_key, brl.market_key],
            rows: vec![vec![(0, -ONE_I / 10), (1, ONE_I / 20)]], // COP −10% loss, BRL +5% gain
        };
        let bd = party_scenario_es_breakdown(&[cop, brl, orphan], &t, FALLBACK_RET_1E18);
        assert_eq!(signed_sum(&bd.contributions), signed_of(bd.tail[0]), "gain + adverse + fallback legs reconcile to the loss");
        // The gain leg (BRL) is the only reducing contribution.
        assert_eq!(bd.contributions.iter().filter(|c| c.neg).count(), 1, "exactly the BRL gain reduces the loss");
        // The fallback leg is present and adverse.
        let fb = bd.contributions.iter().find(|c| c.market_key == [0x9Du8; 32]).unwrap();
        assert!(!fb.neg && fb.mag > 0, "the unlisted leg contributes an adverse fallback");
    }

    #[test]
    fn empty_book_breakdown_is_zero() {
        let bd = party_scenario_es_breakdown(&[], &test_table(), FALLBACK_RET_1E18);
        assert_eq!(bd.im, 0);
        assert_eq!(bd.binding_scenario, 0);
        assert!(bd.tail.is_empty() && bd.contributions.is_empty());
    }

    #[test]
    fn breakdown_tail_holds_m_worst_scenarios() {
        let bx = cop_position(100_000_000, 1, 0x01);
        let mut rets = vec![0i128; 200];
        rets[7] = -ONE_I / 10;
        rets[123] = -ONE_I / 20;
        let t = one_col_table_m(bx.market_key, &rets, 2);
        let bd = party_scenario_es_breakdown(&[bx], &t, FALLBACK_RET_1E18);
        assert_eq!(bd.tail.len(), 2, "m=2 ⇒ two tail scenarios");
        assert_eq!(bd.binding_scenario, 7, "the −10% at index 7 is worst");
        assert_eq!(bd.tail[0].scenario, 7);
        assert_eq!(bd.tail[1].scenario, 123, "the −5% is second-worst");
        // im equals the kernel's ES over the same tail.
        assert_eq!(bd.im, party_scenario_es(&[bx], &t, FALLBACK_RET_1E18));
    }
}
