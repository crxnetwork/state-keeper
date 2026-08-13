//! Every vkey-affecting scalar in one auditable block. Pure data — no logic. Position prices, marks and collateral are
//! 1e6-scaled minor units while the IM kernels run in 1e18, so the two 1e12 constants below carry a value between the
//! two scales; every bps figure divides by `BPS_DENOM` (1e4 = 100%). The freshness windows bound how far back a keeper
//! may reach for a price — outside them a mark is stale and chosen-adverse — and each mirrors an on-chain bound.
//! This crate MUST be built with `overflow-checks = true` (host and guest `Cargo.toml`): cash accumulators use raw
//! `+`/`-` on `u128`/`i128` behind a guarding branch and rely on panic-on-overflow; wide products use `im-math`'s `U256`.

/// Position-price fixed-point scale: 1e6, the divisor in `quantity × rate / 1e6`.
pub const PRICE_SCALE: i128 = 1_000_000;

/// Collateral ledger decimals — every accepted collateral is a fixed 6-decimal ERC-20 (`Crx.setCollateralToken`).
pub const COLLATERAL_DECIMALS: i32 = 6;

/// Basis-point denominator, 1e4 = 100% — the shared divisor for every bps computation in this crate.
pub const BPS_DENOM: u128 = 10_000;

/// NDF instrument tag — the only live instrument (mirrors `Crx.sol INSTRUMENT_NDF`).
pub const INSTRUMENT_NDF: u8 = 1;

/// Proven-hourly-mark recency bound, in seconds (2h — the on-chain `MAX_PROOF_STALENESS`).
pub const MARK_MAX_AGE_SECS: u64 = 2 * 60 * 60;

/// Best-exec multiple on proven `|pnl|`, dimensionless: `spread ≤ K · |pnl| +` the notional floor below.
pub const SPREAD_BEST_EXEC_K: u128 = 2;

/// Best-exec floor, in bps of notional — the bounded baseline C still gets at `|pnl| ≈ 0`, not a free buffer.
pub const SPREAD_BEST_EXEC_FLOOR_BPS: u16 = 100;

/// Closeout-handoff mark recency bound, in seconds (48h — mirrors on-chain `MAX_CLOSEOUT_NOVATION_WINDOW`).
pub const CLOSEOUT_NOVATION_MARK_MAX_AGE_SECS: u64 = 48 * 60 * 60;
