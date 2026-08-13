//! Kernel ⇄ oracle equivalence: replay every pinned Phase-0c vector against `party_scenario_es`.
//!
//! The oracle (`crx-scenario-es-artifacts/oracle/oracle.py`) computes each vector twice — `exact` in
//! infinite-precision rationals and `twin` in the circuit's directed-rounding integer arithmetic — and pins
//! `expected_int = max(max(twin_ES, 0), Σ pushed_im)`. The kernel must reproduce `expected_int` EXACTLY on
//! all 29 vectors; a single wei of drift is a rounding-direction bug.
//!
//! Vector schema (all integers as decimal strings): `book` is a list of `{symbol, net}` signed 1e6-minor
//! nets (a repeated symbol nets again — stage-1); `table.columns` names the market columns, `table.rows`
//! lists sparse `(symbol, return_1e18)` entries; `fallback` is the adverse return parameter; `pushed_ims`
//! parallels `book`. Symbols map to `[u8; 32]` market keys by keccak — any injective map preserves the math.

use crxvm::{keccak, party_scenario_es, PositionRecord, ScenarioTable};
use serde_json::Value;

fn mk(symbol: &str) -> [u8; 32] {
    keccak(&[symbol.as_bytes()])
}

fn as_i128(v: &Value) -> i128 {
    v.as_str().expect("decimal string").parse::<i128>().expect("i128")
}

fn as_u128(v: &Value) -> u128 {
    v.as_str().expect("decimal string").parse::<u128>().expect("u128")
}

/// Build a `PositionRecord` carrying exactly a signed net (the oracle's book is already per-entry nets).
fn position(symbol: &str, net: i128, pushed_im: u128, seq: usize) -> PositionRecord {
    let mut terms_id = [0u8; 32];
    terms_id[..8].copy_from_slice(&(seq as u64).to_be_bytes());
    PositionRecord {
        terms_id,
        counterparty: [0xC0u8; 20],
        oracle: [0x0Eu8; 20],
        // i128::MIN nets are pinned by `max-notional-i128min`: unsigned_abs is the only sound |net|.
        notional: net.unsigned_abs(),
        entry_rate: 1_000_000,
        side: if net < 0 { -1 } else { 1 },
        expiry: 2_000_000_000,
        pushed_im,
        market_key: mk(symbol),
    }
}

fn table_from(v: &Value, k: u32, m: u32) -> ScenarioTable {
    let cols: Vec<String> = v["columns"]
        .as_array()
        .expect("columns")
        .iter()
        .map(|c| c.as_str().expect("symbol").to_string())
        .collect();
    let market_keys: Vec<[u8; 32]> = cols.iter().map(|c| mk(c)).collect();
    let col_of = |sym: &str| cols.iter().position(|c| c == sym).expect("row symbol must be a column") as u16;
    let rows: Vec<Vec<(u16, i128)>> = v["rows"]
        .as_array()
        .expect("rows")
        .iter()
        .map(|row| {
            let mut entries: Vec<(u16, i128)> = row
                .as_array()
                .expect("row")
                .iter()
                .map(|e| {
                    let e = e.as_array().expect("entry");
                    (col_of(e[0].as_str().expect("sym")), as_i128(&e[1]))
                })
                .collect();
            entries.sort_by_key(|&(c, _)| c);
            entries
        })
        .collect();
    ScenarioTable { version: 1, k, m, market_keys, rows }
}

#[test]
fn phase0c_oracle_vectors_all_pass() {
    let raw = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/phase0c-vectors.json"),
    )
    .expect("tests/fixtures/phase0c-vectors.json (copied from crx-scenario-es-artifacts/oracle)");
    let doc: Value = serde_json::from_str(&raw).expect("valid json");
    let vectors = doc["vectors"].as_array().expect("vectors");
    assert!(vectors.len() >= 32, "the Phase-0c m-explicit-v2 set carries 32 pinned vectors");
    assert!(
        vectors.iter().any(|v| v["name"] == "m-convention-divergence-pin-m28-not-1"),
        "the m-convention divergence pin must be present — it is the vector that fails a ceil(K/100) kernel"
    );

    let mut failures: Vec<String> = Vec::new();
    for vec in vectors {
        let name = vec["name"].as_str().expect("name");
        let k = vec["k"].as_u64().expect("k") as u32;
        // The tail count is CARRIED PER VECTOR (spec correction: m ships with the table, never derived
        // from K — the published set is tail-enriched by set-cover reduction).
        let m = vec["m"].as_u64().expect("m") as u32;
        let fallback = as_i128(&vec["fallback"]);
        let table = table_from(&vec["table"], k, m);
        table.validate();

        let book = vec["book"].as_array().expect("book");
        let pushed: Vec<u128> = vec["pushed_ims"].as_array().expect("pushed_ims").iter().map(as_u128).collect();
        assert_eq!(book.len(), pushed.len(), "{name}: pushed_ims parallels book");
        let positions: Vec<PositionRecord> = book
            .iter()
            .zip(pushed.iter())
            .enumerate()
            .map(|(i, (entry, pi))| position(entry["symbol"].as_str().expect("symbol"), as_i128(&entry["net"]), *pi, i))
            .collect();

        // expected_int already folds the clamp AND the seat floor: max(max(ES, 0), Σ pushed_im).
        let seat_floor: u128 = pushed.iter().fold(0u128, |a, p| a.checked_add(*p).expect("seat floor sum"));
        let got = party_scenario_es(&positions, &table, fallback).max(seat_floor);
        let expected = as_u128(&vec["expected_int"]);
        if got != expected {
            failures.push(format!("{name}: kernel={got} expected={expected}"));
        }
    }
    assert!(
        failures.is_empty(),
        "kernel diverged from the exact-rational oracle on {} of {} vectors:\n{}",
        failures.len(),
        vectors.len(),
        failures.join("\n")
    );
}

/// Every vector's tail count must be a VALID table field (0 < m ≤ k) — the kernel takes m from the table.
#[test]
fn phase0c_vector_m_is_a_valid_tail_count() {
    let raw = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/phase0c-vectors.json"),
    )
    .expect("fixture");
    let doc: Value = serde_json::from_str(&raw).expect("valid json");
    for vec in doc["vectors"].as_array().expect("vectors") {
        let k = vec["k"].as_u64().expect("k");
        let m = vec["m"].as_u64().expect("m");
        assert!(m > 0 && m <= k, "{}: 0 < m <= k", vec["name"]);
    }
}
