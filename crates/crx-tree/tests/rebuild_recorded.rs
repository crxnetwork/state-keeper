//! Golden-root parity over RECORDED events — the rebuild, offline, no RPC. Fixtures
//! are verbatim Celo Sepolia calldata: two `openLock` txs and two `applyState` folds
//! carrying the live core from empty to `0x5ea8085a…`.
//!   fold 1  (block 31495775, tx 0xc7dddf95…): 0x00000000… → 0x9f437e02…
//!   fold 2  (block 31663509, tx 0x1b1707a8…): 0x9f437e02… → 0x5ea8085a…

use alloy::primitives::B256;
use alloy::sol;
use alloy::sol_types::SolCall;

use crx_tree::events::{terms_from_open_calldata, terms_rfq_id};
use crx_tree::pv::decode_public_values;
use crx_tree::replay::rebuild;
use crx_tree::scan::{ChainHistory, FoldRecord, OpenRecord};

sol! {
    function applyState(bytes proof, bytes publicValues);
}

fn hex_fixture(name: &str) -> Vec<u8> {
    let raw = match name {
        "open-1" => include_str!("fixtures/celo/open-1-calldata.hex"),
        "open-2" => include_str!("fixtures/celo/open-2-calldata.hex"),
        "fold-1" => include_str!("fixtures/celo/fold-1-calldata.hex"),
        "fold-2" => include_str!("fixtures/celo/fold-2-calldata.hex"),
        _ => unreachable!(),
    };
    hex::decode(raw.trim().trim_start_matches("0x")).expect("fixture is valid hex")
}

fn open_record(name: &str, block: u64) -> OpenRecord {
    let calldata = hex_fixture(name);
    let (terms, sig_a, sig_b) =
        terms_from_open_calldata(&calldata).expect("fixture decodes as openLock");
    let id = terms_rfq_id(&terms);
    OpenRecord { id, terms, sig_a, sig_b, block }
}

fn fold_record(name: &str, block: u64) -> FoldRecord {
    let calldata = hex_fixture(name);
    let call = applyStateCall::abi_decode(&calldata).expect("fixture decodes as applyState");
    let pv = decode_public_values(&call.publicValues).expect("public values decode");
    FoldRecord { block, tx: B256::ZERO, pv }
}

#[test]
fn recorded_celo_events_rebuild_to_the_committed_roots() {
    let history = ChainHistory {
        opens: vec![open_record("open-1", 31_493_003), open_record("open-2", 31_663_433)],
        folds: vec![fold_record("fold-1", 31_495_775), fold_record("fold-2", 31_663_509)],
        twaps: vec![],
        market_sets: vec![],
        head: 31_663_525,
    };

    let (table, table_root) = crx_tree::load_scenario_table(std::path::Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../data/scenario-table.bin"
    )))
    .expect("committed scenario table loads and validates");

    assert_eq!(
        hex::encode(table_root),
        "1d18b1716333c13da3f07d701ac91d1c77a544d889ab4845e4bd95d4ceb39cb1",
        "scenario-table artifact commits the owner-published root"
    );

    // `rebuild` asserts every fold's committed roots itself — a drift panics here.
    let state = rebuild(&history, &table).expect("replay reproduces every committed root");

    assert_eq!(state.accounts.len(), 3, "three accounts hold positions after fold 2");
    assert_eq!(
        hex::encode(state.root()),
        "5ea8085acbf3e966ea18487616778f0b6f718d4060e007c1e642164c2a1f9167",
        "the final root is the one the live core holds"
    );
    assert_eq!(
        hex::encode(state.accounts_root()),
        "9e2fd1ed9680345d29f80c239742f708f41caf164a52aa76998f6e6edb976070",
        "the final registry root matches the chain"
    );
}
