//! Lane presets and the on-chain read/write surface.

use alloy::primitives::Address;
use alloy::providers::Provider;
use alloy::sol;
use anyhow::{anyhow, Context, Result};
use serde::Deserialize;

sol! {
    #[sol(rpc)]
    interface ICrxLens {
        function root() external view returns (bytes32);
        function rootAt() external view returns (uint64);
        function accountsRoot() external view returns (bytes32);
        function scenarioRoot() external view returns (bytes32);
    }

    #[sol(rpc)]
    interface ICrxCore {
        function applyState(bytes proof, bytes publicValues) external;
        function DOMAIN() external view returns (bytes32);
        function imVkey() external view returns (bytes32);
        error StaleRoot();
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Lane {
    pub name: String,
    pub chain_id: u64,
    pub core: String,
    pub lens: String,
    pub deploy_block: u64,
    /// The vkey the core must answer on `imVkey()`.
    pub vkey: String,
    /// The owner-published commitment the committed table must reproduce.
    pub scenario_root: String,
    /// `RPC_URL` overrides it.
    pub rpc_url: String,
}

#[derive(Debug, Deserialize)]
struct ChainsFile {
    lanes: Vec<Lane>,
}

/// Lane preset by name from `chains.json` (searched upward from cwd).
pub fn load_lane(name: &str) -> Result<Lane> {
    let candidates = ["chains.json", "../chains.json", "../../chains.json"];
    let raw = candidates
        .iter()
        .find_map(|p| std::fs::read_to_string(p).ok())
        .ok_or_else(|| anyhow!("chains.json not found — run from the repository root"))?;
    let file: ChainsFile = serde_json::from_str(&raw).context("parse chains.json")?;
    file.lanes
        .into_iter()
        .find(|l| l.name == name)
        .ok_or_else(|| anyhow!("no lane named '{name}' in chains.json"))
}

pub fn parse_addr(s: &str) -> Result<Address> {
    s.parse().map_err(|e| anyhow!("bad address {s}: {e}"))
}

pub fn parse_b32(s: &str) -> Result<[u8; 32]> {
    let h = s.trim_start_matches("0x");
    let v = hex::decode(h).map_err(|e| anyhow!("bad bytes32 {s}: {e}"))?;
    v.try_into().map_err(|_| anyhow!("bytes32 {s}: wrong length"))
}

/// Chain truth, read through the lens (the core reverts the getters).
pub struct ChainState {
    pub root: [u8; 32],
    pub root_at: u64,
    pub accounts_root: [u8; 32],
    pub scenario_root: [u8; 32],
    pub domain: [u8; 32],
    pub vkey: [u8; 32],
}

pub async fn read_chain<P: Provider>(provider: &P, lane: &Lane) -> Result<ChainState> {
    let lens = ICrxLens::new(parse_addr(&lane.lens)?, provider);
    let core = ICrxCore::new(parse_addr(&lane.core)?, provider);
    Ok(ChainState {
        root: lens.root().call().await.context("lens.root()")?.0,
        root_at: lens.rootAt().call().await.context("lens.rootAt()")?,
        accounts_root: lens.accountsRoot().call().await.context("lens.accountsRoot()")?.0,
        scenario_root: lens.scenarioRoot().call().await.context("lens.scenarioRoot()")?.0,
        domain: core.DOMAIN().call().await.context("core.DOMAIN()")?.0,
        vkey: core.imVkey().call().await.context("core.imVkey()")?.0,
    })
}
