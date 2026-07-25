//! Broadcast `applyState(proof, publicValues)`. `eth_estimateGas` runs first — a lost
//! CAS race reverts there as `StaleRoot()` before a nonce is spent, and the caller
//! rebases. A mempool duplicate (`already known`) is SUCCESS: the tx will mine.

use alloy::network::EthereumWallet;
use alloy::primitives::{Address, Bytes};
use alloy::providers::ProviderBuilder;
use alloy::signers::local::PrivateKeySigner;
use anyhow::{anyhow, Result};
use std::str::FromStr;

use crate::chain::ICrxCore;

pub enum SubmitOutcome {
    /// Mined and succeeded; the tx hash.
    Mined(String),
    /// The chain root advanced under us — rebase and retry.
    StaleRoot,
}

fn is_already_known(msg: &str) -> bool {
    let l = msg.to_ascii_lowercase();
    l.contains("already known")
        || l.contains("alreadyknown")
        || l.contains("already imported")
        || l.contains("known transaction")
        || l.contains("transaction already in pool")
}

fn is_stale_root_revert(msg: &str) -> bool {
    let selector = hex::encode(&crx_tree::events::keccak256(&[b"StaleRoot()"])[..4]);
    let lower = msg.to_ascii_lowercase();
    lower.contains("staleroot") || lower.contains(&selector)
}

/// Sign and broadcast one `applyState`. Returns `StaleRoot` when the CAS target moved.
pub async fn submit_apply_state(
    rpc_url: &str,
    core_addr: Address,
    signer_key: &str,
    proof: Vec<u8>,
    public_values: Vec<u8>,
) -> Result<SubmitOutcome> {
    let signer = PrivateKeySigner::from_str(signer_key.trim_start_matches("0x"))
        .map_err(|e| anyhow!("bad PRIVATE_KEY: {e}"))?;
    let wallet = EthereumWallet::from(signer);
    let url: alloy::transports::http::reqwest::Url =
        rpc_url.parse().map_err(|e| anyhow!("bad RPC url: {e}"))?;
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(url);

    let contract = ICrxCore::new(core_addr, &provider);
    let call = contract.applyState(Bytes::from(proof), Bytes::from(public_values));

    if let Err(e) = call.estimate_gas().await {
        let msg = e.to_string();
        if is_stale_root_revert(&msg) {
            tracing::warn!("applyState estimate reverted StaleRoot — rebasing");
            return Ok(SubmitOutcome::StaleRoot);
        }
        return Err(anyhow!("estimate_gas: {msg}"));
    }

    let pending = match call.send().await {
        Ok(p) => p,
        Err(e) => {
            let msg = e.to_string();
            if is_already_known(&msg) {
                tracing::warn!("applyState already in the mempool — it will mine");
                return Ok(SubmitOutcome::Mined("already-known:tx-in-mempool".to_string()));
            }
            if is_stale_root_revert(&msg) {
                return Ok(SubmitOutcome::StaleRoot);
            }
            return Err(anyhow!("send applyState: {msg}"));
        }
    };

    let tx_hash = *pending.tx_hash();
    tracing::info!("applyState broadcast: {tx_hash:#x}");
    let receipt = pending.get_receipt().await.map_err(|e| anyhow!("await receipt: {e}"))?;
    if !receipt.status() {
        return Err(anyhow!(
            "applyState reverted in block {:?} (tx {tx_hash:#x})",
            receipt.block_number
        ));
    }
    Ok(SubmitOutcome::Mined(format!("{tx_hash:#x}")))
}
