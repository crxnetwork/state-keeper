//! Chain scan: every load-bearing event from `deploy_block` to head, enriched with the
//! `applyState` and `openLock` calldata.

use alloy::consensus::Transaction as _;
use alloy::eips::BlockNumberOrTag;
use alloy::primitives::{Address, B256};
use alloy::providers::Provider;
use alloy::rpc::types::{Filter, Log};
use alloy::sol;
use alloy::sol_types::{SolCall, SolEvent};
use anyhow::{anyhow, bail, Context, Result};

use crate::events::{self, terms_from_open_calldata, terms_from_opened_log, OpenLockTerms, Topics};
use crate::pv::{decode_public_values, DecodedPv};

sol! {
    function applyState(bytes proof, bytes publicValues);
}

/// One open. `id` is re-derived and asserted equal to the event's — the decode authenticates itself.
#[derive(Clone)]
pub struct OpenRecord {
    pub id: [u8; 32],
    pub terms: OpenLockTerms,
    pub sig_a: Vec<u8>,
    pub sig_b: Vec<u8>,
    pub block: u64,
}

#[derive(Clone)]
pub struct FoldRecord {
    pub block: u64,
    pub tx: B256,
    pub pv: DecodedPv,
}

#[derive(Clone, Copy)]
pub struct TwapBoundRecord {
    pub feed_id: [u8; 32],
    pub close_time: u64,
    pub twap: i64,
    pub expo: i32,
    pub block: u64,
}

#[derive(Clone, Copy)]
pub struct MarketSetRecord {
    pub block: u64,
    pub log_index: u64,
    pub instrument: u8,
    pub pair_tag: [u8; 32],
    pub enabled: bool,
    pub paused: bool,
}

/// Everything the rebuild consumes, in chain order.
pub struct ChainHistory {
    pub opens: Vec<OpenRecord>,
    pub folds: Vec<FoldRecord>,
    pub twaps: Vec<TwapBoundRecord>,
    pub market_sets: Vec<MarketSetRecord>,
    pub head: u64,
}

impl ChainHistory {
    /// Paused pairTags as of `block` (inclusive), replayed from `MarketSet` history.
    /// enforced by: paused_pairs_replays_last_write_and_answers_sorted
    pub fn paused_pairs_at(&self, block: u64) -> Vec<[u8; 32]> {
        use std::collections::BTreeMap;
        let mut state: BTreeMap<[u8; 32], bool> = BTreeMap::new();
        for m in self.market_sets.iter().filter(|m| m.block <= block) {
            state.insert(m.pair_tag, m.enabled && m.paused);
        }
        state.into_iter().filter_map(|(tag, paused)| paused.then_some(tag)).collect()
    }

    /// Opens no fold has consumed yet — the next epoch's `new_positions`.
    pub fn unfolded_opens(&self) -> Vec<&OpenRecord> {
        let folded: std::collections::BTreeSet<[u8; 32]> = self
            .folds
            .iter()
            .flat_map(|f| f.pv.opened_position_ids.iter().copied())
            .collect();
        self.opens.iter().filter(|o| !folded.contains(&o.id)).collect()
    }
}

/// Max block span per `eth_getLogs` (public endpoints commonly cap at 100k).
const LOG_CHUNK: u64 = 90_000;

pub async fn scan<P: Provider>(provider: &P, core: Address, deploy_block: u64) -> Result<ChainHistory> {
    let head = provider.get_block_number().await.context("get_block_number")?;
    let topics = Topics::new();

    let mut logs: Vec<Log> = Vec::new();
    let mut lo = deploy_block;
    while lo <= head {
        let hi = lo.saturating_add(LOG_CHUNK - 1).min(head);
        let filter = Filter::new()
            .address(core)
            .from_block(BlockNumberOrTag::Number(lo))
            .to_block(BlockNumberOrTag::Number(hi))
            .event_signature(topics.as_filter_topics());
        let chunk = provider
            .get_logs(&filter)
            .await
            .with_context(|| format!("get_logs [{lo}, {hi}]"))?;
        logs.extend(chunk);
        let Some(next) = hi.checked_add(1) else { break };
        lo = next;
    }
    logs.sort_by_key(|l| (l.block_number.unwrap_or(0), l.log_index.unwrap_or(0)));

    let mut opens: Vec<OpenRecord> = Vec::new();
    let mut folds: Vec<FoldRecord> = Vec::new();
    let mut twaps: Vec<TwapBoundRecord> = Vec::new();
    let mut market_sets: Vec<MarketSetRecord> = Vec::new();

    for log in &logs {
        let Some(t0) = log.topics().first().copied() else { continue };
        let block = log.block_number.unwrap_or(0);

        if t0 == topics.terms_opened {
            let (id, terms) = terms_from_opened_log(log)
                .ok_or_else(|| anyhow!("TermsOpened decode failed at block {block}"))?;
            let derived = events::terms_rfq_id(&terms);
            if derived != id {
                bail!(
                    "TermsOpened id mismatch at block {block}: event 0x{}, recomputed 0x{} — refusing",
                    hex::encode(id),
                    hex::encode(derived)
                );
            }
            let tx_hash = log.transaction_hash.ok_or_else(|| anyhow!("TermsOpened log without tx"))?;
            let (sig_a, sig_b) = open_sigs(provider, tx_hash, id).await?;
            opens.push(OpenRecord { id, terms, sig_a, sig_b, block });
        } else if t0 == topics.root_advanced {
            let tx_hash = log.transaction_hash.ok_or_else(|| anyhow!("RootAdvanced log without tx"))?;
            let tx = provider
                .get_transaction_by_hash(tx_hash)
                .await
                .context("get_transaction_by_hash")?
                .ok_or_else(|| anyhow!("fold tx {tx_hash} not found"))?;
            let input = tx.inner.input();
            let call = applyStateCall::abi_decode(input)
                .map_err(|e| anyhow!("fold tx {tx_hash} is not applyState calldata: {e}"))?;
            let pv = decode_public_values(&call.publicValues)
                .with_context(|| format!("decode public values of fold {tx_hash}"))?;
            folds.push(FoldRecord { block, tx: tx_hash, pv });
        } else if t0 == topics.twap_bound {
            let ev = events::TwapBound::decode_log(&log.inner)
                .map_err(|e| anyhow!("TwapBound decode at block {block}: {e}"))?;
            twaps.push(TwapBoundRecord {
                feed_id: ev.feedId.0,
                close_time: ev.closeTime,
                twap: ev.data.twap,
                expo: ev.data.expo,
                block,
            });
        } else if t0 == topics.market_set {
            let ev = events::MarketSet::decode_log(&log.inner)
                .map_err(|e| anyhow!("MarketSet decode at block {block}: {e}"))?;
            market_sets.push(MarketSetRecord {
                block,
                log_index: log.log_index.unwrap_or(0),
                instrument: ev.instrument,
                pair_tag: ev.pairTag.0,
                enabled: ev.data.enabled,
                paused: ev.data.paused,
            });
        }
        // `Bound` rides in the same tx as `TermsOpened`, which is the richer record.
    }

    Ok(ChainHistory { opens, folds, twaps, market_sets, head })
}

/// Recover the two 65-byte sigs from the open's calldata: top-level `openLock` first,
/// else a wrapped open (e.g. Safe) is scanned for the embedded selector.
async fn open_sigs<P: Provider>(
    provider: &P,
    tx_hash: B256,
    expect_id: [u8; 32],
) -> Result<(Vec<u8>, Vec<u8>)> {
    let tx = provider
        .get_transaction_by_hash(tx_hash)
        .await
        .context("get_transaction_by_hash")?
        .ok_or_else(|| anyhow!("open tx {tx_hash} not found"))?;
    let input = tx.inner.input().to_vec();

    if let Some((t, sig_a, sig_b)) = terms_from_open_calldata(&input) {
        if events::terms_rfq_id(&t) == expect_id {
            return Ok((sig_a, sig_b));
        }
    }
    let selector = crate::events::openLockCall::SELECTOR;
    for (at, window) in input.windows(4).enumerate() {
        if window == selector {
            if let Some((t, sig_a, sig_b)) = terms_from_open_calldata(&input[at..]) {
                if events::terms_rfq_id(&t) == expect_id {
                    return Ok((sig_a, sig_b));
                }
            }
        }
    }
    bail!(
        "open tx {tx_hash}: could not recover openLock signatures for id 0x{} from calldata",
        hex::encode(expect_id)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(block: u64, tag: u8, enabled: bool, paused: bool) -> MarketSetRecord {
        MarketSetRecord { block, log_index: 0, instrument: 1, pair_tag: [tag; 32], enabled, paused }
    }

    #[test]
    fn paused_pairs_replays_last_write_and_answers_sorted() {
        let h = ChainHistory {
            opens: vec![],
            folds: vec![],
            twaps: vec![],
            market_sets: vec![
                set(10, 2, true, true),  // paused at 10
                set(11, 1, true, true),  // paused at 11
                set(12, 2, true, false), // unpaused at 12 — last write wins
                set(13, 3, false, true), // paused but disabled — never counts
                set(14, 4, true, true),  // beyond a block-13 cutoff — invisible there
            ],
            head: 20,
        };
        assert_eq!(h.paused_pairs_at(11), vec![[1u8; 32], [2u8; 32]], "sorted by tag");
        assert_eq!(h.paused_pairs_at(13), vec![[1u8; 32]], "unpause and disable both clear");
        assert_eq!(h.paused_pairs_at(20), vec![[1u8; 32], [4u8; 32]], "later pause appears");
    }
}
