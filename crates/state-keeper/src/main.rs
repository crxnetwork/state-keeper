//! state-keeper — the public one-step keeper: `rebuild` / `advance` / `verify`, one step per
//! invocation, no loop. Secrets arrive ONLY via the environment (`.env` + `chains.json`).

#![forbid(unsafe_code)]
#![deny(clippy::arithmetic_side_effects)]

mod chain;
mod gate;
mod submit;

use alloy::providers::{Provider, ProviderBuilder};
use anyhow::{anyhow, bail, Context, Result};
use crx_tree::replay::{EpochInputs, TreeState};
use crx_tree::scan::ChainHistory;
use crxvm as sr;
use im_types as st;

use chain::{load_lane, parse_addr, parse_b32, read_chain, Lane};

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn env_nonempty(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.trim().is_empty())
}

/// Load `.env` (simple KEY=VALUE, `#` comments). Existing env vars win.
fn load_dotenv() {
    let Ok(raw) = std::fs::read_to_string(".env") else { return };
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            let (k, v) = (k.trim(), v.trim().trim_matches('"'));
            if std::env::var_os(k).is_none() {
                std::env::set_var(k, v);
            }
        }
    }
}

struct Ctx {
    lane: Lane,
    rpc_url: String,
    table: sr::ScenarioTable,
    table_root: [u8; 32],
}

fn build_ctx(chain_name: &str) -> Result<Ctx> {
    let lane = load_lane(chain_name)?;
    let rpc_url = env_nonempty("RPC_URL").unwrap_or_else(|| lane.rpc_url.clone());
    let table_path = std::path::Path::new("data/scenario-table.bin");
    let (table, table_root) = crx_tree::load_scenario_table(table_path)?;
    let expect = parse_b32(&lane.scenario_root)?;
    if table_root != expect {
        return Err(gate::Gate::TableArtifactNotThisGeneration {
            local: hex::encode(table_root),
            pinned: hex::encode(expect),
        }
        .into());
    }
    Ok(Ctx { lane, rpc_url, table, table_root })
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter(
        tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| "info".into()),
    ).init();
    load_dotenv();

    let mut args = std::env::args().skip(1);
    let verb = args.next().unwrap_or_default();
    let mut chain_name = "celo".to_string();
    let mut rest = args.peekable();
    while let Some(a) = rest.next() {
        if a == "--chain" {
            chain_name = rest.next().ok_or_else(|| anyhow!("--chain needs a name"))?;
        }
    }

    match verb.as_str() {
        "rebuild" => cmd_rebuild(&chain_name).await,
        "advance" => cmd_advance(&chain_name).await,
        "verify" => cmd_verify(&chain_name).await,
        _ => {
            eprintln!("usage: state-keeper <rebuild|advance|verify> [--chain <name>]");
            std::process::exit(2);
        }
    }
}

async fn scan_and_rebuild(
    ctx: &Ctx,
    provider: &impl Provider,
) -> Result<(ChainHistory, TreeState)> {
    let core = parse_addr(&ctx.lane.core)?;
    let history = crx_tree::scan::scan(provider, core, ctx.lane.deploy_block).await?;
    tracing::info!(
        "scanned to block {}: {} opens, {} folds, {} bound prices, {} market flips",
        history.head,
        history.opens.len(),
        history.folds.len(),
        history.twaps.len(),
        history.market_sets.len()
    );
    let state = crx_tree::replay::rebuild(&history, &ctx.table)?;
    Ok((history, state))
}

async fn cmd_rebuild(chain_name: &str) -> Result<()> {
    let ctx = build_ctx(chain_name)?;
    let provider = ProviderBuilder::new().connect_http(ctx.rpc_url.parse()?);
    let chain = read_chain(&provider, &ctx.lane).await?;

    let (_history, state) = scan_and_rebuild(&ctx, &provider).await?;
    let root = state.root();
    let accounts_root = state.accounts_root();

    println!("accounts rebuilt:      {}", state.accounts.len());
    println!("rebuilt root:          0x{}", hex::encode(root));
    println!("on-chain root:         0x{}", hex::encode(chain.root));
    println!("rebuilt accountsRoot:  0x{}", hex::encode(accounts_root));
    println!("on-chain accountsRoot: 0x{}", hex::encode(chain.accounts_root));
    println!("scenario table root:   0x{}", hex::encode(ctx.table_root));
    println!("on-chain scenarioRoot: 0x{}", hex::encode(chain.scenario_root));

    if root != chain.root {
        return Err(gate::Gate::RebuildRootMismatch.into());
    }
    if accounts_root != chain.accounts_root {
        return Err(gate::Gate::RebuildRegistryMismatch.into());
    }
    if ctx.table_root != chain.scenario_root {
        return Err(gate::Gate::RebuildScenarioRootMismatch.into());
    }
    println!("MATCH — the tree the contract holds is exactly the fold of its own events.");
    Ok(())
}

async fn cmd_verify(chain_name: &str) -> Result<()> {
    let ctx = build_ctx(chain_name)?;
    let provider = ProviderBuilder::new().connect_http(ctx.rpc_url.parse()?);
    let chain = read_chain(&provider, &ctx.lane).await?;

    println!("lane:                  {} (chain id {})", ctx.lane.name, ctx.lane.chain_id);
    println!("core:                  {}", ctx.lane.core);
    println!("on-chain root:         0x{}", hex::encode(chain.root));
    println!("root advanced at:      {} (unix)", chain.root_at);
    println!("on-chain accountsRoot: 0x{}", hex::encode(chain.accounts_root));
    println!("on-chain scenarioRoot: 0x{}", hex::encode(chain.scenario_root));
    println!("on-chain imVkey:       0x{}", hex::encode(chain.vkey));
    println!("pinned vkey:           {}", ctx.lane.vkey);
    println!("local table root:      0x{}", hex::encode(ctx.table_root));

    let pinned = parse_b32(&ctx.lane.vkey)?;
    if chain.vkey != pinned {
        return Err(gate::Gate::VerifyVkeyDrift.into());
    }
    if ctx.table_root != chain.scenario_root {
        return Err(gate::Gate::VerifyScenarioRootDrift.into());
    }
    println!("OK — vkey and scenario root both match the pins.");
    Ok(())
}

/// The next epoch's chain-only inputs: unfolded opens, fresh bound marks, due settle prices, the pause set.
fn fresh_epoch_inputs(
    history: &ChainHistory,
    state: &TreeState,
    domain: [u8; 32],
    now: u64,
) -> Result<EpochInputs> {
    let new_positions = history
        .unfolded_opens()
        .into_iter()
        .map(|o| crx_tree::replay::open_to_new_position(o, domain))
        .collect::<Result<Vec<_>>>()?;

    // Latest bound price per feed, FRESH as an hourly mark at `now`.
    use std::collections::BTreeMap;
    let mut latest: BTreeMap<[u8; 32], &crx_tree::scan::TwapBoundRecord> = BTreeMap::new();
    for t in &history.twaps {
        let e = latest.entry(t.feed_id).or_insert(t);
        if t.close_time > e.close_time {
            *e = t;
        }
    }
    let proven_marks: Vec<st::ProvenMark> = latest
        .values()
        .filter(|t| sr::mark_fresh(t.close_time, now) && t.twap >= 0)
        .map(|t| st::ProvenMark {
            feed_id: t.feed_id,
            mark_time: t.close_time,
            price: t.twap as u128,
            expo: t.expo,
        })
        .collect();

    // Settle prices: bound prices whose close_time equals an open position's expiry.
    let expiries: std::collections::BTreeSet<(u64, [u8; 20])> = state
        .accounts
        .values()
        .flat_map(|a| a.positions.iter().map(|p| (p.expiry, p.oracle)))
        .collect();
    let proven_twaps: Vec<st::ProvenTwap> = history
        .twaps
        .iter()
        .filter(|t| {
            t.twap >= 0 && expiries.contains(&(t.close_time, sr::feed_id_oracle(&t.feed_id)))
        })
        .map(|t| st::ProvenTwap {
            feed_id: t.feed_id,
            close_time: t.close_time,
            settle_price: t.twap as u128,
            expo: t.expo,
        })
        .collect();

    Ok(EpochInputs {
        new_positions,
        proven_marks,
        proven_twaps,
        paused_pairs: history.paused_pairs_at(u64::MAX),
        proof_now: now,
        domain_separator: domain,
    })
}

async fn cmd_advance(chain_name: &str) -> Result<()> {
    let ctx = build_ctx(chain_name)?;
    let signer_key = env_nonempty("PRIVATE_KEY").ok_or(gate::Gate::PrivateKeyUnset)?;
    let provider = ProviderBuilder::new().connect_http(ctx.rpc_url.parse()?);
    let core_addr = parse_addr(&ctx.lane.core)?;

    const MAX_REBASE: u32 = 3;
    for attempt in 1..=MAX_REBASE {
        let chain = read_chain(&provider, &ctx.lane).await?;
        let pinned_vkey = parse_b32(&ctx.lane.vkey)?;
        if chain.vkey != pinned_vkey {
            return Err(gate::Gate::AdvanceWrongGeneration {
                chain: hex::encode(chain.vkey),
                pinned: ctx.lane.vkey.clone(),
            }
            .into());
        }
        if ctx.table_root != chain.scenario_root {
            return Err(gate::Gate::AdvanceScenarioRootDrift.into());
        }

        let (history, state) = scan_and_rebuild(&ctx, &provider).await?;
        let root = state.root();
        if root != chain.root {
            // The chain may have advanced between the read and the scan — rescan.
            tracing::warn!(
                "rebuilt root 0x{} != chain root 0x{} (attempt {attempt}) — rescanning",
                hex::encode(root),
                hex::encode(chain.root)
            );
            continue;
        }

        let now = now_secs();
        let inputs = fresh_epoch_inputs(&history, &state, chain.domain, now)?;
        tracing::info!(
            "epoch inputs: {} new position(s), {} mark(s), {} settle price(s), {} paused pair(s)",
            inputs.new_positions.len(),
            inputs.proven_marks.len(),
            inputs.proven_twaps.len(),
            inputs.paused_pairs.len()
        );

        let adv = crx_tree::frames::build_advance_frames(&state, &inputs, &ctx.table, chain.accounts_root)?;
        if adv.predicted_root == adv.root_prev {
            println!(
                "nothing to advance: the fold would commit the same root 0x{} — no unfolded opens, \
                 no fresh marks, no due settlements. Exiting without proving.",
                hex::encode(adv.root_prev)
            );
            return Ok(());
        }
        println!("advance: 0x{} → 0x{}", hex::encode(adv.root_prev), hex::encode(adv.predicted_root));

        // FREE equivalence gate: CPU-execute the identical guest on the identical
        // stdin; the committed root must equal the prediction BEFORE any fee is spent.
        println!("executing the guest on CPU (free equivalence gate)…");
        let frames = adv.frames.clone();
        let pv_exec = tokio::task::spawn_blocking(move || prove_exec::execute(&frames))
            .await
            .context("join execute")??;
        let decoded = crx_tree::pv::decode_public_values(&pv_exec)?;
        if decoded.roots.root_new != adv.predicted_root {
            bail!(
                "guest execute committed root 0x{} but the host predicted 0x{} — refusing to prove",
                hex::encode(decoded.roots.root_new),
                hex::encode(adv.predicted_root)
            );
        }
        println!("execute OK: guest commits root_new 0x{}", hex::encode(decoded.roots.root_new));
        println!("scenario root committed by the guest: 0x{}", hex::encode(decoded.scenario_root));

        println!("proving (Groth16, Succinct Prover Network)…");
        let frames = adv.frames.clone();
        let (proof_bytes, public_values) =
            tokio::task::spawn_blocking(move || prove_exec::prove_network(&frames))
                .await
                .context("join prove")??;
        println!("proof: {} bytes; public values: {} bytes", proof_bytes.len(), public_values.len());

        // If another keeper advanced while we proved, the CAS target is stale — rebase.
        let fresh = read_chain(&provider, &ctx.lane).await?;
        if fresh.root != adv.root_prev {
            tracing::warn!(
                "root moved while proving (0x{} → 0x{}) — rebasing (attempt {attempt}/{MAX_REBASE})",
                hex::encode(adv.root_prev),
                hex::encode(fresh.root)
            );
            continue;
        }

        match submit::submit_apply_state(
            &ctx.rpc_url,
            core_addr,
            &signer_key,
            proof_bytes,
            public_values,
        )
        .await?
        {
            submit::SubmitOutcome::Mined(tx) => {
                let after = read_chain(&provider, &ctx.lane).await?;
                println!("applyState accepted: {tx}");
                println!("root before: 0x{}", hex::encode(adv.root_prev));
                println!("root after:  0x{}", hex::encode(after.root));
                if after.root != adv.predicted_root {
                    tracing::warn!("the on-chain root differs from this proof's advance — another fold may have landed after ours");
                }
                return Ok(());
            }
            submit::SubmitOutcome::StaleRoot => {
                tracing::warn!("StaleRoot at submit — rebasing (attempt {attempt}/{MAX_REBASE})");
                continue;
            }
        }
    }
    bail!("gave up after {MAX_REBASE} rebase attempts — the lane is advancing faster than this step")
}
