//! The SP1 surface: network Groth16 prove + free CPU execute of the vendored guest ELF.
//!
//! The ELF is the proven artifact (`elf/scenario-es-program`, sha256 `6068e927…ccaa`,
//! vkey `0x005283d6…5a8e`) baked in at compile time; `build.rs` refuses any drifted bytes.

use sp1_sdk::{
    blocking::{ProveRequest, Prover, ProverClient},
    include_elf, HashableKey, ProvingKey, SP1Stdin,
};

/// The scenario-ES state guest ELF, byte-guarded by build.rs.
const ELF: sp1_sdk::Elf = include_elf!("scenario-es-program");

fn stdin_from_frames(frames: &[Vec<u8>]) -> SP1Stdin {
    let mut stdin = SP1Stdin::new();
    for f in frames {
        stdin.write_slice(f);
    }
    stdin
}

/// The vkey of the embedded ELF, as the chain's bytes32 hex string.
pub fn embedded_vkey() -> anyhow::Result<String> {
    let client = ProverClient::builder().cpu().build();
    let pk = client.setup(ELF).map_err(|e| anyhow::anyhow!("setup: {e}"))?;
    Ok(pk.verifying_key().bytes32())
}

/// FREE CPU execute — runs the identical guest on the identical stdin and returns the
/// committed public values. `root_new` here is byte-identical to what a prove would
/// commit, so the caller can decide whether proving is worth a fee.
pub fn execute(frames: &[Vec<u8>]) -> anyhow::Result<Vec<u8>> {
    let client = ProverClient::builder().cpu().build();
    let (public_values, _report) = client
        .execute(ELF, stdin_from_frames(frames))
        .calculate_gas(false)
        .run()
        .map_err(|e| anyhow::anyhow!("guest execute failed: {e}"))?;
    Ok(public_values.as_slice().to_vec())
}

/// Groth16 prove on the Succinct Prover Network — the ONLY prover this binary knows.
/// There is no local proving path: `mock`, `cpu`, `cuda`, or any other `SP1_PROVER`
/// value is refused outright. Requires `NETWORK_PRIVATE_KEY` (a funded requester key).
/// Returns `(proof_bytes, public_values)` — exactly the two `bytes` arguments
/// `applyState` takes.
pub fn prove_network(frames: &[Vec<u8>]) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    if let Ok(mode) = std::env::var("SP1_PROVER") {
        if mode != "network" {
            anyhow::bail!(
                "SP1_PROVER={mode} is not permitted — the Succinct Prover Network is the only \
                 prover here. Unset SP1_PROVER or set SP1_PROVER=network."
            );
        }
    }
    if std::env::var("NETWORK_PRIVATE_KEY").map(|v| v.trim().is_empty()).unwrap_or(true) {
        anyhow::bail!(
            "NETWORK_PRIVATE_KEY is not set — network proving needs a funded Succinct \
             requester key (https://docs.succinct.xyz/)"
        );
    }
    std::env::set_var("SP1_PROVER", "network");

    let client = ProverClient::from_env();
    let pk = client.setup(ELF).map_err(|e| anyhow::anyhow!("setup: {e}"))?;
    let vk = pk.verifying_key();
    eprintln!("prover vkey: {}", vk.bytes32());

    let proof = client
        .prove(&pk, stdin_from_frames(frames))
        .groth16()
        .run()
        .map_err(|e| anyhow::anyhow!("groth16 prove failed: {e}"))?;

    let proof_bytes = proof.bytes();
    let public_values = proof.public_values.as_slice().to_vec();

    // Best-effort local verify — the on-chain SP1 verifier is the authoritative gate.
    match client.verify(&proof, vk, None) {
        Ok(()) => eprintln!("local verify: OK"),
        Err(e) => eprintln!("local verify: NON-FATAL failure ({e})"),
    }
    Ok((proof_bytes, public_values))
}
