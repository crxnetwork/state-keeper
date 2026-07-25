# state-keeper

The public one-step keeper for the CRX state tree. One step per invocation, no loop, no operator.

```sh
cp .env.example .env      # RPC_URL, PRIVATE_KEY, NETWORK_PRIVATE_KEY
cargo build --release
./target/release/state-keeper rebuild --chain celo   # replay events → root; diff vs chain. Read-only.
./target/release/state-keeper advance --chain celo   # build one epoch, prove, submit applyState.
./target/release/state-keeper verify  --chain celo   # check committed artifacts vs on-chain pins.
```

Pins — vkey `0x005283d662917901042cc66534ede1c3ee827fb129293f70239d745485d85a8e`;
guest ELF `elf/scenario-es-program` sha256 `6068e927e1d962783b9b144efd36395ac013f65011e1a1ba567858e735b1ccaa`,
**never rebuilt here** (build.rs sha-guards it; reproduce with SP1 `cargo prove build --docker`, image v6.3.0);
`data/scenario-table.bin` must keccak to the on-chain `scenarioRoot` or the CLI refuses. Lane presets live in `chains.json`.

Rules — the Succinct Prover Network is the *only* prover, with your `NETWORK_PRIVATE_KEY`;
`applyState` is permissionless, signed with your `PRIVATE_KEY`; if another keeper lands first, the step rebases and retries.

Sync — any change to the guest framing, public-values layout, vkey, or scenario table lands here first; downstream bumps one pinned `rev`.

MIT.
