# state-keeper

The public one-step keeper for the CRX state tree — one step per invocation, no loop,
no operator backend.

```
state-keeper rebuild    replay chain events → tree → root; diff against the contract. Read-only.
state-keeper advance    build one epoch from chain-only inputs, prove it, submit applyState.
state-keeper verify     check the committed artifacts against the on-chain roots and pins.
```

Every fold input is on the chain: signed Terms (`TermsOpened` + `openLock` calldata),
fold public values (`applyState` calldata), proven prices (`TwapBound`), pause state
(`MarketSet`), and `data/scenario-table.bin`, keccak-anchored by the on-chain
`scenarioRoot`. `crx-tree` replays them through the vendored engine — the proven
guest's own pure functions — asserting every fold's committed roots; the final root
must equal `root()` on the lens.

`advance` executes the guest on CPU first, free, and spends nothing unless the
committed root moves and matches the host's prediction; proves on the Succinct Prover
Network with *your* `NETWORK_PRIVATE_KEY` — the network is the *only* prover, no local
or mock path; submits `applyState` signed with *your* `PRIVATE_KEY`. If another keeper
advances mid-flight, the step rebases and retries: the tree does not care who folds it.

```sh
cp .env.example .env      # RPC_URL, PRIVATE_KEY, NETWORK_PRIVATE_KEY
cargo build --release
./target/release/state-keeper rebuild --chain celo
```

Lane presets (chain id, core, lens, vkey pin, scenario root, deploy block) are
committed in `chains.json`; `rebuild` needs only an RPC.

`elf/scenario-es-program` is the proven guest ELF — sha256 `6068e927…ccaa`, vkey
`0x005283d6…5a8e` — **never rebuilt here**: build.rs sha-guards the bytes, the chain's
`imVkey()` is asserted before any prove, and the bytes reproduce with SP1's
`cargo prove build --docker`. `data/scenario-table.bin` is the scenario-ES table
(ES99/2d); the CLI refuses to run unless its keccak equals the on-chain `scenarioRoot`.
Any change to the guest framing, public-values layout, vkey, or scenario table lands
here first; downstream follows by bumping one pinned `rev`. MIT for the code; the
artifacts' integrity is enforced on-chain.
