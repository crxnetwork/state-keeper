# state-keeper

The public one-step keeper for the CRX state tree.

Every position lifecycle — IM, VM, novation, open, close, netting, closeout — advances
at the same time, in one SP1 computation. Anyone can rebuild the tree from on-chain
information, call a settlement, and the zk-SNARK proof verifies on-chain. This
repository is that claim, executable.

```
state-keeper rebuild    replay chain events → tree → root; diff against the contract. Read-only.
state-keeper advance    build one epoch from chain-only inputs, prove it, submit applyState. Then exit.
state-keeper verify     read the on-chain roots and pins; check the committed artifacts against them.
```

One step per invocation. No loop, no supervisor, no operator backend.

## How the rebuild works

The tree is key-addressed — one leaf per account, committing only
`{account, vm_equity, positions_root}`. Everything a fold ever consumed is on the
chain itself:

| Input | Where the chain holds it |
|---|---|
| The signed Terms of every open | `TermsOpened` event + `openLock` calldata (both signatures) |
| Every fold's decoded inputs | `applyState` calldata — the committed public values |
| Every proven settle/mark price | `TwapBound` events (the write-once `boundTwap` rail) |
| Pause state | `MarketSet` events |
| The margin model | `data/scenario-table.bin`, keccak-anchored by the on-chain `scenarioRoot` |

`crx-tree` replays those inputs through the **vendored engine** — the same pure
functions the proven guest ELF runs — and asserts, fold by fold, that the recomputed
roots equal each fold's committed roots. The final root must equal `root()` on the
lens, or the command fails loudly.

## How the advance works

`advance` rebuilds the tree, gathers what the chain holds unfolded (new opens, fresh
bound marks, due settlements), assembles the guest's 13-frame stdin, and then:

1. **executes the guest on CPU** — free — and refuses to spend anything unless the
   committed root moves and matches the host's own prediction;
2. **proves on the Succinct Prover Network** with *your* `NETWORK_PRIVATE_KEY`;
3. **submits `applyState(proof, publicValues)`** signed with *your* `PRIVATE_KEY`.

If another keeper advances the root mid-flight, the step detects it (a `StaleRoot`
revert or a moved root), rebases onto the new chain state, and retries. That contention
is by design: the tree does not care who folds it.

## Setup

```sh
cp .env.example .env      # RPC_URL, PRIVATE_KEY, NETWORK_PRIVATE_KEY
cargo build --release
./target/release/state-keeper rebuild --chain celo
```

Lane presets (chain id, core, lens, vkey pin, scenario root, deploy block) are
committed in `chains.json`. `rebuild` needs nothing but an RPC.

## The artifacts

- `elf/scenario-es-program` — the proven guest ELF, vendored byte-for-byte
  (sha256 `6068e927…ccaa`, vkey `0x005283d6…5a8e`). It is **never rebuilt here**: the
  build script sha-guards the bytes, and the chain's `imVkey()` is asserted before any
  prove. Reproducible independently with SP1's `cargo prove build --docker` on the
  pinned guest source.
- `data/scenario-table.bin` — the published scenario-ES table (ES99/2d). The CLI
  recomputes its keccak commitment and refuses to run unless it equals the
  owner-published on-chain `scenarioRoot` — a mismatched table cannot advance, so
  publication is integrity-safe.

## The sync rule

This repository is the heart; the private fleet keeper is the pulse. Any change to the
guest framing, the public-values layout, the vkey, or the scenario table lands **here
first**; downstream consumers follow by bumping a single pinned `rev`. No mirror, no
sync script, no drift.

## License

MIT for the code. The ELF and the scenario table are published artifacts whose
integrity is enforced on-chain.
