# Vendor patches

The off-chain prover (`stellar-coinutils`) and the Poseidon/Merkle circuit
building blocks come from the official, Apache-2.0 `stellar/soroban-examples`
repo (the `privacy-pools` example). That repo is a large external clone and is
**not** committed here (it is gitignored as `.zk-ref/`).

To reproduce the build from a fresh clone:

```bash
git clone https://github.com/stellar/soroban-examples .zk-ref/soroban-examples
cd .zk-ref/soroban-examples
git apply /path/to/shade-protocol/vendor-patches/coinutils-and-circuits.patch
cp /path/to/shade-protocol/vendor-patches/transfer.rs.new \
   privacy-pools/cli/coinutils/src/merkle/transfer.rs
cargo build --release --bin stellar-coinutils
```

## What the patches add (Shade modifications)

- `config.rs` — fixed denomination (0.5 USDC, 7dp), depth 12, and the nullifier
  domain separators `POOL_ID` / `CHAIN_ID` (#3).
- `commitment.circom` fix — `Poseidon255(3)` so the in-circuit commitment matches
  the native `generate_commitment` (the upstream sequential-2-input bug).
- `snark.rs` / `withdrawal.rs` — emit `poolId` / `chainId` in the witness (#3).
- `transfer.rs` (new) + `args.rs` / `commands.rs` / `main.rs` / `merkle/mod.rs`
  — a `transfer` subcommand that builds the hidden-amount PrivateTransfer witness
  (#2): output note value = input − fee, value conservation, output commitment.

Shade's own circuits live in-repo under `circuits/withdraw_public/` and
`circuits/private_transfer/` (the `.circom` sources). Only the upstream
`coinutils` Rust tool and its shared libs are external.
