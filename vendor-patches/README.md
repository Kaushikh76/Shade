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
# Build the binary WITH testutils: coinutils resets the Soroban host budget via
# env.cost_estimate() (a testutils API), so the release binary needs the feature.
cd privacy-pools/cli/coinutils
cargo build --release --features soroban-sdk/testutils --bin stellar-coinutils
```

This build is now verified locally on macOS (Rust 1.89, soroban-sdk 25.1) and in
CI (`.github/workflows/ci.yml` `circuits` job). The earlier "not locally
build-verified" caveat is resolved: the patch now also wires the `--association-file`
flag through the `transfer` subcommand end-to-end (args.rs → main.rs → commands.rs
→ `TransferManager::build_transfer`), and the build uses the `testutils` feature.
`npm run circuits:build` reports `private_transfer nPublic=7` and
`npm run circuits:test` verifies all three circuits' proofs.

## What the patches add (Shade modifications)

- `config.rs` — fixed denomination (0.5 USDC, 7dp), depth 12, and the nullifier
  domain separators `POOL_ID` / `CHAIN_ID` (#3).
- `commitment.circom` fix — `Poseidon255(3)` so the in-circuit commitment matches
  the native `generate_commitment` (the upstream sequential-2-input bug).
- `snark.rs` / `withdrawal.rs` — emit `poolId` / `chainId` in the witness (#3).
- `transfer.rs` (new) + `args.rs` / `commands.rs` / `main.rs` / `merkle/mod.rs`
  — a `transfer` subcommand that builds the hidden-amount PrivateTransfer witness
  (#2): output note value = input − fee, value conservation, output commitment.
  P2 #14 added an optional `--association-file` flag (mirrors `withdraw`'s) that
  proves the spender's label is a member of the ASP allow-set, using the exact
  same tree construction as `WithdrawalManager::handle_association_set` so a
  label's proof is valid regardless of which flow builds it. Without the flag,
  dummy values are used and the proof only verifies against an on-chain
  `associationRoot` of 0 (compliance disabled) — same convention as withdraw.

**Build-verified**: `stellar-coinutils` builds from this patch + `transfer.rs.new`
with the `soroban-sdk/testutils` feature on Rust 1.89 / soroban-sdk 25.1. The
`transfer` subcommand's `--association-file` flag is wired end-to-end and its
`handle_association_set` logic mirrors the proven `withdrawal.rs` path. With the
rebuilt binary, `npm run circuits:build` reports `private_transfer nPublic=7`
(6 public inputs + `nullifierHash`) and `npm run circuits:test` verifies the
withdraw_public, private_transfer (incl. ASP binding), and deposit_note_mint
proofs. Note: regenerating the trusted setup produces new verifying keys, so the
on-chain `private_transfer`/`mpc_settlement` verifier contracts must be
redeployed from the current vks before the on-chain path matches local proofs.

Shade's own circuits live in-repo under `circuits/withdraw_public/` and
`circuits/private_transfer/` (the `.circom` sources). Only the upstream
`coinutils` Rust tool and its shared libs are external.
