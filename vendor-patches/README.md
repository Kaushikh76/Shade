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
  P2 #14 added an optional `--association-file` flag (mirrors `withdraw`'s) that
  proves the spender's label is a member of the ASP allow-set, using the exact
  same tree construction as `WithdrawalManager::handle_association_set` so a
  label's proof is valid regardless of which flow builds it. Without the flag,
  dummy values are used and the proof only verifies against an on-chain
  `associationRoot` of 0 (compliance disabled) — same convention as withdraw.

**Not locally build-verified**: this machine's Rust toolchain is broken for
this dependency graph independent of these changes — confirmed two ways: (1)
the default MSVC host's `link.exe` fails linking `serde`/`proc-macro2`/
`typenum`'s build scripts on an untouched clone of this same commit; (2)
explicitly forcing the GNU toolchain (`rustup run stable-x86_64-pc-windows-gnu
cargo build`) instead fails on a missing `dlltool.exe` compiling `getrandom`.
Neither is related to this patch. The locally pre-built `stellar-coinutils`
binary in `.zk-ref/` therefore still reflects the PRE-P2-#14 source (no
`--association-file` flag) — `npm run circuits:test` will fail on
`private_transfer` locally until someone rebuilds it on a working toolchain.
This does **not** affect CI/fresh clones: they build the binary from source
following the steps above, which already includes this patch, so they get a
correct, current build. The patch was verified to `git apply` cleanly against
a fresh clone; the circuit side (`circuits/private_transfer/main.circom`) was
independently rebuilt and verified here — `circuits:build` reports
`nPublic=7` as expected and the trusted setup completed. Only the native
`transfer.rs` change is unverified locally; its `handle_association_set`
logic is a direct mirror of the proven, already-deployed one in
`withdrawal.rs` (fetched from upstream to copy exactly).

Shade's own circuits live in-repo under `circuits/withdraw_public/` and
`circuits/private_transfer/` (the `.circom` sources). Only the upstream
`coinutils` Rust tool and its shared libs are external.
