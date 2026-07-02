# Asset-Bound Note Model

> Testnet only; no mainnet claim. Spec: `shade_testnet_e2e_agent_build_spec.md` §6.

Two parts: the **asset registry** (done) and the **asset-bound commitment**
(in progress).

## Asset registry (done)

- Contract (`shielded_pool`): `DataKey::AssetToken/NoteSupply`; `register_asset`,
  `get_asset_token` (fails closed with `UnknownAsset`, never defaults to USDC),
  `note_supply`, `vault_balance(asset_id)`, `proof_of_reserves(asset_id)`,
  internal `adjust_note_supply`. Admin-only registration; double-register
  rejected. Tests in `shielded_pool/src/tests.rs`.
- `@shade/assets`: `AssetConfig`, canonical USDC/XLM configs, and the canonical
  asset-id derivation `assetId = int(sha256(tokenContract)[:31])` — the SAME
  `hash_to_field` reduction the circuits and contract use (valid on BN254 and
  BLS12-381). Tests in `packages/assets/src/assets-test.ts`.

## Asset-bound commitment (in progress)

The commitment value must include `assetId`. The **real** current commitment
(coinutils + the working circuits — NOT the stale `circuits/lib/commitment.circom`)
is:

```
precommitment = Poseidon2(nullifier, secret)
commitment    = Poseidon3(value, label, precommitment)   // native soroban-poseidon t=4
nullifierHash = Poseidon1(nullifier)
```

Target (minimal, stays aligned with native `poseidon_hash([...])`):

```
commitment = Poseidon4(assetId, value, label, precommitment)   // native t=5
```

This is one atomic change (the commitment value moves, so all producers/verifiers
must land together) with an iteration-heavy witness-debug loop. Order of work:
withdraw/deposit path first (headline "USDC note can't withdraw as XLM" test),
then extend to private_transfer and MPC.

### Edit list

1. **coinutils (vendored `.zk-ref`, capture in `vendor-patches/`)**
   - `crypto/coin.rs`: `generate_commitment(env, asset_id, value, label, nullifier, secret)` →
     `poseidon_hash(env, &[asset_id, value, label, precommitment])`. `generate_coin`
     takes `asset_id`; store it in `CoinData`.
   - `types/coin.rs`: add `asset_id: String` to `CoinData`.
   - `cli/args.rs` + `main.rs` + `cli/commands.rs`: `generate` gains `--asset-id`
     (no default — required, fail closed).
   - `merkle/withdrawal.rs` + `merkle/transfer.rs`: read `coin.asset_id`, pass to
     `generate_commitment`, and add it to the witness/`SnarkInput` as a public
     signal (`assetId` for withdraw; `inputAssetId`/`outputAssetId` for transfer,
     equal for same-asset).
   - `types/snark.rs`: add `asset_id` (public).
2. **circom** — update `CommitmentHasher` (lib + all copies, identically) to
   `Poseidon255(4)(assetId, value, label, precommitment)`; add `assetId` input.
   Each `main.circom` declares `assetId` (and exposes it public per §6.4:
   withdraw_public/withdraw_cctp → `assetId`; private_transfer →
   `inputAssetId`,`outputAssetId` with equality for same-asset; mpc_settlement →
   asset signals). Bump `nPublic` in `scripts/circuits-build.ts`.
3. **Rebuild**: `CIRCUITS_FORCE_SETUP=1 npm run circuits:build` (new vks; redeploy
   verifier contracts on testnet).
4. **TS proving** (`packages/proving`): thread `assetId` through `generateCoin`,
   `buildNoteProof`, `buildTransferProof`, `buildDepositProof`.
5. **Contract** (`shielded_pool`): `withdraw` asserts `assetId` public signal ==
   registered asset, selects the token via `get_asset_token(assetId)`, and calls
   `adjust_note_supply` on deposit (+) / withdraw (−). Per-asset reserve invariant
   `note_supply(asset) <= vault_balance(asset)`.
6. **Tests** (§6.8): circuit — USDC note cannot prove withdrawal as XLM (and vice
   versa), asset mismatch in transfer/MPC fails; contract — unknown asset withdraw
   fails, withdraw of asset A never moves token B, per-asset reserve invariant;
   property/fuzz — randomized deposits/withdrawals keep `NoteSupply(asset) <=
   vaultBalance(asset)`; E2E — USDC and XLM notes coexist, each withdraws only its
   own token. Add the cross-asset mismatch case to `scripts/circuits-test.ts`.
7. Regenerate `vendor-patches/coinutils-and-circuits.patch`.

### Done when

A USDC note and an XLM note coexist in the pool and every proof/contract path
enforces asset correctness (§6.9).
