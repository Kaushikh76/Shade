# MPC Settlement

> Testnet only; no mainnet claim. MPC supports **same-asset** private crossing
> (§9) and **priced cross-asset** USDC↔XLM crossing (§10). USDC→XLM is ALSO
> available via the atomic RFQ route (see `docs/RFQ_USDC_XLM.md`). MPC dev mode is
> not a distributed trust model.

## Same-asset crossing (§9) — implemented

Two USDC notes cross into two USDC output notes. `shielded_pool::mpc_settle`
enforces (fail-closed):

1. a registered committee and a configured `mpc_verifier`;
2. ≥ ⌈2n/3⌉ **distinct** committee ed25519 signatures over the batch hash
   (duplicate / unregistered signers rejected);
3. a mandatory Groth16 `mpc_settlement` proof that verifies (B1 — no fail-open);
4. proof public signals bound to nullifierA/B, outputCommitmentA/B, a known
   state root, the canonical association root (B2), `hashToField(batch_hash)`,
   poolId/chainId, and a non-expired `deadlineLedger` (B2);
5. both nullifiers spent once; the new root recorded.

**Asset binding:** the `mpc_settlement` circuit binds a single `assetId` into all
four note commitments (input A/B and output A/B), so `assetA == assetB ==
outputAssetA == outputAssetB` (§6.4) and the output notes use the exact same
asset-bound commitment as deposit/withdraw (hence are spendable). The witness
builder rejects a coinA/coinB asset mismatch.

**Batch hash (§9.3):** `computeBatchHash` sorts matches by a total order over the
full signed content (intent ids, matched amount, assets, price) so the hash is
order-independent and any field change flips it.

### Adversarial tests (contract, `shielded_pool/src/tests.rs`)

verifier unset → reject; missing proof → reject; invalid proof → reject; valid
proof → accept; wrong association root → reject; expired deadline → reject;
duplicate signer → reject; below-threshold (1-of-2) → reject; unregistered signer
→ reject; wrong batch hash (proof vs arg) → reject; signature over a different
batch → reject. Shamir + batch-hash + matcher unit tests in `@shade/mpc-crypto`.

## Committee modes (§9.5)

- `dev` in-process (`apps/mpc-committee/src/server.ts`) — a single process for
  same-asset E2E. **Not** a distributed trust model.
- Independent nodes (`node-server.ts` ×3, one secret key each) +
  `coordinator-server.ts` (holds no secret keys) — the real distributed path,
  requiring independent operators.

## Priced cross-asset crossing (§10) — implemented

Party A spends `matchedAmountA` of assetX and receives `matchedAmountB` of
assetY; party B spends assetY and receives assetX, at a fixed price.

Circuit `mpc_priced_settlement` (`nPublic=20`) enforces:
- asset pairing `outputAssetA==inputAssetB`, `outputAssetB==inputAssetA`, and
  `inputAssetA != inputAssetB` (a genuine cross-asset);
- fixed-point price `matchedAmountB == floor(matchedAmountA·priceScaled/priceScale)`
  with `priceScale == 1e9` (`0 <= A·price − B·scale < scale`);
- `minOutputA`/`minOutputB` protections (each party receives at least its min);
- asset-bound commitments for all four notes, Merkle membership of both inputs,
  ASP membership of both labels, domain-separated nullifiers.

Contract `shielded_pool::mpc_settle_priced` binds (fail-closed): committee
threshold over distinct registered signers, a MANDATORY `mpc_priced_settlement`
proof (dedicated verifier), canonical association root, non-expired deadline,
batch hash, poolId/chainId, both assets registered and distinct. Per-asset supply
is conserved (an assetX input note is replaced by an assetX output note, likewise
assetY), so no net supply change.

Coordinator `matchPricedIntents` / `matchPricedPair` cross a party spending X
(wanting Y) with a party spending Y (wanting X) at a single price, no partial
fills, respecting both parties' limit prices and min-outputs; the price is bound
into `computeBatchHash` (§10.5).

### Tests

- Circuit (`circuits:test`): valid cross-asset proof verifies; wrong output
  amount, wrong price, minOutput violation, and wrong asset pair all fail witness
  generation (§10.6).
- Contract (`shielded_pool/src/tests.rs`): valid priced settle accepted; rejects
  same-asset, unregistered asset, missing proof, invalid proof, wrong association
  root, expired deadline.
- Coordinator (`priced-matcher:test`): crossing matches with price bound;
  non-crossing / partial-fill / unmet-limit rejected; price change flips the
  batch hash.

USDC→XLM is ALSO served by the atomic RFQ path (Phase 3). Same-asset and priced
cross-asset MPC testnet E2E run in the Phase 8 acceptance suite.
