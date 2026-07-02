# MPC Settlement

> Testnet only; no mainnet claim. **MPC supports same-asset private crossing
> only. USDC→XLM is the RFQ route** (see `docs/RFQ_USDC_XLM.md`). MPC dev mode is
> not a distributed trust model. Spec: §9 (same-asset), §10 (priced cross-asset).

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

## Priced cross-asset crossing (§10) — DESCOPED

MPC priced USDC↔XLM crossing is **not implemented** and is explicitly out of
scope for this milestone (spec §10.7 permits keeping MPC same-asset only). The
current `mpc_settlement` circuit conserves value for a same-unit crossing
(`outValueA + outValueB == 2·matchedAmount`); a priced cross-asset crossing needs
a different circuit (price + asset-pair constraints), coordinator price matching,
and an extended batch hash.

**USDC→XLM is served by the atomic RFQ path** (Phase 3), which is implemented and
tested. The acceptance suite (`e2e:testnet:all`) prints
`MPC priced cross-asset not implemented; RFQ is the USDC->XLM route.` and no code
or docs claim MPC supports USDC↔XLM.

Same-asset MPC testnet E2E (two USDC notes → two USDC output notes → withdraw)
runs in the Phase 8 acceptance suite.
