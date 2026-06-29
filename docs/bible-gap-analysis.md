# Bible Gap Analysis

Tracks where the implementation differs from `shade_protocol_architecture_bible.md`,
after a full read of the bible. Split into: implemented, intentionally deferred,
and out-of-scope per `phase1.md` (stop before MPC/TEE; no Sefi/indexing/DeFi).

## Implemented privacy upgrades (the bible-wins items 1–4)

| # | Bible requirement | Status |
|---|---|---|
| 1 | Anonymity set (shared pool, hide which note) | DONE — shared pool, k>1 set, leaf index private |
| 2 | `PrivateTransfer` with hidden amounts + value conservation | DONE — circuit + on-chain settle |
| 3 | Domain-separated nullifier (`pool_id`, `chain_id`) | DONE — in circuit + contract-bound |
| 4 | ZK compliance membership (ASP allowlist, no leak) | DONE — enforced in circuit + contract |

## Deferred (bible features not yet built; no phase-1 mandate)

- **`DepositNoteMint` proof.** The bible binds the CCTP deposit to the note with a
  ZK proof (CCTP nonce/amount/asset → commitment). We currently register the
  commitment via an admin-gated call with the off-chain root, not a deposit proof.
  Adding it would prove the deposit amount/asset match the note in zero knowledge.
- **Multi-asset vault (USDC + XLM).** Bible `ShadeVault.initialize` takes both
  `usdc_sac` and `xlm_sac`. We are USDC-only. XLM custody + a swap path (and then
  a price source, see below) are V2.
- **Richer note structure.** Bible commitment binds 10 fields (separate
  `owner_public_key`/`spend_public_key`, `compliance_tag`, `source_context`,
  `memo_commitment`). Ours binds value/label/nullifier/secret. Expanding the
  commitment is a circuit change; the settlement layer is unaffected.
- **Per-operation public-input binding.** Bible `WithdrawPublic` binds
  `recipient`, `fee`, `deadline`, `asset` in-proof. We bind amount/nullifier/root/
  poolId/chainId/assocRoot in-proof; recipient via tx-auth on `to`. RFQ binds
  `quote_hash` at the contract-call level (ed25519 sig verified on-chain) rather
  than as a proof public input — `phase1.md` permitted this substitution but the
  stronger form is to add `quote_hash`/`intent_hash` as RFQ proof signals.
- **Shade View / view-key selective disclosure**, **Shade Remit / SEP-38 anchor
  payout**, **full note recovery** (seed derivation, encrypted cloud backup,
  view-key recovery), **RemitSettlement / ProofOfFillClaim circuits.**
- **Price oracle.** Not needed in v1 (single-asset USDC; RFQ price is the signed
  solver quote — the user is the oracle). Required only with multi-asset swaps /
  Remit corridors. When added, use Reflector (SEP-40) as a solver-side sanity
  bound + proof-of-reserves unit — NOT a live feed in the settlement path.

## Out of scope per phase1.md (do not build now)

- **TEE matcher (V2)** and **MPC matcher (V4)** — orderflow privacy during
  matching. Today's RFQ is the bible's V1 (encrypted intent, permissioned/trusted
  solver). The settlement layer is matcher-agnostic, so TEE/MPC slot in later
  without redesigning settlement.
- **Sefi semantic indexer**, DeFi/market/analytics indexing.

## Known engineering deltas (documented elsewhere)

- Curve: **BLS12-381 Groth16** not BN254 — first-party proven tooling; BN254
  Groth16 verifier PRs (#396/#399) not yet merged. See `docs/zk-proof-system.md`.
- Merkle root computed off-chain, attested on-chain (Soroban Poseidon-insert
  budget limit). All security-critical steps remain on-chain.
