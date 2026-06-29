# Blockers & Status

Updated after PHASE 1 (P1.1–P1.11) completion. Authoritative protocol-fix detail
lives in `docs/protocol-fixes.md`; this file tracks what is done, what is a
deliberate deviation, and what remains real work.

## No hard blockers

All PHASE 1 gating protocol fixes are implemented and verified on Stellar testnet
with real transactions (tx hashes in `docs/protocol-fixes.md`):

- **Proof bindings** — withdraw binds recipient/fee/deadline/op (P1.5); RFQ binds
  quote/intent/fill/op/fee/deadline (P1.6); CCTP exit binds destination/recipient/
  max_fee/finality/op/deadline (P1.7). A relayer cannot mutate any of these.
- **DepositNoteMint (P1.8)** — a separate circuit binds the note commitment to its
  private opening and to the CCTP message; `receive_cctp_deposit` verifies the
  proof and enforces commitment/op/source-domain/dest-domain/amount7/amount6dp/
  nonce/asset/pool/policy/burn-hash before inserting the leaf.
- **Solver authorization (C4)** — `rfq_settle` requires the solver's ed25519 key to
  be in an admin-managed on-chain registry (`set_authorized_solver`); a rogue key
  is rejected `#23`.
- **Lockdowns** — verifier `set_vk` admin-gated + freezable (P1.2); nullifier spend
  authorized-spender-gated (P1.3).
- **Root auditor (P1.9)** — `apps/root-auditor` recomputes the lean-imt root from
  on-chain `deposit` events and flags `ROOT_MISMATCH_CRITICAL`; the API
  (`assertRootHealthy`) refuses withdraw/RFQ/exit preparation while a critical
  finding is unresolved (409).
- **Canonical contract (P1.1)** — `shielded_pool` is the one active settlement
  contract; legacy `shade_vault`/`commitment_tree` are deprecated and unwired.
- **Tooling** — `circuits:build`/`circuits:test` run the real Circom/snarkjs
  pipeline; `test-report` is regenerated fresh per run and fails on any `FAIL`
  (P1.10/P1.11). `contracts:deploy:pool` deploys + wires the canonical stack.

## Deliberate deviations (documented, accepted for testnet)

1. **One shared withdraw circuit for withdraw/RFQ/CCTP (vs three separate
   circuits).** The spec lists `withdraw_public` / `withdraw_cctp` /
   `rfq_settlement` as distinct circuits. Shade uses ONE circuit whose
   `operationType` public signal is enforced per entrypoint (withdraw requires
   op=1, `withdraw_cctp` op=2, `rfq_settle` op=3) plus op-specific bound signals.
   Security-equivalent for cross-op misuse (a withdraw proof cannot be replayed as
   an RFQ settle — the op-type check rejects it), with one verifier/vk to manage.
   `deposit_note_mint` and `private_transfer` ARE separate circuits. Splitting the
   shared circuit into three is a future refactor with marginal security benefit.

2. **RFQ on-chain lifecycle is partial.** `rfq_settle` enforces: solver authorized
   (on-chain registry), solver signed the quote (ed25519), and the proof binds
   quote_hash/intent_hash/fill_receipt_hash (and via quote_hash, transitively the
   output/fee/solver/expiry committed in the quote). It does NOT yet keep on-chain
   quote/intent STATE (quote-exists, quote-accepted, accepted-quote-immutability,
   intent-expiry-from-chain). Those require on-chain quote/intent registries that
   belong with the RFQ API/DB service work in PHASE 2. Today the API/DB hold that
   state off-chain; the on-chain checks prevent relayer mutation of accepted terms.

3. **Off-chain Merkle root, on-chain attestation + audit.** On-chain Poseidon
   inserts exceed the Soroban per-tx budget past one leaf, so the registrar submits
   the off-chain lean-imt root with each deposit; every commitment is emitted
   on-chain and the P1.9 root auditor re-derives + compares the root. Acceptable
   pre-MPC/TEE.

4. **`receive_cctp_deposit` is admin-gated and does not re-read the SAC balance
   delta on-chain.** The deposit proof binds the claimed amount/asset/nonce; the
   registrar is trusted to submit truthful deposits and the auditor polices roots.
   A SAC balance-delta assertion is a possible future hardening.

5. **CCTP outbound mint latency.** The Stellar burn is on-chain and proof-bound;
   the Arbitrum-side mint completes after Circle finalizes the attestation
   (minutes) — a normal CCTP lifecycle follow-up poll, not a blocker.

## Phase-2 PRODUCT wallet architecture (per `audit.md`) — in progress

The service/queue/API layer is done, but the audit found real product gaps. Honest
status of the wallet rebuild (built in dependency order; see
`docs/app-wallet-architecture.md`):

- **Identity:** moving to **Privy-first** (`packages/auth-privy`, Privy DID =
  canonical user). Custom wallet-nonce auth becomes dev-only behind
  `ENABLE_LEGACY_WALLET_AUTH=false`.
- **Note vault:** `packages/note-vault` — random `vault_master_key`, AES-256-GCM +
  AAD, wrapped by passkey-PRF / Stellar-Ed25519 / recovery-kit (EVM diagnostic-only).
  Backend stores only ciphertext + wrapped keys; rejects plaintext fields.
- **Deposit:** must become **user-signed** (the user's EVM wallet signs approve +
  `depositForBurnWithHook`); the backend must NOT use `ARB_SEPOLIA_PRIVATE_KEY` in
  the user path. Relayer validates the user burn tx before mint/forward.
- **Stellar spends:** must become **user-signed** via Freighter/Privy; remove
  `STELLAR_USER_SECRET`/`toSecret` from app routes. Preferred future: proof-auth
  `*_by_proof` entrypoints (no `require_auth`).
- **Frontend:** `apps/web` (Next.js) with the full deposit→restore→spend flow.
- **Recovery gate:** no deposit until vault backup verified + recovery policy
  sufficient (≥1 non-EVM wrapper on testnet).

Until these land, the existing operator-driven deposit and `STELLAR_USER_SECRET`
withdraw paths remain DEV/TEST ONLY and must not be exposed as the app user path.

## Remaining real work (PHASE 2+)

- Real `apps/api` live-action endpoints (currently several return 501): deposit
  burn/attestation/mint-forward/register-note, withdraw submit, outbound submit.
- Real relayer/prover/solver services on a Redis queue; on-chain quote/intent
  registries for full RFQ lifecycle (deviation #2).
- Auth + user DB (PHASE 5), Docker (PHASE 3), Next.js app (PHASE 4), app/UI e2e
  (PHASE 6/7).
