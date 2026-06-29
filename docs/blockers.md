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

## Phase-2 PRODUCT wallet architecture (per `audit.md` + `audit2.md` + `audit3.md`) — P0 FIXES APPLIED

### audit3 (vault UX + WebCrypto fix)
- **Critical bug fixed:** vault creation crashed with `AeadParams: additionalData:
  Not a BufferSource` because AES-GCM was always given `additionalData` (= undefined
  on the no-AAD wrapper path). `aesGcmParams()` now omits it when no AAD is given.
- **Passwordless UX:** vault setup is passkey/wallet-first and downloads an
  emergency recovery file by default (new `recovery_file_secret` wrapper); password
  recovery is hidden under Advanced. Deposit auto-selects a verified vault (no typing
  a vault id) and shows checkout-style steps; restore offers file/Freighter/password.
- **Finality:** user-burn validation now enforces the CCTP `minFinalityThreshold`.
- **Honesty:** the relayer stops at `burn_validated` / `awaiting_proof_witness` when
  no coin witness is supplied and only marks a deposit `active` after a real
  `receiveDepositTxHash`. The deposit UI surfaces this honestly.
- **Repo hygiene (PART10) intentionally skipped:** the `frontend/` folder (including
  `frontend/.next`) is left untouched per the repo owner's instruction; the audit3
  request to `git rm` those artifacts was not performed.


An acceptance audit (`audit2.md`) found 12 P0 gaps in the first wallet pass; all are
now fixed and gated by `npm run phase2:acceptance` (typecheck + vault + auth-privy +
vault-api + deposit-api + route-auth + frontend-flow + relayer-user-burn + security
gates — all PASS offline). What changed since the first pass:
- Vault now uses the real **Privy DID** (`/v1/me.privy_user_id`), not the local UUID.
- **Backup verification is real**: the client fetches the envelope back, unwraps,
  decrypts, compares vault_id + commitments, and only then calls verify-backup with
  a non-empty proof-of-decrypt object (backend rejects empty/insufficient-policy).
- **Restore page** fixed (was indexing a string) — real fetch → unwrap → decrypt →
  compare.
- **Deposit** signs approve + `depositForBurnWithHook` with the user's wallet via
  viem (allowance-checked), auto-submits the burn hash (no `prompt()`).
- **Relayer `CCTP_INBOUND_AFTER_USER_BURN`** completes the Stellar side
  (validate burn → attestation → mint_and_forward → DepositNoteMint proof →
  receive_cctp_deposit), no placeholder.
- **All user-owned state-changing routes require Privy auth + ownership** (27/27
  route-auth checks pass); **Privy wallet sync** (`/v1/me/wallets/sync-privy`) added.
- **RFQ** intent stores user_id; quote-accept checks intent ownership + immutability.
- **Dev/legacy routes** gated behind `ENABLE_DEV_ROUTES`.

### Status of the original wallet rebuild (still true)

The wallet rebuild is implemented and tested (see `docs/app-wallet-architecture.md`,
`docs/note-vault-recovery.md`, `docs/privy-stellar-integration.md`):

- **Identity:** Privy-first (`packages/auth-privy`, Privy DID = canonical user;
  ES256 token verified offline via JWKS). Legacy wallet-nonce auth is dev-only
  behind `ENABLE_LEGACY_WALLET_AUTH`.
- **Note vault:** `packages/note-vault` — random `vault_master_key`, AES-256-GCM +
  AAD, wrapped by passkey-PRF / Stellar-Ed25519 / recovery-kit (EVM diagnostic-only).
  Backend stores only ciphertext + wrapped keys; rejects plaintext fields.
- **Deposit:** **user-signed** — `/v1/deposits/prepare` returns EVM tx requests; the
  relayer `CCTP_INBOUND_AFTER_USER_BURN` validates the burn (sender/amount/domain/
  mintRecipient/destinationCaller/hookData) before the Stellar side. No backend EVM
  key in the user path; operator deposit gated behind `ENABLE_OPERATOR_TESTNET_DEPOSIT`.
- **Stellar spends:** **user-signed** — backend builds XDR (`packages/stellar-actions`),
  Freighter signs, relayer broadcasts. `STELLAR_USER_SECRET`/`toSecret` removed from
  all service runtime (static gate enforces this).
- **Frontend:** `apps/web` (Next.js) — `/ /login /dashboard /vault /deposit /restore
  /withdraw /activity`. Browser note gen + encryption; IndexedDB encrypted-only cache.
- **Recovery gate:** deposit blocked until vault backup verified + recovery policy
  sufficient (≥1 non-EVM wrapper on testnet); EVM-only recovery rejected.
- **Packaging:** services import packages, never `apps/cli` (gate enforced).
- **Docker:** per-service Dockerfiles + `infra/docker-compose.phase2.yml` (7 services).
- **Security gates:** `npm run security:gates` — all pass.

### Remaining (documented, not blockers)
- **Privy Stellar Tier-2 raw signing** is a TODO; Freighter is the active Stellar
  signer (Privy Stellar has no end-to-end tx helper at Tier 2).
- **Proof-authorized no-Stellar-wallet exit** (`withdraw_by_proof` /
  `withdraw_cctp_by_proof`, no `require_auth`) is the preferred future path; today
  Path A (Freighter-signed) is active.
- **Live testnet e2e through the UI** + `docker compose up` live run require a Docker
  host + funded wallets; the stack config validates and all offline + unit tests pass.

## Remaining real work (PHASE 2+)

- Real `apps/api` live-action endpoints (currently several return 501): deposit
  burn/attestation/mint-forward/register-note, withdraw submit, outbound submit.
- Real relayer/prover/solver services on a Redis queue; on-chain quote/intent
  registries for full RFQ lifecycle (deviation #2).
- Auth + user DB (PHASE 5), Docker (PHASE 3), Next.js app (PHASE 4), app/UI e2e
  (PHASE 6/7).
