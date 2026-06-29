# Protocol Fixes (phase2.md PHASE 1)

Tracks the protocol/correctness fixes that gate the backend-service and frontend
work. Each is verified on Stellar testnet.

## Current canonical deployment (after security lockdown)

| Contract | ID | Notes |
|---|---|---|
| ShadePool (shielded_pool) | `CDVEGBVXPIHKHCR7CJDJS4JVCMOVABEFBQ4HZQ7PKK6VIO3J3V5ZRTB5` | canonical settlement contract (C4/C6 redeploy) |
| NullifierRegistry | `CBAKCITRZLJZFQC4ISSYH5UESYFUYBFRANVM5VPDA6OH3VDTSLQ2IH67` | authorized-spender locked |
| VerifierWithdraw | `CCAO4CASJGP57A4SOQTSQO7JWAY4WXXQRU4EUOZGMCR3QF62VOIMCYY5` | admin-gated set_vk; 17-signal vk (P1.7) |
| VerifierDepositNoteMint | `CC4FGBVT4BYYM5S3NJKJGOLMICQV3HADL5XRHXMXFQEZ5XQ2K2EJHNJO` | admin-gated set_vk; 14-signal vk (P1.8) |
| VerifierTransfer | `CDBCXL3RLJM7SSZUV2ULCKIKX3FE4KCXRNRFAUXE7PS4YZGDXQSFZ7T5` | admin-gated set_vk; 6-signal vk |

Deploy + wire the canonical stack with `npm run contracts:deploy:pool`
(`SHADE_REDEPLOY_POOL=1` to force a fresh pool).
| VerifierTransfer | `CDBCXL3RLJM7SSZUV2ULCKIKX3FE4KCXRNRFAUXE7PS4YZGDXQSFZ7T5` | admin-gated set_vk |

## Done

### P1.2 — Verifier set_vk locked down (admin-gated + freezable)
`proof_verifiers` now takes an `admin` in the constructor. `set_vk` requires
admin auth and is forbidden once `freeze_vk` is called (one-way immutability for
production). Added `is_frozen`, `admin`.
- On-chain: non-admin `set_vk` rejected (auth failure). PASS.

### P1.3 — NullifierRegistry authorized-spender
`spend(caller, nullifier)` now requires `caller.require_auth()` AND that `caller`
is in an admin-managed authorized-spender set (`set_authorized_spender`). The
ShadePool passes `env.current_contract_address()`; only authorized contracts can
spend. Random accounts cannot grief nullifiers.
- On-chain: random user `spend` rejected (`unauthorized spender` trap). PASS.
- On-chain: authorized pool spends during withdraw — tx
  `2935718c91080dcadc4273360a159fdbf4e9b84c1f949427404d603619ca5254` (the `spend`
  event carries the pool address as caller). PASS.
- Double-spend still reverts (nullifier already spent). PASS.

### P1.10 — Hardcoded local paths removed
All `/Users/...` and `/private/tmp/claude...` absolute paths replaced with the
env-driven `apps/cli/src/lib/paths.ts` module: `SHADE_ROOT` (default
`process.cwd()`), `SHADE_SCRATCH_DIR`, `SHADE_ZK_REF`, `COINUTILS_BIN`,
`CIRCOM2SOROBAN_BIN`, `CIRCUIT_BUILD_DIR`, plus `SHADE_ENV_FILE`. Fresh clones
resolve everything relative to the repo root. `npm run typecheck` passes.

### P1.5 — WithdrawPublic operation binding (recipient/fee/deadline/op-type)
The withdraw circuit now has 10 public signals:
`[nullifierHash, operationType, withdrawnValue, recipientHash, relayerFee,
deadlineLedger, stateRoot, associationRoot, poolId, chainId]`. The contract
`withdraw` enforces:
- `operationType == WITHDRAW_PUBLIC (1)` (else `#11 WrongOperation`)
- `recipientHash == sha256(to_strkey)[:31]` recomputed on-chain (else
  `#12 WrongRecipient`) — a relayer cannot redirect funds
- `relayerFee <= withdrawnValue`; net `value - fee` released to recipient, fee retained
- `deadlineLedger >= current ledger` (else `#13 Expired`)

On-chain proof (current pool `CCTVKHRPFH3GGUMXWJ3B3KFOGTU6YG3WV263MRK5UL5ELIADA2IVNGTK`):
- Withdraw tx `bcaf316a4d13d0b9ea79bd7756fdad020fff478814efb4a4dc34f2cd59868172`
  — net 4900000 (= 5000000 - 100000 fee) released; recipientHash matched. PASS.
- Relayer redirect to a different recipient rejected with `Error(Contract, #12)`. PASS.
This is Definition-of-Done #4 ("Withdraw proof binds recipient").

NOTE: withdraw/rfq_settle/withdraw_cctp share this circuit; the latter
two now read the new indices (value@2, stateRoot@6, assoc@7, pool@8, chain@9) so
they keep working. P1.6 (below) adds RFQ-specific binding signals; full CCTP term
binding is P1.7.

### P1.6 — RFQ settlement binding (quote/intent/fill/op-type/fee/deadline)
The shared withdraw circuit gained 3 APPENDED public signals so withdraw/cctp
indices [0..9] are unchanged (now 13 signals total):
`[10] quoteHash  [11] intentHash  [12] fillReceiptHash` — each
`int(sha256(..)[:31])`, bound via `x*x` pass-through constraints. The contract
`rfq_settle` now takes `intent_hash` + `fill_receipt_hash` args (alongside the
existing `quote_hash`) and enforces:
- `operationType == RFQ_SETTLEMENT (3)` (else `#11 WrongOperation`)
- `quote_hash arg`  → `hash_to_field` == proof signal[10] (else `#14 WrongQuote`)
- `intent_hash arg` → `hash_to_field` == proof signal[11] (else `#15 WrongIntent`)
- `fill_receipt_hash arg` → `hash_to_field` == proof signal[12] (else `#16 WrongFillReceipt`)
- `relayerFee <= credit`, `deadlineLedger >= ledger` (else `#13 Expired`)
The existing solver ed25519 signature over `quote_hash` is retained. Because
`quote_hash` is `sha256` of the full accepted quote (output asset, net_output,
fee, solver_id, valid_until, settlement_method), binding it into the user's proof
transitively binds all those terms — a relayer cannot settle a valid user proof
against any different quote/intent/fill. This is Definition-of-Done #6.

On-chain proof (pool `CAE7NCPROLSJTN5PCN3VQMBGTLT7UH3KOWDCUULF42SWC5B4MW2A6BPJ`,
verifier `CCQYWSZ7ODLA5RDOA4G52IITQXNVVKQIUDTT34IYMQSUQM2TOESQOYGF`):
- RFQ settlement tx `1dd5830bc6d7694ca15a7fb3e00a4ad0d4d378de9f5a72c118ed31d9b2fbcdc6`
  — proof verified on-chain + ed25519 quote-sig + nullifier spent + solver credited
  5000000 (7dp). PASS.
- NEGATIVE: relayer swaps in a different, validly-signed quote → rejected
  `Error(Contract, #14) WrongQuote` (binding check precedes nullifier spend). PASS.
- Double-settle rejected (nullifier already spent). PASS.

### P1.7 — WithdrawCCTP destination binding (domain/recipient/fee/threshold/op/deadline)
The shared withdraw circuit gained 4 more APPENDED public signals (now 17 total;
indices [0..12] unchanged):
`[13] destinationDomain  [14] destinationRecipient  [15] maxFee  [16] minFinalityThreshold`.
`destinationRecipient` is bound as the integer value of the 32-byte CCTP
mintRecipient (12 leading zero bytes keep it under the field modulus). The
contract `withdraw_cctp` enforces:
- `operationType == WITHDRAW_CCTP (2)` (else `#11 WrongOperation`)
- `deadlineLedger >= ledger` (else `#13 Expired`)
- `destination_domain arg` == proof signal[13] (else `#17 WrongDestDomain`)
- `destination_recipient arg` == proof signal[14] (else `#18 WrongDestRecipient`)
- `max_fee arg` == proof signal[15] (else `#19 WrongMaxFee`)
- `min_finality_threshold arg` == proof signal[16] (else `#20 WrongFinality`)
All binding checks run BEFORE the nullifier spend and the CCTP burn. This closes
the gap that `to.require_auth()` only binds the Stellar note owner, NOT the
Arbitrum destination — so a relayer could previously redirect the burn. This is
Definition-of-Done #5.

On-chain proof (pool `CDW5IPO7IIPC2IBUCLUTZKVNGSJAR62ASXRZZTK5STAQXWAXKOWGCQCE`,
verifier `CCAO4CASJGP57A4SOQTSQO7JWAY4WXXQRU4EUOZGMCR3QF62VOIMCYY5`):
- Proof-bound outbound burn tx `88754dbef2ce344f57914008c359cde3c2f1befdc9fa9a5eb00ccb45cb784e01`
  — pool burned 5000000 (7dp) via Stellar CCTP to the bound Arbitrum recipient. PASS.
- NEGATIVE: relayer redirects recipient → `Error(Contract, #18) WrongDestRecipient`. PASS.
- NEGATIVE: relayer tampers max_fee → `Error(Contract, #19) WrongMaxFee`. PASS.
- NEGATIVE: relayer tampers domain → `Error(Contract, #17) WrongDestDomain`. PASS.
- REGRESSION: RFQ (P1.6) still settles against this 17-signal pool — tx
  `2bf31ede4565f83681de9545136a585fd42cd02d4424c59d95fd4a5fe1944c13`. PASS.

### P1.8 — DepositNoteMint circuit (bind CCTP message to the note commitment)
A NEW, SEPARATE circuit `circuits/deposit_note_mint` (14 public signals; not the
shared withdraw circuit) and its own verifier. The note opening
(value/label/nullifier/secret) is private; the circuit OUTPUTS the commitment
(signal [0]) so it is cryptographically tied to that opening, and enforces
`value <= amount7dp` in-circuit (anti-inflation: a deposit can't mint a note worth
more than the USDC that arrived). Public signals:
`[0] commitment [1] operationType(=4) [2] sourceDomain [3] destinationDomain
[4] cctpNonceHash [5] burnTxHashHash [6] amount6dp [7] amount7dp [8] assetIdHash
[9] recipientPool [10] encryptedNotePayloadHash [11] policyIdHash [12] poolId
[13] chainId`.

The pool gained a `DEPVERIFIER` slot + `set_deposit_verifier` setter (mirroring
the transfer verifier). `receive_cctp_deposit` now takes `proof_bytes` +
`pub_signals_bytes` and, BEFORE inserting the leaf, enforces:
- `commitment arg == signal[0]` (else `#21 WrongCommitment`)
- `operationType == DEPOSIT_NOTE_MINT (4)` (else `#11 WrongOperation`)
- `source_domain == signal[2]`, `amount == signal[7]` (else `#22 WrongDepositField`)
- `hash_to_field(cctp_nonce) == signal[4]`, same for encrypted_note_payload & policy_id (`#22`)
- `recipient_hash(asset) == signal[8]`, `recipient_hash(this pool) == signal[9]` (`#22`)
- `poolId/chainId == config` (else `#9 WrongDomain`)
- DepositNoteMint proof verifies against `DEPVERIFIER` (else `#5 ProofInvalid`)
The deposit stays admin-gated (registrar) and dedup-by-nonce; the proof closes the
gap that a registrar could previously insert an arbitrary commitment for a deposit.
This is Definition-of-Done #8 / phase2 item 8.

On-chain proof (pool `CDUBLMVIRUAIWICRMY4RWUIEYMMMTFGMYZKENVEPKCTGLDOZHI5SJXQQ`,
deposit verifier `CC4FGBVT4BYYM5S3NJKJGOLMICQV3HADL5XRHXMXFQEZ5XQ2K2EJHNJO`):
- Deposit-with-proof tx `0xfde3b4573eff...` registered the note (leaf 0); the note
  was then spent by withdraw tx `3996da39fa0aa33de0600398771af287deec4b35a2219ddf1b7ecfb1b1b8fa72`. PASS.
- NEGATIVE: tampered `amount` arg → `Error(Contract, #22) WrongDepositField`. PASS.
- NEGATIVE: tampered `commitment` arg → `Error(Contract, #21) WrongCommitment`. PASS.

### P1.9 — Root auditor service (`apps/root-auditor`)
A standalone service/job that polices the off-chain-root design. It reconstructs
the commitment list from the pool's on-chain `deposit` events (the contract emits
every commitment; DB `note_commitments` is a fallback when events age out of RPC
retention), recomputes the lean-imt root independently via the new coinutils
`compute-root` command (byte-identical to the circuit's lean-imt), and compares it
to the root the registrar stored on-chain (`get_root`). On divergence it records a
`ROOT_MISMATCH_CRITICAL` finding; the API must refuse spends against a flagged
root. New `db/migrations/002_root_audit.sql` (`root_audit_runs`,
`root_audit_findings`). HTTP surface: `GET /health`, `GET /v1/audit` (200 OK / 409
on critical). One-shot CLI `npm run root-auditor:audit` exits non-zero on mismatch.
- Test `npm run root-auditor:test` (DoD: "wrong root submitted by registrar is
  detected"): honest root → OK; wrong root → `ROOT_MISMATCH_CRITICAL`; swapped-leaf
  root → detected; LIVE audit against the deployed pool reconstructs from events
  and matches the on-chain root. All PASS.

### P1.1 — Canonical contract architecture
`shielded_pool` is documented as the canonical `ShadePool` / `ShadeVaultV2` (header
in `contracts/stellar/shielded_pool/src/lib.rs`). The legacy `shade_vault` and
`commitment_tree` contracts carry DEPRECATED headers and are not wired into any
live flow; all env vars/docs/e2e point at `SHIELDED_POOL_CONTRACT`. There are no
longer two competing settlement paths.

### P1.11 — Fresh test report per run + fail-on-FAIL
The canonical test report is now `docs/test-report.generated.md` (gitignored),
regenerated fresh per run — no more stale-FAIL accumulation in a committed file.
`lib/report.ts` `beginReport()` archives the previous generated report to
`docs/reports/<YYYY-MM-DD-HHMMSS>.md` and writes a header with `run_id`, git
commit, timestamp, node version, network, and the deployed contract IDs;
`writeCheckReport` appends sections to it. Standalone e2e scripts reset on first
write; `e2e:all` calls `beginReport` once and shares a `SHADE_REPORT_RUN_ID` with
its children so the whole suite is one report. `npm run test-report` prints the
generated report and exits non-zero if any `FAIL` line is present (CI gate). The
legacy `docs/test-report.md` is retained as a historical deploy log only.

### Cross-validation fixes (post-audit hardening)
A review flagged gaps between docs and code; fixed:
- **C1** `circuits:build`/`circuits:test` were stale (referenced Noir, claimed no
  circuits). Replaced with the real Circom/snarkjs pipeline (compile + setup + vk
  validation for withdraw_public/private_transfer/deposit_note_mint; prove + local
  verify for each). Both pass.
- **C2** `npm run contracts:deploy:pool` (`scripts/deploy-shielded-pool.ts`) now
  deploys + wires the canonical ShadePool stack and writes `SHIELDED_POOL_CONTRACT`
  + verifier IDs to `.env.generated`; `.env.example` updated with canonical vars
  (legacy marked deprecated). The old `deploy-stellar-contracts.ts` remains for the
  legacy crates only.
- **C3** API `GET /v1/contracts` now exposes `shadePool` + the three verifiers and
  buckets legacy contracts under `deprecated`.
- **C4** `rfq_settle` now enforces solver authorization via an on-chain registry
  (`set_authorized_solver`); rogue solver key rejected `#23 UnauthorizedSolver`
  (proven in rfq-e2e). Full on-chain quote/intent lifecycle state remains PHASE 2
  (see `docs/blockers.md` deviation #2).
- **C5** The shared withdraw circuit (one circuit, op-type-gated, for withdraw/RFQ/
  CCTP) is a documented deliberate deviation, not three separate circuits — see
  `docs/blockers.md` deviation #1.
- **C6** `receive_cctp_deposit` now also enforces signal [3] destinationDomain == 27
  (Stellar CCTP domain), signal [5] burnTxHashHash != 0, and signal [6] amount6dp>0
  with amount6dp*10 >= amount7dp (`#22 WrongDepositField`). Verified by a passing
  real deposit in rfq-e2e.
- **C7** API refuses spends (`assertRootHealthy`, 409) on any unresolved
  `ROOT_MISMATCH_CRITICAL` from the root auditor, wired into withdraw/RFQ/exit prep.
- **C8** `docs/blockers.md` rewritten to reflect current status + deviations.

On-chain re-proof on the C4/C6 pool `CDVEGBVXPIHKHCR7CJDJS4JVCMOVABEFBQ4HZQ7PKK6VIO3J3V5ZRTB5`:
- rfq settle tx `540cf5930f8f93d18883f24be8a31830a9ef4c30cba0c087eb89ea5cdf5c7887`
  (deposit-with-proof leaf 0 → fill → settle), solver authorized, solver credited.
- NEGATIVE: rogue solver → `#23 UnauthorizedSolver`; swapped quote → `#14 WrongQuote`;
  double-settle rejected. All PASS.

## PHASE 1 — COMPLETE ✅
All gating protocol fixes (P1.1–P1.11) are done and verified on testnet. Next is
PHASE 2 (backend services), then 3 (Docker), 4 (Next.js), 5 (auth/user DB), 6/7
(app tests + UI e2e).

## PHASE 2 — backend service conversion (COMPLETE)
The CLI flows are now real, queue-driven services with a full API surface, wallet
auth, and per-user storage — no normal user flow needs the CLI.

### Auth + user storage (migration 004)
Wallet-signature auth: `POST /v1/auth/nonce` → client signs → `POST
/v1/auth/{evm,stellar}/verify` (EVM via ethers.verifyMessage, Stellar via ed25519)
issues an opaque session (httpOnly cookie + bearer). `GET /v1/auth/session`,
`POST /v1/auth/logout`. User: `GET/PATCH /v1/me`, `GET/POST/DELETE /v1/me/wallets`.
Per-user history: `/v1/me/{deposits,notes,withdrawals,rfq,cctp-exits,note-backups}`.
Tables: users, user_profiles, auth_nonces, user_sessions, user_wallets,
encrypted_note_backups (client-side encrypted), user_activity; user_id linked onto
protocol rows. No private keys stored for users.

### Full API surface
Config (`/v1/config`, `/v1/contracts`, `/v1/health/full`), deposits
(prepare + process + granular submit-burn/fetch-attestation/mint-forward/
register-note), notes (commitment, encrypted-backup, status), proofs
(request→queue, status), withdrawals (prepare/submit), RFQ (intents,
request-quotes via solver, quotes, accept, lock, fills, fills/:id/execute, settle),
CCTP outbound (prepare/submit/fetch-attestation/complete-mint), jobs
(`/v1/jobs/:id`), activity (`/v1/activity` + SSE `/v1/activity/stream`). All use
zod validation, idempotency keys, session auth where user-specific, activity
logging, and never log secrets. `api:test` is behavioral (auth → profile/wallets →
proof loop → RFQ → activity → logout) — PASS.

### Workers (all real, queue-driven)
- **Durable queue** (`@shade/queue`, migration 003): Postgres-as-queue with atomic
  `FOR UPDATE SKIP LOCKED`, idempotency, retry-with-backoff, event log.
- **Prover service** = real queue worker: claims proof jobs and runs the actual
  Groth16 pipeline (shared prove.ts builders) through building_witness → proving →
  verifying_locally → converting_for_soroban → ready; stores only public bytes,
  deletes the witness. `npm run prover:test` (offline) PASS for all 5 proof types.
- **API** enqueues real jobs: `POST /v1/proofs/:kind/request` → prover queue;
  `/v1/withdrawals/submit`, `/v1/cctp/outbound/submit`, `/v1/deposits/:id/process`
  → relayer queue; `GET /v1/jobs/:id` surfaces status/result/events. `npm run
  api:test` is now behavioral (drives the API→queue→prover→ready loop) — PASS.
- **Relayer service** = real queue worker: `CCTP_INBOUND` (burn → attestation →
  mint_and_forward → register-note + deposit proof), `WITHDRAW_PUBLIC_SUBMIT`,
  `WITHDRAW_CCTP_BURN`, `RFQ_SETTLE_SUBMIT`, plus granular inbound aliases and
  `CCTP_OUTBOUND_ATTESTATION` (real Circle poll) / `CCTP_OUTBOUND_MINT`. Proven on
  testnet: a queue-driven `CCTP_INBOUND` produced real burn `0x24f2e7bf2d58...` +
  registered leaf 1. `relayer:test` PASS; `RELAYER_LIVE=1` runs the real inbound.
- **Solver service**: quote signing is ed25519 (Stellar) — the scheme `rfq_settle`
  verifies + the C4 authorized-solver registry; `/v1/inventory` reports real
  Arbitrum USDC; `/v1/fill` executes a real Arbitrum USDC payout; refuses
  uncoverable quotes.
- **Root auditor** (`apps/root-auditor`) recomputes the lean-imt root from events
  and accepts either the cumulative or per-deposit (latest-leaf) registrar
  convention while still flagging forged/swapped roots. `root-auditor:test` PASS
  incl. live audit.
- `npm run services:test` aggregates prover + relayer + root-auditor — all PASS.

The **service/queue/API layer** of PHASE 2 is complete. The **product wallet
architecture** (`audit.md`) was then built and subsequently audited (`audit2.md`),
which found 12 P0 gaps in the first wallet pass. Those P0 fixes are now applied and
gated by `npm run phase2:acceptance` (all offline tests PASS):
- Privy-first identity; vault uses the real **Privy DID** (`/v1/me.privy_user_id`),
  not the local UUID. Custom wallet-nonce auth is dev-only behind
  `ENABLE_LEGACY_WALLET_AUTH`.
- **Real backup verification**: client fetch → unwrap → decrypt → compare, then a
  non-empty proof-of-decrypt is required by the backend (empty/insufficient-policy
  rejected). Browser **note vault** with random master key + wrappers
  (`packages/note-vault`).
- **User-signed** CCTP deposit: the user's wallet signs approve + burn via viem (no
  `prompt`, no backend EVM key); the relayer validates the burn and **completes the
  Stellar side** (`CCTP_INBOUND_AFTER_USER_BURN`: attestation → mint_and_forward →
  DepositNoteMint proof → receive_cctp_deposit).
- **User-signed** Stellar spends (Freighter); `STELLAR_USER_SECRET`/`toSecret`
  removed from all service runtime.
- **All user-owned state-changing routes require Privy auth + ownership** (27/27
  route-auth checks); **Privy wallet sync** added; **RFQ** intent/accept hardened;
  **dev/legacy routes** gated behind `ENABLE_DEV_ROUTES`.
- Next.js `apps/web`; services import packages, not `apps/cli`; Docker compose
  config validates; security gates expanded (behavioral). See
  `docs/test-report.generated.md` for the PASS/NOT-RUN matrix.

NOT claimed (require external resources): live Docker `up`, live UI e2e, and the
live user-signed testnet tx run (needs funded wallets + Freighter). Tracked
enhancements (not blockers): full RFQ on-chain lifecycle STATE registries,
true per-step CCTP_INBOUND decomposition, Privy Stellar Tier-2 raw signing,
proof-authorized no-Stellar-wallet exit.
