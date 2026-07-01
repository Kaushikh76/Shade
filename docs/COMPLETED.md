# Shade Protocol — Completed

## Infrastructure

- PostgreSQL 16 + Redis 7 via Docker Compose (`infra/docker-compose.yml`)
- 7 database migrations applied:
  - `001_initial.sql` — core tables (deposits, notes, nullifiers, intents, quotes, fills, settlements, exits)
  - `002_root_audit.sql` — root auditor findings table
  - `003_service_queue.sql` — durable Postgres-backed job queue (prover + relayer)
  - `004_users_auth.sql` — users, wallets, sessions, nonces, activity log
  - `005_mpc_sessions.sql` — MPC sessions table
  - `006_mpc_intents.sql` — MPC intents + encrypted shares tables
  - `007_mpc.sql` — mpc_batches, mpc_batch_signatures (full MPC persistence layer)
- Per-service Dockerfiles + `infra/docker-compose.phase2.yml` (7 services)
- `npm run security:gates` — all pass

---

## Soroban Contracts (Stellar Testnet — all deployed)

| Contract | Address | Status |
|---|---|---|
| ShieldedPool | `CCSC4FB3ZL6TV7FEMRK3QUF5LALTSI5NQFCBH4Q2VMCQMSTQK6HP2XFQ` | Active — canonical settlement, admin = deployer |
| NullifierRegistry | `CBAKCITRZLJZFQC4ISSYH5UESYFUYBFRANVM5VPDA6OH3VDTSLQ2IH67` | Active — double-spend prevention |
| VerifierWithdraw | `CBMRSDKMUKHH3UBHYMMVST2PY4STQS42WRY5IEQJWFW3HEXCHVPHZLUS` | Active — current VK, redeployed 2026-06-30 |
| VerifierTransfer | `CAZHGOFBYWHRRE2UWDMDWJKFPK6WZ47LAQXCJ7MVAYRCOYNQ5BHD5SAG` | Active — current VK |
| VerifierDepositNoteMint | `CBURZBYMSG4I4SC56LIRS3I3HBKEZCRDTTD2QEO2LUNK3YETTMW4PE7M` | Active — current VK |
| CCTP Forwarder | `CA66Q2WFBND6V4UEB7RD4SAXSVIWMD6RA4X3U32ELVFGXV5PJK4T4VSZ` | Active |
| CCTP MessageTransmitter | `CBJ6MTCKKZG73PMDZCJMSFRD7DQEMI4FKDH7CGDSV4W6FHCRBCQAVVJY` | Active |
| USDC SAC | `CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA` | Active |
| ShadeVault (legacy) | `CCUWU6FQOOE3TKZV...` | Deprecated |
| CommitmentTree (legacy) | `CC32BLTLXCAGDDQ2...` | Deprecated |

---

## ZK Circuits (Circom 2.x, BLS12-381 Groth16)

| Circuit | Status |
|---|---|
| `withdraw_public` | Full source + compiled + proven on testnet |
| `private_transfer` | Full source + compiled + proven on testnet |
| `deposit_note_mint` | Full source + compiled |
| `withdraw_cctp` | Reuses withdraw_public circuit (shared verifier) |

Shared circuit library (`circuits/lib/`): Poseidon255, Merkle proof, commitment — all implemented.

---

## Backend Services (all running)

### API — port 8080
Full REST API with:
- Wallet authentication (EVM + Stellar signature challenge/response)
- Session management with nonce TTL
- User profile + multi-wallet management
- CCTP deposit prepare, process, status
- Note commitment derive, status, encrypted backup
- ZK proof job request + status
- Withdrawal prepare + submit
- Intent create, quote fetch
- Quote accept, lock, fill, execute
- RFQ settlement
- CCTP outbound prepare + submit + granular steps
- Activity timeline + SSE stream
- Job queue status (`/v1/jobs/:id`)
- Full health (`/v1/health/full`) — DB + pool + network
- **MPC routes**: `POST /v1/mpc/intents`, `GET /v1/mpc/committee`, `POST /v1/mpc/sessions/:id/match`

### Relayer — port 8082
Postgres job queue worker with 11 job types:
- `CCTP_INBOUND` — composite: burn → attestation → mint_and_forward → register-note
- `CCTP_INBOUND_BURN`, `CCTP_FETCH_ATTESTATION`, `STELLAR_MINT_FORWARD`, `REGISTER_NOTE` — granular aliases
- `WITHDRAW_PUBLIC_SUBMIT` — submit ZK withdraw proof to ShadePool
- `WITHDRAW_CCTP_BURN` — proof-bound outbound CCTP burn
- `RFQ_SETTLE_SUBMIT` — submit RFQ settlement proof
- `CCTP_OUTBOUND_ATTESTATION` — poll Circle Iris for Stellar→Arb attestation
- `CCTP_OUTBOUND_MINT` — complete Arb mint via MessageTransmitter
- **`MPC_SETTLE_SUBMIT`** — verify committee multi-sig + call `mpc_settle` on Stellar testnet

### Solver — port 8081
- Live Arbitrum Sepolia USDC inventory check
- Quote pricing with fee BPS
- Ed25519 quote signing (Stellar keys)
- Real Arbitrum USDC fill execution (ERC-20 transfer)
- Inventory commitment hashing

### Prover — port 8083
Postgres job queue worker with 5 proof job types:
- `withdraw_public`, `withdraw_cctp`, `rfq_settlement`, `private_transfer`, `deposit_note_mint`
- Groth16/BLS12-381 proof generation pipeline (snarkjs)
- Witness deletion after proving (note secrets never persisted)
- Proof serialized to Soroban bytes format via circom2soroban

### Root Auditor
- Monitors on-chain Merkle root vs off-chain computed root
- Blocks withdrawals on `ROOT_MISMATCH_CRITICAL` findings
- Background audit loop (configurable interval)

### MPC Committee — port 8090 (nodes 8091–8093)
- 3-node in-process simulation with coordinator
- Shamir Secret Sharing (2-of-3) over BN254 prime field
- X25519 ECDH + NaCl box (XSalsa20-Poly1305) per-node share encryption
- Ed25519 multi-signature: all 3 nodes sign the match batch hash; ≥2/3 threshold required
- 30-second session matching window (configurable)
- Intent → match → signed batch → DB persistence → settler queue
- `POST /v1/mpc/intents` — submit encrypted intent with shares
- `POST /v1/mpc/sessions/:id/match` — trigger batch match + sign
- `POST /v1/mpc/verify` — verify a signed batch (used by relayer)
- `GET /v1/mpc/committee` — return public encryption/signing keys for all nodes
- Settler loop: polls `mpc_batches` every 10s, queues `MPC_SETTLE_SUBMIT` relayer jobs

---

## Protocol Flows (all proven end-to-end on Stellar Testnet)

Full transaction log: [docs/testnet-transactions.md](testnet-transactions.md)

| Flow | Description | Testnet Tx |
|---|---|---|
| CCTP Inbound | Arb Sepolia burn → Circle attestation → Stellar mint_and_forward → ShadePool note | `78e6379d...` (Stellar) |
| ZK Withdrawal | Groth16 proof (k=3 anonymity set) → nullifier spent → USDC released net of fee | `d3b0224a...` (Stellar) |
| Private Transfer | Input note → ZK proof → output note (hidden amount, no public recipient) | `72ec7c9d...` (Stellar) |
| Full RFQ (Path A) | Encrypted intent → solver ed25519 quote → Arb USDC fill → settlement proof → on-chain verify + nullifier spend | `b8f84c20...` (Stellar) / `0x08347ed9...` (Arb) |
| CCTP Outbound | ZK proof-bound Stellar burn → Circle attestation → Arb mint | `380b2c21...` (Stellar) |
| Nullifier double-spend | Enforced on-chain — second spend reverts with WasmVm InvalidAction | ✅ all flows |
| **MPC Batch Settlement** | **2 crossing intents → Shamir shares → committee match → Ed25519 multi-sig → `mpc_settle` on Soroban → both nullifiers spent atomically** | **`4c3b4ffe...` (2026-06-30)** |

---

## MPC Implementation (completed 2026-06-30)

> **P2 #16 caveat (2026-07):** "MPC" here names the settlement mechanism, not
> a privacy guarantee — the coordinator reconstructs plaintext amounts to run
> matching (see `coordinator.ts::runMatchingRound` and docs/PENDING.md). It is
> Shamir-share transport into a trusted matcher, not multi-party computation
> that keeps amounts hidden from every party. Settlement itself IS proof-backed
> and threshold-enforced with distinct signers (P0 #1/#2/#3).

### Crypto (`packages/mpc-crypto`)
- `shamirSplit` / `shamirReconstruct` — Shamir over BN254 scalar field
- `encryptShareForNode` / `decryptShare` — X25519 ECDH + NaCl box
- `signBatch` / `verifySignedBatch` — Ed25519 batch signing + threshold verification
- `splitAmountForCommittee` — convenience: split an intent amount for all nodes
- `computeBatchHash` — canonical SHA-256 over sorted match list

### Committee Server (`apps/mpc-committee`)
- 4-server in-process mesh (coordinator + node-1/2/3)
- Session assignment: intents grouped into 30s windows
- Coordinator decrypts shares from ≥2/3 nodes, reconstructs amounts, finds crossing intents
- Privacy hygiene: decrypted shares zeroed immediately after match
- Settler loop integrated — picks up signed batches, queues relayer jobs

### On-chain (`contracts/stellar/shielded_pool`)
- `set_committee(pubkeys)` — admin registers Ed25519 committee pubkeys
- `get_committee()` → `Vec<BytesN<32>>`
- `mpc_settle(nullifier_a, nullifier_b, output_commitment_a, output_commitment_b, new_root, batch_hash, signer_pubkeys, signatures)` — threshold sig verification → atomic dual-nullifier spend → Merkle root update → event emit
- Committee registered on-chain: tx `845cc7815654b382fd4401a250dabe3075fc23934cf5275af033940f61a8b550`
- First `mpc_settle` tx: `4c3b4ffee11076b6398c185098d08ece77724cd4759ecdb91d18642a925d0f78`

### Phase 2 Integration Test (`npm run mpc:integration`)
All checks pass:
- API routes ✅
- Committee coordinator ✅
- PostgreSQL persistence (5 MPC tables) ✅
- Threshold signature verification (local + remote) ✅
- Settler queue ✅
- On-chain settlement ✅

---

## Shared Packages

| Package | What it does |
|---|---|
| `cctp-utils` | CCTP constants, attestation fetching, route validation, 6dp↔7dp USDC precision |
| `evm-utils` | Ethers.js helpers, ERC-20 balance |
| `stellar-utils` | Soroban invocation, wallet generation, Friendbot funding |
| `note-crypto` | Poseidon commitment, note preimage generation |
| `proof-utils` | Groth16 proof serialization, public input encoding |
| `queue` | Postgres-backed durable job queue (SELECT FOR UPDATE SKIP LOCKED) |
| `rfq-types` | Zod schemas for intents and quotes |
| `shared-types` | Deterministic ID helpers, JSON hashing |
| **`mpc-crypto`** | **Shamir SSS, X25519 share encryption, Ed25519 batch signing, threshold verification** |

---

## Identity / Wallet Layer (Phase 2)

- **Privy-first identity** (`packages/auth-privy`, ES256 JWT verified via JWKS)
- **Note vault** (`packages/note-vault`) — AES-256-GCM, passkey-PRF / Stellar-Ed25519 / recovery-kit wrapped
- **User-signed deposits** — relayer validates burn before Stellar forward; no backend EVM key
- **User-signed Stellar spends** — backend builds XDR, Freighter signs, relayer broadcasts
- **Frontend** (`apps/web`) — Next.js with Privy login, dashboard, vault, deposit, restore, withdraw, activity
- **Security gates** — all pass (`npm run security:gates`)

---

## CLI E2E Scripts

All 6 flows have working CLI runners:
- `npm run cctp:inbound:e2e`
- `npm run zk:withdraw:e2e`
- `npm run zk:transfer:e2e`
- `npm run rfq:e2e`
- `npm run cctp:outbound:e2e`
- `npm run e2e:all`
- `npm run mpc:e2e` — Phase 1 in-memory MPC demo
- `npm run mpc:integration` — Phase 2 full-stack MPC integration test (API + DB + committee + settler + on-chain)
