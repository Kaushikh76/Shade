# Shade Protocol Backend

Backend-only implementation workspace for Shade Protocol phase 1 through the MPC/TEE boundary.

## What Is Built (working end-to-end on testnet, no mocks)

All five core flows are implemented and verified with real testnet transactions
(tx hashes in `docs/test-report.md`):

1. **CCTP inbound** — real Arbitrum Sepolia `depositForBurnWithHook` -> Circle Iris
   attestation -> Stellar `CctpForwarder.mint_and_forward` -> ShadeVault/pool USDC
   receipt -> note commitment registration. Pre-burn footgun checks block wrong
   domain / wrong forwarder / wrong strkey type.
2. **ZK withdrawal** — real Groth16/BLS12-381 proof generated off-chain, verified
   **on the Soroban verifier contract** (`env.crypto().bls12_381().pairing_check`),
   nullifier spent once, USDC released. Double-spend reverts on-chain.
3. **Full RFQ (Path A)** — AES-256-GCM encrypted intent, ed25519-signed solver
   quote, real Arbitrum USDC fill, on-chain settlement (proof + quote signature +
   nullifier spend + solver credit), double-settle rejection, 14-state machine.
4. **CCTP outbound** — proof-bound Stellar -> Arbitrum CCTP burn; the pool verifies
   the proof, spends the nullifier, and burns via the TokenMessengerMinter.
5. **Nullifier double-spend prevention** — enforced on-chain via NullifierRegistry.

Supporting:
- TypeScript monorepo: API, relayer, solver, prover, CLI e2e runners, shared packages.
- Postgres migrations for protocol state + append-only state transitions.
- Setup script: derives the Arbitrum wallet, validates balances, generates/funds
  Stellar wallets (Friendbot), generates a solver EVM wallet; secrets only in `.env.generated`.
- Soroban contracts: `shielded_pool` (verify + nullifier + USDC release/credit/burn),
  real Groth16/BLS12-381 `proof_verifiers`, NullifierRegistry, ComplianceRegistry,
  IntentEscrow, GovernanceGuardian (legacy ShadeVault/CommitmentTree retained).
- ZK toolchain: `circuits/withdraw_public` (circom 2.x, BLS12-381), `tools/circom2soroban`
  (proof/vk byte converter, vendored Apache-2.0), Groth16 keys.

### ZK design notes (read `docs/zk-proof-system.md`)

- **Curve: BLS12-381 Groth16**, not BN254 — because Stellar's first-party, proven
  shielded-pool kit (`soroban-examples/privacy-pools` + `groth16_verifier` +
  `circom2soroban`) is BLS12-381. BN254 host functions exist (Protocol 25) but lack
  an equivalent complete, tested reference. Both are within Soroban's verify budget.
- **Merkle root computed off-chain, attested on-chain** — on-chain Poseidon inserts
  exceed the per-tx instruction budget beyond one leaf; the registrar submits the
  root with each (auditable) commitment. Security-critical steps stay on-chain.

## What Is Not Built

- No frontend.
- No Sefi, DeFi, market, semantic, or analytics indexing.
- No MPC or TEE matcher.
- No mocked acceptance path. Live commands stop if required testnet support, credentials, proof keys, contract IDs, or toolchains are missing.

## Setup

```bash
npm install
cp .env.example .env
# Fill ARB_SEPOLIA_PRIVATE_KEY and ARB_SEPOLIA_RPC_URL in .env.
npm run research:lock
npm run setup:testnet
```

Toolchains required:

```bash
brew install stellar-cli            # Soroban (v27)
rustup target add wasm32v1-none     # contract builds
cargo install --git https://github.com/iden3/circom circom   # circuit compiler (2.x)
npm install -g circomlib snarkjs    # circuit libs + Groth16 prover
```

Run Postgres:

```bash
docker compose -f infra/docker-compose.yml up -d
```

## Commands

```bash
npm run contracts:build
npm run contracts:test
npm run contracts:deploy:stellar
npm run circuits:build
npm run circuits:test
npm run proofs:test
npm run api:test
npm run cctp:inbound:e2e
npm run zk:withdraw:e2e
npm run rfq:e2e
npm run cctp:outbound:e2e
npm run e2e:all
npm run test-report
```

## Troubleshooting

- If `stellar` is missing, contract build/deploy commands stop and record a blocker.
- If `.env` has no Arbitrum Sepolia key/RPC, setup stops before creating live transactions.
- If CCTP contract IDs for Stellar are not filled from current official docs, inbound/outbound e2e stops before burn.
- If proof keys are missing, prover commands stop before on-chain verification.

Transaction reports are written to `docs/test-report.md` after live e2e execution.
