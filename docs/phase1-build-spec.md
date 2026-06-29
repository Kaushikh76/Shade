You are an autonomous senior protocol/backend engineering agent. Your job is to build the complete working backend for Shade Protocol from this markdown architecture file only.

You may search the web whenever needed. Always prefer official documentation, official SDK examples, protocol repos, and current testnet contract addresses. Do not rely on stale memory for protocol addresses, CCTP domains, Stellar CLI commands, Soroban SDK versions, CCTP function signatures, or ZK verifier examples.

Your target is a real, working testnet backend up to the MPC/TEE stage. Do not implement MPC or TEE yet. Everything before that must be implemented, tested, and proven with real testnet transactions where the relevant protocol supports testnet.

The user will provide an Arbitrum Sepolia wallet private key in `.env`. That wallet will have testnet USDC and should also have enough Arbitrum Sepolia ETH for gas. You must create all needed Stellar Testnet wallets yourself from CLI or SDK, fund them with Friendbot/testnet funding flows, and write the generated Stellar addresses/secrets into `.env.generated` and `.env.local` safely.

Do not build a frontend. Build a clean backend, contracts, circuits, workers, CLI scripts, tests, and documentation.

Do not build Sefi, DeFi indexing, semantic indexing, external protocol indexing, market indexing, or analytics indexing now. Only implement the minimum event/status persistence required to track this protocol’s own transactions, CCTP messages, proof jobs, RFQ states, and settlement records.

Absolutely no mock or simulated protocol data is allowed for acceptance. Unit tests may use local fixtures, but acceptance/e2e tests must use real testnet transactions and real generated proofs. If a live testnet route or protocol feature is unavailable, stop and document the blocker with exact source links, error output, and the smallest real alternative. Do not silently replace it with a mock.

MAIN GOAL

Build a backend that proves this full flow works:

1. Read the user-provided Arbitrum Sepolia private key from `.env`.
2. Verify the Arbitrum Sepolia wallet has testnet USDC and ETH.
3. Generate Stellar Testnet wallets for deployer, protocol user, relayer, solver, and any required admin role.
4. Fund Stellar Testnet wallets with testnet XLM using Friendbot or the current official Stellar Testnet funding flow.
5. Establish any required Stellar Testnet USDC trustlines or SAC/contract setup required by current Circle/Stellar CCTP docs.
6. Deploy Stellar/Soroban contracts:

   * ShadeVault
   * CommitmentTree
   * NullifierRegistry
   * ComplianceRegistry minimal policy module
   * IntentEscrow
   * Proof verifier contracts for deposit note minting, withdrawal, RFQ settlement, and proof-of-fill/solver claim if needed
   * GovernanceGuardian/pause module
7. Generate a private note secret locally before burn.
8. Use Circle CCTP to burn native testnet USDC on Arbitrum Sepolia and mint/forward native testnet USDC into Stellar Testnet.
9. Route minted USDC through Stellar `CctpForwarder` into the Shade Vault.
10. Insert a note commitment into the CommitmentTree only after the Stellar forward and vault receipt finalize.
11. Generate ZK proof for deposit note binding if required by the design.
12. Generate ZK proof for private withdrawal.
13. Verify the proof on Stellar/Soroban using a real verifier contract.
14. Spend a nullifier exactly once and prove double-spend prevention.
15. Implement the full RFQ flow, not RFQ-lite:

    * encrypted private intent creation
    * intent hash
    * solver discovery/config
    * quote submission
    * quote signature
    * quote expiry
    * quote acceptance
    * inventory lock
    * fill object
    * proof generation
    * on-chain proof verification
    * settlement execution
    * solver credit/reimbursement or vault release
    * failure/recovery states
16. Run a real RFQ e2e test using real testnet balances and real transactions.
17. Implement outbound CCTP exit from Stellar Testnet back to Arbitrum Sepolia if currently supported by official Circle/Stellar testnet docs.
18. Bind outbound destination domain, recipient, amount, fee, nullifier, deadline, and relayer to the proof so the relayer cannot mutate them.
19. Produce a final test report with transaction hashes, contract IDs, proof artifacts, verifier results, and exact reproduction commands.

NON-NEGOTIABLES

* No mainnet.
* No real funds.
* No custom wrapped USDC.
* No generic bridge.
* Use Circle CCTP for USDC movement.
* Use Stellar/Soroban for shielded settlement.
* Use private notes with commitments and nullifiers.
* Use ZK proofs for correctness.
* Use real proof generation and real verifier validation.
* Do not store raw note secrets in server logs, database logs, crash logs, analytics, traces, or screenshots.
* Do not print private keys in console after generation.
* Never commit `.env`, `.env.local`, `.env.generated`, proving keys, user secrets, or wallet keys.
* Do not use mock CCTP, mock proofs, fake tx hashes, fake balances, fake quotes, fake attestations, or fake settlement receipts in final acceptance.
* Do not build Sefi or DeFi indexing now.
* Do not build MPC or TEE yet.
* Stop exactly at the boundary where the next module would be TEE/MPC matcher.

REPO STRUCTURE

Create a monorepo:

```text
shade-protocol/
  apps/
    api/                         # Backend API
    relayer/                     # CCTP + Stellar relayer
    solver/                      # RFQ solver service
    prover/                      # Proof generation workers
    cli/                         # One-shot scripts and e2e runners
  contracts/
    stellar/
      shade_vault/
      commitment_tree/
      nullifier_registry/
      compliance_registry/
      intent_escrow/
      governance_guardian/
      proof_verifiers/
      shared/
    evm/
      scripts/                   # CCTP interaction scripts only unless adapter is strictly needed
      abis/
  circuits/
    deposit_note_mint/
    withdraw_public/
    private_transfer/
    rfq_settlement/
    proof_of_fill_claim/
    compliance_membership/
    test_vectors/
  packages/
    shared-types/
    note-crypto/
    cctp-utils/
    stellar-utils/
    evm-utils/
    proof-utils/
    rfq-types/
  db/
    migrations/
    seed/
  docs/
    setup.md
    protocol-addresses.md
    cctp-arbitrum-stellar.md
    zk-proof-system.md
    rfq-lifecycle.md
    test-report.md
    blockers.md
    security-notes.md
  infra/
    docker-compose.yml
  .env.example
  .gitignore
  package.json
  pnpm-workspace.yaml or equivalent
  README.md
```

Use TypeScript/Node.js for backend, relayer, solver, and CLI unless a current official SDK strongly favors another language. Use Rust for Soroban contracts. Use Noir or Circom/Groth16 for circuits, but choose the stack only after confirming the best current Soroban verifier path. If the official current best path is Noir with a Soroban verifier adapter, use that. If not, use Circom/Groth16 and implement a Soroban BN254 verifier using Stellar’s current BN254 host functions.

RESEARCH-FIRST REQUIREMENT

Before writing implementation code, create `docs/research-lock.md` containing verified current facts with links and dates for:

1. Circle CCTP version to use.
2. Whether Arbitrum Sepolia to Stellar Testnet CCTP is supported.
3. Current Circle CCTP domain IDs for Arbitrum Sepolia and Stellar Testnet.
4. Current Arbitrum Sepolia USDC contract address.
5. Current CCTP TokenMessenger/MessageTransmitter addresses on Arbitrum Sepolia.
6. Current Stellar Testnet CCTP contracts:

   * CctpForwarder
   * MessageTransmitter
   * TokenMessenger/Minter if applicable
   * Stellar testnet USDC asset/SAC details
7. Correct CCTP API/Iris attestation endpoint.
8. Correct Circle faucet/testnet USDC flow if more test USDC is needed.
9. Stellar CLI version and install command.
10. Stellar SDK version.
11. Stellar Testnet RPC URL and network passphrase.
12. Soroban SDK version.
13. Current way to deploy Soroban contracts to Stellar Testnet.
14. Current way to fund Stellar accounts using Friendbot or official funding flow.
15. Current BN254/Poseidon/Poseidon2 host function support and example verifier contracts.
16. Current official examples for CCTP to/from Stellar.
17. Exact CCTP Stellar footguns:

    * raw 32-byte address payload
    * Stellar `G`, `M`, `C` address type confusion
    * `mintRecipient` must be `CctpForwarder`
    * `destinationCaller` must be `CctpForwarder`
    * hook data must encode `forwardRecipient`
    * Stellar USDC precision differences

Do not proceed to protocol implementation until `docs/research-lock.md` is complete.

ENVIRONMENT DESIGN

Create `.env.example` with:

```env
NODE_ENV=testnet

# User-provided wallet
ARB_SEPOLIA_PRIVATE_KEY=
ARB_SEPOLIA_RPC_URL=
ARB_SEPOLIA_CHAIN_ID=
ARB_SEPOLIA_USDC_ADDRESS=
ARB_SEPOLIA_CCTP_TOKEN_MESSENGER=
ARB_SEPOLIA_CCTP_MESSAGE_TRANSMITTER=
ARB_SEPOLIA_CCTP_DOMAIN=

# Circle / CCTP
CCTP_ATTESTATION_API_BASE=
CCTP_VERSION=
STELLAR_CCTP_DOMAIN=
STELLAR_CCTP_FORWARDER_CONTRACT=
STELLAR_CCTP_MESSAGE_TRANSMITTER_CONTRACT=
STELLAR_TESTNET_USDC_ASSET_CODE=
STELLAR_TESTNET_USDC_ISSUER=
STELLAR_TESTNET_USDC_SAC_CONTRACT=

# Stellar
STELLAR_NETWORK=testnet
STELLAR_NETWORK_PASSPHRASE="Test SDF Network ; September 2015"
STELLAR_RPC_URL=
STELLAR_HORIZON_URL=
STELLAR_DEPLOYER_SECRET=
STELLAR_DEPLOYER_PUBLIC=
STELLAR_USER_SECRET=
STELLAR_USER_PUBLIC=
STELLAR_RELAYER_SECRET=
STELLAR_RELAYER_PUBLIC=
STELLAR_SOLVER_SECRET=
STELLAR_SOLVER_PUBLIC=

# Generated EVM solver wallet for RFQ cross-chain/proof-of-fill tests
ARB_SOLVER_PRIVATE_KEY=
ARB_SOLVER_ADDRESS=

# Contracts generated after deploy
SHADE_VAULT_CONTRACT=
COMMITMENT_TREE_CONTRACT=
NULLIFIER_REGISTRY_CONTRACT=
COMPLIANCE_REGISTRY_CONTRACT=
INTENT_ESCROW_CONTRACT=
GOVERNANCE_GUARDIAN_CONTRACT=
VERIFIER_DEPOSIT_CONTRACT=
VERIFIER_WITHDRAW_CONTRACT=
VERIFIER_RFQ_CONTRACT=
VERIFIER_FILL_CLAIM_CONTRACT=

# Backend
DATABASE_URL=
REDIS_URL=
API_PORT=8080
SOLVER_PORT=8081
RELAYER_PORT=8082
PROVER_PORT=8083

# Security
ENCRYPTION_MASTER_KEY=
INTENT_ENCRYPTION_PUBLIC_KEY=
INTENT_ENCRYPTION_PRIVATE_KEY=
SOLVER_SIGNING_PRIVATE_KEY=
SOLVER_SIGNING_PUBLIC_KEY=

# Proofs
PROOF_SYSTEM=
PROVING_KEY_PATH=
VERIFYING_KEY_PATH=
CIRCUIT_BUILD_DIR=
```

Create `scripts/setup-env.ts` that:

1. Reads `.env`.
2. Validates `ARB_SEPOLIA_PRIVATE_KEY`.
3. Derives user Arbitrum Sepolia address.
4. Checks ETH balance.
5. Checks USDC balance.
6. Generates missing Stellar wallets.
7. Funds Stellar wallets on Testnet.
8. Establishes required USDC trustlines if current docs require them.
9. Generates a solver EVM wallet if missing.
10. Transfers a small amount of Arbitrum Sepolia ETH and USDC from user wallet to solver wallet if RFQ proof-of-fill requires solver EVM inventory.
11. Writes generated values to `.env.generated`.
12. Updates `.env.local` only if explicitly configured.
13. Never prints private keys to stdout.
14. Prints public addresses, balances, and next actions.

BACKEND SERVICES

Build these services:

1. API service
2. Relayer service
3. Solver service
4. Prover worker
5. CLI/e2e runner

API SERVICE REQUIREMENTS

Implement these endpoints:

```text
GET  /health
GET  /v1/config
GET  /v1/contracts
GET  /v1/balances/testnet
POST /v1/setup/validate

POST /v1/deposits/prepare
GET  /v1/deposits/:deposit_id
POST /v1/deposits/:deposit_id/submit-burn
POST /v1/deposits/:deposit_id/fetch-attestation
POST /v1/deposits/:deposit_id/mint-forward
POST /v1/deposits/:deposit_id/register-note

POST /v1/notes/local/derive
POST /v1/notes/commitment
GET  /v1/notes/:commitment/status

POST /v1/proofs/deposit/request
POST /v1/proofs/withdraw/request
POST /v1/proofs/rfq/request
POST /v1/proofs/fill-claim/request
GET  /v1/proofs/:proof_job_id

POST /v1/withdrawals/prepare
POST /v1/withdrawals/submit
GET  /v1/withdrawals/:withdrawal_id

POST /v1/intents
GET  /v1/intents/:intent_hash
GET  /v1/intents/:intent_hash/quotes
POST /v1/solver/quotes
POST /v1/quotes/:quote_id/accept
POST /v1/quotes/:quote_id/lock
POST /v1/fills
POST /v1/rfq/settle
GET  /v1/settlements/:settlement_id

POST /v1/cctp/outbound/prepare
POST /v1/cctp/outbound/submit
GET  /v1/cctp/outbound/:exit_id

GET  /v1/test-report/latest
```

All endpoints must use strict validation schemas. Use deterministic IDs. Use idempotency keys for state-changing operations. Persist every state transition in Postgres.

DATABASE SCHEMA

Implement migrations for:

```sql
testnet_wallets
protocol_contracts
cctp_deposits
note_commitments
nullifier_spends
proof_jobs
withdrawals
intents
quotes
quote_acceptances
solver_inventory_locks
fills
settlements
cctp_exits
state_transitions
e2e_test_runs
```

Do not store plaintext note secrets, private keys, raw witnesses, or decrypted RFQ payloads in Postgres.

CCTP INBOUND REQUIREMENTS

Implement Arbitrum Sepolia to Stellar Testnet CCTP deposit.

Flow:

1. Generate local private note:

   * asset ID
   * amount
   * owner public key
   * spend public key
   * blinding
   * nonce
   * compliance tag
   * source context
   * memo commitment
2. Compute Poseidon note commitment.
3. Prepare CCTP burn from Arbitrum Sepolia.
4. Set Stellar destination domain correctly.
5. Set `mintRecipient` to Stellar `CctpForwarder`.
6. Set `destinationCaller` to Stellar `CctpForwarder`.
7. Encode hook data so `forwardRecipient` is the ShadeVault contract address.
8. Normalize USDC precision correctly.
9. Submit Arbitrum Sepolia burn transaction.
10. Persist burn tx hash and CCTP nonce/message ID.
11. Poll Circle attestation API until attestation is ready.
12. Submit `mint_and_forward(message, attestation)` to Stellar `CctpForwarder`.
13. Verify the minted USDC reached ShadeVault.
14. Call `receive_cctp_deposit` or equivalent on ShadeVault with:

    * source domain
    * CCTP nonce/message ID
    * source tx hash
    * amount normalized to Stellar precision
    * asset ID
    * note commitment
    * encrypted note payload hash
    * policy ID
15. Insert the note commitment into CommitmentTree.
16. Persist leaf index and root.
17. Write all tx hashes to test report.

CCTP INBOUND TESTS

Must test:

1. Real Arbitrum Sepolia burn.
2. Real Circle attestation fetch.
3. Real Stellar `mint_and_forward`.
4. Real ShadeVault receipt.
5. Real note commitment insertion.
6. Wrong destination domain blocked before burn.
7. Wrong Stellar address type blocked before burn.
8. `mintRecipient` not equal to CctpForwarder blocked before burn.
9. `destinationCaller` not equal to CctpForwarder blocked before burn.
10. Malformed hook data blocked before burn.
11. Duplicate nonce cannot mint second note.
12. Precision conversion tested for small and larger amounts.
13. Forward succeeds but note registration failure is recoverable and documented.

STELLAR CONTRACTS

Implement Soroban contracts.

1. `CommitmentTree`

Required functions:

```rust
initialize(admin, depth)
append(commitment) -> (leaf_index, new_root)
is_known_root(root) -> bool
get_latest_root() -> root
get_leaf_count() -> u32
get_leaf(index) -> commitment
pause()
unpause()
```

Requirements:

* append-only
* deterministic root update
* no duplicate leaf index
* known root history
* bounded root history if needed
* events for insert/root update

2. `NullifierRegistry`

Required functions:

```rust
initialize(admin)
spend(nullifier) -> bool
is_spent(nullifier) -> bool
pause()
unpause()
```

Requirements:

* nullifier can be spent once only
* no overwrite
* emit event
* domain separation included in circuit

3. `ShadeVault`

Required functions:

```rust
initialize(admin, usdc_sac, tree, nullifiers, compliance_registry)
receive_cctp_deposit(source_domain, cctp_nonce, asset, amount, commitment, encrypted_note_payload_hash, policy_id) -> deposit_leaf_index
private_transfer_settle(verifier_id, proof, public_inputs) -> receipt
withdraw_public(proof, public_inputs, recipient) -> receipt
withdraw_cctp(proof, public_inputs, destination_domain, destination_recipient) -> receipt
rfq_settle(proof, public_inputs, quote_hash, solver_id) -> receipt
solver_claim_or_credit(proof, public_inputs) -> receipt
pause(reason_hash)
unpause()
```

Requirements:

* assets released only after valid proof
* vault balance must be >= outstanding commitments where publicly accountable
* no release on failed proof
* no release on spent nullifier
* pause blocks state-changing functions
* no admin fund drain
* events for all state changes

4. `ComplianceRegistry`

Implement minimal real policy support:

```rust
initialize(admin)
set_policy(policy_id, allow_root, deny_root, valid_from, valid_until, rules_hash)
get_policy(policy_id)
is_policy_active(policy_id)
```

No fake compliance checks. If full ASP is not implemented, create a real default testnet policy with active root and bind policy ID into proofs.

5. `IntentEscrow`

Required functions:

```rust
initialize(admin, vault, nullifier_registry)
register_intent(intent_hash, expiry_ledger, policy_id, intent_commitment)
register_quote(quote_hash, solver_id, valid_until_ledger)
accept_quote(intent_hash, quote_hash, user_signature_hash)
lock_solver_inventory(quote_hash, lock_hash)
settle_rfq(proof, public_inputs)
mark_failed_recoverable(intent_hash, reason_hash)
```

Requirements:

* quote expiry enforced
* accepted quote cannot be modified
* solver cannot claim/fill without accepted quote
* settlement proof binds quote hash
* solver fee bound by user-signed max
* replay protection

6. `GovernanceGuardian`

Implement:

```rust
initialize(admin, guardian)
pause_contract(contract_id, reason_hash)
unpause_contract(contract_id)
```

Test only. No upgrade mechanism unless required.

ZK CIRCUITS

Implement real circuits. Choose proof system based on current best working Soroban verifier path.

Minimum circuits:

1. `DepositNoteMint`

Proves:

* note preimage hashes to public commitment
* amount matches public CCTP amount
* asset matches public asset
* policy ID is bound
* CCTP nonce/source context is bound

Public inputs:

```text
source_domain
cctp_nonce_hash
burn_tx_hash_hash
amount_usdc_7dp
asset_id
recipient_vault
commitment
policy_id
deposit_leaf_index
pool_id
chain_id
```

Private witness:

```text
note preimage
blinding
nonce
owner secret or derived owner key material where needed
```

2. `WithdrawPublic`

Proves:

* input note commitment exists in known root
* Merkle path is valid
* nullifier derives from note secret
* asset matches
* amount matches
* recipient is bound
* fee is bound
* deadline is bound
* policy ID is bound
* pool ID/domain prevents replay

Public inputs:

```text
root
nullifier
asset_id
amount_public
recipient
relayer_fee
deadline_ledger
policy_id
pool_id
chain_id
```

Private witness:

```text
note
Merkle path
owner secret
```

3. `PrivateTransfer`

Proves:

* input notes exist
* nullifiers valid
* output commitments formed correctly
* value conservation
* fee bound
* policy bound

4. `RFQSettlement`

This is mandatory and must not be mocked.

Proves:

* user owns valid private input note
* input note is in accepted Merkle root
* nullifier derives correctly
* nullifier is not already spent at contract level
* accepted quote hash matches the user-accepted quote
* quote was signed by the solver
* solver is authorized/configured
* quote has not expired
* fill respects:

  * input asset
  * output asset
  * exact input / exact output / max input mode
  * minimum output
  * maximum fee
  * destination commitment or public recipient
  * settlement method
* output commitment is correctly formed
* settlement conserves value after fee
* policy ID is bound
* pool ID/domain prevents replay

Public inputs:

```text
root
nullifier
quote_hash
intent_hash
solver_id
input_asset
output_asset
public_amount_or_commitment
output_commitment
fee_commitment_or_fee_public
deadline_ledger
valid_until_ledger
policy_id
pool_id
chain_id
```

Private witness:

```text
input note
Merkle path
quote details
solver signature witness if circuit-supported, otherwise quote signature verified in contract and hash bound in proof
fill details
output note preimage
fee details
owner secret
```

If signature verification inside the circuit is too expensive, verify solver signature in Soroban contract and bind the verified `quote_hash` into the proof. Document this design clearly.

5. `ProofOfFillClaim`

Required if RFQ settlement uses solver-fronted destination funds.

Proves:

* accepted intent hash
* fill receipt hash
* solver ID
* destination tx hash hash
* amount
* recipient
* deadline
* quote hash
* policy ID

For cross-chain solver fills, verify the destination transaction as much as possible using available testnet evidence. If on-chain light verification is out of scope, bind the destination tx hash and require an off-chain relayer/oracle attestation signed by a configured testnet verifier key. This is allowed only if the attestation is generated from a real testnet transaction and the real transaction hash is included in the final report. Do not fake a tx hash.

PROOF WORKER

Build a prover service that:

1. Accepts proof jobs.
2. Validates all inputs.
3. Builds witness locally.
4. Generates proof.
5. Stores proof artifact path and public inputs hash.
6. Never stores raw witness after proof generation.
7. Never logs secrets.
8. Submits proof to verifier contract when requested.
9. Returns status:

   * queued
   * generating_witness
   * proving
   * verifying_locally
   * submitting_onchain
   * verified
   * failed

Add local verification before on-chain submission.

RFQ FULL IMPLEMENTATION

Do not build RFQ-lite. Build the full RFQ backend state machine.

RFQ entities:

```text
Intent
Quote
QuoteAcceptance
SolverInventoryLock
Fill
Settlement
RecoveryState
```

Intent fields:

```json
{
  "intent_type": "PRIVATE_RFQ",
  "version": "1.0",
  "user_pubkey_commitment": "field",
  "input_asset": "USDC:Stellar:SAC",
  "output_asset": "USDC:ArbitrumSepolia | USDC:Stellar:SAC | XLM:Stellar",
  "amount_mode": "exact_in | exact_out | max_in",
  "amount_commitment": "field",
  "min_output_commitment": "field",
  "expiry_ledger": 0,
  "allowed_solvers_root": "field",
  "compliance_policy_id": "bytes32",
  "destination_commitment": "field",
  "replay_domain": "shade:stellar:testnet:rfq:v1",
  "signature": "user signature"
}
```

Quote fields:

```json
{
  "quote_id": "uuid",
  "intent_hash": "bytes32",
  "solver_id": "string",
  "input_asset": "USDC",
  "output_asset": "USDC:ArbitrumSepolia | USDC:Stellar | XLM:Stellar",
  "gross_input": "decimal",
  "net_output": "decimal",
  "fee": "decimal",
  "valid_until_ledger": 0,
  "solver_inventory_commitment": "field",
  "settlement_method": "private_note | stellar_payout | cctp_exit | proof_of_fill",
  "quote_signature": "signature"
}
```

RFQ lifecycle:

```text
INTENT_CREATED
INTENT_ENCRYPTED
INTENT_PUBLISHED_TO_ALLOWED_SOLVERS
QUOTE_RECEIVED
QUOTE_VALIDATED
QUOTE_ACCEPTED
SOLVER_INVENTORY_LOCKED
FILL_CREATED
FILL_EXECUTED_IF_REQUIRED
PROOF_REQUESTED
PROOF_GENERATED
PROOF_VERIFIED_LOCALLY
SETTLEMENT_SUBMITTED
SETTLED
FAILED_RECOVERABLE
EXPIRED
CANCELLED
```

RFQ rules:

1. Intent plaintext must be encrypted at rest.
2. Quote must be signed by solver.
3. User acceptance must be signed.
4. Accepted quote cannot be modified.
5. Quote expiry must be enforced.
6. Solver inventory lock must be based on real testnet balances.
7. Settlement must bind quote hash and intent hash.
8. Settlement must spend the user nullifier once.
9. Settlement must create output commitment or execute public payout.
10. Failed settlement must not spend nullifier.
11. Expired intent must be recoverable/cancellable.
12. All state transitions must be persisted.

SOLVER SERVICE

Implement a real testnet solver service.

The solver must:

1. Maintain real testnet wallet balances.
2. Quote only when it has sufficient testnet inventory.
3. Sign quotes.
4. Lock inventory after quote acceptance.
5. Execute fill if settlement method requires it.
6. Produce fill receipt from real testnet transaction.
7. Submit settlement or reimbursement claim.
8. Release inventory lock on expiry/failure.
9. Refuse quotes when balance is insufficient.

For e2e tests, it is acceptable to run one internal solver, but the backend design must support multiple solvers.

Solver quote pricing can use deterministic configured basis points because this is testnet. However, the quote must be generated from real balances, signed, stored, accepted, and settled. Do not call it a mock. Document pricing formula.

Recommended RFQ test path:

Path A: Private Stellar USDC note → RFQ proof-of-fill → Arbitrum Sepolia USDC payout.

1. User starts with Arbitrum Sepolia USDC.
2. Some USDC is bridged into Shade Vault on Stellar through CCTP.
3. Solver EVM wallet is funded with small Arbitrum Sepolia USDC and gas from user test wallet during setup.
4. User creates encrypted RFQ asking for USDC payout on Arbitrum Sepolia.
5. Solver quotes exact output minus fee.
6. User accepts.
7. Solver transfers real Arbitrum Sepolia USDC to destination address.
8. Fill receipt includes real Arbitrum Sepolia tx hash.
9. Prover generates RFQ/proof-of-fill settlement proof.
10. Stellar settlement spends user note nullifier.
11. Solver receives claim/credit from ShadeVault or is marked reimbursed according to implemented design.
12. Final report includes Arbitrum fill tx and Stellar settlement tx.

Path B: Private Stellar USDC note → RFQ → Stellar public USDC payout.

Use this only if Path A is blocked by testnet support. It must still use a real signed quote, real proof, real Stellar transaction, and real vault release.

OUTBOUND CCTP

Implement outbound CCTP from Stellar Testnet to Arbitrum Sepolia if current Circle/Stellar docs support this route.

Requirements:

1. User spends private note.
2. ZK proof binds:

   * root
   * nullifier
   * amount
   * destination CCTP domain
   * Arbitrum recipient bytes
   * relayer fee
   * deadline
   * policy ID
3. Stellar contract releases/burns USDC through the correct CCTP flow.
4. Relayer cannot change destination, recipient, amount, or fee.
5. Attestation/mint on Arbitrum Sepolia is completed if required by route.
6. Final tx hashes are reported.

If outbound Stellar → Arbitrum Sepolia is unavailable, document the exact blocker and implement the closest official supported Stellar Testnet CCTP route with real transactions. Do not mock.

TESTING

Implement these commands:

```bash
npm run research:lock
npm run setup:testnet
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

Acceptance tests must include:

CCTP:

1. Arbitrum Sepolia USDC balance check.
2. Arbitrum Sepolia burn tx.
3. Circle attestation retrieval.
4. Stellar CctpForwarder mint_and_forward tx.
5. ShadeVault receive deposit tx.
6. Commitment insertion.
7. Duplicate nonce rejection.
8. Wrong route pre-burn rejection.
9. Wrong forwarder pre-burn rejection.
10. Precision conversion.

ZK:

1. Deposit commitment proof generated and verified.
2. Withdraw proof generated and verified locally.
3. Withdraw proof verified on Stellar.
4. Wrong root fails.
5. Wrong recipient fails.
6. Wrong amount fails.
7. Wrong asset fails.
8. Double nullifier fails.
9. Replay across pool/chain fails.
10. Fee above max fails.

RFQ:

1. Intent encrypted and stored.
2. Solver receives eligible intent.
3. Solver refuses quote if insufficient real balance.
4. Solver creates signed quote.
5. User accepts quote.
6. Accepted quote cannot be modified.
7. Quote expires correctly.
8. Solver inventory lock created.
9. Real testnet fill executed where required.
10. RFQ settlement proof generated.
11. RFQ settlement proof verified locally.
12. RFQ settlement proof verified on Stellar.
13. Settlement spends nullifier once.
14. Output commitment or public payout created.
15. Solver claim/credit recorded.
16. Failed proof leaves note recoverable.
17. Expired intent leaves note recoverable.

Security:

1. Private keys are not logged.
2. Note secrets are not logged.
3. Witnesses are not persisted after proof generation.
4. `.env*` is gitignored.
5. Secret scanning passes.
6. API validation rejects malformed payloads.
7. State transitions are idempotent.
8. Relayer mutation attempts fail.
9. Solver fee mutation fails.
10. Quote hash mismatch fails.

DOCS TO PRODUCE

1. `README.md`

Must include:

* what was built
* what is not built
* setup steps
* env setup
* testnet funding steps
* exact commands
* troubleshooting
* tx report location

2. `docs/research-lock.md`

Verified current docs and addresses.

3. `docs/cctp-arbitrum-stellar.md`

Detailed CCTP flow with exact fields and footgun warnings.

4. `docs/zk-proof-system.md`

Circuit choice, proof system, public inputs, witnesses, verifier deployment, known limitations.

5. `docs/rfq-lifecycle.md`

Full RFQ lifecycle and state machine.

6. `docs/test-report.md`

Generated after e2e. Must include:

```text
Date/time
Git commit
Network names
Wallet public addresses
Contract IDs
Arbitrum Sepolia balances before/after
Stellar balances before/after
CCTP burn tx hash
CCTP message/nonce
Circle attestation status
Stellar mint_and_forward tx hash
Vault deposit tx hash
Commitment leaf/root
Proof job IDs
Local verifier results
On-chain verifier tx hashes
RFQ intent hash
Quote ID/hash
Quote signature verification result
Fill tx hash
Settlement tx hash
Nullifier
Double-spend test result
Outbound CCTP tx hashes if available
Any blockers
```

7. `docs/blockers.md`

Only for real blockers. Include:

* exact command
* exact error
* source link
* why it blocks no-mock acceptance
* proposed real alternative

IMPLEMENTATION ORDER

Follow this order exactly:

PHASE 0 — Research and Environment

1. Create repo.
2. Install toolchains.
3. Create `.env.example`.
4. Create research lock.
5. Validate Arbitrum Sepolia wallet.
6. Generate/fund Stellar Testnet wallets.
7. Generate/fund solver wallets.
8. Write setup report.

PHASE 1 — Stellar Contracts

1. Implement CommitmentTree.
2. Implement NullifierRegistry.
3. Implement ComplianceRegistry.
4. Implement ShadeVault.
5. Implement IntentEscrow.
6. Implement GovernanceGuardian.
7. Unit tests.
8. Deploy to Stellar Testnet.
9. Record contract IDs.

PHASE 2 — Note Crypto

1. Implement note structure.
2. Implement Poseidon commitment.
3. Implement nullifier derivation.
4. Implement Merkle path utilities.
5. Implement encrypted note payload.
6. Unit tests and test vectors.

PHASE 3 — CCTP Inbound

1. Build CCTP route planner.
2. Build CCTP burn submitter.
3. Build attestation fetcher.
4. Build Stellar mint_and_forward submitter.
5. Build vault deposit registration.
6. Real e2e Arbitrum Sepolia → Stellar Testnet.
7. Record tx hashes.

PHASE 4 — ZK Proofs

1. Choose proof stack.
2. Implement DepositNoteMint.
3. Implement WithdrawPublic.
4. Implement PrivateTransfer if required for RFQ output notes.
5. Implement local verification.
6. Implement Soroban verifier contracts.
7. Deploy verifiers.
8. Run real on-chain verification.

PHASE 5 — Withdrawal

1. Implement withdrawal API.
2. Generate proof.
3. Submit proof to Stellar.
4. Spend nullifier.
5. Release public Stellar asset.
6. Test replay/double-spend prevention.

PHASE 6 — Full RFQ

1. Implement encrypted intent service.
2. Implement solver service.
3. Implement quote lifecycle.
4. Implement inventory lock.
5. Implement fill execution.
6. Implement RFQSettlement circuit.
7. Implement RFQ verifier contract.
8. Implement settlement call.
9. Run full RFQ e2e with real testnet tx.

PHASE 7 — CCTP Outbound

1. Verify official route support.
2. Implement proof-bound outbound CCTP.
3. Run real e2e if supported.
4. Document blocker if unsupported.

PHASE 8 — Final Acceptance

1. Run `npm run e2e:all`.
2. Generate test report.
3. Verify no mocks.
4. Verify no secret leakage.
5. Verify docs.
6. Stop before TEE/MPC.

DEFINITION OF DONE

This task is complete only when:

1. Fresh clone works.
2. `.env.example` is complete.
3. Setup script generates/funds Stellar wallets.
4. Arbitrum Sepolia balances are validated.
5. Stellar contracts are deployed to Testnet.
6. CCTP inbound uses real Arbitrum Sepolia and Stellar Testnet transactions.
7. Private note commitment is inserted on-chain.
8. ZK proofs are generated locally.
9. ZK proofs are verified locally.
10. ZK proofs are verified on Stellar/Soroban.
11. Nullifier double-spend is impossible and tested.
12. Full RFQ state machine is implemented.
13. RFQ uses signed quotes and real inventory checks.
14. RFQ e2e uses real testnet transactions.
15. Outbound CCTP is implemented if official testnet route supports it.
16. No DeFi/Sefi indexing is built.
17. No TEE/MPC is built.
18. Final report contains real tx hashes and contract IDs.
19. No mock data is used in final acceptance.
20. `docs/blockers.md` is empty or contains only genuine protocol/testnet blockers with evidence.

WHEN BLOCKED

If blocked:

1. Search official docs.
2. Search official SDK examples.
3. Search protocol GitHub issues.
4. Try the smallest reproducible command.
5. Record exact error.
6. Do not fake the result.
7. Do not mock.
8. Do not skip silently.
9. Put blocker in `docs/blockers.md`.
10. Continue only if there is a real testnet alternative.

FINAL OUTPUT

When finished, print:

```text
SHADE BACKEND BUILD COMPLETE

Repo:
Commit:
Networks:
Arbitrum Sepolia user address:
Arbitrum Sepolia solver address:
Stellar deployer:
Stellar user:
Stellar relayer:
Stellar solver:

Contracts:
- ShadeVault:
- CommitmentTree:
- NullifierRegistry:
- ComplianceRegistry:
- IntentEscrow:
- GovernanceGuardian:
- VerifierDeposit:
- VerifierWithdraw:
- VerifierRFQ:
- VerifierFillClaim:

E2E Results:
- CCTP inbound: PASS/FAIL
- Deposit note: PASS/FAIL
- ZK withdrawal: PASS/FAIL
- Nullifier double-spend prevention: PASS/FAIL
- Full RFQ: PASS/FAIL
- RFQ settlement proof: PASS/FAIL
- CCTP outbound: PASS/FAIL/SUPPORTED-BLOCKED

Important tx hashes:
- Arbitrum burn:
- Stellar mint_and_forward:
- Vault deposit:
- Withdrawal proof verification:
- RFQ fill:
- RFQ settlement:
- Outbound CCTP:

Docs:
- README.md
- docs/research-lock.md
- docs/cctp-arbitrum-stellar.md
- docs/zk-proof-system.md
- docs/rfq-lifecycle.md
- docs/test-report.md
- docs/blockers.md
```

Remember: build a real backend. No frontend. No mocks. No Sefi. No DeFi indexing. No TEE/MPC yet. Stop only after bridge, notes, ZK proof generation, ZK verification, withdrawal, full RFQ, and testnet settlement are working or a real documented protocol blocker prevents completion.
