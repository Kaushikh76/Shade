
---
title: "Shade Protocol Architecture Bible"
subtitle: "Private cross-chain USDC settlement, RFQ, PayFi, and remittance on Stellar"
author: "Prepared for hackathon build execution"
date: "2026-06-27"
toc: true
toc-depth: 3
numbersections: true
geometry: margin=0.65in
fontsize: 10pt
mainfont: DejaVu Sans
monofont: DejaVu Sans Mono
colorlinks: true
linkcolor: blue
urlcolor: blue
---

# Executive summary

Shade Protocol is a private cross-chain liquidity and PayFi network built around one hard design rule: **do not build a generic bridge first**. Use Circle CCTP for native USDC movement, Stellar/Soroban for shielded settlement, ZK proofs for correctness, and a staged private execution layer for RFQ, remittance, block trades, netting, and later decentralized matching.

The MVP should be **Private USDC Remit + RFQ on Stellar**:

1. A user brings USDC from Base, Ethereum, Arbitrum, Solana, or Stellar.
2. CCTP moves the native USDC into Stellar without wrapped assets or bridge liquidity pools.
3. Stellar `CctpForwarder` forwards minted USDC into the Shade Vault.
4. Shade creates a private note commitment for the user.
5. The user submits an encrypted RFQ/remittance intent.
6. Solvers, market makers, or anchors quote privately.
7. A ZK proof settles the fill on Stellar by spending input nullifiers and creating output commitments.
8. The user withdraws to Stellar, exits to another CCTP-supported chain, receives a fiat payout through an anchor, or generates a view-key compliance receipt.

This document is written as a **build bible for an autonomous AI agent**. It defines system architecture, modules, contracts, circuits, infra, APIs, state machines, testing, deployment, risk gates, and phase-by-phase build tasks. The goal is not just to explain the idea. The goal is to make implementation unambiguous.

## One-line product

**Shade lets users and businesses move USDC privately across chains and into real-world payout rails, using Stellar as the ZK settlement and remittance layer.**

## One-line technical architecture

**CCTP for native USDC transport, SAC assets for Stellar custody, Poseidon commitments/nullifiers for private notes, BN254 verifier contracts for settlement validity, encrypted RFQs for private execution, ASP/view keys for compliance, and Sefi-style semantic indexing for agent-readable blockchain state.**

## Current research anchors

The architecture is grounded in the following verified facts:

- Circle CCTP burns USDC on a source chain and mints native USDC on the destination chain, without traditional bridge liquidity pools or wrapped tokens.[^circle-cctp]
- Stellar's CCTP documentation says CCTP supports native USDC transfers between Stellar and other CCTP-enabled chains with no wrapped assets and no third-party bridges.[^stellar-cctp]
- Circle's Stellar CCTP docs require special handling: Stellar CCTP uses a raw 32-byte address payload and seven-decimal USDC precision, and `mintRecipient` plus `destinationCaller` must be set correctly to the `CctpForwarder` to avoid permanently stuck funds.[^circle-stellar-cctp]
- Stellar Protocol 25 introduced BN254 and Poseidon/Poseidon2 ZK-friendly host functions; Stellar docs also warn that these primitives are not a full privacy system by themselves.[^stellar-zk]
- Stellar privacy docs describe privacy pools, Association Set Providers, view keys, and a Nethermind research prototype that is explicitly not audited for production assets.[^stellar-privacy]
- SAC is the correct way for Soroban contracts to interact with Stellar assets; SAC is an API to the same asset, not a wrapped token, and current SAC does not expose order-book functionality.[^stellar-sac]
- SEP-31 is a Stellar standard for cross-border payments between financial accounts outside Stellar, and SEP-38 is an anchor RFQ/quote API for on-chain/off-chain asset exchange.[^sep31][^sep38]
- MoneyGram Ramps enables wallets and exchanges to facilitate USDC deposits and withdrawals on Stellar, and Stellar's MoneyGram page describes cash-to-digital-dollar and digital-dollar-to-cash access in 180+ countries.[^moneygram-dev][^moneygram-stellar]
- Renegade uses MPC for order matching and ZKPs for settlement, which is the right model for true dark-pool privacy.[^renegade]
- Penumbra records value as private notes in a multi-asset shielded pool and uses nullifiers to prevent double-spends while hiding which note was spent.[^penumbra-pool]
- ERC-7683 defines a solver/filler model for cross-chain intents, where users express outcomes and solvers execute across chains.[^erc7683]
- The Aztec-EVM bridge design validates the filler-based private intent pattern, where fillers claim funds only after proving execution.[^aztec-evm]

# Product definition

## What Shade is

Shade is **not** a mixer. Shade is **not** a general lock-and-mint bridge. Shade is **not** a public DEX.

Shade is a compliance-ready private settlement and execution protocol with these products:

| Product | Description | MVP? |
|---|---|---:|
| Shade Shield | Shield USDC from a CCTP-supported chain into a private Stellar note. | Yes |
| Shade RFQ | Request private quotes for swaps, payouts, and cross-chain movement. | Yes |
| Shade Remit | Use Stellar anchors or payout partners for fiat payout flows. | Yes, simulated or partner-gated |
| Shade Cross | Exit to another CCTP-supported chain or use a solver proof-of-fill. | Yes for CCTP; later for intent fill |
| Shade Pool | Private USDC/XLM or USDC/asset block trade/crossing module. | V2 |
| Shade Net | Institutional private netting layer for market makers and treasuries. | V3 |
| Shade View | Selective disclosure, receipt, view-key and compliance reporting. | Yes |

## What Shade deliberately does not build first

Do not build these in v1:

- Any-token anonymous bridge.
- Custom wrapped USDC.
- Unpermissioned no-compliance remittance.
- Fully decentralized MPC matching.
- Continuous hidden order book.
- All-country fiat payout.
- Production private-payment pool with real assets before audits.

## Why the product wedge is strong

Most private trading ideas depend only on trader flow. Shade combines multiple flow sources:

1. Cross-chain USDC movement.
2. Private RFQs.
3. Remittances.
4. Payroll and contractor payouts.
5. Invoice settlement.
6. Market maker rebalancing.
7. Institutional netting.
8. Eventually, private block trading.

This creates a healthier liquidity flywheel:

```text
Remittance and payout users need quotes
        -> anchors and solvers compete
        -> better quotes attract more users
        -> more predictable flow attracts market makers
        -> deeper private liquidity improves block execution
        -> market makers rebalance through Shade
        -> stronger liquidity improves remittance and RFQ
```

# Full system architecture

![High-level architecture](/mnt/data/shade_arch_diagrams/high_level.png){ width=100% }

## Architectural principles

1. **Use native USDC movement, not wrapped bridge assets.** CCTP is the default transport for USDC.
2. **Make Stellar the private settlement domain.** Stellar holds assets through SAC contracts and verifies settlement proofs.
3. **Keep user secrets local.** Note secrets and nullifier preimages never leave the user device unless explicitly backed up in encrypted form.
4. **Use ZK for correctness, not magical privacy.** ZK proves note ownership, nullifier freshness, limits, quote bounds, and settlement conservation. It does not protect orderflow from a matcher unless the matcher is protected by encryption, TEE, threshold encryption, or MPC.
5. **Stage privacy honestly.** V1 is private from public observers with permissioned solvers. V2 adds TEE matching. V3/V4 can add threshold encryption or MPC.
6. **Treat compliance as a protocol module.** ASP roots, limit proofs, and view keys are part of the core design, not an afterthought.
7. **Make every event indexable and agent-readable.** Sefi indexes chain events, CCTP events, quotes, and settlement provenance into a semantic graph for autonomous agents.
8. **Every module must have testable invariants.** The agent must never ship a module unless its invariants pass unit, integration, fuzz, and e2e tests.

## Core components

| Layer | Component | Job |
|---|---|---|
| Source-chain | Source Chain Adapter | Initiate CCTP burns, validate chain/asset/amount, build hook data. |
| CCTP | Circle CCTP + Iris | Burn USDC, attest message, enable mint on Stellar. |
| Stellar entry | CctpForwarder | Receive minted USDC and atomically forward to Shade Vault. |
| Stellar custody | Shade Vault | Hold SAC USDC/XLM/assets and release funds only after verified settlement. |
| Privacy | Commitment Tree | Store note commitments and root history. |
| Privacy | Nullifier Registry | Prevent double-spends. |
| ZK | Proof Verifier contracts | Verify deposit, withdraw, transfer, RFQ settle, remit and netting proofs. |
| Compliance | Compliance Registry | Store ASP roots, deny roots, policy versions, rate limits, view-key requirements. |
| Off-chain execution | Private Intent API | Receive encrypted RFQs, withdraw requests, remittance requests, and solver intents. |
| Solver | Solver / Matcher | Quote, fill, inventory-manage, and submit settlement calls. |
| Proof | Prover workers | Generate proofs from witnesses and public inputs. |
| Indexing | Sefi semantic indexer | Convert ledger events into agent-queryable knowledge. |
| Apps | Web app, SDK, market maker API | User wallet, local note manager, RFQ UI, payout UI, receipt export. |

# Protocol flows

## Flow 1 - CCTP shielded deposit into Stellar

![Deposit sequence](/mnt/data/shade_arch_diagrams/deposit_sequence.png){ width=100% }

### Deposit requirements

The deposit flow must satisfy these requirements:

- The user must generate a local note secret before initiating the CCTP burn.
- The source-chain burn must include hook data that routes the Stellar mint to `CctpForwarder`, then to the Shade Vault.
- `mintRecipient` and `destinationCaller` must both be configured to the Stellar `CctpForwarder` contract address in the source burn flow.
- The adapter must validate Stellar USDC precision. Stellar USDC has seven decimals, while many source chains use six decimals.
- The vault must not credit a private note until the Stellar forward and SAC transfer have finalized.
- The indexer must record both public deposit events and encrypted note metadata for recovery.

### Deposit public inputs

The note-minting proof or deposit registration should bind:

| Field | Meaning |
|---|---|
| `source_chain_id` | Origin chain domain or protocol-specific chain id. |
| `cctp_nonce` | CCTP message nonce / unique message id. |
| `burn_tx_hash` | Source-chain burn transaction. |
| `amount_usdc_7dp` | Normalized amount in Stellar USDC precision. |
| `recipient_vault` | Shade Vault contract id. |
| `commitment` | Poseidon note commitment. |
| `asset_id` | SAC USDC asset id. |
| `policy_id` | Compliance policy version. |
| `deposit_leaf_index` | Commitment-tree leaf index. |

### Deposit state transitions

![State machine](/mnt/data/shade_arch_diagrams/state_machine.png){ width=100% }

# Flow 2 - Private RFQ execution

![RFQ sequence](/mnt/data/shade_arch_diagrams/rfq_sequence.png){ width=100% }

## RFQ lifecycle

1. User holds one or more private USDC notes.
2. User creates an encrypted RFQ:
   - input asset;
   - output asset;
   - amount or maximum amount;
   - minimum output;
   - source chain / output chain if relevant;
   - expiry;
   - compliance policy;
   - user signature over intent hash.
3. Intent API stores only encrypted raw order details and a minimal public commitment.
4. Permissioned solvers/anchors submit quotes.
5. User accepts one quote.
6. Solver locks inventory and creates a fill object.
7. Prover generates settlement proof.
8. Stellar verifier checks proof.
9. Settlement contract spends user input nullifier and creates output commitment(s).
10. Solver receives settlement credit, vault release, or claimable reimbursement.

## RFQ object

```json
{
  "intent_type": "PRIVATE_RFQ",
  "version": "1.0",
  "user_pubkey_commitment": "field",
  "input_asset": "USDC:Stellar:SAC",
  "output_asset": "XLM:Stellar:SAC | iso4217:INR | USDC:Base",
  "amount_mode": "exact_in | exact_out | max_in",
  "amount_commitment": "field",
  "min_output_commitment": "field",
  "expiry_ledger": 12345678,
  "allowed_solvers_root": "field",
  "compliance_policy_id": "bytes32",
  "destination_commitment": "field",
  "replay_domain": "shade:stellar:mainnet:rfq:v1",
  "signature": "SEP-0053 or wallet-specific signature"
}
```

## Quote object

```json
{
  "quote_id": "uuid",
  "intent_hash": "bytes32",
  "solver_id": "did:shade:solver:...",
  "input_asset": "USDC",
  "output_asset": "XLM",
  "gross_input": "100000.0000000",
  "net_output": "...",
  "fee": "...",
  "valid_until_ledger": 12345699,
  "solver_inventory_commitment": "field",
  "settlement_method": "private_note | stellar_payout | cctp_exit | fiat_payout",
  "quote_signature": "ed25519/secp256k1"
}
```

## RFQ settlement proof must prove

- The user owns a valid input note.
- The input note commitment is in an accepted Merkle root.
- The nullifier derives from the note secret and has not been spent.
- The accepted quote is signed by an allowed solver.
- The fill respects minimum output, maximum fee, deadline, and asset ids.
- The output commitment(s) are correctly formed.
- The settlement conserves value after fees.
- Compliance membership and policy checks are valid.

# Flow 3 - Withdrawal and cross-chain exit

![Withdrawal flow](/mnt/data/shade_arch_diagrams/withdraw_flow.png){ width=100% }

## Withdrawal modes

| Mode | Description | MVP? |
|---|---|---:|
| Stellar public payout | Spend private note and transfer SAC USDC/XLM to a public Stellar account or contract. | Yes |
| New private note | Split/merge notes inside the pool without public recipient. | Yes |
| CCTP exit | Burn Stellar USDC and mint native USDC on another CCTP-supported chain. | Yes |
| Fiat payout | Use anchor/MoneyGram/partner payout flow after private settlement. | Simulated or partner-gated |
| Proof-of-fill exit | A solver fronts funds on destination chain and claims after proof. | V2 |

## Withdraw public inputs

| Field | Meaning |
|---|---|
| `root` | Valid commitment-tree root. |
| `nullifier` | Public spent nullifier. |
| `asset_id` | Asset being withdrawn. |
| `amount_public` or `amount_commitment` | Public for external payout, committed for internal transfer. |
| `recipient_commitment` | For private output. |
| `public_recipient` | For public payout or CCTP exit. |
| `policy_id` | Compliance policy version. |
| `relayer_fee` | Fee paid to relayer/solver. |
| `deadline_ledger` | Replay and stale execution protection. |

# Contract architecture

![Contract dependency map](/mnt/data/shade_arch_diagrams/contracts.png){ width=100% }

## Contract list

| Contract | Network | Responsibility | Critical invariants |
|---|---|---|---|
| `ShadeVault` | Stellar/Soroban | Custody SAC USDC/XLM/assets, credit deposits, release withdrawals, pause. | Assets released only after valid proof or admin emergency mode. Vault balance >= note supply commitments tracked by asset. |
| `CommitmentTree` | Stellar/Soroban | Append note commitments, store root history. | Append-only; no duplicate leaf index; root update deterministic. |
| `NullifierRegistry` | Stellar/Soroban | Store spent nullifiers. | Nullifier can be inserted once only. No overwrite. |
| `ProofVerifierWithdraw` | Stellar/Soroban | Verify withdrawal proofs. | Accepted roots only; valid nullifier; policy satisfied. |
| `ProofVerifierTrade` | Stellar/Soroban | Verify RFQ/trade settlement proofs. | Conservation, fee bounds, quote validity, output correctness. |
| `ProofVerifierRemit` | Stellar/Soroban | Verify payout/remittance proofs. | Limit checks, approved corridor, quote/payout metadata binding. |
| `ComplianceRegistry` | Stellar/Soroban | Store ASP roots, policy versions, view-key rules. | Only authorized ASP/governance updates roots; old roots tracked with expiry. |
| `CCTPAdapter` | Stellar/Soroban + source chain code | Restrict inbound/outbound CCTP handling. | Only supported domains/assets; precision safe; no raw user-controlled forwarder fields. |
| `IntentEscrow` | Stellar/Soroban | Solver quote locks, proof-of-fill claims, dispute accounting. | Solver cannot claim without a valid fill proof and unexpired intent. |
| `GovernanceGuardian` | Stellar/Soroban | Pause, role management, upgrades, emergency safety. | Timelock for upgrades; immediate pause only for guardian quorum. |

## `ShadeVault` minimal interface

```rust
pub trait ShadeVault {
    fn initialize(admin: Address, usdc_sac: Address, xlm_sac: Address, tree: Address, nullifiers: Address);
    fn receive_cctp_deposit(
        source_domain: u32,
        cctp_nonce: BytesN<32>,
        asset: Address,
        amount: i128,
        commitment: BytesN<32>,
        encrypted_note_payload_hash: BytesN<32>,
        policy_id: BytesN<32>
    ) -> u32;
    fn private_transfer_settle(
        verifier_id: Symbol,
        proof: Bytes,
        public_inputs: Vec<Val>
    ) -> SettlementReceipt;
    fn withdraw_public(
        proof: Bytes,
        public_inputs: Vec<Val>,
        recipient: Address
    ) -> WithdrawalReceipt;
    fn withdraw_cctp(
        proof: Bytes,
        public_inputs: Vec<Val>,
        destination_domain: u32,
        destination_recipient: BytesN<32>
    ) -> CctpExitReceipt;
    fn pause(reason_hash: BytesN<32>);
    fn unpause();
}
```

## `CommitmentTree` minimal interface

```rust
pub trait CommitmentTree {
    fn append(commitment: BytesN<32>) -> (u32, BytesN<32>);
    fn is_known_root(root: BytesN<32>) -> bool;
    fn get_latest_root() -> BytesN<32>;
    fn get_leaf_count() -> u32;
}
```

## `NullifierRegistry` minimal interface

```rust
pub trait NullifierRegistry {
    fn spend(nullifier: BytesN<32>) -> bool; // fails if already spent
    fn is_spent(nullifier: BytesN<32>) -> bool;
}
```

## Contract upgrade rule

An AI agent must not deploy upgradeable custody contracts without these controls:

1. deterministic build artifact hash;
2. source commit hash in release notes;
3. testnet deployment proof;
4. automated invariant report;
5. human checkpoint before mainnet;
6. timelock for upgrade execution;
7. emergency pause that cannot steal funds;
8. migration script that proves old note root compatibility or explicitly freezes old pool.

# Private note system

## Note structure

```text
note = {
  version,
  asset_id,
  amount,
  owner_public_key,
  spend_public_key,
  blinding,
  nonce,
  compliance_tag,
  source_context,
  memo_commitment
}
```

## Commitment

```text
commitment = Poseidon(
  version,
  asset_id,
  amount,
  owner_public_key,
  spend_public_key,
  blinding,
  nonce,
  compliance_tag,
  source_context,
  memo_commitment
)
```

## Nullifier

```text
nullifier = Poseidon(
  owner_secret,
  note_id,
  pool_id,
  chain_id,
  nullifier_domain_separator
)
```

## Data visibility

| Data | Public on-chain? | Stored off-chain? | Visible to user? | Visible to solver? |
|---|---:|---:|---:|---:|
| Deposit into vault | Yes | Yes | Yes | Maybe |
| Commitment | Yes | Yes | Yes | Maybe |
| Note plaintext | No | Encrypted only | Yes | No |
| Nullifier | Yes when spent | Yes | Yes | No link to note unless user reveals |
| RFQ plaintext | No | Encrypted | Yes | Only authorized quote participants |
| Quote response | No or minimally public | Yes | Yes | Solver + user |
| Settlement proof | Yes | Yes | Yes | Yes |
| View-key report | No by default | Yes | User-authorized | Authorized recipient only |

## Note recovery model

The protocol must support three recovery modes:

1. **Local wallet recovery:** note secrets derived from a seed or wallet signature.
2. **Encrypted cloud backup:** encrypted note payloads indexed by commitment with user-controlled decryption keys.
3. **View-key recovery:** a limited read key can reconstruct history for audit without spending capability.

The AI agent must not store raw note secrets in server logs, databases, analytics tools, or crash reports.

# ZK circuit architecture

## Circuit set

| Circuit | Purpose | Public inputs | Private witness |
|---|---|---|---|
| `DepositNoteMint` | Bind CCTP deposit to a new note commitment. | CCTP nonce, amount, asset, commitment, policy id. | note preimage. |
| `PrivateTransfer` | Spend one or more notes and create new note(s). | root, nullifier(s), output commitments, fee commitment. | input notes, Merkle path, output note preimages. |
| `WithdrawPublic` | Spend private note and release public asset. | root, nullifier, asset, amount, recipient, fee, policy. | note, Merkle path, owner secret. |
| `RFQSettlement` | Spend note and settle accepted quote. | root, nullifier, quote hash, output commitment, solver id, fee. | note, Merkle path, quote details, fill details. |
| `RemitSettlement` | Bind private funds to anchor/fiat payout quote. | root, nullifier, quote id hash, payout corridor, amount, policy. | note, Merkle path, payout metadata commitment. |
| `ComplianceMembership` | Prove allowlist membership and denylist non-membership. | ASP roots, policy id. | membership path, user credential commitment. |
| `ProofOfFillClaim` | Let solver claim after executing destination payout. | intent hash, fill receipt hash, deadline, solver id. | fill details, proof/witness of execution if available. |

## Recommended proving stack

For a hackathon MVP:

- Use Circom/Groth16 or Noir with a Soroban verifier adapter.
- Use small fixed-depth Merkle trees initially.
- Implement proof generation in a worker process, not inside the main API.
- Treat witness generation as sensitive code.
- Version every circuit and verifier.

For production:

- Benchmark proof generation and verification cost under Stellar Protocol 26/27.
- Use recursive/batched proofs only after simple circuits pass audits.
- Separate circuits by asset type and proof purpose to keep constraints small.

## ZK invariants

The agent must build tests for these invariants:

1. A note cannot be spent if its commitment is not in a known root.
2. A nullifier cannot be spent twice.
3. A proof for one pool cannot be replayed in another pool.
4. A proof for one asset cannot withdraw another asset.
5. A proof for one recipient cannot be redirected by the relayer.
6. A solver quote cannot be modified after user acceptance.
7. A fee cannot exceed the user's signed maximum.
8. A compliance policy root cannot be swapped without changing public inputs.
9. Output commitments must equal the claimed private output notes.
10. Vault asset conservation must hold after settlement.

# CCTP integration design

## Inbound CCTP to Stellar

The CCTP adapter must support:

- supported domain registry;
- source chain burn transaction watcher;
- Circle Iris attestation fetcher;
- attestation retry logic;
- `CctpForwarder` invocation;
- precision normalization;
- duplicate deposit prevention;
- hook data validation;
- stuck transfer detection;
- recovery playbook.

## Stellar CCTP footguns to encode as tests

The agent must implement failing tests for:

1. `mintRecipient` accidentally set to a user account.
2. `destinationCaller` not set to `CctpForwarder`.
3. Hook data with malformed `forwardRecipient`.
4. Address type confusion between `G`, `M`, and `C` strkeys.
5. Six-decimal to seven-decimal precision truncation.
6. Duplicate CCTP message replay.
7. Attestation timeout.
8. Wrong destination domain.
9. Unsupported source domain.
10. Forwarder succeeds but vault note creation fails.

## Outbound CCTP from Stellar

Outbound CCTP is used when a user spends a private note and wants native USDC on another chain. The settlement contract must bind:

- destination chain/domain;
- destination recipient bytes;
- amount;
- fee;
- nullifier;
- deadline;
- relayer address;
- replay domain.

The relayer must not be able to alter destination recipient or amount after the proof is generated.

# Axelar integration design

Axelar is optional in v1. It should be used for:

- non-USDC expansion;
- cross-chain messages;
- remote solver callbacks;
- destination-chain proof-of-fill notifications;
- future interchain token support.

Do **not** use Axelar as the primary USDC bridge when CCTP is available. That keeps the USDC story clean and lowers custody risk.

# Stellar anchor and PayFi design

## SEP modules

| SEP | Use inside Shade |
|---|---|
| SEP-1 | Discover anchor metadata through `stellar.toml`. |
| SEP-10 / SEP-45 | Authenticate users or contract accounts with anchors. |
| SEP-12 | Customer KYC data exchange where legally required. |
| SEP-24 | Hosted deposit/withdrawal flows, including MoneyGram-style ramps. |
| SEP-31 | Cross-border payments between off-chain financial accounts. |
| SEP-38 | Anchor quotes / RFQ for on-chain/off-chain asset exchange. |
| SEP-41 | Token interface for SAC and contract tokens. |
| SEP-53 | Off-chain message signing for Stellar-style order signing where applicable. |

## Shade Remit flow

1. User shields USDC into Stellar.
2. User chooses recipient country, payout method, and amount mode.
3. Shade queries anchors/partners through SEP-38-like quotes.
4. User accepts quote.
5. Shade creates private settlement proof.
6. Anchor receives required public/compliance info through a controlled channel, not public chain leakage.
7. Anchor pays recipient by bank, wallet, or cash pickup.
8. Shade View creates a receipt for the user and authorized counterparties.

## Payout metadata commitment

```json
{
  "recipient_country": "IN",
  "payout_currency": "INR",
  "payout_method": "bank | wallet | cash",
  "quote_id": "anchor-quote-id",
  "purpose_code": "family_support | payroll | invoice | ngo_payout",
  "invoice_id_hash": "bytes32 optional",
  "kyc_ref_hash": "bytes32",
  "anchor_id": "did:shade:anchor:...",
  "view_policy_id": "bytes32"
}
```

The ZK proof should bind the hash of this metadata, not publish all fields on-chain.

# Compliance architecture

![Compliance and view-key flow](/mnt/data/shade_arch_diagrams/compliance.png){ width=100% }

## Compliance model

Shade should use a **compliance-forward privacy** model:

- Public observers do not see unnecessary transaction history, internal balances, or routes.
- Regulated anchors receive the minimum required data for the specific payout or quote.
- Users can generate view-key reports for audits.
- ASPs maintain allow/deny roots.
- The protocol can enforce policy versions and corridor limits.

## ASP data model

| Field | Description |
|---|---|
| `asp_id` | Association Set Provider identifier. |
| `policy_id` | Policy version. |
| `allow_root` | Merkle root of approved credential commitments. |
| `deny_root` | Sparse Merkle root or accumulator for blocked credentials. |
| `valid_from_ledger` | Activation ledger. |
| `valid_until_ledger` | Expiry ledger. |
| `corridor_rules_hash` | Hash of limits and payout corridor policy. |
| `signer_set` | Authorized root update signers. |

## View-key report contents

A report should include:

- report id;
- user-selected time range;
- relevant note commitments;
- nullifiers for disclosed transactions;
- payout quote id;
- amount/currency if user chooses to disclose;
- compliance policy id;
- anchor id;
- proof verification links;
- signature from Shade View service;
- optional encrypted attachment for bank/auditor.

# Private execution layer

## Solver types

| Solver type | Role | V1? |
|---|---|---:|
| Internal demo solver | Provides deterministic fills for hackathon. | Yes |
| Market maker solver | Quotes USDC/XLM and cross-chain exits. | Yes |
| Anchor solver | Quotes fiat payout corridors. | Simulated/partner-gated |
| Proof-of-fill solver | Fronts funds on destination then claims. | V2 |
| TEE matcher | Runs encrypted order book with attestation. | V2 |
| MPC matcher | Multi-party hidden order matching. | V4 |

## TEE stage

A TEE matcher is a pragmatic midpoint between trusted solver and full MPC. It should provide:

- remote attestation;
- signed code/config hash;
- attested TLS endpoint;
- key generation inside enclave/TEE;
- no raw order logs;
- reproducible Docker/compose hash;
- signed settlement outputs.

TEE caveat: it does not eliminate side-channel risks, so the protocol still needs on-chain settlement verification, proof checks, monitoring, and safe fallback.

## MPC stage

MPC should be delayed until:

- RFQ + CCTP + note settlement work reliably;
- there is enough order flow to justify complexity;
- the team can restrict matching to simple assets and batch windows;
- there is a clear liveness/recovery design.

# Infrastructure architecture

![Infrastructure topology](/mnt/data/shade_arch_diagrams/infra.png){ width=100% }

## Services

| Service | Stack suggestion | Responsibility |
|---|---|---|
| Web app | Next.js, Tailwind, wallet adapters | Shield, private balance, RFQ, remit, withdraw, reports. |
| SDK | TypeScript | Wallet integrations, CCTP route builder, note manager, intent client. |
| API Gateway | Node/NestJS or Fastify | Auth, rate limits, API routing, policy checks. |
| Intent Service | Node/Rust | Encrypted intents, RFQ auctions, quote lifecycle. |
| Solver Service | Rust/Node/Python | Inventory, quote engine, settlement calls. |
| Prover Workers | Rust/Node + circuit tooling | Proof generation, witness safety, queue processing. |
| Relayer | Rust/Node | Stellar tx simulation/signing/submission, CCTP attestation fetch. |
| Sefi Indexer | Rust/Node/Python | Events -> semantic graph; chain provenance; agent query. |
| Database | Postgres | Intents, quotes, users, note metadata hashes, anchors, receipts. |
| Queue | Redis/NATS/SQS | Async proof, attestation, settlement jobs. |
| Object storage | S3/R2/MinIO | Encrypted payloads, reports, build artifacts. |
| Monitoring | Prometheus/Grafana/Sentry/OTel | Alerts, traces, incident diagnostics. |
| Key management | KMS/HSM/TEE | Solver keys, relayer keys, signer separation. |

## Sefi semantic indexer

![Data pipeline](/mnt/data/shade_arch_diagrams/data_pipeline.png){ width=100% }

Sefi should not just index raw events. It should convert blockchain data into semantic knowledge for the AI agent.

### Sefi entities

| Entity | Key fields |
|---|---|
| `Deposit` | source chain, burn tx, CCTP nonce, Stellar tx, amount, vault, commitment. |
| `NoteCommitment` | commitment, leaf index, root, asset, policy id, encrypted payload ref. |
| `NullifierSpend` | nullifier, settlement tx, proof type, asset, policy id. |
| `Intent` | intent hash, type, user commitment, expiry, status. |
| `Quote` | quote id, solver id, price, expiry, accepted flag. |
| `Fill` | fill id, intent hash, solver id, proof tx, receipt. |
| `Payout` | anchor id, corridor, quote id, status, receipt ref. |
| `RiskSignal` | stale root, failed forward, duplicate nonce, solver default, liquidity drain. |

### Agent-readable query examples

```text
Find CCTP deposits from Base where Stellar forward succeeded
but note creation failed.

Find nullifiers spent against policy P that are missing from
the indexer's reconstructed root history.

Find quotes where solver fee exceeded 50 bps or expiry was
less than 20 ledgers.

Find open intents expiring in the next 5 minutes with no
accepted quote.

Generate proof-of-reserves: vault SAC balance versus
outstanding note commitments by asset.
```

# API architecture

## Public app APIs

| Endpoint | Method | Purpose |
|---|---|---|
| `/v1/routes/cctp` | GET | Return supported CCTP routes, domains, precision, fees. |
| `/v1/deposits/prepare` | POST | Create deposit plan and note commitment. |
| `/v1/deposits/status/:id` | GET | Track source burn, attestation, forward, note. |
| `/v1/notes/recover` | POST | Return encrypted note payload refs for wallet-owned commitments. |
| `/v1/intents` | POST | Submit encrypted RFQ/remit/withdraw intent. |
| `/v1/intents/:id/quotes` | GET | Fetch quotes visible to the user. |
| `/v1/quotes/:id/accept` | POST | Accept signed quote. |
| `/v1/proofs/request` | POST | Queue proof generation. |
| `/v1/settlements/:id` | GET | Track proof verification and settlement tx. |
| `/v1/reports/view-key` | POST | Generate selective disclosure package. |

## Solver APIs

| Endpoint | Method | Purpose |
|---|---|---|
| `/v1/solver/intents` | GET | Fetch eligible sanitized/encrypted intents. |
| `/v1/solver/quotes` | POST | Submit quote. |
| `/v1/solver/quotes/:id/lock` | POST | Lock inventory after user accepts. |
| `/v1/solver/fills` | POST | Submit fill witness/receipt. |
| `/v1/solver/claims` | POST | Claim reimbursement after proof-of-fill. |
| `/v1/solver/inventory` | GET | Inventory and exposure dashboard. |

## Anchor APIs

| Endpoint | Method | Purpose |
|---|---|---|
| `/v1/anchors/discovery` | GET | Discover SEP-31/SEP-38/MoneyGram-style providers. |
| `/v1/anchors/quotes` | POST | Request payout quote. |
| `/v1/anchors/payouts` | POST | Initiate payout after settlement. |
| `/v1/anchors/payouts/:id` | GET | Track payout status. |
| `/v1/anchors/compliance-package` | POST | Send required encrypted compliance data. |

# Database schema

## Core tables

```sql
CREATE TABLE cctp_deposits (
  id UUID PRIMARY KEY,
  source_domain INT NOT NULL,
  source_tx_hash TEXT NOT NULL,
  cctp_nonce TEXT NOT NULL UNIQUE,
  destination_domain INT NOT NULL,
  amount_usdc_7dp NUMERIC(40,7) NOT NULL,
  forwarder_contract TEXT NOT NULL,
  vault_contract TEXT NOT NULL,
  commitment TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE note_commitments (
  commitment TEXT PRIMARY KEY,
  asset_id TEXT NOT NULL,
  leaf_index BIGINT NOT NULL,
  root TEXT NOT NULL,
  policy_id TEXT NOT NULL,
  encrypted_payload_ref TEXT,
  tx_hash TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE nullifier_spends (
  nullifier TEXT PRIMARY KEY,
  proof_type TEXT NOT NULL,
  root TEXT NOT NULL,
  tx_hash TEXT NOT NULL,
  policy_id TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE intents (
  intent_hash TEXT PRIMARY KEY,
  intent_type TEXT NOT NULL,
  encrypted_payload_ref TEXT NOT NULL,
  status TEXT NOT NULL,
  expiry_ledger BIGINT NOT NULL,
  policy_id TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE quotes (
  quote_id UUID PRIMARY KEY,
  intent_hash TEXT REFERENCES intents(intent_hash),
  solver_id TEXT NOT NULL,
  quote_hash TEXT NOT NULL,
  encrypted_quote_ref TEXT,
  status TEXT NOT NULL,
  valid_until_ledger BIGINT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE settlements (
  settlement_id UUID PRIMARY KEY,
  intent_hash TEXT,
  quote_id UUID,
  proof_type TEXT NOT NULL,
  public_inputs_hash TEXT NOT NULL,
  stellar_tx_hash TEXT,
  status TEXT NOT NULL,
  error_code TEXT,
  created_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL
);
```

# AI agent build system

![Autonomous agent loop](/mnt/data/shade_arch_diagrams/agent_loop.png){ width=100% }

## Agent roles

| Agent | Responsibilities | Must not do |
|---|---|---|
| Planner | Break architecture into tasks, define acceptance tests. | Deploy or merge code. |
| Research Agent | Check docs, protocol versions, contract addresses, known issues. | Trust stale assumptions. |
| Contract Builder | Implement Soroban contracts and source-chain adapters. | Bypass invariants for speed. |
| Circuit Builder | Implement and test ZK circuits. | Log witnesses or secrets. |
| Backend Builder | Implement APIs, queues, DB, relayers. | Store note secrets. |
| Frontend Builder | Wallet UX, note manager, status screens. | Ask user to manually encode CCTP fields. |
| Test Agent | Unit/integration/fuzz/e2e tests. | Mark phase complete without evidence. |
| Security Agent | Static analysis, threat model, invariant checks. | Auto-waive critical findings. |
| Deployment Agent | Testnet deploy, artifact hashing, environment config. | Mainnet deploy without human checkpoint. |
| Runtime Agent | Monitor, alert, rollback suggestions. | Move funds or upgrade contracts alone. |

## Agent task format

Every task must have this format:

```yaml
id: PHASE1-CCTP-003
title: Implement Stellar CctpForwarder integration path
context: Build inbound CCTP deposit into ShadeVault using Circle Stellar rules.
inputs:
  - Circle Stellar CCTP docs
  - Stellar testnet RPC
  - configured CctpForwarder address
outputs:
  - passing unit tests
  - integration test tx hash
  - docs/deposit-flow.md updated
acceptance_tests:
  - wrong destinationCaller fails before source burn
  - malformed forwardRecipient fails before source burn
  - duplicate CCTP nonce does not mint second note
  - precision conversion test passes for small and large amounts
risk_level: critical
human_checkpoint: required before mainnet
```

## Done definition for any phase

A phase is complete only when:

1. Code merged with reviewed tests.
2. Local tests pass.
3. Testnet e2e flow passes.
4. Failure cases are tested, not only happy path.
5. Sefi indexer can reconstruct the phase's events.
6. User-facing status is visible in UI.
7. Security agent produced a findings report.
8. No critical/high findings remain open unless explicitly waived by a human.
9. Architecture docs are updated.
10. Deployment rollback plan exists.

# Build phases

## Phase 0 - Repo and research baseline

**Goal:** Create a stable repo, architecture map, environment, and source-of-truth docs.

### Tasks

- Create monorepo:
  - `contracts/stellar`;
  - `contracts/source-evm`;
  - `circuits`;
  - `apps/web`;
  - `apps/solver`;
  - `apps/relayer`;
  - `apps/indexer`;
  - `packages/sdk`;
  - `packages/shared`;
  - `infra`;
  - `docs`.
- Pin versions for Stellar CLI, SDK, Rust, Node, circuit tooling.
- Create `.env.example` with no secrets.
- Add CI for lint, tests, build, contract wasm build, circuit compile.
- Create docs registry with protocol source links.
- Add threat model file.

### Acceptance tests

- Fresh clone can run local tests.
- CI blocks unsafe secret commits.
- Docs include protocol references and contract addresses as configurable values, not hardcoded production assumptions.

## Phase 1 - Stellar vault and note skeleton

**Goal:** Create local/testnet Stellar contracts for custody, commitments, and nullifiers.

### Tasks

- Implement `ShadeVault` with admin, pause, SAC asset config.
- Implement `CommitmentTree` append and root history.
- Implement `NullifierRegistry` single-use nullifier map.
- Implement events:
  - `VaultDepositReceived`;
  - `NoteCommitmentInserted`;
  - `NullifierSpent`;
  - `VaultWithdrawal`;
  - `EmergencyPaused`.
- Implement simple mock verifier for early integration.
- Deploy to Stellar testnet.

### Tests

- Append commitments updates root.
- Duplicate nullifier fails.
- Vault pause blocks state-changing functions.
- Unauthorized admin actions fail.
- SAC transfer simulation succeeds on testnet.

## Phase 2 - CCTP inbound shielded deposit

**Goal:** Move native USDC through CCTP into Stellar and mint a private note commitment.

### Tasks

- Build source-chain route planner.
- Build CCTP hook generator.
- Validate Stellar `CctpForwarder` fields.
- Implement relayer attestation fetch.
- Implement Stellar `mint_and_forward` submitter.
- Bind incoming amount to `receive_cctp_deposit`.
- Normalize USDC precision to Stellar 7 decimals.
- Add indexer support for CCTP events.

### Tests

- Happy path: Base/EVM testnet to Stellar testnet if supported by current test infra.
- Mock path: simulated burn + attestation + forward.
- Wrong address type blocks before burn.
- Wrong precision blocks before burn.
- Duplicate nonce rejected.
- Indexer reconstructs status from events.

## Phase 3 - Private note UX and recovery

**Goal:** Users can see private balance locally and recover notes securely.

### Tasks

- Implement local note key derivation.
- Implement encrypted note payload schema.
- Implement note discovery by commitment/event scan.
- Implement browser storage with encrypted backup option.
- Build balance screen.
- Add safety warnings for lost note secret.

### Tests

- Same wallet can recover notes from encrypted payloads.
- Different wallet cannot decrypt note payload.
- Note secret never appears in server logs.
- User can split notes in mock/private transfer flow.

## Phase 4 - ZK withdrawal proof

**Goal:** Replace mock verifier with real proof for private note spend and public withdrawal.

### Tasks

- Implement `WithdrawPublic` circuit.
- Generate verification key.
- Implement Stellar verifier contract adapter.
- Add proof generation worker.
- Add nullifier spend on verified proof.
- Add user withdrawal UI.

### Tests

- Valid note withdraws once.
- Same proof cannot replay.
- Same nullifier cannot spend twice.
- Wrong recipient fails.
- Wrong amount fails.
- Wrong root fails.
- Paused vault blocks withdrawal.

## Phase 5 - Private RFQ MVP

**Goal:** User can request private quote and settle with a solver.

### Tasks

- Implement encrypted intent service.
- Implement solver quote API.
- Implement quote acceptance.
- Implement `RFQSettlement` circuit or temporary mock for hackathon if circuit complexity blocks demo.
- Implement solver inventory ledger.
- Implement settlement UI and status tracking.

### Tests

- Quote expires correctly.
- Solver signature required.
- User acceptance cannot be modified.
- Settlement respects min output.
- Solver cannot claim without fill.
- Failed proof returns funds to private note state or marks intent recoverable.

## Phase 6 - Shade Remit and anchor RFQ simulation

**Goal:** Add a private remittance/payout flow with simulated or partner-gated anchors.

### Tasks

- Implement payout corridor config.
- Implement SEP-38-style quote adapter.
- Implement mock anchor payout status.
- Implement payout metadata commitment.
- Implement receipt generation.
- Add compliance package stub.

### Tests

- Quote amount and currency are bound to settlement.
- Payout cannot execute after quote expiry.
- Receipt matches on-chain settlement hash.
- Anchor sees only required information.

## Phase 7 - CCTP outbound exit

**Goal:** User can spend private USDC note and receive native USDC on another CCTP chain.

### Tasks

- Implement outbound CCTP flow from Stellar.
- Bind destination domain and recipient to proof.
- Build relayer support.
- Add status tracking through destination mint.

### Tests

- Destination cannot be changed by relayer.
- Amount cannot be changed by relayer.
- Unsupported destination chain blocked.
- Failure state provides recovery instructions.

## Phase 8 - TEE matcher and private block trades

**Goal:** Move from trusted solver to attested matcher for hidden orders.

### Tasks

- Implement TEE deployment config.
- Generate matching key inside TEE.
- Publish attestation report.
- Build client verification of attested TLS.
- Implement basic private order crossing.
- Add settlement proof binding to matcher signature.

### Tests

- Client rejects non-attested matcher.
- Matcher cannot settle orders not signed by users.
- Settlement proof rejects modified order fields.
- Restart/recovery preserves open order safety.

## Phase 9 - Institutional netting

**Goal:** Batch many obligations and settle netted private flows.

### Tasks

- Implement netting batch data model.
- Implement multi-party settlement proof.
- Add liquidity provider dashboard.
- Add proof-of-reserves and exposure reports.
- Add risk limits per solver/corridor.

### Tests

- Net obligations conserve assets.
- Participant cannot be assigned wrong net liability.
- Batch replay fails.
- Failed participant does not corrupt all settlements.

# Security model

## Threats

| Threat | Impact | Mitigation |
|---|---|---|
| CCTP misrouting | Permanent fund loss | Strict adapter, no manual user fields, pre-burn validation, simulation. |
| Nullifier replay | Double spend | On-chain nullifier registry, domain separation. |
| Malicious solver | Bad fill or stolen quote | Signed quotes, proof-bound settlement, solver staking/limits. |
| Matcher orderflow leak | Strategy leakage | V1 disclosure limitations, V2 TEE, V4 MPC. |
| Relayer mutation | Wrong recipient/amount | Proof binds destination, amount, fee, deadline. |
| Indexer mismatch | User balance confusion | Recompute roots, event provenance, multi-RPC checks. |
| Lost note secret | Loss of funds | Encrypted backup, seed derivation, recovery warnings. |
| ASP root manipulation | Unauthorized access/block | signed root updates, timelock, root expiry, audit logs. |
| Contract upgrade attack | Fund theft | timelock, source attestation, pause-only guardian, human checkpoint. |
| Prover witness leakage | Privacy loss | isolated workers, no logs, memory hygiene, secret scanning. |
| Bridge finality assumption | Reorg/delayed mint | CCTP finality threshold selection and status handling. |
| Liquidity exhaustion | Failed fills | solver limits, inventory monitoring, circuit breakers. |

## Mainnet readiness checklist

Do not mainnet with real assets until:

- independent smart contract audit complete;
- circuit audit complete;
- CCTP integration tested with production addresses and small values;
- view-key/compliance process documented;
- incident response plan exists;
- all admin keys in multisig/HSM;
- proof-of-reserves dashboard live;
- emergency pause tested;
- recovery flows tested;
- legal/regulatory review for payout/remittance corridors complete.

# Testing strategy

## Test matrix

| Layer | Tests |
|---|---|
| Contracts | unit, integration, property, role, pause, upgrade, event. |
| Circuits | valid witness, invalid witness, boundary amounts, wrong roots, replay. |
| CCTP | route validation, hook construction, attestation states, duplicate nonce. |
| Backend | API auth, encryption, idempotency, queues, retries, rate limits. |
| Solver | quote correctness, inventory lock, expiry, bad fill, default. |
| Indexer | root reconstruction, event decoding, fork/retry, semantic query accuracy. |
| Frontend | wallet connect, note generation, recovery, status, error UX. |
| End-to-end | deposit, shield, RFQ, settle, withdraw, remit simulation. |
| Security | static analysis, fuzz, secret scanning, dependency scanning. |
| Load | quote bursts, proof queue, indexer lag, relayer congestion. |

## Critical e2e scenarios

1. Base USDC -> Stellar private note -> public Stellar withdraw.
2. Base USDC -> Stellar private note -> private RFQ -> XLM note.
3. Stellar USDC -> private note -> CCTP exit to Base.
4. Private note -> simulated INR payout quote -> receipt.
5. Duplicate CCTP nonce attempt.
6. Expired quote attempt.
7. Relayer tries to change destination.
8. Solver signs quote then attempts different fee.
9. Wrong ASP policy root.
10. User restores wallet and recovers note balance.

# Observability and operations

## Metrics

| Metric | Alert |
|---|---|
| CCTP attestation wait time | Above expected finality window. |
| Forward failures | Any non-zero production failure. |
| Vault balance by asset | Mismatch against expected outstanding commitments. |
| Nullifier duplicate attempts | Any spike. |
| Unknown root proof attempts | Any spike. |
| Solver quote fail rate | Above threshold. |
| Proof generation latency | Above SLA. |
| Indexer lag | More than N ledgers. |
| Payout pending time | Above corridor SLA. |
| Emergency pause | Page humans immediately. |

## Incident playbooks

### CCTP forward failed

1. Freeze related deposit status.
2. Fetch source burn, CCTP message, Iris attestation.
3. Verify `mintRecipient`, `destinationCaller`, hook data.
4. Check if forwarder invocation reverted or was never submitted.
5. If not minted, retry with same attestation if valid.
6. If minted but not credited, reconcile vault balance and note status.
7. Publish incident note.

### Nullifier anomaly

1. Pause private settlement if duplicate spend is suspected.
2. Export all nullifier events around incident window.
3. Reconstruct roots independently from raw events.
4. Compare contract state to indexer state.
5. Identify whether issue is indexer display, verifier bug, or contract bug.
6. Resume only after invariant proof.

### Solver default

1. Stop routing to solver.
2. Unlock affected intents if possible.
3. Re-run RFQ with other solvers.
4. Slash stake or reduce limits if staking exists.
5. Generate user communication and internal report.

# Repository structure

```text
shade-protocol/
  apps/
    web/                         # Next.js user app
    solver/                      # solver + market maker service
    relayer/                     # CCTP + Stellar transaction relayer
    indexer/                     # Sefi semantic indexer
    agent-runner/                # autonomous task executor with guardrails
  contracts/
    stellar/
      shade_vault/
      commitment_tree/
      nullifier_registry/
      compliance_registry/
      proof_verifiers/
      intent_escrow/
      governance_guardian/
    source-evm/
      cctp_route_adapter/
      tests/
  circuits/
    withdraw_public/
    private_transfer/
    rfq_settlement/
    remit_settlement/
    compliance_membership/
    proof_of_fill/
  packages/
    sdk/
    note-crypto/
    cctp-utils/
    shared-types/
    test-fixtures/
  infra/
    docker/
    terraform/
    k8s/
    monitoring/
  docs/
    architecture/
    runbooks/
    threat-model/
    protocol-references/
```

# Hackathon demo plan

## Demo narrative

"Alice has USDC on Base. She does not want to reveal her trade or payout size publicly. Shade routes her native USDC through CCTP into Stellar, creates a private note, gets a private quote, settles with a ZK proof, and lets her withdraw or receive a payout receipt."

## Demo screen sequence

1. Landing page: "Move size without showing your hand."
2. Shield screen: choose source chain and amount.
3. Deposit status: burn -> attestation -> mint_and_forward -> private note.
4. Private balance screen: USDC shielded balance.
5. RFQ screen: request quote for XLM or INR payout simulation.
6. Solver quote screen: best quote, expiry countdown.
7. Settlement screen: proof generated, nullifier spent, output note created.
8. Withdraw/remit screen: CCTP exit or simulated payout receipt.
9. Shade View: selective disclosure receipt.
10. Sefi Agent console: ask "show me all steps of this transfer with provenance".

## Hackathon acceptable simplifications

- Use testnet or mock CCTP if live testnet route is unstable.
- Use mock INR/PHP anchor quotes.
- Use a mock verifier temporarily for RFQ settlement only if the withdrawal circuit is real.
- Use a trusted solver in v1.
- Clearly label what is real versus simulated.

## Hackathon non-negotiables

- Do not claim full anonymity.
- Do not claim real fiat payout unless a licensed partner is integrated.
- Do not use real mainnet funds.
- Do not bypass CCTP Stellar safety rules.
- Do not store note secrets server-side.

# Implementation priority map

| Priority | Build item | Why |
|---:|---|---|
| P0 | Vault + commitment + nullifier contracts | Core settlement primitive. |
| P0 | CCTP route safety adapter | Prevents catastrophic misrouting. |
| P0 | Private note manager | User cannot use protocol without note handling. |
| P0 | Indexer/Sefi event reconstruction | Needed for status, recovery, and agent autonomy. |
| P1 | Withdraw proof | Proves real ZK utility. |
| P1 | RFQ service + solver | Makes product differentiated. |
| P1 | UI status machine | Demo clarity. |
| P2 | Remit/anchor quote simulation | Adds PayFi wedge. |
| P2 | View-key receipt | Compliance-forward story. |
| P3 | CCTP outbound | Completes cross-chain loop. |
| P4 | TEE matcher | Upgrades from trusted RFQ to stronger privacy. |

# Source references

[^circle-cctp]: Circle Developers, "Cross-Chain Transfer Protocol" - https://developers.circle.com/cctp
[^stellar-cctp]: Stellar Developers, "Cross-Chain USDC Transfers with CCTP" - https://developers.stellar.org/docs/tokens/cross-chain-transfers
[^circle-stellar-cctp]: Circle Developers, "CCTP on Stellar" - https://developers.circle.com/cctp/references/stellar
[^stellar-zk]: Stellar Developers, "ZK Proofs on Stellar" - https://developers.stellar.org/docs/build/apps/zk
[^stellar-privacy]: Stellar Developers, "Privacy on Stellar" - https://developers.stellar.org/docs/build/apps/privacy
[^stellar-sac]: Stellar Developers, "Stellar Asset Contract" - https://developers.stellar.org/docs/tokens/stellar-asset-contract
[^sep31]: Stellar Protocol SEP-0031, "Cross-Border Payments API" - https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0031.md
[^sep38]: Stellar Protocol SEP-0038, "Anchor RFQ API" - https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0038.md
[^moneygram-dev]: MoneyGram Developer, "Integrate MoneyGram Ramps for USDC On/Off-Ramping" - https://developer.moneygram.com/moneygram-developer/docs/integrate-moneygram-ramps
[^moneygram-stellar]: Stellar, "MoneyGram Ramps: One Integration, Cash Access" - https://stellar.org/products-and-tools/moneygram
[^renegade]: Renegade Docs, "What is a Dark Pool?" - https://docs.renegade.fi/concepts/dark-pool-explainer
[^penumbra-pool]: Penumbra Protocol, "Multi-Asset Shielded Pool" - https://protocol.penumbra.zone/main/shielded_pool.html
[^erc7683]: Ethereum Improvement Proposals, "ERC-7683: Cross Chain Intents" - https://eips.ethereum.org/EIPS/eip-7683
[^aztec-evm]: Substance Labs, "Aztec-EVM Bridge" - https://substance-labs.gitbook.io/aztec-evm-bridge
[^stellar-crosschain]: Stellar Developers, "Cross-Chain" - https://developers.stellar.org/docs/tools/infra-tools/cross-chain
[^stellar-versions]: Stellar Developers, "Software Versions" - https://developers.stellar.org/docs/networks/software-versions
[^circle-technical]: Circle Developers, "CCTP technical guide" - https://developers.circle.com/cctp/references/technical-guide
[^stellar-darkpool]: Stellar Blog, "Building a Dark Pool on Stellar: MPC, FHE, and TEEs Compared" - https://stellar.org/blog/developers/building-a-dark-pool-on-stellar-mpc-fhe-and-tees-compared
