# Protocol Fixes (phase2.md PHASE 1)

Tracks the protocol/correctness fixes that gate the backend-service and frontend
work. Each is verified on Stellar testnet.

## Current canonical deployment (after security lockdown)

| Contract | ID | Notes |
|---|---|---|
| ShadePool (shielded_pool) | `CDUBLMVIRUAIWICRMY4RWUIEYMMMTFGMYZKENVEPKCTGLDOZHI5SJXQQ` | canonical settlement contract (P1.8 redeploy) |
| NullifierRegistry | `CBAKCITRZLJZFQC4ISSYH5UESYFUYBFRANVM5VPDA6OH3VDTSLQ2IH67` | authorized-spender locked |
| VerifierWithdraw | `CCAO4CASJGP57A4SOQTSQO7JWAY4WXXQRU4EUOZGMCR3QF62VOIMCYY5` | admin-gated set_vk; 17-signal vk (P1.7) |
| VerifierDepositNoteMint | `CC4FGBVT4BYYM5S3NJKJGOLMICQV3HADL5XRHXMXFQEZ5XQ2K2EJHNJO` | admin-gated set_vk; 14-signal vk (P1.8) |
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

## Remaining PHASE 1 (next)

- **P1.4/8 — deposit_note_mint circuit** binding the CCTP message to the note.
- **P1.1 — Canonical naming:** document `shielded_pool` as `ShadePool` and mark
  legacy `ShadeVault`/`CommitmentTree` deprecated (not on the active path).
- **P1.9 — Root auditor service** (recompute lean-imt root from events, compare
  on-chain, flag `ROOT_MISMATCH_CRITICAL`).
- **P1.11 — Fresh `docs/test-report.generated.md`** per run + archive old; fail
  on `FAIL`.

## Then PHASES 2-7 (multi-session)
Real API endpoints, relayer/prover/solver/root-auditor services + queue, wallet
auth + user DB, Docker for every process, Next.js frontend, app-level e2e.
