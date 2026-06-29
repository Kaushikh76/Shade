# RFQ Lifecycle

States:

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

Rules:

- Intent plaintext is encrypted before persistence.
- Solver quotes are signed.
- User quote acceptance is signed.
- Accepted quote rows are immutable.
- Quote expiry is checked at acceptance, lock, fill, and settlement.
- Solver inventory lock is based on real testnet balances.
- RFQ settlement binds intent hash, quote hash, solver ID, output method, fee, deadline, policy, chain, and pool.
- Failed proof does not spend the nullifier.
- Expiry and recoverable failure leave the note recoverable.

Recommended live e2e path is private Stellar USDC note to proof-of-fill Arbitrum Sepolia USDC payout. The solver EVM wallet is funded during setup from the user-provided Arbitrum Sepolia wallet.
