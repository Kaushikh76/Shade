# ProofOfFillClaim Circuit

Status: specified, not yet compiled.

Must bind accepted intent hash, fill receipt hash, solver ID, destination transaction hash hash, amount, recipient, deadline, quote hash, and policy ID.

For cross-chain proof-of-fill, the destination transaction hash must come from a real testnet transaction. If direct on-chain light verification is unavailable, use an off-chain signed attestation generated from the real transaction.
