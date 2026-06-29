# RFQSettlement Circuit

Status: specified, not yet compiled.

Must bind input note ownership, nullifier, accepted quote hash, intent hash, solver ID, quote expiry, fill constraints, output commitment or public payout, fee, policy, pool, and chain.

Solver signature may be verified in the Soroban contract if in-circuit signature verification is too expensive; in that design the verified `quote_hash` is public input bound to the proof.
