# Blockers

Updated: 2026-06-29 Asia/Kolkata (audit + full build pass)

## All major flows now pass end-to-end with real testnet transactions

No outstanding hard blockers. The four cores the prior pass had stubbed are
implemented and verified on-chain (see `docs/test-report.md` for tx hashes):

- **CCTP inbound** — real Arbitrum Sepolia burn -> Circle attestation -> Stellar
  `mint_and_forward` -> vault USDC receipt -> commitment registration.
- **ZK withdrawal** — real Groth16/BLS12-381 proof verified on Soroban, nullifier
  spent, USDC released; double-spend reverts on-chain.
- **Full RFQ (Path A)** — encrypted intent, ed25519-signed quote, real Arbitrum
  fill, on-chain settlement (proof + signature + nullifier + solver credit),
  double-settle rejected.
- **CCTP outbound** — proof-bound Stellar -> Arbitrum CCTP burn; attestation
  generating (Arbitrum mint completes on finalization — normal CCTP lifecycle).

## Resolved during this pass (were the prior blockers)

- circom 2.x installed (user-provided) — circuits compile, keys generated.
- ZK-on-Soroban feasibility proven; real verifier replaces the fail-closed stub.
- CCTP forwarder hook format + V2 burn signature verified against Circle source.

## Engineering decisions / known limitations (documented, not blockers)

1. **Off-chain Merkle root, on-chain attestation.** On-chain Poseidon Merkle
   inserts exceed the Soroban per-tx instruction budget beyond the first leaf
   (each insert = N native poseidon permutations + bookkeeping). The registrar
   computes the root off-chain (native-speed lean-imt) and submits it with the
   deposit; every commitment is emitted on-chain for auditability. All
   security-critical steps (proof verify, nullifier spend, fund release) remain
   on-chain. See `docs/zk-proof-system.md`. Acceptable pre-MPC/TEE.

2. **Commitment-formula fix.** The upstream privacy-pools `commitment.circom`
   disagreed with its own Rust note-crypto (sequential vs 3-input Poseidon).
   Shade's circuit uses `Poseidon255(3)` to match; verified end-to-end.

3. **CCTP outbound attestation latency.** The Arbitrum-side mint completion
   depends on Circle finalizing the Stellar burn attestation (minutes); the burn
   itself is on-chain and proof-bound. Completing the mint is a follow-up poll.

## Security follow-ups (tracked, for hardening beyond this phase)

- `receive_cctp_deposit` trusts the registrar for the root/amount; it does not
  re-verify the USDC actually arrived. Add a SAC balance-delta check + restrict
  the registrar. (Mitigated today: admin-gated, on-chain commitment audit trail.)
- Bind more public inputs per operation (recipient/fee/deadline) beyond
  amount+nullifier+root (recipient is bound today via tx auth on `to`).
