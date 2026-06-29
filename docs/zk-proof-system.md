# ZK Proof System

## Chosen stack (locked 2026-06-29, proven on testnet)

**Circom 2.x + snarkjs → Groth16 over BLS12-381 → Soroban `pairing_check` verifier.**

Rationale (see `docs/research-lock.md` for sources): this is the only path with
first-party Stellar tooling. The official `stellar/soroban-examples` repo ships:

- `groth16_verifier` — Groth16/BLS12-381 verifier using `env.crypto().bls12_381()`.
- `privacy-pools` — a full shielded pool: Poseidon-over-BLS12-381 commitments, a
  Lean Incremental Merkle Tree, the Groth16 verifier, and the `circom2soroban`
  proof/vk byte converter. This is Shade's shielded core, first-party.

Soroban BLS12-381 host functions (CAP-0059, Protocol 22+) are sufficient for
Groth16: `g1_mul`, `g1_add`, `g1_msm`, and `pairing_check`. BN254 + Poseidon host
functions also exist (Protocol 25 "X-Ray" / 26 "Yardstick"), but the BLS12-381
Groth16 path is what we use because the off-chain prover tooling (snarkjs) and the
byte-serialization (`circom2soroban`) are first-party and proven.

## Verifier contract — DEPLOYED AND PROVEN

`contracts/stellar/proof_verifiers` is a real Groth16/BLS12-381 verifier
(soroban-sdk 25.1.0). One instance per circuit; the verifying key is set at
construction. Public interface (called by ShadeVault/IntentEscrow):

```
__constructor(vk_bytes)            # circom2soroban-encoded verifying key
verify(proof, public_inputs) -> bool
set_vk(vk_bytes)                   # testnet helper
vk_hash() -> BytesN<32>
```

**Feasibility spike (2026-06-29):** built + deployed the verifier to testnet with
the multiplier2 BLS12-381 verifying key, then verified the example proof on-chain:

- correct public input (33) -> `true`
- tampered public input (34) -> `false`

Deploy tx: `177f3ea3e5db38ee965a1207eb8cdc5e2ffaf6ba8a297cba075a21b32835e18a`.
This resolves the central feasibility risk: real Groth16/BLS12-381 proofs verify
on Stellar testnet via the host `pairing_check`. In the withdrawal/RFQ flows the
`verify` call executes inside ShadeVault's state-changing transaction.

## Byte serialization

`tools/circom2soroban` converts snarkjs `verification_key.json` / `proof.json` /
`public.json` into the contract byte layout (arkworks `serialize_uncompressed`,
which is byte-compatible with the Soroban host `G1Affine/G2Affine::from_array`):

```
VK     = alpha(96) | beta(192) | gamma(192) | delta(192) | u32_be(ic_len) | ic[i](96)...
Proof  = a(96) | b(192) | c(96)
Public = u32_be(len) | signal_i(32 BE)...
```

## Circuits (built)

- `circuits/withdraw_public/main.circom` — Shade's withdraw/settlement circuit
  (depth-12 Lean-IMT membership + domain-separated nullifier + enforced ASP
  membership + value range checks). circom 2.2.3, `--prime bls12381`. Public
  signals: `[nullifierHash, withdrawnValue, stateRoot, associationRoot, poolId,
  chainId]`. Backs withdrawal, RFQ settlement (note ownership), and CCTP outbound.
- `circuits/private_transfer/main.circom` — hidden-amount shielded transfer
  (#2): spend input note, create output note + public fee, value conservation
  `inValue == outValue + fee` enforced in-circuit, amounts never revealed. Public
  signals: `[nullifierHash, outputCommitment, feePublic, stateRoot, poolId,
  chainId]`.
- Building blocks vendored in `circuits/lib/` (poseidon255, merkleProof).

### Privacy upgrades (bible-aligned, implemented)

- **#1 Anonymity set / shared pool.** `shielded_pool` is a single persistent pool
  with a fixed note denomination; deposits accumulate so a withdrawal proves
  membership in a k>1 commitment set without revealing which leaf (the leaf index
  is a private witness). The withdrawal e2e builds k=3 (1 real + decoys) and the
  pool's leaf count grows across runs.
- **#3 Domain-separated nullifier.** `nullifierHash = Poseidon(nullifier, poolId,
  chainId)`. The contract binds its own `pool_id`/`chain_id` (set at construction)
  and rejects any proof whose domain differs (`WrongDomain`). Prevents replay
  across pools/chains (bible nullifier requirement).
- **#4 ZK compliance membership.** The association-set (ASP allowlist) Merkle
  membership of the note's `label` is **enforced** in-circuit (no zero-bypass);
  the contract binds the active `association_root` and rejects mismatches
  (`WrongAssociation`). coinutils refuses to build a witness for a non-member
  note. Real allowlist, proven in zero-knowledge.

Note commitments, nullifiers, and Merkle nodes use Poseidon over the BLS12-381
scalar field (`poseidon255`), byte-identical to the on-chain `soroban-poseidon`
used by the `lean-imt` Merkle tree (verified against the repo's poseidon
compatibility test: circom Poseidon255(n) == native poseidon_hash::<n+1>).

### Commitment-formula bug fixed

The upstream privacy-pools `commitment.circom` computed
`commitment = Poseidon2(Poseidon2(value,label), precommitment)` (sequential
2-input), but the Rust `coinutils generate_commitment` (which creates the
deposited leaf) uses `Poseidon(value, label, precommitment)` — a true **3-input**
permutation. These disagree, so the in-circuit leaf never matched the deposited
leaf and Merkle inclusion failed (`Assert Failed ... line 51`). Shade's
`circuits/withdraw_public/commitment.circom` uses `Poseidon255(3)` to match the
native hash. Verified end-to-end: witness generation + Groth16 prove + verify.

## On-chain integration (built + deployed)

- `contracts/stellar/shielded_pool` — holds USDC, tracks note commitments + a set
  of known Merkle roots. `withdraw` / `rfq_settle` / `withdraw_cctp` each call the
  verifier (`verify` -> BLS12-381 pairing_check), spend the nullifier once via
  `NullifierRegistry`, then release/credit/burn USDC. `rfq_settle` additionally
  verifies the solver's ed25519 signature over the quote hash.

### Merkle root: off-chain computation, on-chain attestation (design decision)

On-chain Poseidon Merkle *inserts* are infeasible on Soroban: a single depth-N
insert performs N native `poseidon_permutation` host calls plus tree bookkeeping,
which exceeds the per-transaction instruction budget (~100M) beyond the first
leaf. (The upstream privacy-pools example never hit this — its demo inserts only
one leaf.) `soroban-poseidon` already uses the native host permutation, so this
is a hard VM-budget limit, not an implementation inefficiency.

Shade therefore computes the post-insert root **off-chain** at native speed (the
same `lean-imt` used by `coinutils`) and the authorized registrar (relayer)
submits `(commitment, new_root)` to `receive_cctp_deposit`. The contract appends
the commitment, emits it on-chain (full auditability — anyone can recompute the
root from the on-chain commitment sequence), and records `new_root` as known.

Security: every security-critical step stays fully on-chain and trustless — the
Groth16 proof is verified on-chain, the nullifier is spent on-chain (double-spend
impossible), and funds are released by the contract. The proof binds membership
in a specific root; the contract only releases against a *known* root. The single
trust assumption is that the registrar publishes roots matching the on-chain
commitment list — auditable, and consistent with this phase stopping before the
MPC/TEE matcher. `lean-imt` remains vendored (`contracts/stellar/lean_imt`) for a
future on-chain path if Soroban raises the Poseidon/insert budget.

## Remaining work

- Optional: per-operation public-input binding (recipient/fee/deadline) beyond
  the current amount+nullifier+root binding (recipient bound via tx auth).
