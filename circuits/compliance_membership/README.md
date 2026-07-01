# ComplianceMembership

Status (2026-07): **allow-membership implemented, deny-non-membership NOT implemented.**
No standalone `compliance_membership.circom` exists — the design keeps this reused
across circuits rather than as a separate, independently-invoked circuit.

## Allow-set membership — implemented

ASP allow-list membership is a hard equality Merkle-membership check
(`associationRoot === associationRootChecker.out`, no zero-bypass), embedded in:

- `circuits/withdraw_public/main.circom` (`#4`) — covers deposit/withdraw/CCTP/RFQ,
  since they all reuse this circuit.
- `circuits/private_transfer/main.circom` (P2 #14, added after a prior version of
  this README incorrectly implied it was already covered by contract-level
  logic — it wasn't; transfers had **no** ASP binding at all until this change).

Both check that the *spender's* label is a member of the association tree the
pool's `associationRoot` points at. `shielded_pool::set_association_root`
(admin-gated) and `compliance_registry`'s `allow_root` are the two places this
root can come from; the pool's own `ASSOCROOT` storage slot is what circuits
are actually checked against today (`compliance_registry` is not yet wired in
as the pool's root source — see the contract-wiring note below).

## Deny-set non-membership — NOT implemented (scoped design for future work)

Correcting a prior version of this file: **no deny-root check exists anywhere**
in this protocol today, on-chain or in-circuit. `compliance_registry::Policy`
stores a `deny_root` field, but nothing ever reads it. This is real gap #14
from the remediation plan, not yet closed.

Why it's a separate, larger piece of work than the allow-check above:

1. **No deny-set data model or admin tooling.** There is no equivalent of
   `buildAssociationSet` (`packages/proving` / `coinutils update-association`)
   for a deny-set — nothing populates real denied labels today.
2. **In-circuit non-membership needs a different Merkle scheme.** The current
   `MerkleProof` component only proves a leaf *is* present at a given index —
   it cannot prove absence. The label the circuit is checking is a private
   signal, so the check must happen in-circuit (making the label a public
   signal to check deny-membership off-chain would defeat the point of a
   private label). The standard technique (Tornado Cash / Privacy Pools ASP
   convention) is a **sorted deny-tree + adjacent-leaf range proof**: the
   prover supplies two adjacent leaves `lo < label < hi` from the sorted
   tree, both proven present via ordinary `MerkleProof`, plus a `LessThan`
   comparator (circomlib's `comparators.circom`) proving `lo < label < hi`.
   Absence of `label` follows because the tree is sorted and `lo`/`hi` are
   adjacent (no room for `label` to also be a leaf between them).
   - Needs `circomlib` as a real, always-available build dependency (today
     `scripts/circuits-build.ts` only *optionally* includes it if a global
     npm install happens to have it — that guard would need to become a hard
     requirement).
   - Needs off-chain tooling to build/maintain a *sorted* deny-tree (new
     `coinutils` subcommand, mirroring `update-association`) and to compute
     the two-adjacent-leaf witness for a given label.
   - Alternative: a Sparse Merkle Tree (empty leaf = absence) is cleaner
     conceptually but is a bigger infra change (new tree type, new circuit
     gadget, new off-chain SMT tooling) — not recommended as the first step.
3. **Public-signal layout changes are breaking for already-deployed circuits.**
   `withdraw_public` is reused by 4+ flows (deposit/withdraw/CCTP/RFQ); adding
   a `denyRoot` signal means recompiling, re-running trusted setup, and
   redeploying its verifier, then updating every caller. `private_transfer`
   and `mpc_settlement` have narrower blast radii (one verifier each) and are
   the more tractable place to land this first.

**Recommended next step**, in order: (a) add `denyRoot` + the sorted-tree
non-membership gadget to `private_transfer` only (smallest blast radius,
already being touched for P2 #14); (b) build the off-chain sorted-deny-tree
tooling and wire `compliance_registry.deny_root` as its source of truth;
(c) once proven there, extend to `withdraw_public` and `mpc_settlement` in a
dedicated, circuit-isolated change (not bundled with unrelated work, so a
verifier redeploy failure doesn't block anything else).
