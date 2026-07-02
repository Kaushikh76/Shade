pragma circom 2.2.0;

include "poseidon255.circom";
include "commitment.circom";
include "merkleProof.circom";

// Shade MpcSettlement circuit.
//
// Proves that a two-party MPC committee match is consistent with real deposited
// notes — without revealing the notes' private preimages. The circuit jointly
// proves BOTH sides of a matched pair so the contract can atomically spend both
// nullifiers in a single `mpc_settle` call.
//
// Hash-function architecture (no mismatch):
//   - Committee batch hash: SHA-256 over a canonical JSON string (TypeScript code).
//     This is passed as a PUBLIC input `batchHash`. The contract verifies the
//     committee threshold Ed25519 signature over this hash independently.
//   - In-circuit hashes: all Poseidon255 (commitment, nullifier, Merkle proofs,
//     compliance tree). These NEVER need to match the SHA-256 batch hash.
//   - Link: both the contract (committee sig check) and this circuit (proof)
//     expose `batchHash` as a shared public signal. If they differ the contract
//     rejects. This binds the proof to the committee-approved batch without
//     requiring a SHA-256 gadget inside the circuit.
//
// What the circuit proves:
//   1. Input note A and note B are genuine commitments in the current Merkle tree.
//   2. Both labels satisfy the protocol's ASP compliance policy.
//   3. Domain-separated nullifier hashes are correctly formed.
//   4. Output commitments are well-formed from supplied preimages.
//   5. Matched amount satisfies both trades (matchedAmount ≤ min(valueA, valueB)).
//   6. Value is conserved: outValueA + outValueB == 2 × matchedAmount.
//
// Public-signal order (outputs first, then declared `public` inputs):
//   [0]  nullifierHashA     domain-sep nullifier for note A (spent on-chain)
//   [1]  nullifierHashB     domain-sep nullifier for note B (spent on-chain)
//   [2]  outputCommitmentA  new note commitment (counterparty B will own this)
//   [3]  outputCommitmentB  new note commitment (counterparty A will own this)
//   [4]  stateRoot          Merkle root; both notes must be leaves
//   [5]  associationRoot    ASP compliance root; both labels must be members
//   [6]  batchHash          SHA-256 batch hash the committee signed (pass-through)
//   [7]  poolId             domain separator
//   [8]  chainId            domain separator
//   [9]  matchedAmount7dp   amount of the trade (7dp)
//   [10] deadlineLedger     later of the two intent deadlines

template MpcSettlement(treeDepth, associationDepth) {

    // ── PUBLIC INPUTS ────────────────────────────────────────────────────────
    signal input stateRoot;
    signal input associationRoot;
    // batchHash: the SHA-256 batch hash from `computeBatchHash()` in mpc-crypto.
    // The contract verifies the committee threshold sig over this value and checks
    // that this proof's batchHash == the one that was signed.
    signal input batchHash;
    signal input poolId;
    signal input chainId;
    signal input matchedAmount7dp;
    signal input deadlineLedger;
    // Phase 2/5: single asset id for a SAME-ASSET crossing — bound into all four
    // note commitments (assetA == assetB == outputAssetA == outputAssetB, §6.4).
    signal input assetId;

    // ── PRIVATE INPUTS — NOTE A (the note being spent by party A) ───────────
    signal input labelA;
    signal input valueA;
    signal input nullifierA;
    signal input secretA;
    signal input stateIndexA;
    signal input stateSiblingsA[treeDepth];
    signal input labelIndexA;
    signal input labelSiblingsA[associationDepth];

    // ── PRIVATE INPUTS — OUTPUT NOTE A (new note; counterparty B will own it)─
    signal input outValueA;
    signal input outLabelA;
    signal input outNullifierA;
    signal input outSecretA;

    // ── PRIVATE INPUTS — NOTE B (the note being spent by party B) ───────────
    signal input labelB;
    signal input valueB;
    signal input nullifierB;
    signal input secretB;
    signal input stateIndexB;
    signal input stateSiblingsB[treeDepth];
    signal input labelIndexB;
    signal input labelSiblingsB[associationDepth];

    // ── PRIVATE INPUTS — OUTPUT NOTE B (new note; counterparty A will own it)─
    signal input outValueB;
    signal input outLabelB;
    signal input outNullifierB;
    signal input outSecretB;

    // ── OUTPUTS ──────────────────────────────────────────────────────────────
    signal output nullifierHashA;       // [0]
    signal output nullifierHashB;       // [1]
    signal output outputCommitmentA;    // [2]
    signal output outputCommitmentB;    // [3]

    // ── 1. Compute input commitments ─────────────────────────────────────────
    component cmtA = CommitmentHasher();
    cmtA.assetId   <== assetId;
    cmtA.label     <== labelA;
    cmtA.value     <== valueA;
    cmtA.secret    <== secretA;
    cmtA.nullifier <== nullifierA;
    signal commitmentA   <== cmtA.commitment;
    signal _inNhA        <== cmtA.nullifierHash; // unused output consumed

    component cmtB = CommitmentHasher();
    cmtB.assetId   <== assetId;
    cmtB.label     <== labelB;
    cmtB.value     <== valueB;
    cmtB.secret    <== secretB;
    cmtB.nullifier <== nullifierB;
    signal commitmentB   <== cmtB.commitment;
    signal _inNhB        <== cmtB.nullifierHash;

    // ── 2. Merkle membership: both notes in state tree ───────────────────────
    component merkleA = MerkleProof(treeDepth);
    merkleA.leaf      <== commitmentA;
    merkleA.leafIndex <== stateIndexA;
    merkleA.siblings  <== stateSiblingsA;
    stateRoot === merkleA.out;

    component merkleB = MerkleProof(treeDepth);
    merkleB.leaf      <== commitmentB;
    merkleB.leafIndex <== stateIndexB;
    merkleB.siblings  <== stateSiblingsB;
    stateRoot === merkleB.out;

    // ── 3. ASP compliance: both labels in association tree ───────────────────
    component assocA = MerkleProof(associationDepth);
    assocA.leaf      <== labelA;
    assocA.leafIndex <== labelIndexA;
    assocA.siblings  <== labelSiblingsA;
    associationRoot === assocA.out;

    component assocB = MerkleProof(associationDepth);
    assocB.leaf      <== labelB;
    assocB.leafIndex <== labelIndexB;
    assocB.siblings  <== labelSiblingsB;
    associationRoot === assocB.out;

    // ── 4. Domain-separated nullifier hashes ────────────────────────────────
    component nhA = Poseidon255(3);
    nhA.in[0] <== nullifierA;
    nhA.in[1] <== poolId;
    nhA.in[2] <== chainId;
    nullifierHashA <== nhA.out;

    component nhB = Poseidon255(3);
    nhB.in[0] <== nullifierB;
    nhB.in[1] <== poolId;
    nhB.in[2] <== chainId;
    nullifierHashB <== nhB.out;

    // ── 5. Output commitments ────────────────────────────────────────────────
    component outCmtA = CommitmentHasher();
    outCmtA.assetId   <== assetId;
    outCmtA.label     <== outLabelA;
    outCmtA.value     <== outValueA;
    outCmtA.secret    <== outSecretA;
    outCmtA.nullifier <== outNullifierA;
    outputCommitmentA <== outCmtA.commitment;
    signal _outNhA    <== outCmtA.nullifierHash;

    component outCmtB = CommitmentHasher();
    outCmtB.assetId   <== assetId;
    outCmtB.label     <== outLabelB;
    outCmtB.value     <== outValueB;
    outCmtB.secret    <== outSecretB;
    outCmtB.nullifier <== outNullifierB;
    outputCommitmentB <== outCmtB.commitment;
    signal _outNhB    <== outCmtB.nullifierHash;

    // ── 6. Match value constraints ───────────────────────────────────────────
    // matchedAmount ≤ valueA (difference is non-negative, 128-bit).
    signal remainA <== valueA - matchedAmount7dp;
    component rngA = Num2Bits(128);
    rngA.in <== remainA;
    _ <== rngA.out;

    // matchedAmount ≤ valueB
    signal remainB <== valueB - matchedAmount7dp;
    component rngB = Num2Bits(128);
    rngB.in <== remainB;
    _ <== rngB.out;

    // Value conservation: each party sends matchedAmount to the other.
    signal outSum      <== outValueA + outValueB;
    signal expectedSum <== matchedAmount7dp * 2;
    outSum === expectedSum;

    // ── 7. Bind public inputs into constraint system ─────────────────────────
    // batchHash is a pass-through public signal (SHA-256, not recomputed here).
    // The contract checks: committee_sig_verified_over(batchHash) AND proof.batchHash == batchHash.
    signal bhBind      <== batchHash * batchHash;
    signal dlBind      <== deadlineLedger * deadlineLedger;
}

component main {public [
    stateRoot, associationRoot, batchHash,
    poolId, chainId, matchedAmount7dp, deadlineLedger, assetId
]} = MpcSettlement(12, 2);
