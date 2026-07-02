pragma circom 2.2.0;

include "poseidon255.circom";
include "commitment.circom";
include "merkleProof.circom";
include "bitify.circom";
include "comparators.circom";

// Shade MpcSettlement circuit — MULTI-ASSET, RATE-AWARE.
//
// Proves that a two-party MPC committee match is consistent with real deposited
// notes — without revealing the notes' private preimages. The circuit jointly
// proves BOTH sides of a matched pair so the contract can atomically spend both
// nullifiers in a single `mpc_settle` call.
//
// CROSS-ASSET SETTLEMENT (fixes the prior 1:1 / single-asset assumption):
//   - Note A (spent by party A) holds asset `assetIdA`, note B holds `assetIdB`.
//     assetId is bound into each note's commitment (CommitmentHasher), so a note
//     is cryptographically tied to one asset — settlement can no longer assume
//     USDC.
//   - A crossing trade: A gives `matchedAmount7dp` of assetIdA and receives
//     assetIdB; B gives assetIdB and receives assetIdA.
//   - `rate` = price of 1 unit of assetIdA denominated in assetIdB, scaled by
//     RATE_SCALE = 1e14 (Reflector SEP-40 price convention). The contract
//     validates `rate` against the on-chain Reflector oracle (staleness +
//     deviation guard); this circuit enforces that the output amounts are
//     exactly consistent with that rate.
//   - Output notes (a cross-swap; NO token leaves the pool — ownership of
//     shielded notes changes):
//       outputCommitmentA (owned by B) = asset assetIdA, value matchedAmount7dp
//       outputCommitmentB (owned by A) = asset assetIdB, value
//         floor(matchedAmount7dp * rate / RATE_SCALE)
//
// Hash-function architecture:
//   - Committee batch hash: SHA-256 over canonical JSON (TypeScript). Passed as
//     the PUBLIC input `batchHash`; the contract verifies the committee
//     threshold Ed25519 signature over it independently and checks it equals
//     this proof's batchHash.
//   - In-circuit hashes: all Poseidon255 (commitment, nullifier, Merkle).
//
// Public-signal order (outputs first, then declared `public` inputs):
//   [0]  nullifierHashA     domain-sep nullifier for note A (spent on-chain)
//   [1]  nullifierHashB     domain-sep nullifier for note B (spent on-chain)
//   [2]  outputCommitmentA  new note (counterparty B owns; asset assetIdA)
//   [3]  outputCommitmentB  new note (counterparty A owns; asset assetIdB)
//   [4]  stateRoot          Merkle root; both notes must be leaves
//   [5]  associationRoot    ASP compliance root; both labels must be members
//   [6]  batchHash          SHA-256 batch hash the committee signed (pass-through)
//   [7]  poolId             domain separator
//   [8]  chainId            domain separator
//   [9]  matchedAmount7dp   amount of assetIdA traded (7dp)
//   [10] deadlineLedger     later of the two intent deadlines
//   [11] assetIdA           asset of note A / output note A
//   [12] assetIdB           asset of note B / output note B
//   [13] rate               price(assetIdA in assetIdB) * 1e14 (Reflector-scaled)

template MpcSettlement(treeDepth, associationDepth) {

    // ── PUBLIC INPUTS ────────────────────────────────────────────────────────
    signal input stateRoot;
    signal input associationRoot;
    signal input batchHash;
    signal input poolId;
    signal input chainId;
    signal input matchedAmount7dp;
    signal input deadlineLedger;
    signal input assetIdA;
    signal input assetIdB;
    signal input rate;

    // ── PRIVATE INPUTS — NOTE A (spent by party A; asset assetIdA) ───────────
    signal input labelA;
    signal input valueA;
    signal input nullifierA;
    signal input secretA;
    signal input stateIndexA;
    signal input stateSiblingsA[treeDepth];
    signal input labelIndexA;
    signal input labelSiblingsA[associationDepth];

    // ── PRIVATE INPUTS — OUTPUT NOTE A (counterparty B owns; asset assetIdA) ─
    // value is fixed to matchedAmount7dp (see below), so only the blinding
    // fields are supplied here.
    signal input outLabelA;
    signal input outNullifierA;
    signal input outSecretA;

    // ── PRIVATE INPUTS — NOTE B (spent by party B; asset assetIdB) ───────────
    signal input labelB;
    signal input valueB;
    signal input nullifierB;
    signal input secretB;
    signal input stateIndexB;
    signal input stateSiblingsB[treeDepth];
    signal input labelIndexB;
    signal input labelSiblingsB[associationDepth];

    // ── PRIVATE INPUTS — OUTPUT NOTE B (counterparty A owns; asset assetIdB) ─
    // outValueB = floor(matchedAmount7dp * rate / RATE_SCALE); prover supplies it
    // and the value is verified by the division gadget below.
    signal input outValueB;
    signal input outLabelB;
    signal input outNullifierB;
    signal input outSecretB;

    // ── OUTPUTS ──────────────────────────────────────────────────────────────
    signal output nullifierHashA;       // [0]
    signal output nullifierHashB;       // [1]
    signal output outputCommitmentA;    // [2]
    signal output outputCommitmentB;    // [3]

    // ── 1. Input commitments (asset-bound) ───────────────────────────────────
    component cmtA = CommitmentHasher();
    cmtA.value     <== valueA;
    cmtA.assetId   <== assetIdA;
    cmtA.label     <== labelA;
    cmtA.secret    <== secretA;
    cmtA.nullifier <== nullifierA;
    signal commitmentA <== cmtA.commitment;

    component cmtB = CommitmentHasher();
    cmtB.value     <== valueB;
    cmtB.assetId   <== assetIdB;
    cmtB.label     <== labelB;
    cmtB.secret    <== secretB;
    cmtB.nullifier <== nullifierB;
    signal commitmentB <== cmtB.commitment;

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

    // ── 5. Output commitments (cross-swap assets) ────────────────────────────
    // Output A goes to party B and is in asset assetIdA, value matchedAmount7dp.
    component outCmtA = CommitmentHasher();
    outCmtA.value     <== matchedAmount7dp;
    outCmtA.assetId   <== assetIdA;
    outCmtA.label     <== outLabelA;
    outCmtA.secret    <== outSecretA;
    outCmtA.nullifier <== outNullifierA;
    outputCommitmentA <== outCmtA.commitment;

    // Output B goes to party A and is in asset assetIdB, value outValueB.
    component outCmtB = CommitmentHasher();
    outCmtB.value     <== outValueB;
    outCmtB.assetId   <== assetIdB;
    outCmtB.label     <== outLabelB;
    outCmtB.secret    <== outSecretB;
    outCmtB.nullifier <== outNullifierB;
    outputCommitmentB <== outCmtB.commitment;

    // ── 6. Solvency: each party must own enough of the asset they send ───────
    // A sends matchedAmount7dp of assetIdA: matchedAmount7dp <= valueA.
    signal remainA <== valueA - matchedAmount7dp;
    component rngA = Num2Bits(128);
    rngA.in <== remainA;
    _ <== rngA.out;

    // B sends outValueB of assetIdB: outValueB <= valueB.
    signal remainB <== valueB - outValueB;
    component rngB = Num2Bits(128);
    rngB.in <== remainB;
    _ <== rngB.out;

    // ── 7. Rate correctness: outValueB == floor(matchedAmount7dp * rate / 1e14)
    // Enforced as: matchedAmount7dp * rate == outValueB * RATE_SCALE + remainder,
    // with 0 <= remainder < RATE_SCALE. This uniquely pins outValueB to the
    // Reflector-scaled price the contract independently validates against the
    // oracle. RATE_SCALE = 1e14 (< 2^47); products stay well under the field.
    var RATE_SCALE = 100000000000000;
    signal prod <== matchedAmount7dp * rate;
    signal remainder <== prod - outValueB * RATE_SCALE;
    // remainder >= 0 (fits in 64 bits) — a too-large outValueB makes this negative
    // (wraps to a huge field element) and fails the range check.
    component remRange = Num2Bits(64);
    remRange.in <== remainder;
    _ <== remRange.out;
    // remainder < RATE_SCALE
    component remLt = LessThan(64);
    remLt.in[0] <== remainder;
    remLt.in[1] <== RATE_SCALE;
    remLt.out === 1;

    // ── 8. Bind remaining public inputs into the constraint system ───────────
    // batchHash is a pass-through public signal (SHA-256, not recomputed here).
    signal bhBind <== batchHash * batchHash;
    signal dlBind <== deadlineLedger * deadlineLedger;
}

component main {public [
    stateRoot, associationRoot, batchHash,
    poolId, chainId, matchedAmount7dp, deadlineLedger,
    assetIdA, assetIdB, rate
]} = MpcSettlement(12, 2);
