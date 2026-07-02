pragma circom 2.2.0;

include "commitment.circom";
include "merkleProof.circom";
include "poseidon.circom";

// Shade PrivateTransfer (#2 hidden-amount shielded transfer).
//
// Spends one input note and creates one output note, paying a public fee.
// The input and output AMOUNTS are private (never revealed); only the public
// fee and the output commitment are public. Value conservation is enforced
// in-circuit: value_in == value_out + fee. This is the Zcash/Penumbra-style
// shielded transfer the bible specifies (PrivateTransfer circuit).
//
// P2 #14: prior versions of this circuit had NO ASP binding at all — funds
// could move inside the pool completely outside the compliance envelope that
// deposit/withdraw enforce. This now requires the same hard-equality
// allow-set membership check as withdraw_public (#4): the spender's label
// must be a leaf in the association tree. Deny-root NON-membership is a
// separate, larger piece of work (needs a sorted deny-tree + an in-circuit
// exclusion proof, plus off-chain tooling to build/serve one) — see
// circuits/compliance_membership/README.md for the scoped follow-up design;
// it is intentionally not attempted here alongside an unrelated allow-check.
//
// Public signals (after the output):
//   [0] nullifierHash    (domain-separated input nullifier, #3)
//   [1] outputCommitment (new note; hides value_out)
//   [2] feePublic        (fee paid to relayer, public)
//   [3] stateRoot        (input note membership)
//   [4] associationRoot  (ASP allowlist root; spender's label must be a member)
//   [5] poolId           (#3)
//   [6] chainId          (#3)
template PrivateTransfer(treeDepth, associationDepth) {
    // PUBLIC
    signal input outputCommitment;  // [1]
    signal input feePublic;         // [2]
    signal input stateRoot;         // [3]
    signal input associationRoot;   // [4]
    signal input poolId;            // [5]
    signal input chainId;           // [6]
    signal input assetId;           // [7] asset bound into both note commitments (transfer preserves asset)

    // PRIVATE — input note
    signal input inValue;
    signal input inLabel;
    signal input inNullifier;
    signal input inSecret;
    signal input stateSiblings[treeDepth];
    signal input stateIndex;
    signal input labelIndex;
    signal input labelSiblings[associationDepth];

    // PRIVATE — output note
    signal input outValue;
    signal input outLabel;
    signal input outNullifier;
    signal input outSecret;

    // OUTPUT
    signal output nullifierHash;    // [0]

    // 1) input commitment membership in the state tree
    component inHasher = CommitmentHasher();
    inHasher.value <== inValue;
    inHasher.assetId <== assetId;
    inHasher.label <== inLabel;
    inHasher.nullifier <== inNullifier;
    inHasher.secret <== inSecret;
    signal inCommitment <== inHasher.commitment;

    component stateRootChecker = MerkleProof(treeDepth);
    stateRootChecker.leaf <== inCommitment;
    stateRootChecker.leafIndex <== stateIndex;
    stateRootChecker.siblings <== stateSiblings;
    stateRoot === stateRootChecker.out;

    // 2) domain-separated nullifier for the input note (#3)
    component nullifierHasher = Poseidon255(3);
    nullifierHasher.in[0] <== inNullifier;
    nullifierHasher.in[1] <== poolId;
    nullifierHasher.in[2] <== chainId;
    nullifierHash <== nullifierHasher.out;

    // 3) output commitment is correctly formed and matches the public signal
    component outHasher = CommitmentHasher();
    outHasher.value <== outValue;
    outHasher.assetId <== assetId;
    outHasher.label <== outLabel;
    outHasher.nullifier <== outNullifier;
    outHasher.secret <== outSecret;
    outputCommitment === outHasher.commitment;

    // 4) value conservation: inValue == outValue + feePublic (amounts hidden)
    inValue === outValue + feePublic;

    // 5) range checks: outValue and feePublic in [0, 2^128) so the sum can't wrap
    component outRange = Num2Bits(128);
    outRange.in <== outValue;
    _ <== outRange.out;
    component feeRange = Num2Bits(128);
    feeRange.in <== feePublic;
    _ <== feeRange.out;

    // 6) P2 #14 ENFORCED association-set membership: the spender's label must
    // be in the association tree (hard equality, no zero-bypass) — matches
    // withdraw_public's #4 check so transfers are held to the same compliance
    // envelope as deposit/withdraw.
    component associationRootChecker = MerkleProof(associationDepth);
    associationRootChecker.leaf <== inLabel;
    associationRootChecker.leafIndex <== labelIndex;
    associationRootChecker.siblings <== labelSiblings;
    associationRoot === associationRootChecker.out;
}

component main {public [outputCommitment, feePublic, stateRoot, associationRoot, poolId, chainId, assetId]} = PrivateTransfer(12, 2);
