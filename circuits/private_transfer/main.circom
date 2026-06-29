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
// Public signals (after the output):
//   [0] nullifierHash   (domain-separated input nullifier, #3)
//   [1] outputCommitment (new note; hides value_out)
//   [2] feePublic       (fee paid to relayer, public)
//   [3] stateRoot       (input note membership)
//   [4] poolId          (#3)
//   [5] chainId         (#3)
template PrivateTransfer(treeDepth) {
    // PUBLIC
    signal input outputCommitment;  // [1]
    signal input feePublic;         // [2]
    signal input stateRoot;         // [3]
    signal input poolId;            // [4]
    signal input chainId;           // [5]

    // PRIVATE — input note
    signal input inValue;
    signal input inLabel;
    signal input inNullifier;
    signal input inSecret;
    signal input stateSiblings[treeDepth];
    signal input stateIndex;

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
}

component main {public [outputCommitment, feePublic, stateRoot, poolId, chainId]} = PrivateTransfer(12);
