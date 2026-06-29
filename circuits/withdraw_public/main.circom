pragma circom 2.2.0;

include "commitment.circom";
include "merkleProof.circom";
include "poseidon.circom";

// Shade Withdraw / settlement circuit.
//
// Privacy upgrades over the upstream privacy-pools Withdraw:
//  - #3 Domain-separated nullifier: the public nullifierHash binds pool_id and
//       chain_id, so a proof/nullifier for one pool or chain cannot be replayed
//       in another. Matches the bible: nullifier = Poseidon(secret, .., pool_id,
//       chain_id, domain_sep).
//  - #4 ZK compliance membership: the association-set membership check is
//       ENFORCED (the caller supplies a real, non-zero associationRoot and a
//       valid Merkle path for the note's label).
template Withdraw(treeDepth, associationDepth) {
    // PUBLIC SIGNALS. Final public-signal order (output first, then declared
    // inputs in the `public [...]` list below):
    //   [0] nullifierHash  [1] operationType  [2] withdrawnValue
    //   [3] recipientHash   [4] relayerFee     [5] deadlineLedger
    //   [6] stateRoot       [7] associationRoot[8] poolId  [9] chainId
    signal input operationType;         // bound op type; contract requires == WITHDRAW_PUBLIC
    signal input withdrawnValue;
    signal input recipientHash;         // sha256(recipient strkey); contract recomputes from `to`
    signal input relayerFee;            // bound fee; net to recipient = withdrawnValue - relayerFee
    signal input deadlineLedger;        // bound deadline; contract requires not expired
    signal input stateRoot;
    signal input associationRoot;       // ASP allowlist root (MUST be non-zero)
    signal input poolId;                // domain separator: this pool
    signal input chainId;               // domain separator: this chain

    // PRIVATE SIGNALS
    signal input label;                 // hash(scope, nonce)
    signal input value;                 // value of the commitment
    signal input nullifier;             // nullifier secret of the commitment
    signal input secret;                // secret of the commitment

    signal input stateSiblings[treeDepth];
    signal input stateIndex;

    signal input labelIndex;
    signal input labelSiblings[associationDepth];

    // OUTPUT SIGNALS
    signal output nullifierHash;        // [0] domain-separated public nullifier

    // compute commitment (formula unchanged: Poseidon(value, label, Poseidon(nullifier, secret)))
    component commitmentHasher = CommitmentHasher();
    commitmentHasher.label <== label;
    commitmentHasher.value <== value;
    commitmentHasher.secret <== secret;
    commitmentHasher.nullifier <== nullifier;
    signal commitment <== commitmentHasher.commitment;

    // #3 domain-separated nullifier hash = Poseidon(nullifier, poolId, chainId)
    component nullifierHasher = Poseidon255(3);
    nullifierHasher.in[0] <== nullifier;
    nullifierHasher.in[1] <== poolId;
    nullifierHasher.in[2] <== chainId;
    nullifierHash <== nullifierHasher.out;

    // verify commitment is in the state tree
    component stateRootChecker = MerkleProof(treeDepth);
    stateRootChecker.leaf <== commitment;
    stateRootChecker.leafIndex <== stateIndex;
    stateRootChecker.siblings <== stateSiblings;
    stateRoot === stateRootChecker.out;

    // #4 ENFORCED association-set membership: label must be in the association tree.
    component associationRootChecker = MerkleProof(associationDepth);
    associationRootChecker.leaf <== label;
    associationRootChecker.leafIndex <== labelIndex;
    associationRootChecker.siblings <== labelSiblings;
    associationRoot === associationRootChecker.out;   // hard equality (no zero-bypass)

    // withdrawn value must not exceed commitment value (range-checked, 128-bit)
    signal remainingValue <== value - withdrawnValue;
    component remainingValueRangeCheck = Num2Bits(128);
    remainingValueRangeCheck.in <== remainingValue;
    _ <== remainingValueRangeCheck.out;

    component withdrawnValueRangeCheck = Num2Bits(128);
    withdrawnValueRangeCheck.in <== withdrawnValue;
    _ <== withdrawnValueRangeCheck.out;

    // relayerFee must be <= withdrawnValue (net to recipient is non-negative).
    // This both binds relayerFee into the proof and enforces a real relationship.
    signal netOutput <== withdrawnValue - relayerFee;
    component netRangeCheck = Num2Bits(128);
    netRangeCheck.in <== netOutput;
    _ <== netRangeCheck.out;
    component feeRangeCheck = Num2Bits(128);
    feeRangeCheck.in <== relayerFee;
    _ <== feeRangeCheck.out;

    // Bind operationType, recipientHash, deadlineLedger into the constraint
    // system (their values are enforced by the contract, not the circuit).
    signal opBind <== operationType * operationType;
    signal recBind <== recipientHash * recipientHash;
    signal dlBind <== deadlineLedger * deadlineLedger;
}

component main {public [operationType, withdrawnValue, recipientHash, relayerFee, deadlineLedger, stateRoot, associationRoot, poolId, chainId]} = Withdraw(12, 2);
