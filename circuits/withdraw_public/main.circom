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
    //   [10] quoteHash      [11] intentHash    [12] fillReceiptHash  (P1.6 RFQ)
    //   [13] destinationDomain [14] destinationRecipient [15] maxFee
    //   [16] minFinalityThreshold                              (P1.7 CCTP)
    //
    // P1.6: signals [10..12] are RFQ-settlement bindings; P1.7: signals [13..16]
    // are WithdrawCCTP destination bindings. All are APPENDED so the existing
    // withdraw/cctp/rfq public-signal indices [0..9] are unchanged. Each op sets
    // the signals it doesn't use to 0; the contract enforces arg==proof per op.
    signal input operationType;         // bound op type; contract requires == op for this fn
    signal input withdrawnValue;        // RFQ: solver credit / net output
    signal input recipientHash;         // sha256(recipient strkey); contract recomputes from `to`
    signal input relayerFee;            // bound fee; net to recipient = withdrawnValue - relayerFee
    signal input deadlineLedger;        // bound deadline; contract requires not expired
    signal input stateRoot;
    signal input associationRoot;       // ASP allowlist root (MUST be non-zero)
    signal input poolId;                // domain separator: this pool
    signal input chainId;               // domain separator: this chain
    signal input quoteHash;             // P1.6 RFQ: int(sha256(quote)[:31]); contract binds arg
    signal input intentHash;            // P1.6 RFQ: int(sha256(intent)[:31]); contract binds arg
    signal input fillReceiptHash;       // P1.6 RFQ: int(sha256(fill_tx)[:31]); contract binds arg
    signal input destinationDomain;     // P1.7 CCTP: dest domain; contract binds arg
    signal input destinationRecipient;  // P1.7 CCTP: int(recipient32); contract binds arg
    signal input maxFee;                // P1.7 CCTP: max fee; contract binds arg
    signal input minFinalityThreshold;  // P1.7 CCTP: min finality threshold; contract binds arg
    signal input assetId;               // [17] asset bound into the note commitment; contract binds arg to the SAC being released

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
    commitmentHasher.assetId <== assetId;
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

    // P1.6 RFQ bindings: pass-through public inputs the contract enforces
    // (quote_hash / intent_hash / fill_receipt_hash arg == proof signal).
    signal qhBind <== quoteHash * quoteHash;
    signal ihBind <== intentHash * intentHash;
    signal frBind <== fillReceiptHash * fillReceiptHash;

    // P1.7 CCTP destination bindings: pass-through public inputs the contract
    // enforces (destination_domain / destination_recipient / max_fee /
    // min_finality_threshold arg == proof signal).
    signal ddBind <== destinationDomain * destinationDomain;
    signal drBind <== destinationRecipient * destinationRecipient;
    signal mfBind <== maxFee * maxFee;
    signal ftBind <== minFinalityThreshold * minFinalityThreshold;
}

component main {public [operationType, withdrawnValue, recipientHash, relayerFee, deadlineLedger, stateRoot, associationRoot, poolId, chainId, quoteHash, intentHash, fillReceiptHash, destinationDomain, destinationRecipient, maxFee, minFinalityThreshold, assetId]} = Withdraw(12, 2);
