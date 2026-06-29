pragma circom 2.2.0;

include "poseidon255.circom";

/**
 * Shade CommitmentHasher.
 *
 * Commitment scheme (MUST match the off-chain note-crypto / coinutils
 * `generate_commitment`, which uses the native soroban-poseidon):
 *
 *   precommitment = Poseidon(nullifier, secret)        // 2 inputs
 *   commitment    = Poseidon(value, label, precommitment)  // 3 inputs (native t=4)
 *   nullifierHash = Poseidon(nullifier)                // 1 input
 *
 * NOTE: the original privacy-pools commitment.circom hashed (value,label) and
 * precommitment *sequentially* with Poseidon(2). That does NOT match the Rust
 * `poseidon_hash([value,label,precommitment])` (a true 3-input permutation), so
 * the in-circuit leaf disagreed with the deposited leaf and Merkle inclusion
 * failed. Poseidon255(3) here is byte-identical to soroban-poseidon t=4
 * (verified against the repo poseidon compatibility test).
 */
template CommitmentHasher() {
    signal input value;
    signal input label;
    signal input secret;
    signal input nullifier;

    signal output commitment;
    signal output nullifierHash;

    component nullifierHasher = Poseidon255(1);
    nullifierHasher.in[0] <== nullifier;

    component precommitmentHasher = Poseidon255(2);
    precommitmentHasher.in[0] <== nullifier;
    precommitmentHasher.in[1] <== secret;

    component commitmentHasher = Poseidon255(3);
    commitmentHasher.in[0] <== value;
    commitmentHasher.in[1] <== label;
    commitmentHasher.in[2] <== precommitmentHasher.out;

    commitment <== commitmentHasher.out;
    nullifierHash <== nullifierHasher.out;
}
