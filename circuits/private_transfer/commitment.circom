pragma circom 2.2.0;

include "poseidon255.circom";

/**
 * Shade CommitmentHasher.
 *
 * Commitment scheme (MUST match the off-chain note-crypto / coinutils
 * `generate_commitment`, which uses the native soroban-poseidon):
 *
 *   precommitment = Poseidon(nullifier, secret)             // 2 inputs
 *   boundLabel    = Poseidon(assetId, label)                // 2 inputs (asset binding)
 *   commitment    = Poseidon(value, boundLabel, precommitment)  // 3 inputs (native t=4)
 *   nullifierHash = Poseidon(nullifier)                     // 1 input
 *
 * ASSET BINDING: the note's asset identity is folded into the commitment via
 * `boundLabel = Poseidon(assetId, label)`. `assetId` is a public signal
 * (= int(sha256(asset_strkey)[:31]), matching the deposit circuit's assetIdHash
 * and the contract's recipient_hash(asset)). This makes the commitment — and
 * therefore every Merkle leaf and nullifier spend — cryptographically bound to
 * a single asset, so settlement can no longer assume USDC. The raw `label`
 * (asset-independent) is still what the ASP association tree checks, so the
 * association-set logic in coinutils is unchanged. Arity is preserved: on-chain
 * lean-imt Poseidon hashing and coinutils generate_commitment stay t=4 (3-input)
 * for the outer commitment, adding only one t=3 (2-input) hash for boundLabel.
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
    signal input assetId;
    signal input label;
    signal input secret;
    signal input nullifier;

    signal output commitment;
    signal output nullifierHash;
    signal output boundLabel;

    component nullifierHasher = Poseidon255(1);
    nullifierHasher.in[0] <== nullifier;

    component precommitmentHasher = Poseidon255(2);
    precommitmentHasher.in[0] <== nullifier;
    precommitmentHasher.in[1] <== secret;

    // Asset binding: fold assetId into the label used by the commitment.
    component boundLabelHasher = Poseidon255(2);
    boundLabelHasher.in[0] <== assetId;
    boundLabelHasher.in[1] <== label;

    component commitmentHasher = Poseidon255(3);
    commitmentHasher.in[0] <== value;
    commitmentHasher.in[1] <== boundLabelHasher.out;
    commitmentHasher.in[2] <== precommitmentHasher.out;

    commitment <== commitmentHasher.out;
    nullifierHash <== nullifierHasher.out;
    boundLabel <== boundLabelHasher.out;
}
