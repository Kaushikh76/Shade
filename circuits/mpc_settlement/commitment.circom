pragma circom 2.2.0;

include "poseidon255.circom";

/*
 * Shade CommitmentHasher — ASSET-BOUND (Phase 2, spec §6.3).
 *
 * Commitment scheme (MUST match the off-chain coinutils `generate_commitment`,
 * which uses the native soroban-poseidon):
 *
 *   precommitment    = Poseidon(nullifier, secret)             // 2 inputs (t=3)
 *   assetValueLabel  = Poseidon(assetId, value, label)         // 3 inputs (t=4)
 *   commitment       = Poseidon(assetValueLabel, precommitment)// 2 inputs (t=3)
 *   nullifierHash    = Poseidon(nullifier)                     // 1 input  (t=2)
 *
 * assetId binds the note to its asset so USDC and XLM notes are distinct at the
 * proof layer. Only 1/2/3-input Poseidon widths are used — the widths already
 * verified byte-identical to native soroban-poseidon (no unproven t=5).
 */
template CommitmentHasher() {
    // inputs
    signal input assetId;
    signal input value;
    signal input label;
    signal input secret;
    signal input nullifier;

    // outputs
    signal output commitment;
    signal output nullifierHash;

    component nullifierHasher = Poseidon255(1);
    nullifierHasher.in[0] <== nullifier;

    component precommitmentHasher = Poseidon255(2);
    precommitmentHasher.in[0] <== nullifier;
    precommitmentHasher.in[1] <== secret;

    component assetValueLabel = Poseidon255(3);
    assetValueLabel.in[0] <== assetId;
    assetValueLabel.in[1] <== value;
    assetValueLabel.in[2] <== label;

    component commitmentHasher = Poseidon255(2);
    commitmentHasher.in[0] <== assetValueLabel.out;
    commitmentHasher.in[1] <== precommitmentHasher.out;

    commitment <== commitmentHasher.out;
    nullifierHash <== nullifierHasher.out;
}
