pragma circom 2.2.0;

include "poseidon255.circom";
include "commitment.circom";
include "merkleProof.circom";
include "comparators.circom"; // circomlib: LessThan / LessEqThan / GreaterEqThan / IsEqual

// Shade MpcPricedSettlement circuit (Phase 6, spec §10).
//
// A PRICED CROSS-ASSET two-party crossing:
//   Party A spends `matchedAmountA` of assetX (inputAssetA) and receives
//     `matchedAmountB` of assetY (outputAssetA == inputAssetB);
//   Party B spends `matchedAmountB` of assetY (inputAssetB) and receives
//     `matchedAmountA` of assetX (outputAssetB == inputAssetA).
//
// Fixed-point price (assetY units per assetX unit):
//   matchedAmountB == floor(matchedAmountA * priceScaled / priceScale)
// enforced as: 0 <= matchedAmountA*priceScaled - matchedAmountB*priceScale < priceScale.
//
// No partial fills: each input note's full value equals its matched amount.
template MpcPricedSettlement(treeDepth, associationDepth) {
    // ── PUBLIC INPUTS ────────────────────────────────────────────────────────
    signal input stateRoot;
    signal input associationRoot;
    signal input batchHash;
    signal input poolId;
    signal input chainId;
    signal input deadlineLedger;
    signal input inputAssetA;   // assetX
    signal input outputAssetA;  // assetY (what A receives)
    signal input inputAssetB;   // assetY
    signal input outputAssetB;  // assetX (what B receives)
    signal input matchedAmountA; // X crossing (A spends, B receives)
    signal input matchedAmountB; // Y crossing (B spends, A receives)
    signal input priceScaled;    // assetY per assetX * priceScale
    signal input priceScale;     // == 1e9
    signal input minOutputA;     // A's min acceptable Y
    signal input minOutputB;     // B's min acceptable X

    // ── PRIVATE: input note A (assetX, value = matchedAmountA) ───────────────
    signal input labelA;
    signal input nullifierA;
    signal input secretA;
    signal input stateIndexA;
    signal input stateSiblingsA[treeDepth];
    signal input labelIndexA;
    signal input labelSiblingsA[associationDepth];
    // input note B (assetY, value = matchedAmountB)
    signal input labelB;
    signal input nullifierB;
    signal input secretB;
    signal input stateIndexB;
    signal input stateSiblingsB[treeDepth];
    signal input labelIndexB;
    signal input labelSiblingsB[associationDepth];
    // output note A (assetY, value = matchedAmountB) — goes to A
    signal input outLabelA;
    signal input outNullifierA;
    signal input outSecretA;
    // output note B (assetX, value = matchedAmountA) — goes to B
    signal input outLabelB;
    signal input outNullifierB;
    signal input outSecretB;

    // ── OUTPUTS ──────────────────────────────────────────────────────────────
    signal output nullifierHashA;    // [0]
    signal output nullifierHashB;    // [1]
    signal output outputCommitmentA; // [2]
    signal output outputCommitmentB; // [3]

    // ── 1. Asset pairing: A gives X gets Y, B gives Y gets X (cross-asset) ────
    outputAssetA === inputAssetB;
    outputAssetB === inputAssetA;
    component sameAsset = IsEqual();
    sameAsset.in[0] <== inputAssetA;
    sameAsset.in[1] <== inputAssetB;
    sameAsset.out === 0; // inputAssetA != inputAssetB (must be a genuine cross-asset)

    priceScale === 1000000000;

    // ── 2. Input commitments (asset-bound) + state membership ────────────────
    component cmtA = CommitmentHasher();
    cmtA.assetId <== inputAssetA;
    cmtA.value <== matchedAmountA;
    cmtA.label <== labelA;
    cmtA.secret <== secretA;
    cmtA.nullifier <== nullifierA;
    signal commitmentA <== cmtA.commitment;
    signal _nhA <== cmtA.nullifierHash;

    component cmtB = CommitmentHasher();
    cmtB.assetId <== inputAssetB;
    cmtB.value <== matchedAmountB;
    cmtB.label <== labelB;
    cmtB.secret <== secretB;
    cmtB.nullifier <== nullifierB;
    signal commitmentB <== cmtB.commitment;
    signal _nhB <== cmtB.nullifierHash;

    component merkleA = MerkleProof(treeDepth);
    merkleA.leaf <== commitmentA;
    merkleA.leafIndex <== stateIndexA;
    merkleA.siblings <== stateSiblingsA;
    stateRoot === merkleA.out;

    component merkleB = MerkleProof(treeDepth);
    merkleB.leaf <== commitmentB;
    merkleB.leafIndex <== stateIndexB;
    merkleB.siblings <== stateSiblingsB;
    stateRoot === merkleB.out;

    // ── 3. ASP compliance membership for both labels ─────────────────────────
    component assocA = MerkleProof(associationDepth);
    assocA.leaf <== labelA;
    assocA.leafIndex <== labelIndexA;
    assocA.siblings <== labelSiblingsA;
    associationRoot === assocA.out;

    component assocB = MerkleProof(associationDepth);
    assocB.leaf <== labelB;
    assocB.leafIndex <== labelIndexB;
    assocB.siblings <== labelSiblingsB;
    associationRoot === assocB.out;

    // ── 4. Domain-separated nullifier hashes ─────────────────────────────────
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

    // ── 5. Output commitments: A receives Y (matchedAmountB), B receives X ────
    component outCmtA = CommitmentHasher();
    outCmtA.assetId <== outputAssetA;      // Y
    outCmtA.value <== matchedAmountB;
    outCmtA.label <== outLabelA;
    outCmtA.secret <== outSecretA;
    outCmtA.nullifier <== outNullifierA;
    outputCommitmentA <== outCmtA.commitment;
    signal _onhA <== outCmtA.nullifierHash;

    component outCmtB = CommitmentHasher();
    outCmtB.assetId <== outputAssetB;      // X
    outCmtB.value <== matchedAmountA;
    outCmtB.label <== outLabelB;
    outCmtB.secret <== outSecretB;
    outCmtB.nullifier <== outNullifierB;
    outputCommitmentB <== outCmtB.commitment;
    signal _onhB <== outCmtB.nullifierHash;

    // ── 6. Fixed-point price: matchedAmountB == floor(matchedAmountA*price/scale)
    signal prod   <== matchedAmountA * priceScaled;  // ~ up to 2^90
    signal scaled <== matchedAmountB * priceScale;
    signal rem    <== prod - scaled;
    // scaled <= prod  (rem >= 0)
    component le = LessEqThan(128);
    le.in[0] <== scaled;
    le.in[1] <== prod;
    le.out === 1;
    // rem < priceScale  (uniqueness of the floor)
    component lt = LessThan(64);
    lt.in[0] <== rem;
    lt.in[1] <== priceScale;
    lt.out === 1;

    // ── 7. minOutput protections: A gets >= minOutputA of Y, B gets >= minOutputB of X
    component geA = GreaterEqThan(64);
    geA.in[0] <== matchedAmountB;
    geA.in[1] <== minOutputA;
    geA.out === 1;
    component geB = GreaterEqThan(64);
    geB.in[0] <== matchedAmountA;
    geB.in[1] <== minOutputB;
    geB.out === 1;
}

component main {public [
    stateRoot, associationRoot, batchHash, poolId, chainId, deadlineLedger,
    inputAssetA, outputAssetA, inputAssetB, outputAssetB,
    matchedAmountA, matchedAmountB, priceScaled, priceScale, minOutputA, minOutputB
]} = MpcPricedSettlement(12, 2);
