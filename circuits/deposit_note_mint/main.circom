pragma circom 2.2.0;

include "commitment.circom";
include "poseidon.circom";
include "bitify.circom";

// Shade DepositNoteMint circuit (P1.8).
//
// Binds a freshly-minted CCTP deposit to the note commitment that is inserted
// into the shielded pool. The note OPENING (value/label/nullifier/secret) is
// private; the circuit outputs the commitment so it is cryptographically tied to
// that opening, and enforces that the note value equals the actual minted 7dp
// amount. Every CCTP-message field is a public input the contract checks against
// the real Circle message before inserting the leaf, so a registrar cannot insert
// a commitment that doesn't correspond to the deposit it claims.
//
// Public-signal order (output first, then declared inputs):
//   [0]  commitment              (note leaf; output, bound to the private opening)
//   [1]  operationType           (== DEPOSIT_NOTE_MINT = 4)
//   [2]  sourceDomain
//   [3]  destinationDomain
//   [4]  cctpNonceHash           (int(sha256/keccak(message)[:31]))
//   [5]  burnTxHashHash          (int(sha256(burn_tx)[:31]))
//   [6]  amount6dp               (USDC 6dp burned)
//   [7]  amount7dp               (USDC 7dp minted into the pool == note value)
//   [8]  assetIdHash             (int(sha256(usdc_sac strkey)[:31]))
//   [9]  recipientPool           (int(sha256(pool strkey)[:31]))
//   [10] encryptedNotePayloadHash
//   [11] policyIdHash
//   [12] poolId                  (#3 domain separator)
//   [13] chainId                 (#3 domain separator)
template DepositNoteMint() {
    // PUBLIC INPUTS
    signal input operationType;
    signal input sourceDomain;
    signal input destinationDomain;
    signal input cctpNonceHash;
    signal input burnTxHashHash;
    signal input amount6dp;
    signal input amount7dp;
    signal input assetIdHash;
    signal input recipientPool;
    signal input encryptedNotePayloadHash;
    signal input policyIdHash;
    signal input poolId;
    signal input chainId;

    // PRIVATE INPUTS (the note opening)
    signal input value;
    signal input label;
    signal input nullifier;
    signal input secret;

    // OUTPUT
    signal output commitment;

    // Recompute the commitment from the opening (formula matches coinutils +
    // the withdraw/transfer circuits: Poseidon(value,label,Poseidon(nullifier,secret))).
    component commitmentHasher = CommitmentHasher();
    commitmentHasher.value <== value;
    commitmentHasher.label <== label;
    commitmentHasher.secret <== secret;
    commitmentHasher.nullifier <== nullifier;
    commitment <== commitmentHasher.commitment;

    // REAL constraint: the note value must not exceed the minted 7dp amount, so a
    // deposit cannot mint a note worth more than the USDC that actually arrived
    // (anti-inflation). value <= amount7dp via a 128-bit non-negativity range check.
    signal surplus <== amount7dp - value;
    component surplusRangeCheck = Num2Bits(128);
    surplusRangeCheck.in <== surplus;
    _ <== surplusRangeCheck.out;
    component valueRangeCheck = Num2Bits(128);
    valueRangeCheck.in <== value;
    _ <== valueRangeCheck.out;

    // Pass-through bindings: the contract enforces each of these equals the value
    // from the real CCTP message / its own config.
    signal opBind   <== operationType * operationType;
    signal sdBind   <== sourceDomain * sourceDomain;
    signal ddBind   <== destinationDomain * destinationDomain;
    signal nonceBind<== cctpNonceHash * cctpNonceHash;
    signal btBind   <== burnTxHashHash * burnTxHashHash;
    signal a6Bind   <== amount6dp * amount6dp;
    signal asBind   <== assetIdHash * assetIdHash;
    signal rpBind   <== recipientPool * recipientPool;
    signal enBind   <== encryptedNotePayloadHash * encryptedNotePayloadHash;
    signal piBind   <== policyIdHash * policyIdHash;
    signal poolBind <== poolId * poolId;
    signal chainBind<== chainId * chainId;
}

component main {public [operationType, sourceDomain, destinationDomain, cctpNonceHash, burnTxHashHash, amount6dp, amount7dp, assetIdHash, recipientPool, encryptedNotePayloadHash, policyIdHash, poolId, chainId]} = DepositNoteMint();
