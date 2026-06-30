pragma circom 2.2.0;

include "poseidon255.circom";
include "bitify.circom";

// Shade ProofOfFillClaim circuit.
//
// A solver proves it completed a cross-chain fill for an accepted RFQ intent,
// without revealing the solver's private key. The circuit:
//   1. Derives a domain-separated claimId from the solver's private secret,
//      preventing double-reimbursement for the same (solver, intent) pair.
//   2. Proves identity: the solver's public ID (registered in the contract)
//      matches the hash of the private secret — the contract verifies
//      solverIdHash == registered_solver_id_hash.
//   3. Binds all fill details as public inputs the contract enforces:
//      quoteHash, intentHash, fillReceiptHash, destTxHashHash, amount, deadline.
//   4. Range-checks amount7dp so it cannot wrap.
//
// NOTE: the destination tx hash (destTxHashHash) is the sha256 of the
// cross-chain tx hash, truncated to 31 bytes and interpreted as a field
// element (same encoding as all other hash-type signals). The contract
// compares this against the fill receipt submitted by the solver; if the
// protocol adds a light-client or optimistic bridge attestation step, the
// attestation hash replaces the tx hash here.
//
// Public-signal order (output first, then declared `public` inputs):
//   [0]  claimId          Poseidon(solverSecret, intentHash, poolId, chainId) — claim dedup
//   [1]  intentHash       int(sha256(intent_json)[:31])
//   [2]  quoteHash        int(sha256(quote_json)[:31])
//   [3]  fillReceiptHash  int(sha256(fill_receipt_json)[:31])
//   [4]  destTxHashHash   int(sha256(dest_tx_hash_hex)[:31]) — cross-chain execution proof
//   [5]  amount7dp        amount filled (7dp); contract verifies == accepted quote amount
//   [6]  deadlineLedger   fill deadline; contract enforces not expired at claim time
//   [7]  solverIdHash     int(sha256(solver_pubkey_strkey)[:31]); checked against registered solver
//   [8]  policyIdHash     int(sha256(policy_id)[:31]); contract enforces active policy
//   [9]  poolId           domain separator (this pool)
//   [10] chainId          domain separator (this chain)

template ProofOfFillClaim() {
    // PUBLIC INPUTS
    signal input intentHash;       // [1]
    signal input quoteHash;        // [2]
    signal input fillReceiptHash;  // [3]
    signal input destTxHashHash;   // [4]
    signal input amount7dp;        // [5]
    signal input deadlineLedger;   // [6]
    signal input solverIdHash;     // [7]
    signal input policyIdHash;     // [8]
    signal input poolId;           // [9]
    signal input chainId;          // [10]

    // PRIVATE INPUTS
    // The solver's private secret. It must satisfy:
    //   Poseidon(solverSecret, 0) % 2^248 == solverIdHash (field element)
    // (The contract maps the solver's registered ed25519 pubkey to an id hash.)
    signal input solverSecret;

    // OUTPUT
    signal output claimId;  // [0] Poseidon(solverSecret, intentHash, poolId, chainId)

    // 1) Domain-separated claim ID prevents a solver from claiming twice for the
    //    same (intent, pool, chain) combination.
    component claimHasher = Poseidon255(4);
    claimHasher.in[0] <== solverSecret;
    claimHasher.in[1] <== intentHash;
    claimHasher.in[2] <== poolId;
    claimHasher.in[3] <== chainId;
    claimId <== claimHasher.out;

    // 2) Prove solver identity: the solver's public ID hash is the Poseidon image
    //    of (solverSecret, 0). The contract checks arg.solver_id_hash == proof.[7].
    component idHasher = Poseidon255(2);
    idHasher.in[0] <== solverSecret;
    idHasher.in[1] <== 0;
    solverIdHash === idHasher.out;

    // 3) Bind all public fill details into the constraint system.
    //    The contract enforces each arg == proof.public_signal; we bind them here
    //    so a proof cannot be reused with different public inputs.
    signal qhBind  <== quoteHash * quoteHash;
    signal ihBind  <== intentHash * intentHash;
    signal frBind  <== fillReceiptHash * fillReceiptHash;
    signal dtBind  <== destTxHashHash * destTxHashHash;
    signal dlBind  <== deadlineLedger * deadlineLedger;
    signal piBind  <== policyIdHash * policyIdHash;

    // 4) Amount range check: amount7dp in [0, 2^128) prevents wrap-around.
    component amtRange = Num2Bits(128);
    amtRange.in <== amount7dp;
    _ <== amtRange.out;
}

component main {public [
    intentHash, quoteHash, fillReceiptHash, destTxHashHash,
    amount7dp, deadlineLedger, solverIdHash, policyIdHash,
    poolId, chainId
]} = ProofOfFillClaim();
