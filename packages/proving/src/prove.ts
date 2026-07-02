import { execFileSync } from "node:child_process";
import { writeFileSync, readFileSync, rmSync } from "node:fs";
import { createHash } from "node:crypto";
import { resolve } from "node:path";

import { SHADE_ROOT, COINUTILS_BIN, CIRCOM2SOROBAN_BIN, withdrawCircuitDir, transferCircuitDir, depositCircuitDir } from "./paths.js";

// Invoke snarkjs via the Node binary rather than relying on a global PATH entry.
// On Windows, node_modules/.bin/snarkjs is a .cmd shim that execFileSync can't
// run without shell:true; using node + cli.js is cross-platform and avoids PATH.
const SNARKJS_CLI = resolve(SHADE_ROOT, "node_modules/snarkjs/cli.js");
function snarkjs(args: string[], opts: { cwd?: string; timeout?: number } = {}): string {
  return execFileSync(process.execPath, [SNARKJS_CLI, ...args], { encoding: "utf8", ...opts });
}

export const COINUTILS = COINUTILS_BIN;
// Shade's own corrected withdraw circuit (commitment = Poseidon(value,label,precommit),
// matching coinutils native poseidon). build/ + output/ live here.
export const CIRCUITS = withdrawCircuitDir();
export const C2S = CIRCOM2SOROBAN_BIN;

export type GeneratedCoin = {
  path: string;
  commitmentHex: string;
  commitmentDecimal: string;
  value7dp: string;
  // multi-asset: decimal field element bound into the commitment
  // (= int(sha256(asset_strkey)[:31])), matching the contract's
  // recipient_hash(asset_sac). "0" for legacy/unbound coins.
  assetId: string;
};

// multi-asset: `value7dp`/`assetId`, when provided, are passed to coinutils'
// `--value`/`--asset-id` so the generated note is bound to a real denomination
// and asset instead of the legacy fixed COIN_VALUE/unbound (assetId="0").
export function generateCoin(scope: string, outPath: string, value7dp?: string, assetId?: string): GeneratedCoin {
  const args = ["generate", scope, "-o", outPath];
  if (value7dp) args.push("--value", value7dp);
  if (assetId) args.push("--asset-id", assetId);
  execFileSync(COINUTILS, args, { encoding: "utf8" });
  const coin = JSON.parse(readFileSync(outPath, "utf8"));
  return {
    path: outPath,
    commitmentHex: coin.commitment_hex,
    commitmentDecimal: coin.coin.commitment,
    value7dp: coin.coin.value,
    assetId: coin.coin.asset_id ?? "0"
  };
}

// multi-asset: the field-element hash the contract/circuits use to identify an
// asset (int(sha256(asset_strkey)[:31])). Matches recipientHashField below but
// exported under an asset-specific name for call-site clarity.
export function assetIdField(assetStrkey: string): string {
  return recipientHashField(assetStrkey);
}

// #4 Build a real ASP association set containing this coin's label and return
// both the association-set file path and its root (0x-32-byte) for the contract.
export function buildAssociationSet(coin: GeneratedCoin, scratch: string, tag: string): { assocPath: string; rootHex: string } {
  const label = JSON.parse(readFileSync(coin.path, "utf8")).coin.label as string;
  const assocPath = `${scratch}/${tag}_assoc.json`;
  try { rmSync(assocPath, { force: true }); } catch { /* ignore */ }
  execFileSync(COINUTILS, ["update-association", assocPath, label], { encoding: "utf8" });
  const root = JSON.parse(readFileSync(assocPath, "utf8")).root as string;
  return { assocPath, rootHex: "0x" + BigInt(root).toString(16).padStart(64, "0") };
}

// Compute the Poseidon Merkle root for a commitment list (off-chain, native
// lean-imt via coinutils) WITHOUT generating a proof. Used by the registrar to
// supply the post-insert root to the on-chain pool.
export function computeStateRoot(coin: GeneratedCoin, commitmentsDecimal: string[], scope: string, scratch: string, tag: string, assocPath?: string): string {
  const statePath = `${scratch}/${tag}_rootstate.json`;
  writeFileSync(statePath, JSON.stringify({ commitments: commitmentsDecimal, scope }));
  const inputPath = `${scratch}/${tag}_rootinput.json`;
  const args = assocPath
    ? ["withdraw", coin.path, statePath, assocPath, "-o", inputPath]
    : ["withdraw", coin.path, statePath, "-o", inputPath];
  execFileSync(COINUTILS, args, { encoding: "utf8" });
  const input = JSON.parse(readFileSync(inputPath, "utf8"));
  return "0x" + BigInt(input.stateRoot).toString(16).padStart(64, "0");
}

export function hexRoot(decimal: string): string {
  return "0x" + BigInt(decimal).toString(16).padStart(64, "0");
}

const PT_CIRCUITS = transferCircuitDir();

export type TransferProof = {
  proofHex: string;
  publicHex: string;
  stateRootHex: string;
  associationRootHex: string;
  outputCommitmentHex: string;
  feePublic: string;
  outValue: string;
  locallyVerified: boolean;
};

// #2 Build a hidden-amount PrivateTransfer proof: spend `coin`, create an output
// note of (value - fee). Amounts stay private; only fee + output commitment public.
// P2 #14: `assocPath`, when provided, proves the spender's label is in the ASP
// allow-set (see circuits/private_transfer/main.circom). Omitting it produces a
// proof that only verifies on-chain against an associationRoot of 0 (compliance
// disabled) — callers doing real settlement should always supply it, the same
// way buildNoteProof requires it for withdraw.
export function buildTransferProof(coin: GeneratedCoin, commitmentsDecimal: string[], scope: string, fee7dp: string, scratch: string, tag: string, assocPath?: string): TransferProof {
  const statePath = `${scratch}/${tag}_xstate.json`;
  writeFileSync(statePath, JSON.stringify({ commitments: commitmentsDecimal, scope }));
  const witnessPath = `${scratch}/${tag}_xfer.json`;
  const outCoinPath = `${scratch}/${tag}_xout.json`;
  const args = ["transfer", coin.path, statePath, fee7dp, "--out-scope", `${scope}_out`, "-o", witnessPath, "--out-coin", outCoinPath];
  if (assocPath) args.push("--association-file", assocPath);
  execFileSync(COINUTILS, args, { encoding: "utf8" });
  const witness = JSON.parse(readFileSync(witnessPath, "utf8"));

  const wtns = `${scratch}/${tag}_x.wtns`;
  const proofJson = `${scratch}/${tag}_x_proof.json`;
  const publicJson = `${scratch}/${tag}_x_public.json`;
  snarkjs(["wtns", "calculate", `${PT_CIRCUITS}/build/main_js/main.wasm`, witnessPath, wtns]);
  snarkjs(["groth16", "prove", `${PT_CIRCUITS}/output/main_final.zkey`, wtns, proofJson, publicJson]);
  const verify = snarkjs(["groth16", "verify", `${PT_CIRCUITS}/output/main_verification_key.json`, publicJson, proofJson]);

  const proofHex = execFileSync(C2S, ["proof", proofJson], { encoding: "utf8" }).trim();
  const publicHex = execFileSync(C2S, ["public", publicJson], { encoding: "utf8" }).trim();
  return {
    proofHex, publicHex,
    stateRootHex: hexRoot(witness.stateRoot),
    associationRootHex: hexRoot(witness.associationRoot),
    outputCommitmentHex: hexRoot(witness.outputCommitment),
    feePublic: witness.feePublic,
    outValue: witness.outValue,
    locallyVerified: /OK!/.test(verify)
  };
}

export type NoteProof = {
  proofHex: string;
  publicHex: string;
  stateRootHex: string; // 0x-prefixed 32-byte
  locallyVerified: boolean;
};

// Build a Groth16 note-ownership proof for a coin against a state tree of
// `commitmentsDecimal`. Requires an ASP association-set file (#4 enforced).
// `commitmentsDecimal` is the full leaf set in the pool (anonymity set, #1).
// P1.5 operation-binding fields for the withdraw circuit.
export type WithdrawBinding = {
  operationType: string; // "1" withdraw, "2" cctp, "3" rfq
  recipientHash: string; // decimal field element = int(sha256(strkey)[:31])
  relayerFee: string;    // 7dp
  deadlineLedger: string;
  // P1.6 RFQ-settlement bindings (decimal field elements; default "0" for non-RFQ).
  quoteHash?: string;
  intentHash?: string;
  fillReceiptHash?: string;
  // P1.7 WithdrawCCTP destination bindings (decimal field elements; default "0").
  destinationDomain?: string;
  destinationRecipient?: string; // int(recipient32 bytes)
  maxFee?: string;
  minFinalityThreshold?: string;
};

// P1.7: convert a 0x-prefixed 32-byte CCTP mintRecipient to the contract's field
// element (the integer value of the 32 bytes). The 12 leading zero bytes keep it
// well under the BLS field modulus; the contract compares the raw 32-byte arg.
export function recipient32ToField(hex32: string): string {
  const h = hex32.startsWith("0x") ? hex32.slice(2) : hex32;
  return BigInt("0x" + h).toString();
}

// recipient_hash field element matching the contract: sha256(strkey)[:31 bytes].
export function recipientHashField(strkey: string): string {
  const sha = createHash("sha256").update(strkey).digest();
  return BigInt("0x" + sha.subarray(0, 31).toString("hex")).toString();
}

// P1.6: reduce an existing 0x-prefixed 32-byte hash (e.g. a quote/intent/fill
// hash) to the contract's field element: int(hash[:31 bytes]). The contract's
// `hash_to_field` recomputes the identical value from the raw 32-byte arg.
export function hashToField(hex32: string): string {
  const h = hex32.startsWith("0x") ? hex32.slice(2) : hex32;
  return BigInt("0x" + h.slice(0, 62)).toString(); // first 31 bytes = 62 hex chars
}

export function buildNoteProof(
  coin: GeneratedCoin,
  commitmentsDecimal: string[],
  scope: string,
  scratch: string,
  tag: string,
  assocPath: string,
  binding?: WithdrawBinding
): NoteProof {
  const b = binding ?? { operationType: "1", recipientHash: "0", relayerFee: "0", deadlineLedger: "0" };
  const statePath = `${scratch}/${tag}_state.json`;
  writeFileSync(statePath, JSON.stringify({ commitments: commitmentsDecimal, scope }));
  const inputPath = `${scratch}/${tag}_input.json`;
  execFileSync(COINUTILS, [
    "withdraw", coin.path, statePath, assocPath, "-o", inputPath,
    "--operation-type", b.operationType,
    "--recipient-hash", b.recipientHash,
    "--relayer-fee", b.relayerFee,
    "--deadline-ledger", b.deadlineLedger,
    // P1.6 RFQ bindings (default "0" for withdraw/cctp).
    "--quote-hash", b.quoteHash ?? "0",
    "--intent-hash", b.intentHash ?? "0",
    "--fill-receipt-hash", b.fillReceiptHash ?? "0",
    // P1.7 CCTP bindings (default "0" for withdraw/rfq).
    "--destination-domain", b.destinationDomain ?? "0",
    "--destination-recipient", b.destinationRecipient ?? "0",
    "--max-fee", b.maxFee ?? "0",
    "--min-finality-threshold", b.minFinalityThreshold ?? "0"
  ], { encoding: "utf8" });
  const input = JSON.parse(readFileSync(inputPath, "utf8"));
  const stateRootHex = "0x" + BigInt(input.stateRoot).toString(16).padStart(64, "0");

  const wtns = `${scratch}/${tag}_witness.wtns`;
  const proofJson = `${scratch}/${tag}_proof.json`;
  const publicJson = `${scratch}/${tag}_public.json`;
  // Use snarkjs `wtns calculate` (the circuit wasm directly) instead of the
  // generated generate_witness.js, which is CommonJS and breaks under this
  // ESM ("type":"module") workspace.
  snarkjs(["wtns", "calculate", `${CIRCUITS}/build/main_js/main.wasm`, inputPath, wtns]);
  snarkjs(["groth16", "prove", `${CIRCUITS}/output/main_final.zkey`, wtns, proofJson, publicJson]);
  const verify = snarkjs(["groth16", "verify", `${CIRCUITS}/output/main_verification_key.json`, publicJson, proofJson]);

  const proofHex = execFileSync(C2S, ["proof", proofJson], { encoding: "utf8" }).trim();
  const publicHex = execFileSync(C2S, ["public", publicJson], { encoding: "utf8" }).trim();
  return { proofHex, publicHex, stateRootHex, locallyVerified: /OK!/.test(verify) };
}

const DEPOSIT_CIRCUITS = depositCircuitDir();

export type DepositProof = {
  proofHex: string;
  publicHex: string;
  commitmentHex: string; // 0x-32-byte, == public signal [0]
  locallyVerified: boolean;
};

// P1.8 inputs that bind the CCTP message to the note commitment. Hash fields are
// reduced to the contract's field element (int(hash[:31])); domains/amounts are
// decimal. assetIdHash/recipientPool use the strkey-sha256 reduction the contract
// applies via `recipient_hash` (sha256(strkey)[:31]).
export type DepositBinding = {
  sourceDomain: string;
  destinationDomain: string;
  cctpNonceHex: string;        // 0x keccak(message); reduced to field
  burnTxHashHex: string;       // 0x burn tx hash; sha256 then reduced (informational)
  amount6dp: string;
  amount7dp: string;           // minted delta (7dp); circuit enforces value <= this
  assetStrkey: string;         // USDC SAC contract id (C...)
  poolStrkey: string;          // this pool contract id (C...)
  encryptedNotePayloadHashHex: string; // 0x sha256; reduced to field
  policyIdHex: string;         // 0x; reduced to field
  poolId: string;
  chainId: string;
};

// P1.8: build a DepositNoteMint proof. The note opening (value/label/nullifier/
// secret) comes from the coin file; the public signals bind the CCTP message.
export function buildDepositProof(coin: GeneratedCoin, b: DepositBinding, scratch: string, tag: string): DepositProof {
  const opening = JSON.parse(readFileSync(coin.path, "utf8")).coin as {
    value: string; label: string; nullifier: string; secret: string;
  };
  const input = {
    operationType: "4",
    sourceDomain: b.sourceDomain,
    destinationDomain: b.destinationDomain,
    cctpNonceHash: hashToField(b.cctpNonceHex),
    burnTxHashHash: hashToField(createHash("sha256").update(b.burnTxHashHex).digest("hex")),
    amount6dp: b.amount6dp,
    amount7dp: b.amount7dp,
    assetIdHash: recipientHashField(b.assetStrkey),
    recipientPool: recipientHashField(b.poolStrkey),
    encryptedNotePayloadHash: hashToField(b.encryptedNotePayloadHashHex),
    policyIdHash: hashToField(b.policyIdHex),
    poolId: b.poolId,
    chainId: b.chainId,
    value: opening.value,
    label: opening.label,
    nullifier: opening.nullifier,
    secret: opening.secret
  };
  const inputPath = `${scratch}/${tag}_dep_input.json`;
  writeFileSync(inputPath, JSON.stringify(input));

  const wtns = `${scratch}/${tag}_dep.wtns`;
  const proofJson = `${scratch}/${tag}_dep_proof.json`;
  const publicJson = `${scratch}/${tag}_dep_public.json`;
  snarkjs(["wtns", "calculate", `${DEPOSIT_CIRCUITS}/build/main_js/main.wasm`, inputPath, wtns]);
  snarkjs(["groth16", "prove", `${DEPOSIT_CIRCUITS}/output/main_final.zkey`, wtns, proofJson, publicJson]);
  const verify = snarkjs(["groth16", "verify", `${DEPOSIT_CIRCUITS}/output/main_verification_key.json`, publicJson, proofJson]);

  const proofHex = execFileSync(C2S, ["proof", proofJson], { encoding: "utf8" }).trim();
  const publicHex = execFileSync(C2S, ["public", publicJson], { encoding: "utf8" }).trim();
  return { proofHex, publicHex, commitmentHex: coin.commitmentHex, locallyVerified: /OK!/.test(verify) };
}
