import { execFileSync } from "node:child_process";
import { writeFileSync, readFileSync } from "node:fs";
import { createHash } from "node:crypto";

import { COINUTILS_BIN, CIRCOM2SOROBAN_BIN, withdrawCircuitDir, transferCircuitDir } from "./paths.js";

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
};

export function generateCoin(scope: string, outPath: string): GeneratedCoin {
  execFileSync(COINUTILS, ["generate", scope, "-o", outPath], { encoding: "utf8" });
  const coin = JSON.parse(readFileSync(outPath, "utf8"));
  return {
    path: outPath,
    commitmentHex: coin.commitment_hex,
    commitmentDecimal: coin.coin.commitment,
    value7dp: coin.coin.value
  };
}

// #4 Build a real ASP association set containing this coin's label and return
// both the association-set file path and its root (0x-32-byte) for the contract.
export function buildAssociationSet(coin: GeneratedCoin, scratch: string, tag: string): { assocPath: string; rootHex: string } {
  const label = JSON.parse(readFileSync(coin.path, "utf8")).coin.label as string;
  const assocPath = `${scratch}/${tag}_assoc.json`;
  // fresh file each run
  try { execFileSync("rm", ["-f", assocPath]); } catch { /* ignore */ }
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
  outputCommitmentHex: string;
  feePublic: string;
  outValue: string;
  locallyVerified: boolean;
};

// #2 Build a hidden-amount PrivateTransfer proof: spend `coin`, create an output
// note of (value - fee). Amounts stay private; only fee + output commitment public.
export function buildTransferProof(coin: GeneratedCoin, commitmentsDecimal: string[], scope: string, fee7dp: string, scratch: string, tag: string): TransferProof {
  const statePath = `${scratch}/${tag}_xstate.json`;
  writeFileSync(statePath, JSON.stringify({ commitments: commitmentsDecimal, scope }));
  const witnessPath = `${scratch}/${tag}_xfer.json`;
  const outCoinPath = `${scratch}/${tag}_xout.json`;
  execFileSync(COINUTILS, ["transfer", coin.path, statePath, fee7dp, "--out-scope", `${scope}_out`, "-o", witnessPath, "--out-coin", outCoinPath], { encoding: "utf8" });
  const witness = JSON.parse(readFileSync(witnessPath, "utf8"));

  const wtns = `${scratch}/${tag}_x.wtns`;
  const proofJson = `${scratch}/${tag}_x_proof.json`;
  const publicJson = `${scratch}/${tag}_x_public.json`;
  execFileSync("snarkjs", ["wtns", "calculate", `${PT_CIRCUITS}/build/main_js/main.wasm`, witnessPath, wtns], { encoding: "utf8" });
  execFileSync("snarkjs", ["groth16", "prove", `${PT_CIRCUITS}/output/main_final.zkey`, wtns, proofJson, publicJson], { encoding: "utf8" });
  const verify = execFileSync("snarkjs", ["groth16", "verify", `${PT_CIRCUITS}/output/main_verification_key.json`, publicJson, proofJson], { encoding: "utf8" });

  const proofHex = execFileSync(C2S, ["proof", proofJson], { encoding: "utf8" }).trim();
  const publicHex = execFileSync(C2S, ["public", publicJson], { encoding: "utf8" }).trim();
  return {
    proofHex, publicHex,
    stateRootHex: hexRoot(witness.stateRoot),
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
};

// recipient_hash field element matching the contract: sha256(strkey)[:31 bytes].
export function recipientHashField(strkey: string): string {
  const sha = createHash("sha256").update(strkey).digest();
  return BigInt("0x" + sha.subarray(0, 31).toString("hex")).toString();
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
    "--deadline-ledger", b.deadlineLedger
  ], { encoding: "utf8" });
  const input = JSON.parse(readFileSync(inputPath, "utf8"));
  const stateRootHex = "0x" + BigInt(input.stateRoot).toString(16).padStart(64, "0");

  const wtns = `${scratch}/${tag}_witness.wtns`;
  const proofJson = `${scratch}/${tag}_proof.json`;
  const publicJson = `${scratch}/${tag}_public.json`;
  // Use snarkjs `wtns calculate` (the circuit wasm directly) instead of the
  // generated generate_witness.js, which is CommonJS and breaks under this
  // ESM ("type":"module") workspace.
  execFileSync("snarkjs", ["wtns", "calculate", `${CIRCUITS}/build/main_js/main.wasm`, inputPath, wtns], { encoding: "utf8" });
  execFileSync("snarkjs", ["groth16", "prove", `${CIRCUITS}/output/main_final.zkey`, wtns, proofJson, publicJson], { encoding: "utf8" });
  const verify = execFileSync("snarkjs", ["groth16", "verify", `${CIRCUITS}/output/main_verification_key.json`, publicJson, proofJson], { encoding: "utf8" });

  const proofHex = execFileSync(C2S, ["proof", proofJson], { encoding: "utf8" }).trim();
  const publicHex = execFileSync(C2S, ["public", publicJson], { encoding: "utf8" }).trim();
  return { proofHex, publicHex, stateRootHex, locallyVerified: /OK!/.test(verify) };
}
