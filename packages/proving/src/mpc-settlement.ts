import { execFileSync } from "node:child_process";
import { writeFileSync, readFileSync, existsSync } from "node:fs";
import { resolve } from "node:path";
import { randomBytes } from "node:crypto";

import {
  SHADE_ROOT, COINUTILS_BIN, CIRCOM2SOROBAN_BIN,
  CIRCUIT_BUILD_DIR, mpcSettlementCircuitDir
} from "./paths.js";
import type { GeneratedCoin } from "./prove.js";

const SNARKJS_CLI = resolve(SHADE_ROOT, "node_modules/snarkjs/cli.js");
function snarkjs(args: string[]): string {
  return execFileSync(process.execPath, [SNARKJS_CLI, ...args], { encoding: "utf8" });
}

// Check whether all three circuit artifacts are present (wasm + zkey + vk).
export function hasMpcSettlementArtifacts(): boolean {
  const d = mpcSettlementCircuitDir();
  return (
    existsSync(resolve(d, "build/main_js/main.wasm")) &&
    existsSync(resolve(d, "output/main_final.zkey")) &&
    existsSync(resolve(d, "output/main_verification_key.json"))
  );
}

// Thrown when proof generation is requested but the circuit has not been compiled.
export class MpcCircuitNotBuiltError extends Error {
  constructor() {
    super(
      "mpc_settlement circuit not compiled yet. " +
      "Run: bash circuits/mpc_settlement/build.sh"
    );
    this.name = "MpcCircuitNotBuiltError";
  }
}

export type MpcSettlementParams = {
  coinA: GeneratedCoin;
  coinB: GeneratedCoin;
  // All current pool note commitments as decimal strings (order = leaf order).
  commitmentsDecimal: string[];
  // ASP association file. Both coinA.label and coinB.label must be members.
  assocPath: string;
  scope: string;
  // 0x-prefixed 32-byte SHA-256 hash of the canonical batch JSON the committee signed.
  batchHashHex: string;
  // Domain separators (decimal field elements matching the pool contract).
  poolId: string;
  chainId: string;
  matchedAmount7dp: string;
  deadlineLedger: string;
  scratch: string;
  tag: string;
};

export type MpcSettlementProof = {
  proofHex: string;
  publicHex: string;
  // All four circuit output commitments as 0x-prefixed 32-byte hex.
  nullifierHashAHex: string;    // public[0]
  nullifierHashBHex: string;    // public[1]
  outputCommitmentAHex: string; // public[2]
  outputCommitmentBHex: string; // public[3]
  // Output note preimages — the receiving parties need these to later spend the notes.
  outPreimageA: NotePreimage;
  outPreimageB: NotePreimage;
  locallyVerified: boolean;
};

export type NotePreimage = {
  value: string;
  label: string;
  nullifier: string;
  secret: string;
};

const BN254_P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

function randField(): string {
  return (BigInt("0x" + randomBytes(31).toString("hex")) % BN254_P).toString();
}

// Reduce a 0x-prefixed 32-byte hex hash to a BN254 field element by taking
// the first 31 bytes (248 bits — always < BN254 prime). Matches hashToField()
// in prove.ts and the contract's hash_to_field() helper.
function hashToField(hex32: string): string {
  const h = hex32.startsWith("0x") ? hex32.slice(2) : hex32;
  return BigInt("0x" + h.slice(0, 62)).toString();
}

function hexOut(decimal: string): string {
  return "0x" + BigInt(decimal).toString(16).padStart(64, "0");
}

function readCoinPreimage(coin: GeneratedCoin): NotePreimage {
  const raw = JSON.parse(readFileSync(coin.path, "utf8"));
  const c = raw.coin as { value: string; label: string; nullifier: string; secret: string };
  return { value: c.value, label: c.label, nullifier: c.nullifier, secret: c.secret };
}

// Build the mpc_settlement circuit witness input JSON from two coin files.
//
// Runs `coinutils withdraw` once per coin to derive each note's Merkle proof
// paths from the pool state. The binding fields (operation-type, recipient, etc.)
// are dummies — only the Merkle/ASP path fields are extracted and renamed for the
// mpc_settlement input signals (labelA/B, stateSiblingsA/B, etc.).
//
// Returns the witness JSON plus the freshly generated output note preimages.
// Callers should persist outPreimageA to party B and outPreimageB to party A
// (cross-swap: A's output is B's new note and vice versa).
export function buildMpcSettlementWitness(p: MpcSettlementParams): {
  witnessJson: Record<string, unknown>;
  outPreimageA: NotePreimage;
  outPreimageB: NotePreimage;
} {
  const statePath = `${p.scratch}/${p.tag}_mpc_state.json`;
  writeFileSync(statePath, JSON.stringify({ commitments: p.commitmentsDecimal, scope: p.scope }));

  const inputPathA = `${p.scratch}/${p.tag}_mpc_coinA_withdraw.json`;
  const inputPathB = `${p.scratch}/${p.tag}_mpc_coinB_withdraw.json`;

  // Run coinutils to compute each note's Merkle + ASP proof paths from the pool state.
  // operation-type 1 = plain withdraw; only the path fields matter here.
  const dummyBindArgs = [
    "--operation-type", "1",
    "--recipient-hash", "0", "--relayer-fee", "0", "--deadline-ledger", "0",
    "--quote-hash", "0", "--intent-hash", "0", "--fill-receipt-hash", "0",
    "--destination-domain", "0", "--destination-recipient", "0",
    "--max-fee", "0", "--min-finality-threshold", "0"
  ];

  execFileSync(
    COINUTILS_BIN,
    ["withdraw", p.coinA.path, statePath, p.assocPath, "-o", inputPathA, ...dummyBindArgs],
    { encoding: "utf8" }
  );
  execFileSync(
    COINUTILS_BIN,
    ["withdraw", p.coinB.path, statePath, p.assocPath, "-o", inputPathB, ...dummyBindArgs],
    { encoding: "utf8" }
  );

  const wA = JSON.parse(readFileSync(inputPathA, "utf8")) as Record<string, unknown>;
  const wB = JSON.parse(readFileSync(inputPathB, "utf8")) as Record<string, unknown>;

  const preA = readCoinPreimage(p.coinA);
  const preB = readCoinPreimage(p.coinB);

  // Fresh output notes. Each party receives exactly matchedAmount7dp.
  // outValueA + outValueB == 2 * matchedAmount7dp (value conservation in circuit).
  const outPreimageA: NotePreimage = {
    value: p.matchedAmount7dp,
    label: randField(),
    nullifier: randField(),
    secret: randField()
  };
  const outPreimageB: NotePreimage = {
    value: p.matchedAmount7dp,
    label: randField(),
    nullifier: randField(),
    secret: randField()
  };

  // The coinutils withdraw output uses the same field names as the withdraw circuit
  // signals: label, value, nullifier, secret, stateIndex, stateSiblings, labelIndex,
  // labelSiblings, stateRoot, associationRoot. Map to the mpc_settlement A/B suffix form.
  const witnessJson: Record<string, unknown> = {
    // Public inputs
    stateRoot:        wA.stateRoot,
    associationRoot:  wA.associationRoot,
    batchHash:        hashToField(p.batchHashHex),
    poolId:           p.poolId,
    chainId:          p.chainId,
    matchedAmount7dp: p.matchedAmount7dp,
    deadlineLedger:   p.deadlineLedger,

    // Input note A
    labelA:          preA.label,
    valueA:          preA.value,
    nullifierA:      preA.nullifier,
    secretA:         preA.secret,
    stateIndexA:     wA.stateIndex,
    stateSiblingsA:  wA.stateSiblings,
    labelIndexA:     wA.labelIndex,
    labelSiblingsA:  wA.labelSiblings,

    // Output note A (goes to party B)
    outValueA:    outPreimageA.value,
    outLabelA:    outPreimageA.label,
    outNullifierA: outPreimageA.nullifier,
    outSecretA:   outPreimageA.secret,

    // Input note B
    labelB:          preB.label,
    valueB:          preB.value,
    nullifierB:      preB.nullifier,
    secretB:         preB.secret,
    stateIndexB:     wB.stateIndex,
    stateSiblingsB:  wB.stateSiblings,
    labelIndexB:     wB.labelIndex,
    labelSiblingsB:  wB.labelSiblings,

    // Output note B (goes to party A)
    outValueB:    outPreimageB.value,
    outLabelB:    outPreimageB.label,
    outNullifierB: outPreimageB.nullifier,
    outSecretB:   outPreimageB.secret
  };

  return { witnessJson, outPreimageA, outPreimageB };
}

// Build a Groth16 proof for an MPC committee-matched settlement.
//
// Requires compiled circuit artifacts in circuits/mpc_settlement/build/ and output/.
// If they are absent, throws MpcCircuitNotBuiltError — callers catch this and fall
// back to committee-signature-only settlement (still valid on testnet).
//
// Public signal layout (matches main.circom component declaration):
//   [0] nullifierHashA   [1] nullifierHashB
//   [2] outputCommitmentA [3] outputCommitmentB
//   [4] stateRoot         [5] associationRoot
//   [6] batchHash         [7] poolId
//   [8] chainId           [9] matchedAmount7dp
//   [10] deadlineLedger
export function buildMpcSettlementProof(p: MpcSettlementParams): MpcSettlementProof {
  if (!hasMpcSettlementArtifacts()) throw new MpcCircuitNotBuiltError();

  const circuitDir = mpcSettlementCircuitDir();
  const { witnessJson, outPreimageA, outPreimageB } = buildMpcSettlementWitness(p);

  const inputPath  = `${p.scratch}/${p.tag}_mpc_witness.json`;
  const wtns       = `${p.scratch}/${p.tag}_mpc.wtns`;
  const proofJson  = `${p.scratch}/${p.tag}_mpc_proof.json`;
  const publicJson = `${p.scratch}/${p.tag}_mpc_public.json`;

  writeFileSync(inputPath, JSON.stringify(witnessJson));
  snarkjs(["wtns", "calculate", resolve(circuitDir, "build/main_js/main.wasm"), inputPath, wtns]);
  snarkjs(["groth16", "prove", resolve(circuitDir, "output/main_final.zkey"), wtns, proofJson, publicJson]);
  const verifyOut = snarkjs([
    "groth16", "verify",
    resolve(circuitDir, "output/main_verification_key.json"),
    publicJson, proofJson
  ]);

  const pub = JSON.parse(readFileSync(publicJson, "utf8")) as string[];

  const proofHex  = execFileSync(CIRCOM2SOROBAN_BIN, ["proof",   proofJson],  { encoding: "utf8" }).trim();
  const publicHex = execFileSync(CIRCOM2SOROBAN_BIN, ["public",  publicJson], { encoding: "utf8" }).trim();

  return {
    proofHex,
    publicHex,
    nullifierHashAHex:    hexOut(pub[0]),
    nullifierHashBHex:    hexOut(pub[1]),
    outputCommitmentAHex: hexOut(pub[2]),
    outputCommitmentBHex: hexOut(pub[3]),
    outPreimageA,
    outPreimageB,
    locallyVerified: /OK!/.test(verifyOut)
  };
}
