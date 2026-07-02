import { execFileSync } from "node:child_process";
import { writeFileSync, readFileSync, existsSync } from "node:fs";
import { resolve } from "node:path";
import { randomBytes } from "node:crypto";

import { SHADE_ROOT, COINUTILS_BIN, mpcPricedSettlementCircuitDir } from "./paths.js";
import type { GeneratedCoin } from "./prove.js";

// Phase 6 (spec §10): priced cross-asset MPC settlement witness + proof builder.
// Party A spends coinX (assetX) and receives assetY; party B spends coinY
// (assetY) and receives assetX, at a fixed-point price. Because coinutils uses a
// fixed COIN_VALUE, the default matched amounts are equal (price 1.0); callers
// override for other prices when notes of matching value exist.

const SNARKJS_CLI = resolve(SHADE_ROOT, "node_modules/snarkjs/cli.js");
function snarkjs(args: string[]): string {
  return execFileSync(process.execPath, [SNARKJS_CLI, ...args], { encoding: "utf8" });
}

export function hasMpcPricedArtifacts(): boolean {
  const d = mpcPricedSettlementCircuitDir();
  return (
    existsSync(resolve(d, "build/main_js/main.wasm")) &&
    existsSync(resolve(d, "output/main_final.zkey")) &&
    existsSync(resolve(d, "output/main_verification_key.json"))
  );
}

const BN254_P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
function randField(): string {
  return (BigInt("0x" + randomBytes(31).toString("hex")) % BN254_P).toString();
}
function hashToField(hex32: string): string {
  const h = hex32.startsWith("0x") ? hex32.slice(2) : hex32;
  return BigInt("0x" + h.slice(0, 62)).toString();
}
function readOpening(coin: GeneratedCoin): { value: string; label: string; nullifier: string; secret: string; asset_id: string } {
  const c = JSON.parse(readFileSync(coin.path, "utf8")).coin;
  return { value: c.value, label: c.label, nullifier: c.nullifier, secret: c.secret, asset_id: c.asset_id };
}

export type PricedParams = {
  coinX: GeneratedCoin;      // party A's input note (assetX)
  coinY: GeneratedCoin;      // party B's input note (assetY)
  commitmentsDecimal: string[]; // pool state (must contain both commitments)
  assocPath: string;
  scope: string;
  batchHashHex: string;
  poolId: string;
  chainId: string;
  priceScaled: string;       // assetY per assetX * 1e9
  minOutputA: string;
  minOutputB: string;
  deadlineLedger: string;
  scratch: string;
  tag: string;
};

// Assemble the priced-settlement witness. Runs coinutils `withdraw` per coin to
// derive Merkle/ASP paths from the shared pool state, then maps into the
// mpc_priced_settlement input signals.
export function buildMpcPricedWitness(p: PricedParams): { witnessJson: Record<string, unknown> } {
  const statePath = `${p.scratch}/${p.tag}_priced_state.json`;
  writeFileSync(statePath, JSON.stringify({ commitments: p.commitmentsDecimal, scope: p.scope }));
  const inA = `${p.scratch}/${p.tag}_priced_wX.json`;
  const inB = `${p.scratch}/${p.tag}_priced_wY.json`;
  const dummy = [
    "--operation-type", "0", "--recipient-hash", "0", "--relayer-fee", "0", "--deadline-ledger", "0",
    "--quote-hash", "0", "--intent-hash", "0", "--fill-receipt-hash", "0",
    "--destination-domain", "0", "--destination-recipient", "0", "--max-fee", "0", "--min-finality-threshold", "0"
  ];
  execFileSync(COINUTILS_BIN, ["withdraw", p.coinX.path, statePath, p.assocPath, "-o", inA, ...dummy], { encoding: "utf8" });
  execFileSync(COINUTILS_BIN, ["withdraw", p.coinY.path, statePath, p.assocPath, "-o", inB, ...dummy], { encoding: "utf8" });
  const wX = JSON.parse(readFileSync(inA, "utf8")) as Record<string, unknown>;
  const wY = JSON.parse(readFileSync(inB, "utf8")) as Record<string, unknown>;

  const preX = readOpening(p.coinX);
  const preY = readOpening(p.coinY);
  const assetX = preX.asset_id;
  const assetY = preY.asset_id;
  if (assetX === assetY) throw new Error("priced settlement requires a genuine cross-asset (assetX != assetY)");

  // matchedAmountA = X spent (coinX value); matchedAmountB = floor(A * price / 1e9).
  const matchedA = BigInt(preX.value);
  const priceScaled = BigInt(p.priceScaled);
  const matchedB = (matchedA * priceScaled) / 1_000_000_000n;
  if (matchedB.toString() !== preY.value) {
    throw new Error(`priced witness: coinY value ${preY.value} != floor(matchedA*price/1e9)=${matchedB} (choose notes/price so they match)`);
  }

  const witnessJson: Record<string, unknown> = {
    // public
    stateRoot: wX.stateRoot,
    associationRoot: wX.associationRoot,
    batchHash: hashToField(p.batchHashHex),
    poolId: p.poolId,
    chainId: p.chainId,
    deadlineLedger: p.deadlineLedger,
    inputAssetA: assetX,
    outputAssetA: assetY,
    inputAssetB: assetY,
    outputAssetB: assetX,
    matchedAmountA: matchedA.toString(),
    matchedAmountB: matchedB.toString(),
    priceScaled: p.priceScaled,
    priceScale: "1000000000",
    minOutputA: p.minOutputA,
    minOutputB: p.minOutputB,
    // private — input X (A)
    labelA: preX.label, nullifierA: preX.nullifier, secretA: preX.secret,
    stateIndexA: wX.stateIndex, stateSiblingsA: wX.stateSiblings,
    labelIndexA: wX.labelIndex, labelSiblingsA: wX.labelSiblings,
    // private — input Y (B)
    labelB: preY.label, nullifierB: preY.nullifier, secretB: preY.secret,
    stateIndexB: wY.stateIndex, stateSiblingsB: wY.stateSiblings,
    labelIndexB: wY.labelIndex, labelSiblingsB: wY.labelSiblings,
    // output A (assetY) and output B (assetX): fresh nullifier/secret/label
    outLabelA: randField(), outNullifierA: randField(), outSecretA: randField(),
    outLabelB: randField(), outNullifierB: randField(), outSecretB: randField()
  };
  return { witnessJson };
}

export type PricedProof = { proofHex?: string; publicHex?: string; locallyVerified: boolean; witnessJson: Record<string, unknown> };

// Full proof (wtns + groth16 prove + verify). Returns witnessJson too so callers
// can build adversarial variants that must FAIL wtns calculation.
export function buildMpcPricedProof(p: PricedParams): PricedProof {
  if (!hasMpcPricedArtifacts()) throw new Error("mpc_priced_settlement circuit not built; run npm run circuits:build");
  const dir = mpcPricedSettlementCircuitDir();
  const { witnessJson } = buildMpcPricedWitness(p);
  const inputPath = `${p.scratch}/${p.tag}_priced_input.json`;
  const wtns = `${p.scratch}/${p.tag}_priced.wtns`;
  const proofJson = `${p.scratch}/${p.tag}_priced_proof.json`;
  const publicJson = `${p.scratch}/${p.tag}_priced_public.json`;
  writeFileSync(inputPath, JSON.stringify(witnessJson));
  snarkjs(["wtns", "calculate", resolve(dir, "build/main_js/main.wasm"), inputPath, wtns]);
  snarkjs(["groth16", "prove", resolve(dir, "output/main_final.zkey"), wtns, proofJson, publicJson]);
  const verify = snarkjs(["groth16", "verify", resolve(dir, "output/main_verification_key.json"), publicJson, proofJson]);
  return { locallyVerified: /OK!/.test(verify), witnessJson };
}

// Run ONLY witness calculation for a (possibly tampered) witness — used by
// adversarial tests: a witness violating a circuit constraint must throw.
export function calcPricedWitness(witnessJson: Record<string, unknown>, scratch: string, tag: string): void {
  const dir = mpcPricedSettlementCircuitDir();
  const inputPath = `${scratch}/${tag}_priced_adv_input.json`;
  const wtns = `${scratch}/${tag}_priced_adv.wtns`;
  writeFileSync(inputPath, JSON.stringify(witnessJson));
  snarkjs(["wtns", "calculate", resolve(dir, "build/main_js/main.wasm"), inputPath, wtns]);
}
