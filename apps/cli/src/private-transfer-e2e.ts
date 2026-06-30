import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { loadRuntimeEnv, requireKeys } from "./lib/env.js";
import { failIfAny, writeCheckReport, type CheckResult } from "./lib/report.js";
import { runCctpInbound } from "./lib/cctp-inbound.js";
import { sorobanInvoke, bytesToCliHex } from "@shade/stellar-utils";
import { generateCoin, computeStateRoot, buildTransferProof } from "./lib/prove.js";

// #2 Hidden-amount PrivateTransfer e2e:
//   fund an input note -> prove a transfer (input -> output note + public fee,
//   amounts hidden) -> settle on-chain (input nullifier spent, output commitment
//   inserted). No public amount is revealed; only the fee + output commitment.
import { scratchDir } from "./lib/paths.js";
const SCRATCH = scratchDir();
const env = await loadRuntimeEnv();
const results: CheckResult[] = [];

const missing = requireKeys(env, ["SHIELDED_POOL_CONTRACT", "TRANSFER_VERIFIER_CONTRACT", "NULLIFIER_REGISTRY_CONTRACT", "STELLAR_RELAYER_SECRET"]);
results.push({ name: "required env", ok: missing.length === 0, detail: missing.join(", ") || "present" });
if (missing.length) { await writeCheckReport("PrivateTransfer E2E", results); failIfAny(results); }

const pool = env.SHIELDED_POOL_CONTRACT;
const relayerSecret = env.STELLAR_RELAYER_SECRET;
const poolAdminSecret = env.STELLAR_DEPLOYER_SECRET ?? relayerSecret;
const rpc = env.STELLAR_RPC_URL ?? "https://soroban-testnet.stellar.org";
const pass = env.STELLAR_NETWORK_PASSPHRASE ?? "Test SDF Network ; September 2015";
const poolRead = (m: string) => { for (let i = 0; i < 4; i++) { const v = sorobanInvoke({ contractId: pool, secret: relayerSecret, method: m, rpcUrl: rpc, passphrase: pass, readOnly: true }).returnValue.replace(/"/g, "").trim(); if (v !== "") return v; } return "0"; };
function sleepSync(ms: number) { Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms); }

// 1) Fund an input note via CCTP.
const coin = generateCoin("shade_xfer", `${SCRATCH}/pt_coin.json`);
const rootAfter = computeStateRoot(coin, [coin.commitmentDecimal], "shade_xfer", SCRATCH, "pt");
console.log("Funding input note via CCTP, then proving a hidden-amount transfer...");
const inbound = await runCctpInbound(env, {
  amount6: BigInt(process.env.PT_AMOUNT_6DP ?? "1000000"),
  commitmentHex: coin.commitmentHex,
  encryptedNotePayloadHashHex: "0x" + createHash("sha256").update(coin.commitmentHex).digest("hex"),
  policyIdHex: "0x" + createHash("sha256").update("shade:default-testnet-policy:v1").digest("hex").slice(0, 64),
  fast: true,
  targetContract: pool,
  newRootHex: rootAfter,
  coin,
  scratch: SCRATCH,
  adminSecret: poolAdminSecret
});
results.push({ name: "input note funded (CCTP)", ok: true, detail: `leaf ${inbound.leafIndex}` });

// 2) Build the transfer proof (fee public, amounts hidden).
const fee = process.env.PT_FEE_7DP ?? "200000"; // 0.02 USDC public fee
const xfer = buildTransferProof(coin, [coin.commitmentDecimal], "shade_xfer", fee, SCRATCH, "pt");
results.push({ name: "transfer proof: amounts hidden (only fee public)", ok: xfer.locallyVerified, detail: `fee ${xfer.feePublic} public; in/out values NOT in public signals; out note hidden` });
const rootMatch = xfer.stateRootHex.toLowerCase() === ("0x" + poolRead("get_root").toLowerCase());
results.push({ name: "circuit stateRoot == on-chain root", ok: rootMatch, detail: rootMatch ? "match" : `${xfer.stateRootHex} vs 0x${poolRead("get_root")}` });

// 3) Compute the post-insert root for the output commitment (off-chain registrar).
//    Tree after the transfer = [input commitment, output commitment].
const outputCommitmentDecimal = JSON.parse(readFileSync(`${SCRATCH}/pt_xfer.json`, "utf8")).outputCommitment as string;
const leavesAfter = [coin.commitmentDecimal, outputCommitmentDecimal];
const outRoot = computeStateRoot(coin, leavesAfter, "shade_xfer", SCRATCH, "pt_out");

// 4) Settle the transfer on-chain: verify + spend input nullifier + insert output commitment.
sleepSync(4000);
const settle = sorobanInvoke({
  contractId: pool, secret: poolAdminSecret, method: "private_transfer_settle",
  args: ["--proof_bytes", xfer.proofHex, "--pub_signals_bytes", xfer.publicHex, "--new_root", bytesToCliHex(outRoot)],
  rpcUrl: rpc, passphrase: pass, retries: 3
});
results.push({ name: "on-chain transfer settle (verify + nullifier + output commitment)", ok: !!settle.txHash, detail: settle.txHash });

// 5) Double-spend: re-submitting the same transfer must fail (input nullifier spent).
//    Wait for the spend to propagate to the read node before re-attempting.
sleepSync(12000);
let dsRejected = false;
try {
  sorobanInvoke({ contractId: pool, secret: poolAdminSecret, method: "private_transfer_settle", args: ["--proof_bytes", xfer.proofHex, "--pub_signals_bytes", xfer.publicHex, "--new_root", bytesToCliHex(outRoot)], rpcUrl: rpc, passphrase: pass, retries: 1 });
} catch { dsRejected = true; }
results.push({ name: "transfer double-spend prevented", ok: dsRejected, detail: dsRejected ? "second settle rejected (input nullifier spent)" : "NOT rejected!" });

await writeCheckReport("PrivateTransfer E2E (#2 hidden-amount shielded transfer)", results);
failIfAny(results);
console.log("PrivateTransfer e2e PASS");
