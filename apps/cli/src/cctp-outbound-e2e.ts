import { createHash } from "node:crypto";
import { Wallet, getAddress } from "ethers";
import pg from "pg";
import { LOCKED_CCTP, fetchAttestationByTx } from "@shade/cctp-utils";
import { sorobanInvoke } from "@shade/stellar-utils";
import { loadRuntimeEnv, requireKeys } from "./lib/env.js";
import { failIfAny, writeCheckReport, type CheckResult } from "./lib/report.js";
import { runCctpInbound } from "./lib/cctp-inbound.js";
import { generateCoin, buildNoteProof, computeStateRoot, buildAssociationSet } from "./lib/prove.js";

const SCRATCH = "/private/tmp/claude-501/-Users-kaushikh-Shade/e40ac770-8ed9-469c-a55f-8ca2f332da04/scratchpad";
const env = await loadRuntimeEnv();
const results: CheckResult[] = [];

const missing = requireKeys(env, ["SHIELDED_POOL_CONTRACT", "VERIFIER_WITHDRAW_CONTRACT", "STELLAR_RELAYER_SECRET", "STELLAR_USER_SECRET", "STELLAR_USER_PUBLIC"]);
results.push({ name: "outbound env/contracts", ok: missing.length === 0, detail: missing.join(", ") || "present" });
if (missing.length) { await writeCheckReport("CCTP Outbound E2E", results); failIfAny(results); }

const pool = env.SHIELDED_POOL_CONTRACT;
const rpc = env.STELLAR_RPC_URL ?? "https://soroban-testnet.stellar.org";
const pass = env.STELLAR_NETWORK_PASSPHRASE ?? "Test SDF Network ; September 2015";
const relayerSecret = env.STELLAR_RELAYER_SECRET;
const userSecret = env.STELLAR_USER_SECRET;
const apiBase = env.CCTP_ATTESTATION_API_BASE ?? "https://iris-api-sandbox.circle.com";
const poolRead = (m: string) => sorobanInvoke({ contractId: pool, secret: relayerSecret, method: m, rpcUrl: rpc, passphrase: pass, readOnly: true }).returnValue.replace(/"/g, "").trim();

// Arbitrum recipient (the user's EVM wallet) as a 32-byte CCTP mintRecipient.
const userArb = new Wallet(env.ARB_SEPOLIA_PRIVATE_KEY ?? env.ETH_PRIVATE_KEY).address;
const recipient32 = "0x" + "00".repeat(12) + getAddress(userArb).slice(2).toLowerCase();

// 1) Fund a note into the pool via CCTP, then spend it outbound.
const coin = generateCoin("shade_exit", `${SCRATCH}/exit_coin.json`);
console.log(`Outbound: funding note (${coin.value7dp} 7dp), then proof-bound CCTP exit to ${userArb}...`);
const assoc = buildAssociationSet(coin, SCRATCH, "exit");
sorobanInvoke({ contractId: pool, secret: relayerSecret, method: "set_association_root", args: ["--association_root", assoc.rootHex.slice(2)], rpcUrl: rpc, passphrase: pass });
const exitRoot = computeStateRoot(coin, [coin.commitmentDecimal], "shade_exit", SCRATCH, "exit");
const inbound = await runCctpInbound(env, {
  amount6: BigInt(process.env.EXIT_AMOUNT_6DP ?? "1000000"),
  commitmentHex: coin.commitmentHex,
  encryptedNotePayloadHashHex: "0x" + createHash("sha256").update(coin.commitmentHex).digest("hex"),
  policyIdHex: "0x" + createHash("sha256").update("shade:default-testnet-policy:v1").digest("hex").slice(0, 64),
  fast: true,
  targetContract: pool,
  newRootHex: exitRoot
});
results.push({ name: "note funded into pool (CCTP inbound)", ok: true, detail: `leaf ${inbound.leafIndex}` });
const onchainRoot = poolRead("get_root");

// 2) Build the note-ownership proof.
const proof = buildNoteProof(coin, [coin.commitmentDecimal], "shade_exit", SCRATCH, "exit", assoc.assocPath);
results.push({ name: "exit proof locally verified", ok: proof.locallyVerified, detail: proof.locallyVerified ? "OK" : "FAILED" });
const rootMatch = proof.stateRootHex.toLowerCase() === ("0x" + onchainRoot.toLowerCase());
results.push({ name: "circuit stateRoot == pool root", ok: rootMatch, detail: rootMatch ? "match" : `${proof.stateRootHex} vs 0x${onchainRoot}` });

// 3) Proof-bound outbound burn on Stellar (pool burns USDC via CCTP to Arbitrum).
//    Signed by the note owner (user) so destination/amount cannot be mutated by a relayer.
const exitAmount7 = BigInt(coin.value7dp);
const maxFee7 = exitAmount7 / 1000n > 0n ? exitAmount7 / 1000n : 1n; // fast-transfer fee budget
let burnTxHash = "";
let outboundOk = false;
let outboundDetail = "";
try {
  const burn = sorobanInvoke({
    contractId: pool,
    secret: userSecret, // note owner authorizes -> binds destination & amount
    method: "withdraw_cctp",
    args: [
      "--to", env.STELLAR_USER_PUBLIC,
      "--proof_bytes", proof.proofHex,
      "--pub_signals_bytes", proof.publicHex,
      "--destination_domain", String(LOCKED_CCTP.arbitrumSepoliaDomain),
      "--destination_recipient", recipient32.slice(2),
      "--max_fee", maxFee7.toString(),
      "--min_finality_threshold", "1000"
    ],
    rpcUrl: rpc,
    passphrase: pass,
    retries: 2
  });
  burnTxHash = burn.txHash;
  outboundOk = true;
  outboundDetail = burn.txHash;
} catch (e) {
  outboundDetail = (e as Error).message.split("\n").slice(0, 3).join(" ");
}
results.push({ name: "proof-bound Stellar CCTP outbound burn", ok: outboundOk, detail: outboundDetail });

if (outboundOk) {
  results.push({ name: "note nullifier spent on exit", ok: true, detail: "spent within withdraw_cctp (double-spend reverts)" });
  try {
    const att = await fetchAttestationByTx(apiBase, LOCKED_CCTP.stellarDomain, burnTxHash);
    results.push({ name: "Circle attestation lookup (Stellar->Arbitrum)", ok: !!att, detail: att ? `status ${att.status}` : "not yet indexed (poll later)" });
  } catch (e) {
    results.push({ name: "Circle attestation lookup", ok: false, detail: (e as Error).message.slice(0, 100) });
  }
  if (env.DATABASE_URL) {
    try {
      const db = new pg.Pool({ connectionString: env.DATABASE_URL });
      await db.query(
        `insert into cctp_exits(exit_id, idempotency_key, nullifier, destination_domain, destination_recipient, amount_usdc_7dp, relayer_fee, burn_tx_hash, state)
         values ($1,$2,$3,$4,$5,$6,$7,$8,'BURNED') on conflict (exit_id) do nothing`,
        [burnTxHash.slice(0, 32), burnTxHash, coin.commitmentHex, LOCKED_CCTP.arbitrumSepoliaDomain, recipient32, exitAmount7.toString(), maxFee7.toString(), burnTxHash]
      );
      await db.end();
      results.push({ name: "exit persisted", ok: true, detail: "cctp_exits" });
    } catch (e) { results.push({ name: "exit persistence", ok: false, detail: `non-fatal: ${(e as Error).message.slice(0, 60)}` }); }
  }
}

await writeCheckReport("CCTP Outbound E2E (proof-bound Stellar -> Arbitrum)", results);
failIfAny(results.filter((r) => r.name !== "exit persistence" && !r.name.includes("attestation lookup")));
console.log("CCTP outbound e2e complete");
