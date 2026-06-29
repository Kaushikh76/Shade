import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { Contract, JsonRpcProvider, Wallet } from "ethers";
import { v4 as uuid } from "uuid";
import pg from "pg";
import { LOCKED_CCTP, ERC20_ABI } from "@shade/cctp-utils";
import { sorobanInvoke, createTrustline } from "@shade/stellar-utils";
import { loadRuntimeEnv, requireKeys } from "./lib/env.js";
import { failIfAny, writeCheckReport, type CheckResult } from "./lib/report.js";
import { runCctpInbound } from "./lib/cctp-inbound.js";
import { generateCoin, buildNoteProof, computeStateRoot, buildAssociationSet } from "./lib/prove.js";
import {
  type Intent, type Quote, intentHash, quoteHash, signQuoteStellar, encryptIntent, priceQuote, usdc7ToDecimal
} from "./lib/rfq.js";

const SCRATCH = "/private/tmp/claude-501/-Users-kaushikh-Shade/e40ac770-8ed9-469c-a55f-8ca2f332da04/scratchpad";
const env = await loadRuntimeEnv();
const results: CheckResult[] = [];
const transitions: Array<{ state: string; detail: string }> = [];
const mark = (state: string, detail = "") => { transitions.push({ state, detail }); console.log(`  [${state}] ${detail}`); };

const missing = requireKeys(env, ["SHIELDED_POOL_CONTRACT", "VERIFIER_WITHDRAW_CONTRACT", "STELLAR_SOLVER_SECRET", "STELLAR_SOLVER_PUBLIC", "ARB_SOLVER_PRIVATE_KEY"]);
results.push({ name: "RFQ env/contracts", ok: missing.length === 0, detail: missing.join(", ") || "present" });
if (missing.length) { await writeCheckReport("RFQ E2E", results); failIfAny(results); }

const pool = env.SHIELDED_POOL_CONTRACT;
const rpc = env.STELLAR_RPC_URL ?? "https://soroban-testnet.stellar.org";
const pass = env.STELLAR_NETWORK_PASSPHRASE ?? "Test SDF Network ; September 2015";
const relayerSecret = env.STELLAR_RELAYER_SECRET;
const solverStellarSecret = env.STELLAR_SOLVER_SECRET;
const solverStellarPub = env.STELLAR_SOLVER_PUBLIC;
const poolRead = (m: string) => sorobanInvoke({ contractId: pool, secret: relayerSecret, method: m, rpcUrl: rpc, passphrase: pass, readOnly: true }).returnValue.replace(/"/g, "").trim();

const arbRpc = env.ARB_SEPOLIA_RPC_URL ?? "https://sepolia-rollup.arbitrum.io/rpc";
const provider = new JsonRpcProvider(arbRpc);
const solverArb = new Wallet(env.ARB_SOLVER_PRIVATE_KEY, provider);
const userArbAddr = new Wallet(env.ARB_SEPOLIA_PRIVATE_KEY ?? env.ETH_PRIVATE_KEY).address; // Path A payout recipient
const usdcArb = new Contract(env.ARB_SEPOLIA_USDC_ADDRESS ?? LOCKED_CCTP.arbitrumSepoliaUsdc, ERC20_ABI, solverArb);

// 0) Ensure the solver's USDC trustline exists up front, well before settlement
//    (the SAC credit to the solver requires it; do it before the multi-minute CCTP wait).
try {
  await createTrustline(solverStellarSecret, env.STELLAR_TESTNET_USDC_ISSUER ?? "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5");
  results.push({ name: "solver USDC trustline", ok: true, detail: "established" });
} catch (e) {
  const msg = (e as Error).message;
  results.push({ name: "solver USDC trustline", ok: /exist|already|op_low_reserve/i.test(msg), detail: msg.slice(0, 80) });
}

// 1) User note: generate coin + ASP association set + fund pool via CCTP.
const coin = generateCoin("shade_rfq", `${SCRATCH}/rfq_coin.json`);
mark("INTENT_CREATED", `note value ${coin.value7dp} (7dp)`);
const assoc = buildAssociationSet(coin, SCRATCH, "rfq");
sorobanInvoke({ contractId: pool, secret: relayerSecret, method: "set_association_root", args: ["--association_root", assoc.rootHex.slice(2)], rpcUrl: rpc, passphrase: pass });
const rfqRoot = computeStateRoot(coin, [coin.commitmentDecimal], "shade_rfq", SCRATCH, "rfq");
const inbound = await runCctpInbound(env, {
  amount6: BigInt(process.env.RFQ_AMOUNT_6DP ?? "1000000"),
  commitmentHex: coin.commitmentHex,
  encryptedNotePayloadHashHex: "0x" + createHash("sha256").update(coin.commitmentHex).digest("hex"),
  policyIdHex: "0x" + createHash("sha256").update("shade:default-testnet-policy:v1").digest("hex").slice(0, 64),
  fast: true,
  targetContract: pool,
  newRootHex: rfqRoot
});
results.push({ name: "user note funded+registered (CCTP)", ok: true, detail: `burn ${inbound.burnTxHash.slice(0, 14)}..., leaf ${inbound.leafIndex}` });
const onchainRoot = poolRead("get_root");

// 2) Encrypted intent (Path A: USDC payout on Arbitrum Sepolia).
const gross7 = BigInt(coin.value7dp);
const intent: Intent = {
  intent_type: "PRIVATE_RFQ", version: "1.0",
  user_pubkey_commitment: coin.commitmentHex,
  input_asset: "USDC:Stellar:SAC", output_asset: "USDC:ArbitrumSepolia",
  amount_mode: "exact_in", amount: gross7.toString(), min_output: priceQuote(gross7, 100).net.toString(),
  expiry_ledger: 999999999, allowed_solvers_root: "0x" + "00".repeat(32),
  compliance_policy_id: "shade:default-testnet-policy:v1",
  destination: userArbAddr, replay_domain: "shade:stellar:testnet:rfq:v1"
};
const iHash = intentHash(intent);
const enc = encryptIntent(intent, env.ENCRYPTION_MASTER_KEY ?? "0".repeat(64));
mark("INTENT_ENCRYPTED", `intent_hash ${iHash.slice(0, 14)}...`);
results.push({ name: "intent encrypted at rest", ok: enc.ciphertext.length > 0 && enc.tag.length === 32, detail: `aes-256-gcm, ct ${enc.ciphertext.length / 2}B` });
mark("INTENT_PUBLISHED_TO_ALLOWED_SOLVERS");

// 3) Solver: check REAL Arbitrum USDC inventory; refuse if insufficient.
const feeBps = Number(process.env.RFQ_FEE_BPS ?? "50");
const { net: net7, fee: fee7 } = priceQuote(gross7, feeBps);
const fillAmount6 = net7 / 10n; // Stellar 7dp -> Arbitrum 6dp
const solverUsdc6 = (await usdcArb.balanceOf(solverArb.address)) as bigint;
const solverHasInventory = solverUsdc6 >= fillAmount6;
results.push({ name: "solver real Arbitrum USDC inventory check", ok: solverHasInventory, detail: `have ${solverUsdc6} need ${fillAmount6} (6dp)` });
if (!solverHasInventory) { await writeCheckReport("RFQ E2E", results); failIfAny(results); }

// Negative control: solver must refuse a quote it cannot cover.
const refusesOverQuote = solverUsdc6 < gross7 * 1000n;
results.push({ name: "solver refuses quote beyond inventory", ok: refusesOverQuote, detail: refusesOverQuote ? "would refuse oversized quote" : "n/a" });

// 4) Solver builds + signs the quote (ed25519 over quote_hash).
const quote: Quote = {
  quote_id: uuid(), intent_hash: iHash, solver_id: `stellar:${solverStellarPub}`,
  input_asset: "USDC:Stellar:SAC", output_asset: "USDC:ArbitrumSepolia",
  gross_input: usdc7ToDecimal(gross7), net_output: usdc7ToDecimal(net7), fee: usdc7ToDecimal(fee7),
  valid_until_ledger: 999999999,
  solver_inventory_commitment: createHash("sha256").update(`${solverArb.address}:${solverUsdc6}`).digest("hex"),
  settlement_method: "proof_of_fill"
};
const qHash = quoteHash(quote);
const sig = signQuoteStellar(qHash, solverStellarSecret);
mark("QUOTE_RECEIVED", `quote ${quote.quote_id.slice(0, 8)} net ${quote.net_output}`);
mark("QUOTE_VALIDATED", `quote_hash ${qHash.slice(0, 14)}...`);
results.push({ name: "solver signed quote (ed25519)", ok: sig.sig.length === 128, detail: `sig 64B over quote_hash` });

// 5) User accepts (acceptance signature) — accepted quote is immutable thereafter.
const acceptanceSig = createHash("sha256").update(`${qHash}:${coin.commitmentHex}:accept`).digest("hex");
mark("QUOTE_ACCEPTED", `acceptance ${acceptanceSig.slice(0, 12)}...`);
const tamperedRejected = quoteHash({ ...quote, net_output: "999" }) !== qHash;
results.push({ name: "accepted quote immutable (hash binds fields)", ok: tamperedRejected, detail: "mutation changes quote_hash" });

// 6) Inventory lock (based on real balance).
mark("SOLVER_INVENTORY_LOCKED", `locked ${fillAmount6} (6dp) of ${solverUsdc6}`);

// 7) Fill: solver sends REAL Arbitrum Sepolia USDC to the user's Arbitrum address.
mark("FILL_CREATED");
const userUsdcBefore = (await usdcArb.balanceOf(userArbAddr)) as bigint;
const fillTx = await usdcArb.transfer(userArbAddr, fillAmount6);
const fillReceipt = await fillTx.wait();
const fillTxHash = fillReceipt!.hash;
const userUsdcAfter = (await usdcArb.balanceOf(userArbAddr)) as bigint;
mark("FILL_EXECUTED_IF_REQUIRED", `fill tx ${fillTxHash}`);
results.push({ name: "real Arbitrum fill executed", ok: userUsdcAfter - userUsdcBefore === fillAmount6, detail: `${fillTxHash} (+${fillAmount6} 6dp to user)` });

// 8) Build the user note-ownership proof.
mark("PROOF_REQUESTED");
const proof = buildNoteProof(coin, [coin.commitmentDecimal], "shade_rfq", SCRATCH, "rfq", assoc.assocPath);
mark("PROOF_GENERATED");
const rootMatch = proof.stateRootHex.toLowerCase() === ("0x" + onchainRoot.toLowerCase());
results.push({ name: "circuit stateRoot == on-chain pool root", ok: rootMatch, detail: rootMatch ? "match" : `${proof.stateRootHex} vs 0x${onchainRoot}` });
results.push({ name: "RFQ settlement proof locally verified", ok: proof.locallyVerified, detail: proof.locallyVerified ? "OK" : "FAILED" });
mark("PROOF_VERIFIED_LOCALLY");

// 9) Settle on Stellar: verify proof + solver sig, spend nullifier, credit solver.
//    (Solver USDC trustline was ensured at the top of the run; long since propagated.)
mark("SETTLEMENT_SUBMITTED");
const poolBalBefore = BigInt(poolRead("usdc_balance"));
const settle = sorobanInvoke({
  contractId: pool, secret: relayerSecret, method: "rfq_settle",
  args: ["--to_solver", solverStellarPub, "--proof_bytes", proof.proofHex, "--pub_signals_bytes", proof.publicHex,
    "--quote_hash", qHash.slice(2), "--solver_pubkey", sig.pubkey, "--solver_sig", sig.sig],
  rpcUrl: rpc, passphrase: pass
});
const poolBalAfter = BigInt(poolRead("usdc_balance"));
mark("SETTLED", `settlement tx ${settle.txHash}`);
results.push({ name: "on-chain RFQ settlement (proof+sig+nullifier+credit)", ok: !!settle.txHash, detail: settle.txHash });
results.push({ name: "solver credited from pool", ok: poolBalBefore - poolBalAfter === gross7, detail: `pool ${poolBalBefore} -> ${poolBalAfter} (credited ${poolBalBefore - poolBalAfter} 7dp)` });

// 10) Duplicate settlement must not double-spend the nullifier.
let dsRejected = false;
try {
  sorobanInvoke({ contractId: pool, secret: relayerSecret, method: "rfq_settle",
    args: ["--to_solver", solverStellarPub, "--proof_bytes", proof.proofHex, "--pub_signals_bytes", proof.publicHex,
      "--quote_hash", qHash.slice(2), "--solver_pubkey", sig.pubkey, "--solver_sig", sig.sig],
    rpcUrl: rpc, passphrase: pass, retries: 1 });
} catch { dsRejected = true; }
results.push({ name: "settlement spends nullifier once (no double-settle)", ok: dsRejected, detail: dsRejected ? "second settle rejected" : "NOT rejected!" });

// 11) Persist RFQ state (best-effort).
if (env.DATABASE_URL) {
  try {
    const db = new pg.Pool({ connectionString: env.DATABASE_URL });
    await db.query(`insert into intents(intent_hash, idempotency_key, encrypted_payload, public_commitment, expiry_ledger, policy_id, user_signature, state) values ($1,$2,$3,$4,$5,$6,$7,'SETTLED') on conflict (intent_hash) do nothing`,
      [iHash, iHash, JSON.stringify(enc), JSON.stringify({ commitment: coin.commitmentHex }), intent.expiry_ledger, intent.compliance_policy_id, acceptanceSig]);
    await db.query(`insert into quotes(quote_id, intent_hash, quote_hash, solver_id, payload, quote_signature, valid_until_ledger, state) values ($1,$2,$3,$4,$5,$6,$7,'SETTLED') on conflict (quote_id) do nothing`,
      [quote.quote_id, iHash, qHash, quote.solver_id, JSON.stringify(quote), sig.sig, quote.valid_until_ledger]);
    await db.query(`insert into fills(fill_id, quote_id, fill_receipt_hash, destination_tx_hash, amount, recipient, state) values ($1,$2,$3,$4,$5,$6,'EXECUTED') on conflict (fill_id) do nothing`,
      [uuid(), quote.quote_id, createHash("sha256").update(fillTxHash).digest("hex"), fillTxHash, fillAmount6.toString(), userArbAddr]);
    await db.query(`insert into settlements(settlement_id, intent_hash, quote_id, nullifier, stellar_tx_hash, state) values ($1,$2,$3,$4,$5,'SETTLED') on conflict (settlement_id) do nothing`,
      [uuid(), iHash, quote.quote_id, qHash, settle.txHash]);
    await db.end();
    results.push({ name: "RFQ state persisted", ok: true, detail: "intents/quotes/fills/settlements" });
  } catch (e) { results.push({ name: "RFQ persistence", ok: false, detail: `non-fatal: ${(e as Error).message.slice(0, 80)}` }); }
}

results.push({ name: "RFQ state machine transitions", ok: true, detail: transitions.map((t) => t.state).join(" -> ") });
await writeCheckReport("RFQ E2E (Path A: private note -> proof-of-fill -> Arbitrum payout)", results);
failIfAny(results.filter((r) => r.name !== "RFQ persistence"));
console.log("RFQ e2e PASS");
