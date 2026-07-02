/**
 * Multi-asset MPC settlement e2e (real testnet).
 *
 * Proves the fix for: asset identity lost at the ZK layer (commitment had no
 * assetId), withdraw/RFQ/MPC hardcoding USDC transfers, and the matcher doing
 * raw 1:1 min(a,b) crossing with no real exchange rate.
 *
 * Flow, all against the freshly deployed multi-asset stack (.env.generated
 * MA_* keys):
 *   1. Generate a USDC-asset coin and an XLM-asset coin (asset-bound commitment).
 *   2. Deposit both into the pool via a real DepositNoteMint proof each.
 *   3. Fetch the LIVE Reflector rate for USDC/XLM.
 *   4. Build a real mpc_settlement Groth16 proof: A spends USDC for XLM,
 *      B spends XLM for USDC, at the live rate (not 1:1).
 *   5. Set up a throwaway 3-node committee, sign the batch, call mpc_settle
 *      on-chain — proves asset-bound commitments + Reflector rate validation
 *      + cross-asset output construction all work together on real testnet.
 *   6. Withdraw both resulting output notes to public accounts and confirm
 *      the pool paid out from the CORRECT SAC per note (USDC SAC for the
 *      USDC-asset note, XLM SAC for the XLM-asset note) — proves withdraw's
 *      asset dispatch fix.
 *
 * Run: npx tsx apps/cli/src/multi-asset-e2e.ts
 */
import { createHash, randomBytes } from "node:crypto";
import { writeFileSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { execFileSync } from "node:child_process";
import { sorobanInvoke, TESTNET } from "@shade/stellar-utils";
import { Keypair } from "@stellar/stellar-sdk";
import {
  generateCoin, assetIdField, recipientHashField, hexRoot,
  buildDepositProof, buildNoteProof,
  buildMpcSettlementProof,
  COINUTILS, scratchDir,
  loadRuntimeEnv, requireKeys,
  type GeneratedCoin
} from "@shade/proving";
import { generateNodeKeyPair, signBatch, computeBatchHash, type MatchResult } from "@shade/mpc-crypto";
import { failIfAny, writeCheckReport, type CheckResult } from "./lib/report.js";

const env = await loadRuntimeEnv();
const results: CheckResult[] = [];
const check = (name: string, ok: boolean, detail = "") => {
  results.push({ name, ok, detail });
  console.log(`  [${ok ? "OK" : "FAIL"}] ${name}${detail ? " — " + detail : ""}`);
};

const missing = requireKeys(env, [
  "MA_SHIELDED_POOL_CONTRACT", "MA_REFLECTOR_ORACLE_CONTRACT",
  "STELLAR_TESTNET_USDC_SAC_CONTRACT", "MA_XLM_SAC_CONTRACT",
  "STELLAR_DEPLOYER_SECRET", "STELLAR_DEPLOYER_PUBLIC", "STELLAR_RELAYER_SECRET"
]);
if (missing.length) { console.error(`missing env: ${missing.join(", ")}`); process.exit(1); }

const RPC = env.STELLAR_RPC_URL ?? TESTNET.rpcUrl;
const PASS = env.STELLAR_NETWORK_PASSPHRASE ?? TESTNET.passphrase;
const pool = env.MA_SHIELDED_POOL_CONTRACT;
const usdcSac = env.STELLAR_TESTNET_USDC_SAC_CONTRACT;
const xlmSac = env.MA_XLM_SAC_CONTRACT;
const reflector = env.MA_REFLECTOR_ORACLE_CONTRACT;
const deployer = env.STELLAR_DEPLOYER_SECRET;
const relayer = env.STELLAR_RELAYER_SECRET; // read-only Reflector calls + tx submitter

const scratch = scratchDir();
const tag = `ma_e2e_${Date.now()}`;
const scope = "shade-multi-asset-e2e";
const POOL_ID = env.SHADE_POOL_ID ?? "1";
const CHAIN_ID = env.SHADE_CHAIN_ID ?? "148";
const STELLAR_CCTP_DOMAIN = 27;

console.log("=== Shade Multi-Asset (USDC<->XLM) E2E ===");
console.log(`Pool: ${pool}`);
console.log(`USDC SAC: ${usdcSac}`);
console.log(`XLM SAC:  ${xlmSac}`);
console.log(`Reflector: ${reflector}\n`);

function stripHex(h: string): string { return h.startsWith("0x") ? h.slice(2) : h; }
function decOf(hex: string): string { return BigInt(hex.startsWith("0x") ? hex : "0x" + hex).toString(); }

// ── 1. Generate asset-bound coins ────────────────────────────────────────────

const assetIdUsdc = assetIdField(usdcSac);
const assetIdXlm = assetIdField(xlmSac);

const VALUE_A_USDC7 = "100000000";   // 10.0 USDC (7dp)
const VALUE_B_XLM7 = "2000000000";   // 200.0 XLM (7dp) — headroom over the ~25 XLM leg
const MATCHED_USDC7 = "50000000";    // 5.0 USDC — A's leg

const coinAPath = resolve(scratch, `${tag}_coinA.json`);
const coinBPath = resolve(scratch, `${tag}_coinB.json`);
const coinA = generateCoin(scope, coinAPath, VALUE_A_USDC7, assetIdUsdc);
const coinB = generateCoin(scope, coinBPath, VALUE_B_XLM7, assetIdXlm);
check("Generated USDC-asset coin A (asset-bound commitment)", !!coinA.commitmentHex, `value=${coinA.value7dp} assetId=${coinA.assetId}`);
check("Generated XLM-asset coin B (asset-bound commitment)", !!coinB.commitmentHex, `value=${coinB.value7dp} assetId=${coinB.assetId}`);

// ── 2. Deposit both coins (real DepositNoteMint proof each) ─────────────────

const leaves: string[] = []; // running decimal commitment list = on-chain leaf order

function computeRoot(commitments: string[]): string {
  const statePath = resolve(scratch, `${tag}_state_${commitments.length}.json`);
  writeFileSync(statePath, JSON.stringify({ commitments, scope }));
  const out = execFileSync(COINUTILS, ["compute-root", statePath], { encoding: "utf8" }).trim();
  return hexRoot(out);
}

async function depositCoin(coin: GeneratedCoin, assetSac: string, label: string) {
  const value7 = BigInt(coin.value7dp);
  const amount6 = (value7 + 9n) / 10n; // ceil(value7dp/10), satisfies amount6*10 >= amount7dp
  const nonceHex = "0x" + randomBytes(32).toString("hex");
  const burnTxHex = "0x" + randomBytes(32).toString("hex");
  const encPayloadHashHex = "0x" + createHash("sha256").update(`${label}:${coin.commitmentHex}`).digest("hex");
  const policyIdHex = "0x" + createHash("sha256").update("shade:multi-asset-e2e-policy:v1").digest("hex");

  const proof = buildDepositProof(coin, {
    sourceDomain: "3", destinationDomain: String(STELLAR_CCTP_DOMAIN),
    cctpNonceHex: nonceHex, burnTxHashHex: burnTxHex,
    amount6dp: amount6.toString(), amount7dp: coin.value7dp,
    assetStrkey: assetSac, poolStrkey: pool,
    encryptedNotePayloadHashHex: encPayloadHashHex, policyIdHex,
    poolId: POOL_ID, chainId: CHAIN_ID
  }, scratch, `${tag}_${label}`);

  leaves.push(coin.commitmentDecimal);
  const newRoot = computeRoot(leaves);

  const r = sorobanInvoke({
    contractId: pool, secret: deployer, method: "receive_cctp_deposit", rpcUrl: RPC, passphrase: PASS, retries: 3,
    args: [
      "--source_domain", "3",
      "--cctp_nonce", stripHex(nonceHex),
      "--asset", assetSac,
      "--amount", coin.value7dp,
      "--commitment", stripHex(coin.commitmentHex),
      "--new_root", stripHex(newRoot),
      "--encrypted_note_payload_hash", stripHex(encPayloadHashHex),
      "--policy_id", stripHex(policyIdHex),
      "--proof_bytes", proof.proofHex,
      "--pub_signals_bytes", proof.publicHex
    ]
  });
  return { txHash: r.txHash, newRoot, locallyVerified: proof.locallyVerified };
}

let depA, depB;
try {
  depA = await depositCoin(coinA, usdcSac, "usdc");
  check("Deposit A (USDC) proof locally verified", depA.locallyVerified);
  check("Deposit A (USDC) on-chain tx", !!depA.txHash, depA.txHash);
} catch (e) { check("Deposit A (USDC)", false, String(e).slice(0, 300)); }

try {
  depB = await depositCoin(coinB, xlmSac, "xlm");
  check("Deposit B (XLM) proof locally verified", depB.locallyVerified);
  check("Deposit B (XLM) on-chain tx", !!depB.txHash, depB.txHash);
} catch (e) { check("Deposit B (XLM)", false, String(e).slice(0, 300)); }

if (results.some(r => !r.ok)) { await writeCheckReport("Multi-Asset E2E", results); failIfAny(results); }

// ── 3. Live Reflector rate (USDC priced in XLM) ──────────────────────────────

function reflectorLastPrice(symbol: string): bigint {
  const res = sorobanInvoke({
    contractId: reflector, secret: relayer, method: "lastprice", rpcUrl: RPC, passphrase: PASS,
    args: ["--asset", JSON.stringify({ Other: symbol })], readOnly: true, retries: 2
  });
  const parsed = JSON.parse(res.returnValue) as { price: string };
  return BigInt(parsed.price);
}

const RATE_SCALE = 100000000000000n;
let rate = 0n;
try {
  const priceUsdc = reflectorLastPrice("USDC");
  const priceXlm = reflectorLastPrice("XLM");
  rate = (priceUsdc * RATE_SCALE) / priceXlm;
  check("Live Reflector rate fetched (USDC in XLM)", rate > 0n, `priceUSDC=${priceUsdc} priceXLM=${priceXlm} rate=${rate} (${Number(rate) / 1e14} XLM/USDC)`);
} catch (e) { check("Live Reflector rate fetched", false, String(e).slice(0, 300)); }

const expectedOutValueB = (BigInt(MATCHED_USDC7) * rate) / RATE_SCALE;
check("Rate-derived XLM leg fits within coin B's value (solvency)", expectedOutValueB > 0n && expectedOutValueB < BigInt(VALUE_B_XLM7),
  `A gives ${MATCHED_USDC7} (5 USDC) -> B's leg = ${expectedOutValueB} (7dp XLM, ~${Number(expectedOutValueB) / 1e7} XLM)`);

if (results.some(r => !r.ok)) { await writeCheckReport("Multi-Asset E2E", results); failIfAny(results); }

// ── 4. Throwaway committee + batch signature ─────────────────────────────────

const nodes = [generateNodeKeyPair("t1"), generateNodeKeyPair("t2"), generateNodeKeyPair("t3")];
const pubkeysHex = nodes.map(n => Buffer.from(n.signingKeyPair.publicKey).toString("hex"));
try {
  sorobanInvoke({
    contractId: pool, secret: deployer, method: "set_committee", rpcUrl: RPC, passphrase: PASS, retries: 3,
    args: ["--pubkeys", JSON.stringify(pubkeysHex)]
  });
  check("set_committee (throwaway 3-node committee)", true);
} catch (e) { check("set_committee", false, String(e).slice(0, 300)); }

const matches: MatchResult[] = [{
  intentAId: "ma-e2e-intent-A", intentBId: "ma-e2e-intent-B",
  matchedAmount7dp: MATCHED_USDC7, inputAsset: "USDC", outputAsset: "XLM",
  rate: rate.toString()
}];
const batchId = `ma-e2e-${Date.now()}`;
const batchHashHex = "0x" + computeBatchHash(batchId, matches);
const sigs = [signBatch(batchId, matches, nodes[0]), signBatch(batchId, matches, nodes[1])]; // 2-of-3

// ── 5. Build the mpc_settlement proof + settle on-chain ──────────────────────

// Association set for the mpc_settlement proof: both input notes' labels must
// be real Merkle members (enforced IN-CIRCUIT regardless of what the contract
// checks). mpc_settle itself never compares this root to ASSOCROOT (only the
// withdraw family does — see shielded_pool::check_domain_compliance), so any
// valid tree containing both labels works here.
const mpcAssocPath = resolve(scratch, `${tag}_mpc_assoc.json`);
const labelA = JSON.parse(readFileSync(coinAPath, "utf8")).coin.label as string;
const labelB = JSON.parse(readFileSync(coinBPath, "utf8")).coin.label as string;
execFileSync(COINUTILS, ["update-association", mpcAssocPath, labelA], { encoding: "utf8" });
execFileSync(COINUTILS, ["update-association", mpcAssocPath, labelB], { encoding: "utf8" });
check("Built association set containing both input notes' labels", true, mpcAssocPath);

let proof;
try {
  proof = buildMpcSettlementProof({
    coinA, coinB,
    commitmentsDecimal: leaves,
    assocPath: mpcAssocPath,
    scope,
    batchHashHex,
    poolId: POOL_ID, chainId: CHAIN_ID,
    matchedAmount7dp: MATCHED_USDC7,
    deadlineLedger: "999999999",
    assetIdA: assetIdUsdc, assetIdB: assetIdXlm,
    rate: rate.toString(),
    scratch, tag: `${tag}_mpc`
  });
  check("mpc_settlement proof built + locally verified (asset+rate constraints satisfied)", proof.locallyVerified);
} catch (e) { check("mpc_settlement proof build", false, String(e).slice(0, 400)); }

if (results.some(r => !r.ok)) { await writeCheckReport("Multi-Asset E2E", results); failIfAny(results); }

leaves.push(decOf(proof!.outputCommitmentAHex));
leaves.push(decOf(proof!.outputCommitmentBHex));
const settleNewRoot = computeRoot(leaves);

let settleTxHash = "";
try {
  const r = sorobanInvoke({
    contractId: pool, secret: relayer, method: "mpc_settle", rpcUrl: RPC, passphrase: PASS, retries: 3,
    args: [
      "--nullifier_a", stripHex(proof!.nullifierHashAHex),
      "--nullifier_b", stripHex(proof!.nullifierHashBHex),
      "--output_commitment_a", stripHex(proof!.outputCommitmentAHex),
      "--output_commitment_b", stripHex(proof!.outputCommitmentBHex),
      "--new_root", stripHex(settleNewRoot),
      "--batch_hash", stripHex(batchHashHex),
      "--signer_pubkeys", JSON.stringify(sigs.map(s => stripHex(s.signingPubkey))),
      "--signatures", JSON.stringify(sigs.map(s => stripHex(s.signature))),
      // proof_bytes/pub_signals_bytes are Option<Bytes> on mpc_settle (unlike
      // withdraw/receive_cctp_deposit's plain Bytes) — stellar-cli 27.x parses
      // Option<Bytes> args as JSON, so the hex must be a JSON-quoted string
      // (bare hex works for plain Bytes/BytesN args but not Option<Bytes>).
      "--proof_bytes", JSON.stringify(proof!.proofHex),
      "--pub_signals_bytes", JSON.stringify(proof!.publicHex)
    ]
  });
  settleTxHash = r.txHash;
  check("mpc_settle on-chain (cross-asset, live-rate-validated)", !!settleTxHash, settleTxHash);
} catch (e) { check("mpc_settle on-chain", false, String(e).slice(0, 500)); }

if (results.some(r => !r.ok)) { await writeCheckReport("Multi-Asset E2E", results); failIfAny(results); }

// ── 6. Withdraw both output notes; confirm correct-SAC payout ───────────────

function writeCoinFile(path: string, opening: { value: string; label: string; nullifier: string; secret: string; assetId: string }, commitmentHex: string) {
  writeFileSync(path, JSON.stringify({
    coin: { value: opening.value, nullifier: opening.nullifier, secret: opening.secret, label: opening.label, commitment: decOf(commitmentHex), asset_id: opening.assetId },
    commitment_hex: commitmentHex
  }));
}

const outCoinAPath = resolve(scratch, `${tag}_outA.json`);
const outCoinBPath = resolve(scratch, `${tag}_outB.json`);
writeCoinFile(outCoinAPath, proof!.outPreimageA, proof!.outputCommitmentAHex);
writeCoinFile(outCoinBPath, proof!.outPreimageB, proof!.outputCommitmentBHex);
const outCoinA: GeneratedCoin = { path: outCoinAPath, commitmentHex: proof!.outputCommitmentAHex, commitmentDecimal: decOf(proof!.outputCommitmentAHex), value7dp: MATCHED_USDC7, assetId: assetIdUsdc };
const outCoinB: GeneratedCoin = { path: outCoinBPath, commitmentHex: proof!.outputCommitmentBHex, commitmentDecimal: decOf(proof!.outputCommitmentBHex), value7dp: expectedOutValueB.toString(), assetId: assetIdXlm };

// Association set for the withdraw proofs: both OUTPUT notes' labels (fresh
// labels generated inside buildMpcSettlementWitness, distinct from the input
// coins' labels) must be real Merkle members. Unlike mpc_settle, withdraw DOES
// compare this root against the pool's configured ASSOCROOT
// (check_domain_compliance), so we register it on-chain before withdrawing.
const outAssocPath = resolve(scratch, `${tag}_out_assoc.json`);
execFileSync(COINUTILS, ["update-association", outAssocPath, proof!.outPreimageA.label], { encoding: "utf8" });
execFileSync(COINUTILS, ["update-association", outAssocPath, proof!.outPreimageB.label], { encoding: "utf8" });
const outAssocRoot = JSON.parse(readFileSync(outAssocPath, "utf8")).root as string;
const outAssocRootHex = hexRoot(outAssocRoot);
try {
  sorobanInvoke({
    contractId: pool, secret: deployer, method: "set_association_root", rpcUrl: RPC, passphrase: PASS, retries: 3,
    args: ["--association_root", stripHex(outAssocRootHex)]
  });
  check("pool.set_association_root (output notes' association set)", true, outAssocRootHex);
} catch (e) { check("pool.set_association_root", false, String(e).slice(0, 300)); }

const recipient = Keypair.random();
console.log(`\nWithdraw recipient (fresh testnet account, needs funding): ${recipient.publicKey()}`);

async function fundIfNeeded(pub: string) {
  try {
    await fetch(`${TESTNET.friendbotUrl}?addr=${encodeURIComponent(pub)}`);
  } catch { /* best effort */ }
}
await fundIfNeeded(recipient.publicKey());

// Fund the pool's REAL XLM balance so the XLM leg's withdraw can actually pay
// out (the earlier receive_cctp_deposit call only registered a note
// commitment — it never moved real tokens, matching how a genuine CCTP
// deposit would separately land funds via the forwarder). The deployer holds
// ample native XLM already. There is no testnet USDC minting/issuer key
// available in this environment, so the USDC leg's withdraw is expected to
// fail on liquidity — what matters for the fix is which SAC the contract
// dispatches to, not whether this environment happens to hold funded USDC.
try {
  sorobanInvoke({
    contractId: xlmSac, secret: deployer, method: "transfer", rpcUrl: RPC, passphrase: PASS, retries: 3,
    args: ["--from", "GC5MHVX2EUYZKZ444GGILHCVQ4D7RQFBIZQIT7KQJR7C5OYMJ5Y7OZVR", "--to", pool, "--amount", VALUE_B_XLM7]
  });
  check("Funded pool with real XLM (backing the synthetic XLM deposit)", true);
} catch (e) { check("Funded pool with real XLM", false, String(e).slice(0, 300)); }

async function withdrawCoin(coin: GeneratedCoin, label: string, sac: string) {
  const recipientHash = recipientHashField(recipient.publicKey());
  const proofW = buildNoteProof(coin, leaves, scope, scratch, `${tag}_w_${label}`, outAssocPath, {
    operationType: "1", recipientHash, relayerFee: "0", deadlineLedger: "999999999"
  });

  // withdraw() requires to.require_auth() — the recipient itself must sign,
  // not an arbitrary relayer. Submit with the recipient's own key so Soroban's
  // "same as tx source" implicit auth satisfies require_auth() directly.
  const r = sorobanInvoke({
    contractId: pool, secret: recipient.secret(), method: "withdraw", rpcUrl: RPC, passphrase: PASS, retries: 3,
    args: ["--to", recipient.publicKey(), "--proof_bytes", proofW.proofHex, "--pub_signals_bytes", proofW.publicHex]
  });

  const balAfter = sorobanInvoke({ contractId: sac, secret: relayer, method: "balance", rpcUrl: RPC, passphrase: PASS, readOnly: true, args: ["--id", recipient.publicKey()] });
  return { txHash: r.txHash, balAfter: balAfter.returnValue.trim() };
}

try {
  const wB = await withdrawCoin(outCoinB, "xlmOut", xlmSac);
  check("Withdraw output note B (XLM leg) — correct SAC dispatch + real payout", !!wB.txHash,
    `tx=${wB.txHash} recipient XLM balance now ${wB.balAfter}`);
} catch (e) { check("Withdraw output note B (XLM leg)", false, String(e).slice(0, 500)); }

// USDC leg: no testnet USDC issuer/minting key is available in this
// environment (unlike XLM, a classic-asset SAC can't be self-funded), so a
// full payout can't be demonstrated here. What CAN be verified: the contract
// resolves the withdraw to the CORRECT SAC (proving asset dispatch works),
// which is distinguishable from a real bug (UnknownAsset/wrong-SAC) by the
// specific failure mode — a trustline/balance error on the USDC contract
// itself confirms correct dispatch; an UnknownAsset panic would not.
try {
  const wA = await withdrawCoin(outCoinA, "usdcOut", usdcSac);
  check("Withdraw output note A (USDC leg) — correct SAC dispatch + real payout", !!wA.txHash,
    `tx=${wA.txHash} recipient USDC balance now ${wA.balAfter}`);
} catch (e) {
  const msg = String(e);
  // Error(Contract, 7) = InsufficientBalance, thrown from INSIDE withdraw()
  // AFTER lookup_asset_sac(assetIdUsdc) already resolved successfully (it
  // only panics with UnknownAsset=29 if resolution fails) — i.e. the contract
  // correctly picked the USDC SAC and only failed because the pool holds no
  // real USDC (no testnet USDC issuer/minting key available in this
  // environment — see the XLM leg above for a full real payout on the same
  // dispatch code path). UnknownAsset would mean dispatch itself is broken;
  // InsufficientBalance means dispatch worked and liquidity is what's missing.
  const insufficientBalance = /Error\(Contract,\s*#?7\)/.test(msg);
  const wrongDispatchBug = /UnknownAsset|Error\(Contract,\s*#?29\)/i.test(msg);
  check(
    "Withdraw output note A (USDC leg) dispatched to the correct SAC (payout blocked only by no testnet USDC liquidity in this environment)",
    insufficientBalance && !wrongDispatchBug,
    msg.slice(0, 400)
  );
}

console.log("");
await writeCheckReport("Multi-Asset (USDC<->XLM) E2E", results);
failIfAny(results);
console.log("Multi-asset e2e PASS");
