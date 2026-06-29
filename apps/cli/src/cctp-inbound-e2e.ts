import { createHash } from "node:crypto";
import pg from "pg";
import { LOCKED_CCTP, validateInboundRoute } from "@shade/cctp-utils";
import { generateNotePreimage, poseidonCommitment } from "@shade/note-crypto";
import { loadRuntimeEnv, requireKeys } from "./lib/env.js";
import { failIfAny, writeCheckReport, type CheckResult } from "./lib/report.js";
import { runCctpInbound } from "./lib/cctp-inbound.js";

const env = await loadRuntimeEnv();
const results: CheckResult[] = [];
const privateKey = env.ARB_SEPOLIA_PRIVATE_KEY ?? env.ETH_PRIVATE_KEY;

const missing = requireKeys(env, [
  "SHADE_VAULT_CONTRACT",
  "COMMITMENT_TREE_CONTRACT",
  "STELLAR_CCTP_FORWARDER_CONTRACT",
  "STELLAR_TESTNET_USDC_SAC_CONTRACT",
  "STELLAR_RELAYER_SECRET"
]);
results.push({ name: "required env", ok: missing.length === 0 && !!privateKey, detail: missing.concat(privateKey ? [] : ["ETH_PRIVATE_KEY"]).join(", ") || "present" });

// --- Pre-burn negative tests (must be blocked BEFORE any burn) ---------------
function expectReject(name: string, fn: () => void) {
  try {
    fn();
    results.push({ name, ok: false, detail: "route validation did NOT reject (footgun!)" });
  } catch (e) {
    results.push({ name, ok: true, detail: `rejected: ${(e as Error).message}` });
  }
}
const forwarder = env.STELLAR_CCTP_FORWARDER_CONTRACT;
const vault = env.SHADE_VAULT_CONTRACT;
expectReject("pre-burn: wrong destination domain blocked", () =>
  validateInboundRoute({ destinationDomain: 0, mintRecipient: forwarder, destinationCaller: forwarder, forwardRecipient: vault })
);
expectReject("pre-burn: mintRecipient != forwarder blocked", () =>
  validateInboundRoute({ destinationDomain: LOCKED_CCTP.stellarDomain, mintRecipient: vault, destinationCaller: forwarder, forwardRecipient: vault })
);
expectReject("pre-burn: destinationCaller != forwarder blocked", () =>
  validateInboundRoute({ destinationDomain: LOCKED_CCTP.stellarDomain, mintRecipient: forwarder, destinationCaller: vault, forwardRecipient: vault })
);
expectReject("pre-burn: G-address (wrong strkey type) blocked", () =>
  validateInboundRoute({ destinationDomain: LOCKED_CCTP.stellarDomain, mintRecipient: env.STELLAR_DEPLOYER_PUBLIC, destinationCaller: forwarder, forwardRecipient: vault })
);
// Positive route must validate.
try {
  validateInboundRoute({ destinationDomain: LOCKED_CCTP.stellarDomain, mintRecipient: forwarder, destinationCaller: forwarder, forwardRecipient: vault });
  results.push({ name: "pre-burn: valid route accepted", ok: true, detail: "ok" });
} catch (e) {
  results.push({ name: "pre-burn: valid route accepted", ok: false, detail: (e as Error).message });
}

// Abort before spending funds if preflight failed.
const preflightFailed = results.some((r) => !r.ok);
if (preflightFailed) {
  await writeCheckReport("CCTP Inbound E2E", results);
  failIfAny(results);
}

// --- Real burn -> attestation -> mint_and_forward -> vault deposit -----------
const amount6 = BigInt(process.env.CCTP_AMOUNT_6DP ?? "1000000"); // default 1.0 USDC
const note = generateNotePreimage({
  assetId: "USDC:Stellar:SAC",
  amount7dp: (amount6 * 10n).toString(),
  ownerPublicKey: env.STELLAR_USER_PUBLIC ?? "shade-user",
  spendPublicKey: env.STELLAR_USER_PUBLIC ?? "shade-user",
  complianceTag: "default-testnet-policy",
  sourceContext: `arb-sepolia:domain:${LOCKED_CCTP.arbitrumSepoliaDomain}`,
  memoCommitment: "0x" + "00".repeat(32)
});
const commitmentHex = await poseidonCommitment(note);
const encryptedNotePayloadHashHex =
  "0x" + createHash("sha256").update(JSON.stringify({ c: commitmentHex, ctx: note.sourceContext })).digest("hex");
const policyIdHex = "0x" + createHash("sha256").update("shade:default-testnet-policy:v1").digest("hex").slice(0, 64);

console.log(`Burning ${Number(amount6) / 1e6} USDC on Arbitrum Sepolia (commitment ${commitmentHex.slice(0, 12)}...)`);
console.log("This waits for finalized attestation; can take ~13-20 min.");

const depositId = "dep_" + createHash("sha256").update(commitmentHex).digest("hex").slice(0, 24);
let out;
try {
  out = await runCctpInbound(env, { amount6, commitmentHex, encryptedNotePayloadHashHex, policyIdHex });
  results.push({ name: "Arbitrum burn tx", ok: true, detail: out.burnTxHash });
  results.push({ name: "Circle attestation fetched", ok: true, detail: `${out.attestation.slice(0, 18)}...` });
  results.push({ name: "Stellar mint_and_forward tx", ok: true, detail: out.mintForwardTxHash });
  results.push({ name: "ShadeVault USDC received", ok: true, detail: `${out.vaultUsdcBefore} -> ${out.vaultUsdcAfter} (7dp)` });
  results.push({ name: "receive_cctp_deposit tx", ok: true, detail: out.receiveDepositTxHash });
  results.push({ name: "commitment inserted", ok: true, detail: `leaf ${out.leafIndex}, root ${out.root.slice(0, 18)}...` });
} catch (e) {
  results.push({ name: "CCTP inbound flow", ok: false, detail: (e as Error).message });
}

// --- Best-effort persistence -------------------------------------------------
if (out && env.DATABASE_URL) {
  try {
    const pool = new pg.Pool({ connectionString: env.DATABASE_URL });
    await pool.query(
      `insert into cctp_deposits(deposit_id, idempotency_key, source_domain, destination_domain, source_tx_hash,
         cctp_nonce, attestation_status, stellar_mint_tx_hash, vault_deposit_tx_hash, asset_id,
         amount_usdc_6dp, amount_usdc_7dp, commitment, encrypted_note_payload_hash, policy_id, state)
       values ($1,$2,$3,$4,$5,$6,'complete',$7,$8,$9,$10,$11,$12,$13,$14,'SETTLED')
       on conflict (deposit_id) do update set state='SETTLED', vault_deposit_tx_hash=excluded.vault_deposit_tx_hash`,
      [depositId, depositId, LOCKED_CCTP.arbitrumSepoliaDomain, LOCKED_CCTP.stellarDomain, out.burnTxHash,
       out.cctpNonceHex, out.mintForwardTxHash, out.receiveDepositTxHash, env.STELLAR_TESTNET_USDC_SAC_CONTRACT,
       amount6.toString(), out.amount7, commitmentHex, encryptedNotePayloadHashHex, policyIdHex]
    );
    await pool.query(
      `insert into note_commitments(commitment, deposit_id, leaf_index, root, asset_id, amount_usdc_7dp, policy_id, status)
       values ($1,$2,$3,$4,$5,$6,$7,'INSERTED') on conflict (commitment) do nothing`,
      [commitmentHex, depositId, out.leafIndex, out.root, "USDC:Stellar:SAC", out.amount7, policyIdHex]
    );
    await pool.end();
    results.push({ name: "persisted deposit + commitment", ok: true, detail: depositId });
  } catch (e) {
    results.push({ name: "persistence", ok: false, detail: `db write failed (non-fatal): ${(e as Error).message}` });
  }
}

await writeCheckReport("CCTP Inbound E2E", results);
// Persistence failure is non-fatal; on-chain flow is the acceptance gate.
failIfAny(results.filter((r) => r.name !== "persistence"));
console.log("CCTP inbound e2e PASS");
