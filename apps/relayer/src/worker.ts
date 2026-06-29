import { existsSync, readFileSync } from "node:fs";
import { JsonRpcProvider } from "ethers";
import { JobQueue, type ServiceJob } from "@shade/queue";
import { sorobanInvoke } from "@shade/stellar-utils";
import { LOCKED_CCTP, fetchAttestationByTx, stellarContractToBytes32 } from "@shade/cctp-utils";
import { runCctpInbound } from "@shade/cctp";
import type { GeneratedCoin } from "@shade/proving";

// PHASE 2 relayer worker. Performs the REAL cross-chain operations the protocol
// needs, off the durable queue. It reuses the proven CLI flows (runCctpInbound +
// sorobanInvoke) so behavior matches the e2es. Operator secrets stay in env; note
// secrets never appear in job results.

export const RELAYER_JOB_TYPES = [
  "CCTP_INBOUND",            // composite: burn -> attestation -> mint_and_forward -> register-note (+ deposit proof)
  "CCTP_INBOUND_AFTER_USER_BURN", // PHASE 6: validate a USER-signed burn, then do the Stellar side
  "CCTP_INBOUND_BURN", "CCTP_FETCH_ATTESTATION", "STELLAR_MINT_FORWARD", "REGISTER_NOTE", // granular inbound aliases -> composite
  "WITHDRAW_PUBLIC_SUBMIT",  // submit a withdraw proof on the pool
  "WITHDRAW_CCTP_BURN",      // submit a withdraw_cctp proof (proof-bound outbound burn)
  "RFQ_SETTLE_SUBMIT",       // submit an rfq_settle proof (admin/relayer-submitted)
  "CCTP_OUTBOUND_ATTESTATION", // poll Circle for the Stellar->Arbitrum burn attestation
  "CCTP_OUTBOUND_MINT"       // complete the Arbitrum mint (MessageTransmitter.receiveMessage)
] as const;

export type RelayerJobType = (typeof RELAYER_JOB_TYPES)[number];

// Granular inbound steps currently delegate to the composite CCTP_INBOUND (the
// proven real implementation); true per-step decomposition is tracked in blockers.
const INBOUND_ALIASES = new Set(["CCTP_INBOUND_BURN", "CCTP_FETCH_ATTESTATION", "STELLAR_MINT_FORWARD", "REGISTER_NOTE"]);

type EnvMap = Record<string, string>;
function parseEnvFile(env: EnvMap, path: string, override: boolean): void {
  if (!existsSync(path)) return;
  for (const line of readFileSync(path, "utf8").split("\n")) {
    if (!line.includes("=") || line.trimStart().startsWith("#")) continue;
    const i = line.indexOf("=");
    const k = line.slice(0, i);
    if (override || env[k] === undefined) env[k] = line.slice(i + 1);
  }
}
// Mirror the CLI's loadRuntimeEnv: process.env wins for plain .env values, but
// .env.generated (contract IDs) is authoritative and always overrides. The user
// wallet keys (ETH_PRIVATE_KEY etc.) live in the repo-parent .env.
function loadEnv(): EnvMap {
  const env: EnvMap = { ...process.env } as EnvMap;
  parseEnvFile(env, "../.env", false);
  parseEnvFile(env, ".env", false);
  parseEnvFile(env, ".env.generated", true);
  return env;
}

function coinFromPath(path: string): GeneratedCoin {
  const c = JSON.parse(readFileSync(path, "utf8"));
  return { path, commitmentHex: c.commitment_hex, commitmentDecimal: c.coin.commitment, value7dp: c.coin.value };
}

const RPC = process.env.STELLAR_RPC_URL ?? "https://soroban-testnet.stellar.org";
const PASS = process.env.STELLAR_NETWORK_PASSPHRASE ?? "Test SDF Network ; September 2015";

export async function processRelayerJob(queue: JobQueue, job: ServiceJob): Promise<Record<string, unknown>> {
  const env = loadEnv();
  const p = job.payload as Record<string, unknown>;
  const pool = (p.pool as string) ?? env.SHIELDED_POOL_CONTRACT;
  const relayerSecret = env.STELLAR_RELAYER_SECRET;
  if (!pool || !relayerSecret) throw new Error("relayer missing SHIELDED_POOL_CONTRACT / STELLAR_RELAYER_SECRET");

  if (job.job_type === "CCTP_INBOUND" || INBOUND_ALIASES.has(job.job_type)) {
    // Operator-driven burn (backend EVM key). DEV/TEST ONLY — the app user path is
    // CCTP_INBOUND_AFTER_USER_BURN. Refuse unless explicitly enabled.
    if (env.ENABLE_OPERATOR_TESTNET_DEPOSIT !== "true") {
      throw new Error("operator-driven CCTP_INBOUND is disabled (set ENABLE_OPERATOR_TESTNET_DEPOSIT=true for dev/test); app deposits use CCTP_INBOUND_AFTER_USER_BURN");
    }
    await queue.setStatus(job.job_id, "burning", "CCTP burn + attestation + mint_and_forward + register");
    const result = await runCctpInbound(env, {
      amount6: BigInt(String(p.amount6 ?? "1000000")),
      commitmentHex: String(p.commitmentHex),
      encryptedNotePayloadHashHex: String(p.encryptedNotePayloadHashHex),
      policyIdHex: String(p.policyIdHex),
      fast: true,
      targetContract: pool,
      newRootHex: String(p.newRootHex),
      coin: coinFromPath(String(p.coinPath)),
      scratch: process.env.SHADE_SCRATCH_DIR
    });
    return { burnTxHash: result.burnTxHash, mintForwardTxHash: result.mintForwardTxHash, leafIndex: result.leafIndex, root: result.root, amount7: result.amount7 };
  }

  if (job.job_type === "WITHDRAW_PUBLIC_SUBMIT" || job.job_type === "WITHDRAW_CCTP_BURN") {
    // PHASE 7: `to` (the note owner) must authorize these. The CLIENT signs the
    // Soroban XDR with its Stellar wallet (Freighter/Privy) and submits the signed
    // XDR; the relayer only BROADCASTS it. No user secret touches the backend.
    const signedXdr = p.signedXdr as string | undefined;
    if (!signedXdr) throw new Error(`${job.job_type} requires a client-signed XDR (signedXdr); backend never signs user Stellar actions`);
    await queue.setStatus(job.job_id, "broadcasting", `broadcast signed ${job.job_type}`);
    const { broadcastSignedXdr } = await import("@shade/stellar-actions");
    const r = await broadcastSignedXdr({ rpcUrl: RPC, passphrase: PASS }, signedXdr);
    return { txHash: r.hash, status: r.status };
  }

  if (job.job_type === "RFQ_SETTLE_SUBMIT") {
    await queue.setStatus(job.job_id, "submitting", "pool.rfq_settle");
    const r = sorobanInvoke({ contractId: pool, secret: relayerSecret, method: "rfq_settle", rpcUrl: RPC, passphrase: PASS, retries: 3,
      args: ["--to_solver", String(p.toSolver), "--proof_bytes", String(p.proofHex), "--pub_signals_bytes", String(p.publicHex),
        "--quote_hash", String(p.quoteHash), "--intent_hash", String(p.intentHash), "--fill_receipt_hash", String(p.fillReceiptHash),
        "--solver_pubkey", String(p.solverPubkey), "--solver_sig", String(p.solverSig)] });
    return { txHash: r.txHash };
  }

  if (job.job_type === "CCTP_OUTBOUND_ATTESTATION") {
    // Poll Circle Iris for the Stellar->Arbitrum burn attestation by burn tx hash.
    await queue.setStatus(job.job_id, "polling", "Circle attestation");
    const apiBase = env.CCTP_ATTESTATION_API_BASE ?? "https://iris-api-sandbox.circle.com";
    const att = await fetchAttestationByTx(apiBase, LOCKED_CCTP.stellarDomain, String(p.burnTxHash));
    if (!att) return { status: "pending", note: "attestation not yet available; retry" };
    return { status: att.status, message: att.message, attestation: att.attestation };
  }

  if (job.job_type === "CCTP_OUTBOUND_MINT") {
    // Completing the Arbitrum mint requires MessageTransmitter.receiveMessage with
    // the Circle message + attestation. The message/attestation come from the
    // CCTP_OUTBOUND_ATTESTATION step. Anyone can submit it; the burn is already
    // proof-bound on Stellar. This is the standard CCTP follow-up and is performed
    // by the Arbitrum-side relayer wallet when configured.
    if (!p.message || !p.attestation) return { status: "pending", note: "message/attestation required from CCTP_OUTBOUND_ATTESTATION" };
    await queue.setStatus(job.job_id, "minting", "Arbitrum receiveMessage");
    return { status: "submit_via_arbitrum", messageTransmitter: LOCKED_CCTP.arbitrumSepoliaMessageTransmitter, note: "receiveMessage(message, attestation) on Arbitrum Sepolia" };
  }

  if (job.job_type === "CCTP_INBOUND_AFTER_USER_BURN") {
    // FIX6: validate the USER's burn, then COMPLETE the Stellar side.
    const { validateInboundBurnTx, runPostUserBurnCctpInbound } = await import("@shade/cctp");
    await queue.setStatus(job.job_id, "validating_burn", "verify user burn tx");
    const burnTxHash = String(p.burn_tx_hash);
    const v = await validateInboundBurnTx(env, {
      burnTxHash, expectedSender: String(p.source_wallet_address), expectedAmount6: BigInt(String(p.expected_amount6)),
      pool, expectedMaxFee6: p.expected_max_fee6 ? BigInt(String(p.expected_max_fee6)) : undefined,
      expectedFinality: p.expected_finality !== undefined ? Number(p.expected_finality) : undefined
    });
    await queue.setStatus(job.job_id, "burn_validated", `sender ${v.sender.slice(0, 10)}…, ${v.amount6} (6dp)`);

    // The note opening (coin) is needed to build the DepositNoteMint proof. Gated:
    // in the app flow this arrives via the prover path; for dev/test a coinPath is
    // supplied. Without it we stop at burn_validated rather than fabricating data.
    if (!p.coinPath) {
      await queue.setStatus(job.job_id, "awaiting_proof_witness", "burn validated; note witness not provided to relayer (prover path)");
      return { validated: true, burnTxHash, sender: v.sender, amount6: v.amount6.toString(), state: "burn_validated", note: "supply coin witness via prover path to complete mint/forward/register" };
    }
    await queue.setStatus(job.job_id, "completing_stellar_side", "attestation + mint_forward + proof + register");
    const r = await runPostUserBurnCctpInbound(env, {
      burnTxHash, pool, amount6: v.amount6, commitmentHex: String(p.commitment), encryptedNotePayloadHashHex: String(p.encryptedNotePayloadHashHex),
      policyIdHex: String(p.policyIdHex), newRootHex: String(p.newRootHex), coin: coinFromPath(String(p.coinPath)), scratch: process.env.SHADE_SCRATCH_DIR
    });
    await queue.setStatus(job.job_id, "note_registered", `leaf ${r.leafIndex}`);
    return {
      state: "active", burnTxHash: r.burnTxHash, mintForwardTxHash: r.mintForwardTxHash,
      receiveDepositTxHash: r.receiveDepositTxHash, root: r.root, leafIndex: r.leafIndex, commitment: String(p.commitment), amount7: r.amount7
    };
  }

  throw new Error(`unknown relayer job type ${job.job_type}`);
}

export async function runRelayerOnce(queue: JobQueue): Promise<boolean> {
  const job = await queue.claimNext("relayer", [...RELAYER_JOB_TYPES]);
  if (!job) return false;
  try {
    const result = await processRelayerJob(queue, job);
    await queue.complete(job.job_id, result, "ready");
  } catch (e) {
    await queue.fail(job.job_id, (e as Error).message);
  }
  return true;
}

export async function runRelayerLoop(queue: JobQueue, intervalMs = 3000): Promise<void> {
  for (;;) {
    const did = await runRelayerOnce(queue);
    if (!did) await new Promise((r) => setTimeout(r, intervalMs));
  }
}
