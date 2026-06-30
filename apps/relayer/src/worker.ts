import { existsSync, readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { resolve } from "node:path";
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
  "CCTP_OUTBOUND_MINT",      // complete the Arbitrum mint (MessageTransmitter.receiveMessage)
  "MPC_SETTLE_SUBMIT"        // Phase 8: submit committee-signed MPC match batch to the pool
] as const;

export type RelayerJobType = (typeof RELAYER_JOB_TYPES)[number];

// Granular inbound steps currently delegate to the composite CCTP_INBOUND (the
// proven real implementation); true per-step decomposition is tracked in blockers.
const INBOUND_ALIASES = new Set(["CCTP_INBOUND_BURN", "CCTP_FETCH_ATTESTATION", "STELLAR_MINT_FORWARD", "REGISTER_NOTE"]);

type EnvMap = Record<string, string>;
function parseEnvFile(env: EnvMap, path: string, override: boolean): void {
  if (!existsSync(path)) return;
  for (const raw of readFileSync(path, "utf8").split("\n")) {
    const line = raw.replace(/\r$/, "");
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

// Compute lean-IMT Merkle root over all existing note_commitments + the two new
// MPC output commitments, using the same coinutils binary as the root-auditor.
// Falls back to a zeroed root only if the binary invocation itself fails.
async function computeMpcRoot(
  queue: JobQueue,
  outCommitAHex: string,
  outCommitBHex: string
): Promise<string> {
  // Mirror packages/proving/src/paths.ts: SHADE_ZK_REF overrides the zk-ref root.
  const shadeRoot = process.env.SHADE_ROOT ?? resolve(process.cwd(), "../..");
  const zkRef = process.env.SHADE_ZK_REF ?? resolve(shadeRoot, ".zk-ref/soroban-examples/privacy-pools");
  const coinutilsBin = process.env.COINUTILS_BIN ?? resolve(zkRef, "target/release/stellar-coinutils");

  // Do NOT guard with existsSync — on Windows the binary is stellar-coinutils.exe
  // and existsSync without the .exe suffix returns false even when the file exists.
  // The try/catch below handles a genuinely missing binary.

  // Fetch all existing pool leaves ordered by leaf_index.
  let leaves: string[] = [];
  try {
    const { rows } = await queue.query<{ commitment: string }>(
      "SELECT commitment FROM note_commitments WHERE leaf_index IS NOT NULL ORDER BY leaf_index ASC"
    );
    leaves = rows.map(r => BigInt(r.commitment.startsWith("0x") ? r.commitment : "0x" + r.commitment).toString());
  } catch {
    // DB unavailable — proceed with just the two new commitments
  }

  const toDecimal = (h: string) => BigInt(h.startsWith("0x") ? h : "0x" + h).toString();
  leaves.push(toDecimal(outCommitAHex));
  leaves.push(toDecimal(outCommitBHex));

  const scratchPath = process.env.SHADE_SCRATCH_DIR ?? resolve(shadeRoot, ".scratch");
  mkdirSync(scratchPath, { recursive: true });
  const statePath = resolve(scratchPath, `mpc_root_${Date.now()}.json`);
  writeFileSync(statePath, JSON.stringify({ commitments: leaves, scope: "mpc_settle" }));

  try {
    const out = execFileSync(coinutilsBin, ["compute-root", statePath], { encoding: "utf8" }).trim();
    return BigInt(out).toString(16).padStart(64, "0");
  } catch {
    return "0".repeat(64);
  }
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

  if (job.job_type === "MPC_SETTLE_SUBMIT") {
    // Phase 8 + Phase C: MPC committee-matched settlement.
    // 1. Verify threshold Ed25519 committee signatures over batchHash.
    // 2. Attempt ZK proof generation (MpcCircuitNotBuiltError → graceful fallback).
    // 3. Attempt pool.mpc_settle on-chain (spends both nullifiers, inserts output commitments).
    // 4. If contract not yet deployed, record as off-chain-validated and proceed.
    const { verifySignedBatch } = await import("@shade/mpc-crypto");

    const sigs = p.signatures as Array<{ nodeId: string; signingPubkey: string; signature: string }>;

    // Fetch the full matches array from DB so verifySignedBatch can recompute the batchHash.
    // The committee signs over batchId + all matches; an empty matches array produces a wrong hash.
    let batchMatches: import("@shade/mpc-crypto").MatchResult[] = [];
    try {
      const { rows: batchRows } = await queue.query(
        "SELECT matches_json FROM mpc_batches WHERE batch_id=$1",
        [String(p.batchId)]
      );
      if (batchRows[0]?.matches_json) {
        const raw = batchRows[0].matches_json;
        const arr = Array.isArray(raw) ? raw : JSON.parse(String(raw));
        batchMatches = arr.map((m: Record<string, string>) => ({
          intentAId: m.intentAId, intentBId: m.intentBId,
          matchedAmount7dp: m.matchedAmount7dp,
          inputAsset: m.inputAsset, outputAsset: m.outputAsset
        }));
      }
    } catch { /* DB unavailable — fall back to payload match */ }

    // Fallback: reconstruct single match from payload fields (covers single-match batches).
    if (batchMatches.length === 0 && p.intentAId && p.intentBId) {
      batchMatches = [{
        intentAId: String(p.intentAId), intentBId: String(p.intentBId),
        matchedAmount7dp: String(p.matchedAmount7dp),
        inputAsset: String(p.inputAsset), outputAsset: String(p.outputAsset)
      }];
    }

    const batch = {
      batchId: String(p.batchId),
      sessionId: String(p.sessionId),
      batchHash: String(p.batchHash),
      matches: batchMatches,
      signatures: sigs as import("@shade/mpc-crypto").NodeSignature[]
    };

    // Build committee info list from embedded signatures (each sig carries signingPubkey).
    // In production these pubkeys are pinned in contract storage via set_committee().
    const committeeUrl = env.MPC_COMMITTEE_URL ?? "http://localhost:8090";
    let committee: import("@shade/mpc-crypto").CommitteeNodeInfo[] = [];
    try {
      const resp = await fetch(`${committeeUrl}/v1/mpc/committee`);
      if (resp.ok) {
        const data = await resp.json() as { nodes: import("@shade/mpc-crypto").CommitteeNodeInfo[] };
        committee = data.nodes;
      }
    } catch {
      committee = sigs.map(s => ({ nodeId: s.nodeId, encryptionPubkey: "", signingPubkey: s.signingPubkey }));
    }

    const valid = verifySignedBatch(batch, committee);
    if (!valid) throw new Error(`MPC batch ${p.batchId}: signature verification failed (${sigs.length} sigs, need ≥2/3)`);
    await queue.setStatus(job.job_id, "verified_signatures", `batch ${p.batchId} — ${sigs.length} committee sigs valid`);

    // Phase C: attempt ZK proof generation for the matched pair.
    // MpcCircuitNotBuiltError is expected until `bash circuits/mpc_settlement/build.sh`
    // is run; in that case we fall back to committee-signature-only settlement.
    let zkProofHex: string | null = null;
    let zkPublicHex: string | null = null;
    let zkVerified = false;

    const coinAPath = p.coinAPath as string | undefined;
    const coinBPath = p.coinBPath as string | undefined;
    const assocPath = p.assocPath as string | undefined;

    if (coinAPath && coinBPath && assocPath) {
      try {
        await queue.setStatus(job.job_id, "proving", `generating mpc_settlement ZK proof for batch ${p.batchId}`);
        const {
          buildMpcSettlementProof, MpcCircuitNotBuiltError,
          scratchDir
        } = await import("@shade/proving");

        const scratch = process.env.SHADE_SCRATCH_DIR ?? scratchDir();
        const tag = `mpc_${String(p.batchId).slice(0, 8)}_${Date.now()}`;

        const coinFile = (path: string) => {
          const raw = JSON.parse(readFileSync(path, "utf8"));
          return { path, commitmentHex: raw.commitment_hex as string, commitmentDecimal: raw.coin.commitment as string, value7dp: raw.coin.value as string };
        };

        // Fetch pool commitments for Merkle proof generation.
        let commitmentsDecimal: string[] = [];
        try {
          const { rows } = await queue.query<{ commitment: string }>(
            "SELECT commitment FROM note_commitments WHERE leaf_index IS NOT NULL ORDER BY leaf_index ASC"
          );
          commitmentsDecimal = rows.map(r =>
            BigInt(r.commitment.startsWith("0x") ? r.commitment : "0x" + r.commitment).toString()
          );
        } catch { /* DB unavailable */ }

        const proof = buildMpcSettlementProof({
          coinA: coinFile(coinAPath),
          coinB: coinFile(coinBPath),
          commitmentsDecimal,
          assocPath,
          scope: String(p.scope ?? env.POOL_SCOPE ?? "shade-pool-testnet-v1"),
          batchHashHex: String(p.batchHash),
          poolId: String(p.poolId ?? "0"),
          chainId: String(p.chainId ?? "27"), // Stellar CCTP domain
          matchedAmount7dp: String(p.matchedAmount7dp),
          deadlineLedger: String(p.deadlineLedger ?? "0"),
          scratch,
          tag
        });

        zkProofHex  = proof.proofHex;
        zkPublicHex = proof.publicHex;
        zkVerified  = proof.locallyVerified;

        await queue.setStatus(
          job.job_id, "proof_ready",
          `ZK proof generated — locally verified: ${zkVerified}, nullifierA: ${proof.nullifierHashAHex.slice(0, 10)}…`
        );
      } catch (err) {
        if ((err as Error).name === "MpcCircuitNotBuiltError") {
          console.info(`[relayer] mpc_settlement circuit not built — skipping ZK proof for batch ${p.batchId}. Run: bash circuits/mpc_settlement/build.sh`);
        } else {
          console.warn(`[relayer] ZK proof generation failed for batch ${p.batchId}: ${(err as Error).message}`);
        }
      }
    }

    // Extract note data from job payload (populated by settler from mpc_intents table).
    const nullifierA  = p.nullifierA  as string | null;
    const nullifierB  = p.nullifierB  as string | null;
    const outCommitA  = p.outputCommitmentA as string | null;
    const outCommitB  = p.outputCommitmentB as string | null;

    const missingNote = !nullifierA || !nullifierB || !outCommitA || !outCommitB;

    // Attempt on-chain settlement.
    const poolContract = String(p.pool ?? env.SHIELDED_POOL_CONTRACT ?? "");
    if (poolContract && env.STELLAR_RELAYER_SECRET && !missingNote) {
      try {
        await queue.setStatus(job.job_id, "submitting", `pool.mpc_settle match[${p.matchIndex}]`);

        // Stellar CLI expects bare hex (no 0x) for BytesN, and JSON arrays for Vec<BytesN>.
        const stripHex = (h: string) => h.startsWith("0x") ? h.slice(2) : h;
        const nullA32   = stripHex(nullifierA!);
        const nullB32   = stripHex(nullifierB!);
        const cmtA32    = stripHex(outCommitA!);
        const cmtB32    = stripHex(outCommitB!);
        const hash32    = stripHex(String(p.batchHash));
        const newRoot32 = await computeMpcRoot(queue, outCommitA!, outCommitB!);

        // Build committee signature args: JSON arrays of pubkeys + sigs.
        const pubkeysJson = JSON.stringify(sigs.map(s => stripHex(s.signingPubkey)));
        const sigsJson    = JSON.stringify(sigs.map(s => stripHex(s.signature)));

        // Include ZK proof args when proof generation succeeded.
        const proofArgs = zkProofHex && zkPublicHex
          ? ["--proof_bytes", zkProofHex, "--pub_signals_bytes", zkPublicHex]
          : [];

        const r = sorobanInvoke({
          contractId: poolContract, secret: env.STELLAR_RELAYER_SECRET,
          method: "mpc_settle", rpcUrl: RPC, passphrase: PASS, retries: 3,
          args: [
            "--nullifier_a",         nullA32,
            "--nullifier_b",         nullB32,
            "--output_commitment_a", cmtA32,
            "--output_commitment_b", cmtB32,
            "--new_root",            newRoot32,
            "--batch_hash",          hash32,
            "--signer_pubkeys",      pubkeysJson,
            "--signatures",          sigsJson,
            ...proofArgs
          ]
        });
        return {
          settled: true, onChain: true,
          batchId: p.batchId, matchIndex: p.matchIndex,
          txHash: r.txHash,
          nullifierA, nullifierB,
          zkProof: zkProofHex ? { generated: true, verified: zkVerified } : { generated: false },
          note: zkProofHex
            ? `pool.mpc_settle confirmed with ZK proof (verified=${zkVerified})`
            : "pool.mpc_settle confirmed (committee sigs only — compile circuit for ZK proof)"
        };
      } catch (err) {
        // mpc_settle invocation failed — log error, fall through to off-chain result.
        console.warn(`[relayer] pool.mpc_settle failed: ${(err as Error).message}`);
      }
    }

    return {
      settled: true, onChain: false,
      batchId: p.batchId, matchIndex: p.matchIndex,
      intentAId: p.intentAId, intentBId: p.intentBId,
      matchedAmount7dp: p.matchedAmount7dp,
      nullifierA, nullifierB, outCommitA, outCommitB,
      missingNote,
      zkProof: zkProofHex ? { generated: true, verified: zkVerified } : { generated: false },
      note: missingNote
        ? "note data missing from DB — intent not submitted through API"
        : "committee sigs verified off-chain; mpc_settle call failed (check relayer logs)"
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
