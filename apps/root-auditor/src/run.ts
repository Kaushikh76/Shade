import { execSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import pg from "pg";
import { sorobanInvoke } from "@shade/stellar-utils";
import { type AuditResult, type DepositLeaf, readDepositLeavesFromEvents, compareRoots } from "./audit.js";

type EnvMap = Record<string, string>;

// Self-contained env loader (mirrors apps/cli/src/lib/env.ts): process.env plus
// any key=value lines from .env.generated (contract IDs + operator secrets).
function loadRuntimeEnv(): EnvMap {
  const env: EnvMap = { ...process.env } as EnvMap;
  if (existsSync(".env.generated")) {
    for (const raw of readFileSync(".env.generated", "utf8").split("\n")) {
      const line = raw.replace(/\r$/, "");
      if (!line.includes("=") || line.trimStart().startsWith("#")) continue;
      const i = line.indexOf("=");
      env[line.slice(0, i)] = line.slice(i + 1);
    }
  }
  return env;
}
function requireKeys(env: EnvMap, keys: string[]): string[] {
  return keys.filter((k) => !env[k]);
}

// Read the pool's current on-chain root (the value the registrar submitted).
function readOnchainRoot(pool: string, secret: string, rpc: string, pass: string): string {
  const res = sorobanInvoke({ contractId: pool, secret, method: "get_root", rpcUrl: rpc, passphrase: pass, readOnly: true });
  const raw = res.returnValue.replace(/"/g, "").trim();
  return raw.startsWith("0x") ? raw : "0x" + raw;
}

// Fallback commitment source: the registrar's own DB record (note_commitments).
// Used only if event lookback returns nothing (e.g. events aged out of retention).
async function readLeavesFromDb(databaseUrl: string): Promise<DepositLeaf[]> {
  const db = new pg.Pool({ connectionString: databaseUrl });
  try {
    const { rows } = await db.query<{ commitment: string; leaf_index: string }>(
      "select commitment, leaf_index from note_commitments where leaf_index is not null order by leaf_index asc"
    );
    return rows.map((r) => {
      const hex = r.commitment.startsWith("0x") ? r.commitment : "0x" + r.commitment;
      return { leafIndex: Number(r.leaf_index), commitmentHex: hex, commitmentDecimal: BigInt(hex).toString() };
    });
  } finally {
    await db.end();
  }
}

function gitCommit(): string {
  try { return execSync("git rev-parse --short HEAD", { encoding: "utf8" }).trim(); } catch { return "unknown"; }
}

async function persist(env: EnvMap, result: AuditResult): Promise<void> {
  if (!env.DATABASE_URL) return;
  const db = new pg.Pool({ connectionString: env.DATABASE_URL });
  try {
    const { rows } = await db.query<{ run_id: string }>(
      `insert into root_audit_runs(pool_contract, leaf_count, recomputed_root, onchain_root, source, status, git_commit)
       values ($1,$2,$3,$4,$5,$6,$7) returning run_id`,
      [result.poolContract, result.leafCount, result.recomputedRootHex, result.onchainRootHex, result.source, result.status, gitCommit()]
    );
    if (result.status !== "OK") {
      await db.query(
        `insert into root_audit_findings(run_id, severity, code, detail, recomputed_root, onchain_root)
         values ($1,'CRITICAL','ROOT_MISMATCH_CRITICAL',$2,$3,$4)`,
        [rows[0].run_id, result.detail, result.recomputedRootHex, result.onchainRootHex]
      );
    }
  } finally {
    await db.end();
  }
}

// Run one audit pass against the configured ShadePool and persist the result.
export async function runAudit(envOverride?: EnvMap): Promise<AuditResult> {
  const env = envOverride ?? loadRuntimeEnv();
  const missing = requireKeys(env, ["SHIELDED_POOL_CONTRACT", "STELLAR_RELAYER_SECRET"]);
  if (missing.length) throw new Error(`root-auditor missing env: ${missing.join(", ")}`);
  const pool = env.SHIELDED_POOL_CONTRACT;
  const rpc = env.STELLAR_RPC_URL ?? "https://soroban-testnet.stellar.org";
  const pass = env.STELLAR_NETWORK_PASSPHRASE ?? "Test SDF Network ; September 2015";

  let source: "events" | "db" = "events";
  let leaves = await readDepositLeavesFromEvents(pool, rpc);
  if (leaves.length === 0 && env.DATABASE_URL) {
    source = "db";
    leaves = await readLeavesFromDb(env.DATABASE_URL);
  }
  const onchainRoot = readOnchainRoot(pool, env.STELLAR_RELAYER_SECRET, rpc, pass);
  const result = compareRoots(pool, leaves, onchainRoot, source);
  await persist(env, result);
  return result;
}
