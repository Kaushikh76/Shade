import { appendFileSync, existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { execSync } from "node:child_process";
import { randomUUID } from "node:crypto";

export type CheckResult = {
  name: string;
  ok: boolean;
  detail: string;
};

// P1.11: the canonical report is regenerated fresh per run (no stale FAIL
// accumulation). The previous report is archived under docs/reports/<ts>.md.
const GENERATED = process.env.SHADE_REPORT_FILE ?? "docs/test-report.generated.md";
const ARCHIVE_DIR = "docs/reports";

let startedThisProcess = false;

function gitCommit(): string {
  try { return execSync("git rev-parse --short HEAD", { encoding: "utf8" }).trim(); } catch { return "unknown"; }
}

// Read contract IDs from .env.generated for the report fingerprint (no secrets).
function contractFingerprint(): string[] {
  if (!existsSync(".env.generated")) return [];
  const lines: string[] = [];
  for (const raw of readFileSync(".env.generated", "utf8").split("\n")) {
    const line = raw.replace(/\r$/, "");
    const m = line.match(/^([A-Z0-9_]*(CONTRACT|POOL|VERIFIER|REGISTRY|SAC|FORWARDER|MESSENGER))=([A-Z0-9]{56})$/);
    if (m) lines.push(`  - ${m[1]}: ${m[3]}`);
  }
  return lines;
}

function timestampSlug(): string {
  // YYYY-MM-DD-HHMMSS (UTC)
  return new Date().toISOString().replace(/T/, "-").replace(/:/g, "").replace(/\..+$/, "");
}

// Start a fresh report: archive any previous generated report, then write a header
// with run_id, git commit, env fingerprint, contract IDs, and timestamp.
export function beginReport(meta?: { runId?: string; title?: string }): string {
  mkdirSync(ARCHIVE_DIR, { recursive: true });
  if (existsSync(GENERATED)) {
    renameSync(GENERATED, `${ARCHIVE_DIR}/${timestampSlug()}.md`);
  }
  const runId = meta?.runId ?? process.env.SHADE_REPORT_RUN_ID ?? randomUUID();
  const header = [
    `# Shade Test Report (generated)`,
    "",
    `- run_id: ${runId}`,
    `- git_commit: ${gitCommit()}`,
    `- timestamp: ${new Date().toISOString()}`,
    `- node: ${process.version}`,
    `- network: ${process.env.STELLAR_NETWORK_PASSPHRASE ?? "Test SDF Network ; September 2015"}`,
    `- contracts:`,
    ...contractFingerprint(),
    ""
  ];
  writeFileSync(GENERATED, `${header.join("\n")}\n`, { mode: 0o644 });
  startedThisProcess = true;
  return runId;
}

// Ensure the generated report exists and is fresh for this run. Standalone scripts
// reset on first write; children spawned by e2e-all (SHADE_REPORT_RUN_ID set) append
// to the report the parent already started.
function ensureStarted(): void {
  if (startedThisProcess) return;
  if (process.env.SHADE_REPORT_RUN_ID && existsSync(GENERATED)) {
    startedThisProcess = true;
    return;
  }
  beginReport();
}

export async function writeCheckReport(title: string, results: CheckResult[]): Promise<void> {
  ensureStarted();
  const lines = ["", `## ${title}`, "", ...results.map((r) => `- ${r.name}: ${r.ok ? "PASS" : "FAIL"} - ${r.detail}`)];
  appendFileSync(GENERATED, `${lines.join("\n")}\n`);
}

export function failIfAny(results: CheckResult[]): void {
  const failed = results.filter((result) => !result.ok);
  if (failed.length) {
    throw new Error(failed.map((result) => `${result.name}: ${result.detail}`).join("\n"));
  }
}
