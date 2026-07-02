import { spawnSync } from "node:child_process";
import { appendFileSync } from "node:fs";
import { randomUUID } from "node:crypto";
import { beginReport } from "./lib/report.js";

// `npm run e2e:testnet:all` — the single reproducible testnet acceptance command
// required by shade_testnet_e2e_agent_build_spec.md §0.7 / §12.
//
// It executes the full functional + adversarial scenario matrix from spec §12.2
// and §12.3. Scenarios whose implementation is not yet complete are reported with
// an explicit NOT_IMPLEMENTED code (spec §4.5) rather than silently passing — the
// command fails with a clear incomplete-task list until every required scenario
// is green. There is NO mock-success fallback (spec §0.3).

type Status = "PASS" | "FAIL" | "NOT_IMPLEMENTED" | "SKIPPED_NO_TESTNET";

type Scenario = {
  id: string;
  phase: string;
  name: string;
  kind: "functional" | "adversarial";
  // `command` is the npm script that proves this scenario on testnet. When null,
  // the scenario is not yet implemented and is reported NOT_IMPLEMENTED.
  command: string | null;
  optional?: boolean; // e.g. MPC priced cross-asset (spec §12.2.9)
};

// Whether real testnet credentials/contracts are configured. Without them the
// on-chain scenarios cannot assert real state and are SKIPPED_NO_TESTNET (a
// distinct, honest status — not a pass).
const TESTNET_READY = Boolean(
  process.env.SHADE_TESTNET_READY === "true" ||
    (process.env.STELLAR_RPC_URL && process.env.SHIELDED_POOL_CONTRACT_ID)
);

// Scenario matrix. `command: null` == not yet implemented. As each phase lands,
// wire the command that asserts real testnet state.
const SCENARIOS: Scenario[] = [
  // ---- Functional (spec §12.2) ----
  { id: "F1", phase: "4", name: "CCTP inbound -> private USDC note", kind: "functional", command: null },
  { id: "F2", phase: "2", name: "private USDC note -> public Stellar USDC withdraw", kind: "functional", command: null },
  { id: "F3", phase: "3", name: "RFQ USDC->XLM public XLM >= min_output", kind: "functional", command: null },
  { id: "F4", phase: "5", name: "MPC same-asset: two USDC notes -> two USDC output notes", kind: "functional", command: null },
  { id: "F5", phase: "4", name: "CCTP exit to destination", kind: "functional", command: null },
  { id: "F6", phase: "7", name: "Remit simulated INR quote -> receipt", kind: "functional", command: null },
  { id: "F7", phase: "7", name: "Shade View report verifies against F1-F4", kind: "functional", command: null },
  { id: "F8", phase: "7", name: "Recovery: wipe client -> recover notes", kind: "functional", command: null },
  { id: "F9", phase: "6", name: "MPC priced cross-asset USDC<->XLM", kind: "functional", command: null },

  // ---- Adversarial (spec §12.3) ----
  { id: "A1", phase: "4", name: "duplicate CCTP nonce -> no second note", kind: "adversarial", command: null },
  { id: "A2", phase: "3", name: "expired quote -> rejected", kind: "adversarial", command: null },
  { id: "A3", phase: "4", name: "relayer changes destination -> rejected", kind: "adversarial", command: null },
  { id: "A4", phase: "3", name: "relayer changes amount -> rejected", kind: "adversarial", command: null },
  { id: "A5", phase: "2", name: "relayer changes asset -> rejected", kind: "adversarial", command: null },
  { id: "A6", phase: "3", name: "solver changes fee after signing -> rejected", kind: "adversarial", command: null },
  { id: "A7", phase: "1", name: "wrong ASP root -> rejected", kind: "adversarial", command: null },
  { id: "A8", phase: "7", name: "denied compliance label -> rejected", kind: "adversarial", command: null },
  { id: "A9", phase: "8", name: "forged tree root -> rejected", kind: "adversarial", command: null },
  { id: "A10", phase: "5", name: "duplicate committee signer -> rejected", kind: "adversarial", command: null },
  { id: "A11", phase: "5", name: "threshold-1 committee -> rejected", kind: "adversarial", command: null },
  { id: "A12", phase: "1", name: "missing MPC proof -> rejected", kind: "adversarial", command: null },
  { id: "A13", phase: "1", name: "MPC verifier unset -> rejected", kind: "adversarial", command: null },
  { id: "A14", phase: "5", name: "wrong batch hash -> rejected", kind: "adversarial", command: null },
  { id: "A15", phase: "5", name: "wrong output commitment -> rejected", kind: "adversarial", command: null },
  { id: "A16", phase: "2", name: "wrong asset ID -> rejected", kind: "adversarial", command: null },
  { id: "A17", phase: "2", name: "double spend nullifier -> rejected", kind: "adversarial", command: null }
];

function runScenario(s: Scenario): { status: Status; detail: string } {
  if (s.command === null) {
    return { status: "NOT_IMPLEMENTED", detail: `implement in Phase ${s.phase}` };
  }
  if (!TESTNET_READY) {
    return {
      status: "SKIPPED_NO_TESTNET",
      detail: "set SHADE_TESTNET_READY=true with deployed contracts + funded keys"
    };
  }
  const result = spawnSync("npm", ["run", s.command], { encoding: "utf8", stdio: "pipe", env: process.env });
  process.stdout.write(result.stdout ?? "");
  process.stderr.write(result.stderr ?? "");
  return result.status === 0
    ? { status: "PASS", detail: "ok" }
    : { status: "FAIL", detail: `exit ${result.status}` };
}

const runId = randomUUID();
beginReport({ runId });

const rows: string[] = [];
let hardFail = false;
let notImplemented = 0;
let skipped = 0;

console.log("Shade testnet E2E acceptance — spec §12\n");
for (const s of SCENARIOS) {
  const { status, detail } = runScenario(s);
  const tag = s.optional ? " (optional)" : "";
  rows.push(`| ${s.id} | ${s.kind} | ${s.name}${tag} | ${status} | ${detail} |`);
  console.log(`[${status}] ${s.id} ${s.name}${tag} — ${detail}`);
  if (status === "FAIL") hardFail = true;
  if (status === "NOT_IMPLEMENTED" && !s.optional) notImplemented++;
  if (status === "SKIPPED_NO_TESTNET") skipped++;
}


const summary = [
  "",
  "## Testnet E2E Acceptance Matrix",
  "",
  "| ID | Kind | Scenario | Status | Detail |",
  "| -- | ---- | -------- | ------ | ------ |",
  ...rows,
  "",
  `Required not-implemented: ${notImplemented}, skipped (no testnet): ${skipped}, hard failures: ${hardFail ? "yes" : "no"}`
].join("\n");

const reportFile = process.env.SHADE_REPORT_FILE ?? "docs/test-report.generated.md";
appendFileSync(reportFile, `\n${summary}\n`);
console.log(summary);

// Exit non-zero unless EVERY required scenario is PASS. Until all phases land,
// this fails with a clear incomplete list (spec §4.5). SKIPPED_NO_TESTNET also
// fails the gate — the acceptance suite must assert real testnet state.
if (hardFail || notImplemented > 0 || skipped > 0) {
  const reasons: string[] = [];
  if (hardFail) reasons.push("scenario failures");
  if (notImplemented > 0) reasons.push(`${notImplemented} required scenario(s) not implemented`);
  if (skipped > 0) reasons.push(`${skipped} scenario(s) skipped (no testnet config)`);
  console.error(`\nE2E TESTNET ACCEPTANCE NOT COMPLETE: ${reasons.join("; ")}`);
  process.exit(1);
}

console.log("\nE2E TESTNET ACCEPTANCE COMPLETE: all required scenarios passed.");
