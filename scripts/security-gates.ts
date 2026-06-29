import { execSync } from "node:child_process";

// audit.md PHASE 12 static security gates. Fails the build if any forbidden
// pattern is present. Each gate is a grep; a non-empty result (after allowed
// exclusions) is a failure.

type Gate = { name: string; cmd: string; allow?: RegExp };
const ROOT = process.env.SHADE_ROOT ?? process.cwd();

function run(cmd: string): string[] {
  try { return execSync(cmd, { cwd: ROOT, encoding: "utf8" }).split("\n").filter(Boolean); }
  catch { return []; } // grep exits 1 on no match
}

const gates: Gate[] = [
  {
    name: "services must not import apps/cli internals",
    cmd: `grep -rn "cli/src" apps/api/src apps/relayer/src apps/prover/src apps/solver/src apps/root-auditor/src 2>/dev/null | grep "from \\"" || true`
  },
  {
    name: "no STELLAR_USER_SECRET / toSecret in service runtime (non-test)",
    cmd: `grep -rn "STELLAR_USER_SECRET\\|toSecret" apps/api/src apps/relayer/src apps/solver/src apps/prover/src 2>/dev/null | grep -v "\\-test.ts" || true`,
    allow: /redact|never signs|removed|comment/i
  },
  {
    name: "no backend EVM user key in api/relayer user paths (non-test)",
    cmd: `grep -rn "ARB_SEPOLIA_PRIVATE_KEY\\|ETH_PRIVATE_KEY" apps/api/src apps/relayer/src 2>/dev/null | grep -v "\\-test.ts" || true`,
    allow: /\/\/|live in the repo-parent|comment/i
  },
  {
    name: "no plaintext note secret fields stored/logged in API",
    cmd: `grep -rn "owner_secret\\|spend_secret\\|note_preimage\\|vault_master_key" apps/api/src 2>/dev/null | grep -v "\\-test.ts" || true`,
    allow: /assertNoPlaintextNoteFields|PLAINTEXT_FORBIDDEN|reject|forbidden|comment|scan/i
  },
  {
    name: "operator-driven deposit is gated (ENABLE_OPERATOR_TESTNET_DEPOSIT)",
    cmd: `grep -rn "ENABLE_OPERATOR_TESTNET_DEPOSIT" apps/relayer/src/worker.ts || echo MISSING_GATE`,
    // here a MATCH is REQUIRED; invert below
  }
];

let failed = 0;
for (const g of gates) {
  const lines = run(g.cmd).filter((l) => !(g.allow && g.allow.test(l)));
  if (g.name.includes("operator-driven deposit is gated")) {
    // require the gate to be present
    const ok = lines.some((l) => l.includes("ENABLE_OPERATOR_TESTNET_DEPOSIT")) && !lines.includes("MISSING_GATE");
    console.log(`${ok ? "PASS" : "FAIL"}  ${g.name}`);
    if (!ok) failed++;
    continue;
  }
  const ok = lines.length === 0;
  console.log(`${ok ? "PASS" : "FAIL"}  ${g.name}${ok ? "" : "\n  " + lines.slice(0, 5).join("\n  ")}`);
  if (!ok) failed++;
}

if (failed) { console.error(`\nSECURITY GATES FAILED: ${failed}`); process.exit(1); }
console.log("\nSECURITY GATES PASS");
