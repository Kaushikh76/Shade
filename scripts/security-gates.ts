import { execSync } from "node:child_process";

// audit.md PHASE 12 static security gates. Fails the build if any forbidden
// pattern is present. Each gate is a grep; a non-empty result (after allowed
// exclusions) is a failure.

type Gate = { name: string; cmd: string; allow?: RegExp };
const ROOT = process.env.SHADE_ROOT ?? process.cwd();

// On Windows, cmd.exe lacks grep/awk; use bash (available via Git for Windows).
const SHELL = process.platform === "win32" ? "bash" : "/bin/sh";
function run(cmd: string): string[] {
  try { return execSync(cmd, { cwd: ROOT, encoding: "utf8", shell: SHELL }).split("\n").filter(Boolean); }
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
  },
  // FIX11 audit2: deeper behavioral gates.
  {
    name: "deposit page has NO paste-burn-hash prompt",
    // match real prompt() calls, not the word in a // comment
    cmd: `grep -rn 'prompt(' apps/web/src/app/deposit/page.tsx | grep -v '^[^:]*:[0-9]*://' || true`
  },
  {
    name: "deposit page sends wallet transactions (sendTransaction)",
    cmd: `grep -rln "sendTransaction" apps/web/src/app/deposit/page.tsx | grep -q . && echo "" || echo MISSING_SENDTX`,
    // MATCH of MISSING_SENDTX means failure
  },
  {
    name: "restore page fetches envelope + decrypts",
    cmd: `( grep -q "getVault" apps/web/src/app/restore/page.tsx && grep -q "decryptEnvelope" apps/web/src/app/restore/page.tsx ) && echo "" || echo RESTORE_INCOMPLETE`
  },
  {
    name: "relayer CCTP_INBOUND_AFTER_USER_BURN is not a placeholder",
    cmd: `grep -q "runPostUserBurnCctpInbound" apps/relayer/src/worker.ts && echo "" || echo RELAYER_PLACEHOLDER`
  },
  {
    name: "frontend does NOT use local id as privy_user_id",
    cmd: `grep -rn 'privyUserId = .*\\.id ?? "me"\\|privyUserId = .*as { id' apps/web/src/app/vault/page.tsx || true`
  },
  {
    name: "verify-backup requires a verification body (schema)",
    cmd: `grep -q "verifyBackupSchema.parse" apps/api/src/routes.ts && echo "" || echo VERIFY_NO_SCHEMA`
  },
  {
    // FIX10/FIX11: blockers.md must not BOTH claim Phase-2 DONE and list the same
    // work as remaining/in-progress. We allow the historical "P0 FIXES APPLIED"
    // heading but forbid a bare "PRODUCT wallet architecture ... — DONE".
    name: "docs: no Phase-2 DONE/remaining contradiction",
    cmd: `grep -n "wallet architecture.*— DONE\\b" docs/blockers.md || true`
  },
  // audit3 PART13 gates.
  {
    name: "vault page is not password-first (no prompt before securing)",
    // the only prompt() allowed is inside the Advanced password handler; the default
    // createVault path must not call prompt(). Fail if prompt appears before the
    // "Advanced" marker line.
    cmd: `awk '/async function addPasswordRecovery/{adv=1} /\\bprompt\\(/ && !adv && $0 !~ /^[[:space:]]*\\/\\// {print FILENAME":"NR": "$0}' apps/web/src/app/vault/page.tsx || true`
  },
  {
    name: "deposit page has NO manual vault id input",
    cmd: `grep -rni 'verified vault id\\|placeholder="vault-' apps/web/src/app/deposit/page.tsx || true`
  },
  {
    name: "no additionalData: bs(aad) pattern (the AES-GCM crash)",
    cmd: `grep -rn 'additionalData: bs(aad)' packages/note-vault/src/index.ts || true`
  },
  {
    name: "UI does not show raw CCTP_INBOUND_AFTER_USER_BURN as primary text",
    // allowed in non-display contexts; forbid it appearing in JSX text of web pages.
    cmd: `grep -rn 'CCTP_INBOUND_AFTER_USER_BURN' apps/web/src/app 2>/dev/null || true`
  },
  // Phase 1 B1/B2 fail-closed gates (spec §5.1, §5.2).
  {
    // FORBID the fail-open pattern: mpc_settle must not gate proof verification
    // on `if let Some(mpc_verifier)`, which skips verification when unset.
    name: "mpc_settle proof mandatory: no if-let-Some(mpc_verifier) fail-open (B1)",
    cmd: `grep -n "if let Some(mpc_verifier)" contracts/stellar/shielded_pool/src/lib.rs || true`
  },
  {
    // REQUIRE the relayer to refuse a proofless mpc_settle submission.
    name: "relayer refuses proofless mpc_settle (B1)",
    cmd: `grep -q "refusing to submit proofless mpc_settle" apps/relayer/src/worker.ts && echo "" || echo RELAYER_PROOFLESS_MISSING`
  },
  {
    // REQUIRE mpc_settle to bind the canonical association root and the deadline.
    name: "mpc_settle binds canonical association root + deadline (B2)",
    cmd: `( grep -q "canonical_assoc" contracts/stellar/shielded_pool/src/lib.rs && grep -q "deadline_ledger" contracts/stellar/shielded_pool/src/lib.rs ) && echo "" || echo MPC_B2_BINDING_MISSING`
  }
];

// Sentinels that, if present in output, mean the REQUIRED condition is missing.
const FAILURE_SENTINELS = ["MISSING_GATE", "MISSING_SENDTX", "RESTORE_INCOMPLETE", "RELAYER_PLACEHOLDER", "VERIFY_NO_SCHEMA"];

let failed = 0;
for (const g of gates) {
  const lines = run(g.cmd).filter((l) => !(g.allow && g.allow.test(l)));
  if (g.name.includes("operator-driven deposit is gated")) {
    const ok = lines.some((l) => l.includes("ENABLE_OPERATOR_TESTNET_DEPOSIT")) && !lines.includes("MISSING_GATE");
    console.log(`${ok ? "PASS" : "FAIL"}  ${g.name}`); if (!ok) failed++; continue;
  }
  // "presence-required" gates emit a sentinel when the required code is absent.
  const sentinelHit = lines.some((l) => FAILURE_SENTINELS.includes(l.trim()));
  // "forbidden-pattern" gates fail when any (non-sentinel, non-empty) line remains.
  const forbiddenHit = lines.some((l) => l.trim() && !FAILURE_SENTINELS.includes(l.trim()));
  const ok = !sentinelHit && !forbiddenHit;
  console.log(`${ok ? "PASS" : "FAIL"}  ${g.name}${ok ? "" : "\n  " + lines.slice(0, 5).join("\n  ")}`);
  if (!ok) failed++;
}

if (failed) { console.error(`\nSECURITY GATES FAILED: ${failed}`); process.exit(1); }
console.log("\nSECURITY GATES PASS");
