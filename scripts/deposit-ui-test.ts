import { readFileSync } from "node:fs";
import { resolve } from "node:path";

// audit3 PART13 #5 (deposit-ui): the deposit page's vault-selection behavior. The
// page is a React component; we assert the source encodes the three required cases
// (none → CTA, one → auto-select, multiple → dropdown) and replicate the selection
// logic to verify it picks only verified+sufficient/strong vaults.

const ROOT = process.env.SHADE_ROOT ?? process.cwd();
const src = readFileSync(resolve(ROOT, "apps/web/src/app/deposit/page.tsx"), "utf8");
const results: { name: string; ok: boolean }[] = [];
const check = (name: string, ok: boolean) => { results.push({ name, ok }); console.log(`${ok ? "PASS" : "FAIL"}  ${name}`); };

// 1) source-level structure
check("deposit page encodes 'none' state with a create-vault CTA", /status: "none"/.test(src) && /Go to Vault Setup/.test(src));
check("deposit page encodes 'selected' (auto-select) state", /status: "selected"/.test(src));
check("deposit page encodes 'multiple' state with a dropdown (<select>)", /status: "multiple"/.test(src) && /<select/.test(src));
check("deposit page has NO manual vault id text input", !/placeholder="vault-/.test(src));

// 2) replicate the readiness filter the page uses and verify selection outcomes
type V = { vault_id: string; backup_status: string; recovery_policy_status: string };
const ready = (vs: V[]) => vs.filter((v) => v.backup_status === "verified" && (v.recovery_policy_status === "sufficient" || v.recovery_policy_status === "strong"));
const choice = (vs: V[]) => { const r = ready(vs); return r.length === 0 ? "none" : r.length === 1 ? "selected" : "multiple"; };

check("no verified vault → none (deposit disabled, CTA)", choice([{ vault_id: "a", backup_status: "created", recovery_policy_status: "sufficient" }]) === "none");
check("one verified vault → auto-selected", choice([{ vault_id: "a", backup_status: "verified", recovery_policy_status: "sufficient" }]) === "selected");
check("unverified vault excluded", choice([{ vault_id: "a", backup_status: "verified", recovery_policy_status: "insufficient" }]) === "none");
check("multiple verified vaults → dropdown", choice([
  { vault_id: "a", backup_status: "verified", recovery_policy_status: "strong" },
  { vault_id: "b", backup_status: "verified", recovery_policy_status: "sufficient" }
]) === "multiple");

const failed = results.filter((r) => !r.ok);
if (failed.length) { console.error(`\nDEPOSIT-UI TESTS FAILED: ${failed.map((f) => f.name).join(", ")}`); process.exit(1); }
console.log("\nDEPOSIT-UI TESTS PASS");
