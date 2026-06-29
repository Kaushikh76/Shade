import { readFileSync } from "node:fs";
import { resolve } from "node:path";

// FIX12 frontend-flow test: static assertions that the web flow is real (not a
// stub). The full live browser e2e is Playwright (P1, NOT RUN here); this guards
// the source against regressing to the audited-failed states.

const ROOT = process.env.SHADE_ROOT ?? process.cwd();
const read = (p: string) => readFileSync(resolve(ROOT, p), "utf8");
const results: { name: string; ok: boolean }[] = [];
const check = (name: string, ok: boolean) => { results.push({ name, ok }); console.log(`${ok ? "PASS" : "FAIL"}  ${name}`); };

const deposit = read("apps/web/src/app/deposit/page.tsx");
const restore = read("apps/web/src/app/restore/page.tsx");
const vault = read("apps/web/src/app/vault/page.tsx");

// Deposit
// real prompt() calls only — ignore lines that are // comments
check("deposit: no prompt() burn-hash entry", !deposit.split("\n").some((l) => /\bprompt\(/.test(l) && !l.trim().startsWith("//")));
check("deposit: sends approve (encodeFunctionData approve)", /functionName:\s*"approve"/.test(deposit));
check("deposit: sends CCTP burn (depositForBurnWithHook)", /depositForBurnWithHook/.test(deposit) && /sendTransaction/.test(deposit));
check("deposit: checks allowance before approve", /functionName:\s*"allowance"/.test(deposit));
check("deposit: auto-submits burn hash to backend", /burnSubmitted\(/.test(deposit) && /burn_tx_hash:\s*burnHash/.test(deposit));
check("deposit: shows staged UI", /relayer_validating/.test(deposit) && /note_active/.test(deposit));

// Restore
check("restore: fetches envelope via getVault", /getVault\(/.test(restore));
check("restore: decrypts the envelope", /decryptEnvelope\(/.test(restore));
check("restore: does NOT index a string for envelope", !/JSON\.stringify\(await ApiClient\.getVault/.test(restore));
check("restore: clears cache + sets memory vault", /clearLocalCache\(/.test(restore) && /setMemoryVault\(/.test(restore));

// Vault
check("vault: uses Privy DID (privy_user_id), not local id", /privy_user_id/.test(vault) && !/\.id \?\? "me"/.test(vault));
check("vault: proves restore before verify-backup", /decryptEnvelope\(/.test(vault) && /verifyBackup\(/.test(vault));

const failed = results.filter((r) => !r.ok);
if (failed.length) { console.error(`\nFRONTEND-FLOW TESTS FAILED: ${failed.map((f) => f.name).join(", ")}`); process.exit(1); }
console.log("\nFRONTEND-FLOW TESTS PASS");
