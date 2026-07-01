import { matchIntents } from "./coordinator.js";

// B5.3 (spec §5.3.3): the matcher must not skip valid counterparties, and must
// never pair an intent with itself.

let failed = 0;
function check(name: string, ok: boolean, detail = ""): void {
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${detail ? " — " + detail : ""}`);
  if (!ok) failed++;
}

type Intent = { intentId: string; amount7dp: bigint; inputAsset: string; outputAsset: string };

// --- Same-asset group (Phase 5 scope): reverse group == this group, so a naive
// two-pointer can pair sorted[0] with itself and skip the valid pair. ---
{
  const intents: Intent[] = [
    { intentId: "X", amount7dp: 10_000000n, inputAsset: "USDC", outputAsset: "USDC" },
    { intentId: "Y", amount7dp: 10_000000n, inputAsset: "USDC", outputAsset: "USDC" },
    { intentId: "Z", amount7dp: 10_000000n, inputAsset: "USDC", outputAsset: "USDC" }
  ];
  const matches = matchIntents(intents);
  const selfPair = matches.some(m => m.intentAId === m.intentBId);
  check("matcher: never pairs an intent with itself", !selfPair, JSON.stringify(matches));
  check("matcher: finds the valid same-asset pair (X-Y) among 3 intents", matches.length === 1);
  if (matches.length === 1) {
    const ids = [matches[0].intentAId, matches[0].intentBId].sort();
    check("matcher: the matched pair is two DISTINCT intents", ids[0] !== ids[1], ids.join("-"));
  }
}

// --- Cross-asset complementary pair still matches, once, no duplicates. ---
{
  const intents: Intent[] = [
    { intentId: "A", amount7dp: 5_000000n, inputAsset: "USDC", outputAsset: "XLM" },
    { intentId: "B", amount7dp: 5_000000n, inputAsset: "XLM", outputAsset: "USDC" }
  ];
  const matches = matchIntents(intents);
  check("matcher: cross-asset complementary pair matches exactly once", matches.length === 1, JSON.stringify(matches));
}

// --- Non-complementary intents do not match. ---
{
  const intents: Intent[] = [
    { intentId: "A", amount7dp: 5_000000n, inputAsset: "USDC", outputAsset: "XLM" },
    { intentId: "B", amount7dp: 5_000000n, inputAsset: "USDC", outputAsset: "XLM" }
  ];
  const matches = matchIntents(intents);
  check("matcher: same-direction (non-complementary) cross-asset intents do not match", matches.length === 0);
}

if (failed > 0) {
  console.error(`\nMATCHER TESTS FAILED: ${failed} failing`);
  process.exit(1);
}
console.log("\nMATCHER TESTS PASS");
