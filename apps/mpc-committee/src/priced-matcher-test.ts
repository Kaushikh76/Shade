import { matchPricedPair, matchPricedIntents, type PricedIntent } from "./coordinator.js";
import { computeBatchHash } from "@shade/mpc-crypto";

// Phase 6 (spec §10.4/§10.6): priced cross-asset matching + batch-hash price binding.

let failed = 0;
function check(name: string, ok: boolean, detail = ""): void {
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${detail ? " — " + detail : ""}`);
  if (!ok) failed++;
}

const USDC = "usdc-asset";
const XLM = "xlm-asset";
const PRICE = 1_000_000_000n; // 1e9

// A spends 4 USDC wanting XLM at price 0.5 XLM/USDC; B spends 2 XLM wanting USDC.
const a: PricedIntent = { intentId: "A", inputAsset: USDC, outputAsset: XLM, amount: 4_000_000n, minOutput: 1_900_000n, limitPriceScaled: 500_000_000n };
const b: PricedIntent = { intentId: "B", inputAsset: XLM, outputAsset: USDC, amount: 2_000_000n, minOutput: 3_900_000n, limitPriceScaled: 2_000_000_000n }; // wants >= 2 USDC per XLM

// --- crossing pair matches with price bound ---
{
  const m = matchPricedPair(a, b);
  check("crossing priced pair matches", m !== null);
  if (m) {
    check("matchedAmountA = A's X spend", m.matchedAmountA === "4000000");
    check("matchedAmountB = floor(X*price/1e9) Y", m.matchedAmountB === "2000000", m.matchedAmountB);
    check("priceScaled bound in match", m.priceScaled === "500000000");
    check("asset pair cross (A gives USDC, B gives XLM)", m.inputAssetA === USDC && m.inputAssetB === XLM);
  }
}

// --- non-crossing: same-direction (both spend USDC) rejected ---
{
  const b2: PricedIntent = { ...b, inputAsset: USDC, outputAsset: XLM };
  check("non-crossing (same-direction) pair rejected", matchPricedPair(a, b2) === null);
}

// --- non-crossing: B doesn't spend the exact Y A receives (no partial fills) ---
{
  const b3: PricedIntent = { ...b, amount: 1_500_000n };
  check("size-mismatch (partial fill) rejected", matchPricedPair(a, b3) === null);
}

// --- non-crossing: B's limit price not met ---
{
  const bGreedy: PricedIntent = { ...b, limitPriceScaled: 3_000_000_000n }; // wants >= 3 USDC per XLM (unmet)
  check("B limit price unmet rejected", matchPricedPair(a, bGreedy) === null);
}

// --- greedy over a set ---
{
  const matches = matchPricedIntents([a, b, { ...a, intentId: "C" }]);
  check("greedy matches exactly one pair (A-B), C unmatched", matches.length === 1 && matches[0].intentAId === "A" && matches[0].intentBId === "B");
}

// --- §10.5: price is bound into the batch hash; changing it changes the hash ---
{
  const m = matchPricedPair(a, b)!;
  const row = { intentAId: m.intentAId, intentBId: m.intentBId, matchedAmount7dp: m.matchedAmountA, inputAsset: m.inputAssetA, outputAsset: m.outputAssetA, priceScaled: m.priceScaled, assetIn: m.inputAssetA, assetOut: m.outputAssetA };
  const h1 = computeBatchHash("batch-priced", [row as never]);
  const h2 = computeBatchHash("batch-priced", [{ ...row, priceScaled: "600000000" } as never]);
  check("changing priceScaled changes the batch hash (§10.5)", h1 !== h2);
}

if (failed > 0) {
  console.error(`\nPRICED MATCHER TESTS FAILED: ${failed} failing`);
  process.exit(1);
}
console.log("\nPRICED MATCHER TESTS PASS");
