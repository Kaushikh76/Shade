import { Keypair } from "@stellar/stellar-sdk";
import { atomicSwapHash, signAtomicSwap, quotedFromPrice, PRICE_SCALE, type AtomicSwapTerms } from "./rfq.js";

// Phase 3 (spec §7.6/§7.7/§7.8): the solver-signed atomic swap terms must bind
// every field, be deterministic, and match the on-chain fixed-point price rule.

let failed = 0;
function check(name: string, ok: boolean, detail = ""): void {
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${detail ? " — " + detail : ""}`);
  if (!ok) failed++;
}

const recipient = Keypair.random().publicKey();
const base: AtomicSwapTerms = {
  quoteHashHex: "0x" + "11".repeat(32),
  outputAssetIdHex: "0x" + "22".repeat(32),
  quotedOutput: 2_000_000n,
  minOutput: 1_900_000n,
  priceScaled: 500_000_000n,
  recipientStrkey: recipient
};

// --- deterministic ---
check("atomicSwapHash is deterministic", atomicSwapHash(base) === atomicSwapHash({ ...base }));
check("atomicSwapHash is 0x + 64 hex", /^0x[0-9a-f]{64}$/.test(atomicSwapHash(base)));

// --- every field is bound (any change flips the hash) ---
const h0 = atomicSwapHash(base);
check("changing quoteHash changes swap_hash", atomicSwapHash({ ...base, quoteHashHex: "0x" + "99".repeat(32) }) !== h0);
check("changing outputAssetId changes swap_hash", atomicSwapHash({ ...base, outputAssetIdHex: "0x" + "33".repeat(32) }) !== h0);
check("changing quotedOutput changes swap_hash", atomicSwapHash({ ...base, quotedOutput: 2_000_001n }) !== h0);
check("changing minOutput changes swap_hash", atomicSwapHash({ ...base, minOutput: 1_800_000n }) !== h0);
check("changing priceScaled changes swap_hash", atomicSwapHash({ ...base, priceScaled: 400_000_000n }) !== h0);
check("changing recipient changes swap_hash", atomicSwapHash({ ...base, recipientStrkey: Keypair.random().publicKey() }) !== h0);

// --- signing yields a 64-byte sig + 32-byte pubkey over the swap_hash ---
{
  const solver = Keypair.random();
  const s = signAtomicSwap(base, solver.secret());
  check("signAtomicSwap returns the bound swap_hash", s.swapHash === h0);
  check("signAtomicSwap sig is 64 bytes", /^[0-9a-f]{128}$/.test(s.sig));
  check("signAtomicSwap pubkey is 32 bytes", /^[0-9a-f]{64}$/.test(s.pubkey));
  // Verify the signature the way the contract does (ed25519 over the 32-byte hash).
  const ok = solver.verify(Buffer.from(s.swapHash.slice(2), "hex"), Buffer.from(s.sig, "hex"));
  check("solver signature verifies over swap_hash", ok);
}

// --- fixed-point price rule matches the contract ---
check("quotedFromPrice: 4M * 0.5 = 2M", quotedFromPrice(4_000_000n, 500_000_000n) === 2_000_000n);
check("quotedFromPrice floors", quotedFromPrice(3n, PRICE_SCALE / 2n) === 1n); // floor(3*0.5)=1

if (failed > 0) {
  console.error(`\nRFQ ATOMIC TESTS FAILED: ${failed} failing`);
  process.exit(1);
}
console.log("\nRFQ ATOMIC TESTS PASS");
