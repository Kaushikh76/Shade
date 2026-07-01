import { shamirSplit, shamirReconstruct, encodeShare, decodeShare } from "./shamir.js";

// mpc-crypto unit tests. Phase 1 B5 expands this with batch-hash total-order and
// coordinator matching tests; this file starts with the Shamir sharing core.

const BN254_P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

let failed = 0;
function check(name: string, ok: boolean, detail = ""): void {
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${detail ? " — " + detail : ""}`);
  if (!ok) failed++;
}

// --- Shamir split/reconstruct roundtrip ---
{
  const secret = 123456789012345678901234567890n % BN254_P;
  const shares = shamirSplit(secret, 3, 5);
  check("shamir: produces `total` shares", shares.length === 5);
  const recovered = shamirReconstruct(shares.slice(0, 3));
  check("shamir: any threshold shares reconstruct the secret", recovered === secret, recovered.toString());
  const recovered2 = shamirReconstruct([shares[1], shares[3], shares[4]]);
  check("shamir: a different threshold subset reconstructs the same secret", recovered2 === secret);
}

// --- Shares are in field range [0, P) (rejection sampling, B5.1) ---
{
  let allInRange = true;
  for (let i = 0; i < 50; i++) {
    const shares = shamirSplit(BigInt(i + 1), 2, 4);
    for (const s of shares) {
      if (s.y < 0n || s.y >= BN254_P) allInRange = false;
    }
  }
  check("shamir: all share values are in [0, P)", allInRange);
}

// --- Fewer than threshold shares do NOT recover the secret ---
{
  const secret = 999999999999n;
  const shares = shamirSplit(secret, 3, 5);
  const tooFew = shamirReconstruct(shares.slice(0, 2)); // 2 < threshold 3
  check("shamir: sub-threshold shares do not reveal the secret", tooFew !== secret);
}

// --- Encode/decode roundtrip ---
{
  const shares = shamirSplit(42n, 2, 3);
  const roundtrip = shares.map((s) => decodeShare(encodeShare(s)));
  const same = roundtrip.every((s, i) => s.x === shares[i].x && s.y === shares[i].y);
  check("shamir: encode/decode share roundtrip", same);
}

// --- Invalid thresholds are rejected (fail-closed) ---
{
  let threw = false;
  try { shamirSplit(1n, 1, 3); } catch { threw = true; }
  check("shamir: threshold < 2 rejected", threw);
  threw = false;
  try { shamirSplit(1n, 4, 3); } catch { threw = true; }
  check("shamir: threshold > total rejected", threw);
}

if (failed > 0) {
  console.error(`\nMPC-CRYPTO TESTS FAILED: ${failed} failing`);
  process.exit(1);
}
console.log("\nMPC-CRYPTO TESTS PASS");
