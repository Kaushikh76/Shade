import { resolve } from "node:path";
import { beginReport, writeCheckReport, failIfAny, type CheckResult } from "../apps/cli/src/lib/report.js";
import {
  generateCoin, buildAssociationSet, buildNoteProof, buildTransferProof, buildDepositProof
} from "../apps/cli/src/lib/prove.js";

// C1: real circuit tests — generate a sample witness for each circuit, produce a
// Groth16 proof, and verify it locally (snarkjs groth16 verify). Pure offline; no
// chain. Fails if any circuit's proof does not verify against its vk.

const SCRATCH = process.env.SHADE_SCRATCH_DIR ?? resolve(process.env.SHADE_ROOT ?? process.cwd(), ".scratch");
const checks: CheckResult[] = [];

try {
  // withdraw_public: note-ownership proof over a 1-leaf anonymity set + ASP membership.
  const wc = generateCoin("ctest_withdraw", `${SCRATCH}/ctest_w.json`);
  const wassoc = buildAssociationSet(wc, SCRATCH, "ctest_w");
  const wproof = buildNoteProof(wc, [wc.commitmentDecimal], "ctest_withdraw", SCRATCH, "ctest_w", wassoc.assocPath, {
    operationType: "1", recipientHash: "0", relayerFee: "0", deadlineLedger: "999999999"
  });
  checks.push({ name: "withdraw_public proof verifies", ok: wproof.locallyVerified, detail: wproof.locallyVerified ? "OK" : "verify FAILED" });
} catch (e) { checks.push({ name: "withdraw_public proof verifies", ok: false, detail: (e as Error).message.slice(0, 160) }); }

try {
  // private_transfer: spend input note, create output note, public fee, ASP allow-set membership.
  const tc = generateCoin("ctest_xfer", `${SCRATCH}/ctest_x.json`);
  const tassoc = buildAssociationSet(tc, SCRATCH, "ctest_x");
  const tproof = buildTransferProof(tc, [tc.commitmentDecimal], "ctest_xfer", "100000", SCRATCH, "ctest_x", tassoc.assocPath);
  checks.push({ name: "private_transfer proof verifies", ok: tproof.locallyVerified, detail: tproof.locallyVerified ? "OK" : "verify FAILED" });
  checks.push({ name: "private_transfer ASP binding matches", ok: tproof.associationRootHex.toLowerCase() === tassoc.rootHex.toLowerCase(), detail: tproof.associationRootHex });
} catch (e) { checks.push({ name: "private_transfer proof verifies", ok: false, detail: (e as Error).message.slice(0, 160) }); }

try {
  // deposit_note_mint: bind a CCTP message to the note commitment.
  const dc = generateCoin("ctest_deposit", `${SCRATCH}/ctest_d.json`);
  const dproof = buildDepositProof(dc, {
    sourceDomain: "3", destinationDomain: "27", cctpNonceHex: "0x" + "ab".repeat(32),
    burnTxHashHex: "0x" + "cd".repeat(32), amount6dp: "1000000", amount7dp: dc.value7dp,
    assetStrkey: "CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA",
    poolStrkey: "CDUBLMVIRUAIWICRMY4RWUIEYMMMTFGMYZKENVEPKCTGLDOZHI5SJXQQ",
    encryptedNotePayloadHashHex: "0x" + "ef".repeat(32), policyIdHex: "0x" + "12".repeat(32),
    poolId: "1", chainId: "148"
  }, SCRATCH, "ctest_d");
  const commitOk = dproof.commitmentHex === dc.commitmentHex;
  checks.push({ name: "deposit_note_mint proof verifies + commitment bound", ok: dproof.locallyVerified && commitOk, detail: dproof.locallyVerified ? (commitOk ? "OK" : "commitment mismatch") : "verify FAILED" });
} catch (e) { checks.push({ name: "deposit_note_mint proof verifies + commitment bound", ok: false, detail: (e as Error).message.slice(0, 160) }); }

beginReport({ title: "Circuit Tests" });
await writeCheckReport("Circuit Tests (prove + local verify)", checks);
for (const c of checks) console.log(`${c.ok ? "PASS" : "FAIL"}  ${c.name}${c.detail ? " — " + c.detail : ""}`);
failIfAny(checks);
console.log("circuits:test PASS");
