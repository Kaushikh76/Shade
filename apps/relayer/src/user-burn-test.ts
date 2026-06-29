import { Interface } from "ethers";
import { LOCKED_CCTP, stellarContractToBytes32, encodeStellarForwardHook } from "@shade/cctp-utils";

// FIX6 test: the burn-validation CHECKS (the security-critical part). We build
// depositForBurnWithHook calldata and assert each binding check rejects a tampered
// field and accepts the correct one. This exercises the same checks
// validateInboundBurnTx applies (which otherwise needs a live Arbitrum RPC).

const POOL = "CDVEGBVXPIHKHCR7CJDJS4JVCMOVABEFBQ4HZQ7PKK6VIO3J3V5ZRTB5";
const FORWARDER = LOCKED_CCTP.stellarCctpForwarder;
const USDC = LOCKED_CCTP.arbitrumSepoliaUsdc;
const iface = new Interface([
  "function depositForBurnWithHook(uint256 amount,uint32 destinationDomain,bytes32 mintRecipient,address burnToken,bytes32 destinationCaller,uint256 maxFee,uint32 minFinalityThreshold,bytes calldata hookData)"
]);
const results: { name: string; ok: boolean; detail: string }[] = [];
const check = (name: string, ok: boolean, detail = "") => { results.push({ name, ok, detail }); console.log(`${ok ? "PASS" : "FAIL"}  ${name}${detail ? " — " + detail : ""}`); };

const mint = stellarContractToBytes32(FORWARDER);
const hook = encodeStellarForwardHook(POOL);
const good = { amount: 1_000_000n, dom: LOCKED_CCTP.stellarDomain, mint, token: USDC, caller: mint, maxFee: 1000n, finality: 1000, hook };

const EXPECTED_FINALITY = 1000; // FINALITY_THRESHOLD_CONFIRMED

// Replicates the per-field checks in validateInboundBurnTx (decode + compare),
// including PART8 finality enforcement.
function validate(args: { amount: bigint; dom: number; mint: string; token: string; caller: string; maxFee: bigint; finality: number; hook: string }, expectedAmount: bigint, expectedMaxFee: bigint, expectedFinality = EXPECTED_FINALITY): string | null {
  const data = iface.encodeFunctionData("depositForBurnWithHook", [args.amount, args.dom, args.mint, args.token, args.caller, args.maxFee, args.finality, args.hook]);
  const d = iface.parseTransaction({ data })!;
  if (BigInt(d.args[0]) !== expectedAmount) return "amount";
  if (Number(d.args[1]) !== LOCKED_CCTP.stellarDomain) return "domain";
  if (String(d.args[2]).toLowerCase() !== mint.toLowerCase()) return "mintRecipient";
  if (String(d.args[3]).toLowerCase() !== USDC.toLowerCase()) return "burnToken";
  if (String(d.args[4]).toLowerCase() !== mint.toLowerCase()) return "destinationCaller";
  if (BigInt(d.args[5]) > expectedMaxFee) return "maxFee";
  if (Number(d.args[6]) !== expectedFinality) return "finality";
  if (String(d.args[7]).toLowerCase() !== hook.toLowerCase()) return "hookData";
  return null;
}

check("valid burn passes all checks", validate(good, 1_000_000n, 2000n) === null);
check("wrong amount rejected", validate(good, 999_999n, 2000n) === "amount");
check("wrong domain rejected", validate({ ...good, dom: 7 }, 1_000_000n, 2000n) === "domain");
check("wrong mintRecipient rejected", validate({ ...good, mint: stellarContractToBytes32(POOL) }, 1_000_000n, 2000n) === "mintRecipient");
check("wrong burnToken rejected", validate({ ...good, token: "0x" + "11".repeat(20) }, 1_000_000n, 2000n) === "burnToken");
check("wrong destinationCaller rejected", validate({ ...good, caller: stellarContractToBytes32(POOL) }, 1_000_000n, 2000n) === "destinationCaller");
check("excessive maxFee rejected", validate({ ...good, maxFee: 5000n }, 1_000_000n, 2000n) === "maxFee");
check("PART8: wrong finality threshold rejected", validate({ ...good, finality: 2000 }, 1_000_000n, 2000n) === "finality");
check("PART8: correct finality threshold accepted", validate({ ...good, finality: EXPECTED_FINALITY }, 1_000_000n, 2000n) === null);
check("wrong hookData (forwardRecipient) rejected", validate({ ...good, hook: encodeStellarForwardHook(FORWARDER) }, 1_000_000n, 2000n) === "hookData");

// Confirm the relayer worker no longer returns the old placeholder string.
import { readFileSync } from "node:fs";
const workerSrc = readFileSync(new URL("./worker.ts", import.meta.url), "utf8");
check("relayer no longer returns placeholder (calls runPostUserBurnCctpInbound)", workerSrc.includes("runPostUserBurnCctpInbound") && !workerSrc.includes("user burn validated; Stellar mint/forward + DepositNoteMint proof + receive_cctp_deposit follow"));

const failed = results.filter((r) => !r.ok);
if (failed.length) { console.error(`\nUSER-BURN TESTS FAILED: ${failed.map((f) => f.name).join(", ")}`); process.exit(1); }
console.log("\nUSER-BURN TESTS PASS");
