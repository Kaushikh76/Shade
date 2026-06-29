import "dotenv/config";
import { createHash } from "node:crypto";
import Fastify from "fastify";
import { Contract, JsonRpcProvider, Wallet } from "ethers";
import { v4 as uuidv4 } from "uuid";
import { erc20Balance } from "@shade/evm-utils";
import { LOCKED_CCTP, ERC20_ABI } from "@shade/cctp-utils";
import { type Quote, quoteHash, signQuoteStellar, priceQuote, usdc7ToDecimal } from "@shade/rfq";

// PHASE 2 solver service. Quote-signing is ed25519 over the quote hash (the
// canonical scheme the on-chain `rfq_settle` verifies, plus the C4 authorized-
// solver registry) — NOT EVM signatures. The solver keeps real Arbitrum Sepolia
// USDC inventory, refuses quotes it cannot cover, signs with its Stellar key, and
// exposes inventory/health for the API and operators.

const app = Fastify({ logger: { redact: ["*.privateKey", "*.secret", "*.STELLAR_SOLVER_SECRET"] } });

function requireEnv(keys: string[]): void {
  const missing = keys.filter((k) => !process.env[k]);
  if (missing.length) throw Object.assign(new Error(`solver env required: ${missing.join(", ")}`), { statusCode: 503 });
}

async function arbInventory(): Promise<{ address: string; usdc6: bigint }> {
  const solver = new Wallet(process.env.ARB_SOLVER_PRIVATE_KEY as string);
  const bal = await erc20Balance(process.env.ARB_SEPOLIA_RPC_URL as string, process.env.ARB_SEPOLIA_USDC_ADDRESS as string, solver.address);
  return { address: solver.address, usdc6: bal.raw };
}

app.get("/health", async () => ({ ok: true, service: "solver", signing: "ed25519", solverStellarPubkey: process.env.STELLAR_SOLVER_PUBLIC }));

// Real Arbitrum USDC inventory + the Stellar solver identity used for signing.
app.get("/v1/inventory", async () => {
  requireEnv(["ARB_SOLVER_PRIVATE_KEY", "ARB_SEPOLIA_RPC_URL", "ARB_SEPOLIA_USDC_ADDRESS", "STELLAR_SOLVER_PUBLIC"]);
  const inv = await arbInventory();
  return { solver_id: `stellar:${process.env.STELLAR_SOLVER_PUBLIC}`, arbitrum_address: inv.address, arbitrum_usdc_6dp: inv.usdc6.toString() };
});

// Price + sign a quote for an intent. Refuses if real inventory can't cover the
// fill. Signature is ed25519 (Stellar) over the quote hash; the response includes
// the solver pubkey + signature in the hex form the contract consumes.
app.post("/v1/quote", async (request) => {
  requireEnv(["ARB_SOLVER_PRIVATE_KEY", "ARB_SEPOLIA_RPC_URL", "ARB_SEPOLIA_USDC_ADDRESS", "STELLAR_SOLVER_SECRET", "STELLAR_SOLVER_PUBLIC"]);
  const inv = await arbInventory();
  const intent = request.body as Record<string, unknown>;
  const gross7 = BigInt(String(intent.amount ?? "0"));
  if (gross7 <= 0n) throw Object.assign(new Error("intent amount required (7dp)"), { statusCode: 400 });

  const feeBps = Number(process.env.RFQ_FEE_BPS ?? "50");
  const { net: net7, fee: fee7 } = priceQuote(gross7, feeBps);
  const fillAmount6 = net7 / 10n; // 7dp -> 6dp for the Arbitrum payout
  if (inv.usdc6 < fillAmount6) {
    throw Object.assign(new Error(`insufficient inventory: have ${inv.usdc6} (6dp), need ${fillAmount6}`), { statusCode: 409 });
  }

  const quote: Quote = {
    quote_id: uuidv4(),
    intent_hash: String(intent.intent_hash ?? ""),
    solver_id: `stellar:${process.env.STELLAR_SOLVER_PUBLIC}`,
    input_asset: "USDC:Stellar:SAC",
    output_asset: "USDC:ArbitrumSepolia",
    gross_input: usdc7ToDecimal(gross7),
    net_output: usdc7ToDecimal(net7),
    fee: usdc7ToDecimal(fee7),
    valid_until_ledger: Number(intent.expiry_ledger ?? 999999999),
    solver_inventory_commitment: createHash("sha256").update(`${inv.address}:${inv.usdc6}`).digest("hex"),
    settlement_method: "proof_of_fill"
  };
  const qHash = quoteHash(quote);
  const sig = signQuoteStellar(qHash, process.env.STELLAR_SOLVER_SECRET as string);
  return { quote, quote_hash: qHash, solver_pubkey: sig.pubkey, solver_sig: sig.sig, fill_amount_6dp: fillAmount6.toString() };
});

// Execute a real Arbitrum Sepolia USDC fill (Path A payout to the user) and return
// the on-chain tx hash + a fill receipt hash the API/settlement binds.
app.post("/v1/fill", async (request, reply) => {
  requireEnv(["ARB_SOLVER_PRIVATE_KEY", "ARB_SEPOLIA_RPC_URL", "ARB_SEPOLIA_USDC_ADDRESS"]);
  const body = request.body as { recipient?: string; amount_6dp?: string };
  if (!body.recipient || !body.amount_6dp) { reply.code(400); return { error: "recipient and amount_6dp required" }; }
  const provider = new JsonRpcProvider(process.env.ARB_SEPOLIA_RPC_URL);
  const solver = new Wallet(process.env.ARB_SOLVER_PRIVATE_KEY as string, provider);
  const usdc = new Contract(process.env.ARB_SEPOLIA_USDC_ADDRESS ?? LOCKED_CCTP.arbitrumSepoliaUsdc, ERC20_ABI, solver);
  const amount6 = BigInt(body.amount_6dp);
  const bal = (await usdc.balanceOf(solver.address)) as bigint;
  if (bal < amount6) { reply.code(409); return { error: `insufficient inventory: have ${bal}, need ${amount6}` }; }
  const tx = await usdc.transfer(body.recipient, amount6);
  const receipt = await tx.wait();
  const fillTxHash = receipt!.hash;
  return { fill_tx_hash: fillTxHash, fill_receipt_hash: createHash("sha256").update(fillTxHash).digest("hex"), amount_6dp: amount6.toString(), recipient: body.recipient };
});

await app.listen({ port: Number(process.env.SOLVER_PORT ?? 8081), host: "0.0.0.0" });
