import "dotenv/config";
import Fastify from "fastify";
import { Wallet } from "ethers";
import { v4 as uuidv4 } from "uuid";
import { hashJson } from "@shade/shared-types/ids";
import { erc20Balance } from "@shade/evm-utils";

const app = Fastify({ logger: { redact: ["*.privateKey", "*.secret"] } });

app.get("/health", async () => ({ ok: true, service: "solver" }));
app.post("/v1/quote", async (request) => {
  if (!process.env.ARB_SOLVER_PRIVATE_KEY || !process.env.ARB_SEPOLIA_RPC_URL || !process.env.ARB_SEPOLIA_USDC_ADDRESS) {
    throw Object.assign(new Error("solver wallet/rpc/usdc env required"), { statusCode: 503 });
  }
  const solver = new Wallet(process.env.ARB_SOLVER_PRIVATE_KEY);
  const balance = await erc20Balance(process.env.ARB_SEPOLIA_RPC_URL, process.env.ARB_SEPOLIA_USDC_ADDRESS, solver.address);
  if (balance.raw === 0n) throw Object.assign(new Error("solver has insufficient real testnet USDC inventory"), { statusCode: 409 });
  const intent = request.body as Record<string, unknown>;
  const gross = String(intent.amount ?? "0");
  const quote = {
    quote_id: uuidv4(),
    intent_hash: String(intent.intent_hash ?? hashJson(intent)),
    solver_id: `evm:${solver.address}`,
    input_asset: "USDC",
    output_asset: "USDC:ArbitrumSepolia",
    gross_input: gross,
    net_output: gross,
    fee: "0",
    valid_until_ledger: Number(intent.expiry_ledger ?? 0),
    solver_inventory_commitment: hashJson({ balance: balance.raw.toString(), solver: solver.address }),
    settlement_method: "proof_of_fill",
    quote_signature: ""
  };
  quote.quote_signature = await solver.signMessage(hashJson(quote));
  return quote;
});

await app.listen({ port: Number(process.env.SOLVER_PORT ?? 8081), host: "0.0.0.0" });
