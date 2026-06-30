import { config } from "dotenv";
import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { Contract, JsonRpcProvider, parseEther, parseUnits, Wallet } from "ethers";
import { LOCKED_CCTP } from "@shade/cctp-utils";

const ERC20 = [
  "function balanceOf(address) view returns (uint256)",
  "function transfer(address to, uint256 amount) returns (bool)"
] as const;

for (const path of [process.env.SHADE_ENV_FILE ?? ".env", ".env", "../.env", ".env.generated"]) {
  if (existsSync(path)) config({ path, override: false });
}

const generated = await loadGenerated();
const rpcUrl = process.env.ARB_SEPOLIA_RPC_URL ?? generated.ARB_SEPOLIA_RPC_URL ?? "https://sepolia-rollup.arbitrum.io/rpc";
const privateKey = process.env.ARB_SEPOLIA_PRIVATE_KEY ?? process.env.ETH_PRIVATE_KEY;
const solver = generated.ARB_SOLVER_ADDRESS;
if (!privateKey) throw new Error("ETH_PRIVATE_KEY or ARB_SEPOLIA_PRIVATE_KEY is required");
if (!solver) throw new Error("ARB_SOLVER_ADDRESS missing; run npm run setup:testnet");

const wallet = new Wallet(privateKey, new JsonRpcProvider(rpcUrl));
const usdcAddress = process.env.ARB_SEPOLIA_USDC_ADDRESS ?? generated.ARB_SEPOLIA_USDC_ADDRESS ?? LOCKED_CCTP.arbitrumSepoliaUsdc;
const usdc = new Contract(usdcAddress, ERC20, wallet);
const [solverEth, solverUsdc, userEth, userUsdc] = await Promise.all([
  wallet.provider!.getBalance(solver),
  usdc.balanceOf(solver) as Promise<bigint>,
  wallet.provider!.getBalance(wallet.address),
  usdc.balanceOf(wallet.address) as Promise<bigint>
]);

const targetEth = parseEther("0.005");
const targetUsdc = parseUnits("1", 6);

if (solverEth < targetEth) {
  const delta = targetEth - solverEth;
  if (userEth <= delta + parseEther("0.001")) throw new Error("User wallet lacks enough ETH to fund solver plus gas");
  const tx = await wallet.sendTransaction({ to: solver, value: delta });
  console.log(`Solver ETH funding tx: ${tx.hash}`);
  await tx.wait();
} else {
  console.log("Solver ETH funding: already sufficient");
}

if (solverUsdc < targetUsdc) {
  const delta = targetUsdc - solverUsdc;
  if (userUsdc < delta) throw new Error("User wallet lacks enough USDC to fund solver");
  const tx = await usdc.transfer(solver, delta);
  console.log(`Solver USDC funding tx: ${tx.hash}`);
  await tx.wait();
} else {
  console.log("Solver USDC funding: already sufficient");
}

async function loadGenerated(): Promise<Record<string, string>> {
  if (!existsSync(".env.generated")) return {};
  const text = await readFile(".env.generated", "utf8");
  const out: Record<string, string> = {};
  for (const raw of text.split("\n")) {
    const line = raw.replace(/\r$/, "");
    if (!line.includes("=") || line.trimStart().startsWith("#")) continue;
    const index = line.indexOf("=");
    out[line.slice(0, index)] = line.slice(index + 1);
  }
  return out;
}
