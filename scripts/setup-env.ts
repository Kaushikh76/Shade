import { config } from "dotenv";
import { chmod, readFile, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { Wallet } from "ethers";
import { erc20Balance, ethBalance, walletFromPrivateKey } from "@shade/evm-utils";
import { generateStellarWallet, fundWithFriendbot } from "@shade/stellar-utils";
import { LOCKED_CCTP } from "@shade/cctp-utils";

type EnvMap = Record<string, string>;

for (const path of [process.env.SHADE_ENV_FILE ?? ".env", "../.env", ".env.generated"]) {
  if (existsSync(path)) config({ path, override: false });
}

const DEFAULT_ARB_SEPOLIA_RPC_URL = "https://sepolia-rollup.arbitrum.io/rpc";

async function main() {
  const privateKey = process.env.ARB_SEPOLIA_PRIVATE_KEY ?? process.env.ETH_PRIVATE_KEY;
  const rpcUrl = process.env.ARB_SEPOLIA_RPC_URL ?? process.env.ETH_RPC_URL ?? DEFAULT_ARB_SEPOLIA_RPC_URL;
  if (!privateKey) throw new Error("ARB_SEPOLIA_PRIVATE_KEY or ETH_PRIVATE_KEY is required in .env");

  const user = walletFromPrivateKey(privateKey, rpcUrl);
  const [eth, usdc] = await Promise.all([
    ethBalance(user),
    erc20Balance(rpcUrl, process.env.ARB_SEPOLIA_USDC_ADDRESS ?? LOCKED_CCTP.arbitrumSepoliaUsdc, user.address)
  ]);

  if (eth === 0n) throw new Error(`Arbitrum Sepolia wallet ${user.address} has zero ETH for gas`);
  if (usdc.raw === 0n) throw new Error(`Arbitrum Sepolia wallet ${user.address} has zero testnet USDC`);

  const generated: EnvMap = await loadGenerated();
  const stellarRoles = ["DEPLOYER", "USER", "RELAYER", "SOLVER"] as const;
  for (const role of stellarRoles) {
    const publicKey = `STELLAR_${role}_PUBLIC`;
    const secretKey = `STELLAR_${role}_SECRET`;
    if (!generated[publicKey] || !generated[secretKey]) {
      const wallet = generateStellarWallet(role.toLowerCase());
      generated[publicKey] = wallet.publicKey;
      generated[secretKey] = wallet.secret;
      await fundWithFriendbot(wallet.publicKey);
    }
  }

  if (!generated.ARB_SOLVER_PRIVATE_KEY || !generated.ARB_SOLVER_ADDRESS) {
    const solver = Wallet.createRandom();
    generated.ARB_SOLVER_PRIVATE_KEY = solver.privateKey;
    generated.ARB_SOLVER_ADDRESS = solver.address;
  }

  generated.ARB_SEPOLIA_CHAIN_ID = process.env.ARB_SEPOLIA_CHAIN_ID ?? "421614";
  generated.ARB_SEPOLIA_RPC_URL = rpcUrl;
  generated.ARB_SEPOLIA_USDC_ADDRESS = process.env.ARB_SEPOLIA_USDC_ADDRESS ?? LOCKED_CCTP.arbitrumSepoliaUsdc;
  generated.ARB_SEPOLIA_CCTP_DOMAIN = String(LOCKED_CCTP.arbitrumSepoliaDomain);
  generated.STELLAR_CCTP_DOMAIN = String(LOCKED_CCTP.stellarDomain);
  generated.STELLAR_CCTP_FORWARDER_CONTRACT = process.env.STELLAR_CCTP_FORWARDER_CONTRACT || LOCKED_CCTP.stellarCctpForwarder;
  generated.STELLAR_CCTP_MESSAGE_TRANSMITTER_CONTRACT = process.env.STELLAR_CCTP_MESSAGE_TRANSMITTER_CONTRACT || LOCKED_CCTP.stellarMessageTransmitter;

  await writeEnvGenerated(generated);

  console.log("Setup validation PASS");
  console.log(`Arbitrum Sepolia user: ${user.address}`);
  console.log(`Arbitrum ETH wei: ${eth.toString()}`);
  console.log(`Arbitrum USDC: ${usdc.formatted}`);
  for (const role of stellarRoles) console.log(`Stellar ${role.toLowerCase()}: ${generated[`STELLAR_${role}_PUBLIC`]}`);
  console.log(`Arbitrum solver: ${generated.ARB_SOLVER_ADDRESS}`);
  console.log("Secrets written to .env.generated with mode 0600");
}

async function loadGenerated(): Promise<EnvMap> {
  if (!existsSync(".env.generated")) return {};
  const text = await readFile(".env.generated", "utf8");
  return Object.fromEntries(
    text
      .split("\n")
      .map((line) => line.replace(/\r$/, ""))
      .filter((line) => line.includes("=") && !line.trim().startsWith("#"))
      .map((line) => {
        const index = line.indexOf("=");
        return [line.slice(0, index), line.slice(index + 1)];
      })
  );
}

async function writeEnvGenerated(values: EnvMap): Promise<void> {
  const body = Object.entries(values)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([key, value]) => `${key}=${value}`)
    .join("\n");
  await writeFile(".env.generated", `${body}\n`, { mode: 0o600 });
  await chmod(".env.generated", 0o600);
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
});
