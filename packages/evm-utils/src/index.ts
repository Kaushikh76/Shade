import { Contract, JsonRpcProvider, Wallet, formatUnits } from "ethers";

const ERC20_ABI = [
  "function balanceOf(address owner) view returns (uint256)",
  "function decimals() view returns (uint8)",
  "function transfer(address to, uint256 amount) returns (bool)"
] as const;

export function walletFromPrivateKey(privateKey: string, rpcUrl: string): Wallet {
  return new Wallet(privateKey, new JsonRpcProvider(rpcUrl));
}

export async function ethBalance(wallet: Wallet): Promise<bigint> {
  return wallet.provider!.getBalance(wallet.address);
}

export async function erc20Balance(rpcUrl: string, token: string, owner: string): Promise<{ raw: bigint; decimals: number; formatted: string }> {
  const contract = new Contract(token, ERC20_ABI, new JsonRpcProvider(rpcUrl));
  const [raw, decimals] = await Promise.all([contract.balanceOf(owner) as Promise<bigint>, contract.decimals() as Promise<number>]);
  return { raw, decimals, formatted: formatUnits(raw, decimals) };
}
