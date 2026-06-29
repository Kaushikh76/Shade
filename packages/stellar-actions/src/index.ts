import { rpc, TransactionBuilder, Contract, Address, nativeToScVal, BASE_FEE, xdr, type Transaction } from "@stellar/stellar-sdk";

// @shade/stellar-actions — build UNSIGNED Soroban transaction XDR on the backend
// and broadcast SIGNED XDR. The user's Stellar wallet (Freighter / Privy raw)
// signs client-side; NO user secret ever reaches the backend (audit.md PHASE 7).

export type Network = { rpcUrl: string; passphrase: string };
export function testnet(): Network {
  return { rpcUrl: process.env.STELLAR_RPC_URL ?? "https://soroban-testnet.stellar.org", passphrase: process.env.STELLAR_NETWORK_PASSPHRASE ?? "Test SDF Network ; September 2015" };
}

// ScVal helpers for the pool entrypoints.
const addr = (s: string) => new Address(s).toScVal();
const bytes = (hex: string) => nativeToScVal(Buffer.from(hex.replace(/^0x/, ""), "hex"), { type: "bytes" });
const i128 = (v: string | number | bigint) => nativeToScVal(BigInt(v), { type: "i128" });
const u32 = (v: number) => nativeToScVal(v, { type: "u32" });

// Build an unsigned, simulated+prepared Soroban invocation tx and return its base64
// XDR. `source` is the account that will sign (the note owner for require_auth).
export async function buildInvokeXdr(args: {
  network: Network; source: string; contractId: string; method: string; params: xdr.ScVal[];
}): Promise<string> {
  const server = new rpc.Server(args.network.rpcUrl, { allowHttp: args.network.rpcUrl.startsWith("http://") });
  const account = await server.getAccount(args.source);
  const contract = new Contract(args.contractId);
  const tx = new TransactionBuilder(account, { fee: BASE_FEE, networkPassphrase: args.network.passphrase })
    .addOperation(contract.call(args.method, ...args.params))
    .setTimeout(120)
    .build();
  // simulate + assemble (footprint + soroban data + auth) — still unsigned.
  const prepared = await server.prepareTransaction(tx);
  return prepared.toXDR();
}

// Build the withdraw(to, proof, public) tx XDR (Path A; to == source signs).
export function withdrawParams(to: string, proofHex: string, publicHex: string): xdr.ScVal[] {
  return [addr(to), bytes(proofHex), bytes(publicHex)];
}
export function withdrawCctpParams(to: string, proofHex: string, publicHex: string, destinationDomain: number, destinationRecipientHex: string, maxFee: string, minFinality: number): xdr.ScVal[] {
  return [addr(to), bytes(proofHex), bytes(publicHex), u32(destinationDomain), bytes(destinationRecipientHex), i128(maxFee), u32(minFinality)];
}

// Broadcast a client-signed transaction XDR. Returns the tx hash; polls to confirm.
export async function broadcastSignedXdr(network: Network, signedXdr: string): Promise<{ hash: string; status: string }> {
  const server = new rpc.Server(network.rpcUrl, { allowHttp: network.rpcUrl.startsWith("http://") });
  const tx = TransactionBuilder.fromXDR(signedXdr, network.passphrase) as Transaction;
  const sent = await server.sendTransaction(tx);
  if (sent.status === "ERROR") throw new Error(`Soroban sendTransaction error: ${JSON.stringify(sent.errorResult)}`);
  let getResp = await server.getTransaction(sent.hash);
  for (let i = 0; i < 30 && getResp.status === "NOT_FOUND"; i++) {
    await new Promise((r) => setTimeout(r, 2000));
    getResp = await server.getTransaction(sent.hash);
  }
  if (getResp.status !== "SUCCESS") throw new Error(`tx ${sent.hash} status ${getResp.status}`);
  return { hash: sent.hash, status: getResp.status };
}
