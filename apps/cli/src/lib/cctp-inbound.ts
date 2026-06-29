import { Contract, JsonRpcProvider, Wallet, keccak256 } from "ethers";
import {
  LOCKED_CCTP,
  TOKEN_MESSENGER_V2_ABI,
  ERC20_ABI,
  FINALITY_THRESHOLD_FINALIZED,
  FINALITY_THRESHOLD_CONFIRMED,
  encodeStellarForwardHook,
  stellarContractToBytes32,
  pollAttestation,
  usdc6ToStellar7
} from "@shade/cctp-utils";
import { sorobanInvoke, bytesToCliHex } from "@shade/stellar-utils";
import type { EnvMap } from "./env.js";

export type InboundParams = {
  amount6: bigint; // USDC in 6dp subunits to burn
  commitmentHex: string; // 0x.. 32-byte note commitment
  encryptedNotePayloadHashHex: string; // 0x.. 32-byte
  policyIdHex: string; // 0x.. 32-byte
  fast?: boolean; // CCTP fast transfer (confirmed finality, ~minutes) vs standard (finalized)
  maxFee6?: bigint; // max fee (6dp) for fast transfer; required when fast=true
  targetContract?: string; // override forwardRecipient + receive target (e.g. shielded_pool)
  rootMethod?: string; // method to read the post-insert root on the target (default get_root)
  newRootHex?: string; // off-chain-computed post-insert Merkle root (shielded_pool)
};

export type InboundResult = {
  burnTxHash: string;
  message: string;
  attestation: string;
  cctpNonceHex: string; // keccak(message) used as dedup nonce on Stellar
  mintForwardTxHash: string;
  vaultUsdcBefore: string;
  vaultUsdcAfter: string;
  receiveDepositTxHash: string;
  leafIndex: string;
  root: string;
  amount7: string;
};

function need(env: EnvMap, key: string): string {
  const v = env[key];
  if (!v) throw new Error(`missing env ${key}`);
  return v;
}

// Read a Stellar contract's USDC SAC balance via the SAC `balance` fn (read-only).
// Read-only simulations can briefly return empty/stale right after a state change,
// so retry on an empty result.
function sacBalance(env: EnvMap, sac: string, ofContract: string, secret: string): bigint {
  for (let i = 0; i < 5; i++) {
    const res = sorobanInvoke({
      contractId: sac,
      secret,
      method: "balance",
      args: ["--id", ofContract],
      rpcUrl: env.STELLAR_RPC_URL,
      passphrase: env.STELLAR_NETWORK_PASSPHRASE,
      readOnly: true
    });
    const cleaned = res.returnValue.replace(/"/g, "").trim();
    if (cleaned !== "") return BigInt(cleaned);
  }
  return 0n;
}

function sleepSync(ms: number) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

export async function runCctpInbound(env: EnvMap, p: InboundParams): Promise<InboundResult> {
  const rpcUrl = env.ARB_SEPOLIA_RPC_URL ?? "https://sepolia-rollup.arbitrum.io/rpc";
  const privateKey = env.ARB_SEPOLIA_PRIVATE_KEY ?? env.ETH_PRIVATE_KEY;
  if (!privateKey) throw new Error("ARB_SEPOLIA_PRIVATE_KEY/ETH_PRIVATE_KEY required");

  const forwarder = need(env, "STELLAR_CCTP_FORWARDER_CONTRACT");
  const vault = p.targetContract ?? need(env, "SHADE_VAULT_CONTRACT");
  const sac = need(env, "STELLAR_TESTNET_USDC_SAC_CONTRACT");
  const relayerSecret = need(env, "STELLAR_RELAYER_SECRET");
  const apiBase = env.CCTP_ATTESTATION_API_BASE ?? "https://iris-api-sandbox.circle.com";

  const provider = new JsonRpcProvider(rpcUrl);
  const wallet = new Wallet(privateKey, provider);
  const usdcAddr = env.ARB_SEPOLIA_USDC_ADDRESS ?? LOCKED_CCTP.arbitrumSepoliaUsdc;
  const tokenMessenger = env.ARB_SEPOLIA_CCTP_TOKEN_MESSENGER ?? LOCKED_CCTP.arbitrumSepoliaTokenMessenger;

  const usdc = new Contract(usdcAddr, ERC20_ABI, wallet);
  const messenger = new Contract(tokenMessenger, TOKEN_MESSENGER_V2_ABI, wallet);

  const bal = (await usdc.balanceOf(wallet.address)) as bigint;
  if (bal < p.amount6) throw new Error(`insufficient USDC: have ${bal}, need ${p.amount6}`);

  // 1) Approve the TokenMessenger to pull USDC for the burn (only if needed).
  const allowance = (await usdc.allowance(wallet.address, tokenMessenger)) as bigint;
  if (allowance < p.amount6) {
    const approveTx = await usdc.approve(tokenMessenger, p.amount6 * 100n);
    await approveTx.wait();
  }

  // 2) Build burn params. mintRecipient + destinationCaller MUST be the forwarder.
  const mintRecipient = stellarContractToBytes32(forwarder);
  const destinationCaller = stellarContractToBytes32(forwarder);
  const hookData = encodeStellarForwardHook(vault);

  // Fast transfer (CONFIRMED, ~minutes) requires a non-zero maxFee; the actual
  // fee is deducted from the minted amount. Standard (FINALIZED) waits for source
  // finality with maxFee = 0.
  const fast = p.fast ?? true;
  const maxFee = fast ? (p.maxFee6 ?? (p.amount6 / 1000n > 0n ? p.amount6 / 1000n : 1n)) : 0n;
  const finalityThreshold = fast ? FINALITY_THRESHOLD_CONFIRMED : FINALITY_THRESHOLD_FINALIZED;

  const burnTx = await messenger.depositForBurnWithHook(
    p.amount6,
    LOCKED_CCTP.stellarDomain,
    mintRecipient,
    usdcAddr,
    destinationCaller,
    maxFee,
    finalityThreshold,
    hookData
  );
  const burnReceipt = await burnTx.wait();
  const burnTxHash = burnReceipt!.hash;

  // 3) Poll Circle Iris for the attestation (standard transfers wait for finality).
  const att = await pollAttestation(apiBase, LOCKED_CCTP.arbitrumSepoliaDomain, burnTxHash, {
    onTick: (s) => process.stdout.write(`\r  attestation status: ${s}            `)
  });
  process.stdout.write("\n");

  const cctpNonceHex = keccak256(att.message);

  // 4) Submit mint_and_forward on the Stellar forwarder (mints USDC into ShadeVault).
  const vaultUsdcBefore = sacBalance(env, sac, vault, relayerSecret);
  const mintForward = sorobanInvoke({
    contractId: forwarder,
    secret: relayerSecret,
    method: "mint_and_forward",
    args: ["--message", bytesToCliHex(att.message), "--attestation", bytesToCliHex(att.attestation)],
    rpcUrl: env.STELLAR_RPC_URL,
    passphrase: env.STELLAR_NETWORK_PASSPHRASE
  });
  // mint_and_forward succeeded (txHash returned); poll until the SAC balance
  // reflects the mint (read-only sims can lag a freshly closed ledger).
  let vaultUsdcAfter = sacBalance(env, sac, vault, relayerSecret);
  for (let i = 0; i < 10 && vaultUsdcAfter <= vaultUsdcBefore; i++) {
    sleepSync(3000);
    vaultUsdcAfter = sacBalance(env, sac, vault, relayerSecret);
  }

  // For fast transfers a fee (<= maxFee) is deducted, so the minted amount is
  // amount - fee. Use the actual minted delta for the on-chain note amount.
  const mintedDelta7 = vaultUsdcAfter - vaultUsdcBefore;
  const expectedMax7 = usdc6ToStellar7(p.amount6);
  if (mintedDelta7 <= 0n || mintedDelta7 > expectedMax7) {
    throw new Error(`vault USDC delta ${mintedDelta7} not in (0, ${expectedMax7}]`);
  }
  const amount7 = mintedDelta7;

  // 5) Register the note commitment. The shielded_pool takes the off-chain-computed
  //    post-insert root; the legacy vault (CommitmentTree-backed) does not.
  const receiveArgs = [
    "--source_domain", String(LOCKED_CCTP.arbitrumSepoliaDomain),
    "--cctp_nonce", bytesToCliHex(cctpNonceHex),
    "--asset", sac,
    "--amount", amount7.toString(),
    "--commitment", bytesToCliHex(p.commitmentHex),
    ...(p.targetContract ? ["--new_root", bytesToCliHex(p.newRootHex ?? (() => { throw new Error("newRootHex required for shielded_pool deposit"); })())] : []),
    "--encrypted_note_payload_hash", bytesToCliHex(p.encryptedNotePayloadHashHex),
    "--policy_id", bytesToCliHex(p.policyIdHex)
  ];
  const receive = sorobanInvoke({
    contractId: vault,
    secret: relayerSecret,
    method: "receive_cctp_deposit",
    args: receiveArgs,
    rpcUrl: env.STELLAR_RPC_URL,
    passphrase: env.STELLAR_NETWORK_PASSPHRASE
  });
  const leafIndex = receive.returnValue.replace(/"/g, "").trim();

  // 6) Read the latest root (from the target's embedded tree, or the standalone tree).
  const rootContract = p.targetContract ?? need(env, "COMMITMENT_TREE_CONTRACT");
  const rootMethod = p.rootMethod ?? (p.targetContract ? "get_root" : "get_latest_root");
  const rootRes = sorobanInvoke({
    contractId: rootContract,
    secret: relayerSecret,
    method: rootMethod,
    rpcUrl: env.STELLAR_RPC_URL,
    passphrase: env.STELLAR_NETWORK_PASSPHRASE,
    readOnly: true
  });

  return {
    burnTxHash,
    message: att.message,
    attestation: att.attestation,
    cctpNonceHex,
    mintForwardTxHash: mintForward.txHash,
    vaultUsdcBefore: vaultUsdcBefore.toString(),
    vaultUsdcAfter: vaultUsdcAfter.toString(),
    receiveDepositTxHash: receive.txHash,
    leafIndex,
    root: rootRes.returnValue.replace(/"/g, "").trim(),
    amount7: amount7.toString()
  };
}
