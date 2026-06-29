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
import type { EnvMap } from "@shade/proving/env";
import { buildDepositProof, type GeneratedCoin } from "@shade/proving";

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
  coin?: GeneratedCoin; // P1.8: the note (opening) — REQUIRED for shielded_pool deposit proof
  scratch?: string; // scratch dir for P1.8 deposit proof artifacts
  poolId?: string; // P1.8 domain separator (default "1")
  chainId?: string; // P1.8 domain separator (default "148")
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
  //    post-insert root AND a P1.8 DepositNoteMint proof binding the commitment to
  //    the CCTP message; the legacy vault (CommitmentTree-backed) does neither.
  let depositProofArgs: string[] = [];
  if (p.targetContract) {
    if (!p.coin) throw new Error("P1.8: coin (note opening) required for shielded_pool deposit proof");
    const dep = buildDepositProof(p.coin, {
      sourceDomain: String(LOCKED_CCTP.arbitrumSepoliaDomain),
      destinationDomain: String(LOCKED_CCTP.stellarDomain),
      cctpNonceHex,
      burnTxHashHex: burnTxHash,
      amount6dp: p.amount6.toString(),
      amount7dp: amount7.toString(),
      assetStrkey: sac,
      poolStrkey: p.targetContract,
      encryptedNotePayloadHashHex: p.encryptedNotePayloadHashHex,
      policyIdHex: p.policyIdHex,
      poolId: p.poolId ?? "1",
      chainId: p.chainId ?? "148"
    }, p.scratch ?? ".scratch", "inbound");
    if (!dep.locallyVerified) throw new Error("P1.8 deposit proof failed local verification");
    depositProofArgs = ["--proof_bytes", dep.proofHex, "--pub_signals_bytes", dep.publicHex];
  }
  const receiveArgs = [
    "--source_domain", String(LOCKED_CCTP.arbitrumSepoliaDomain),
    "--cctp_nonce", bytesToCliHex(cctpNonceHex),
    "--asset", sac,
    "--amount", amount7.toString(),
    "--commitment", bytesToCliHex(p.commitmentHex),
    ...(p.targetContract ? ["--new_root", bytesToCliHex(p.newRootHex ?? (() => { throw new Error("newRootHex required for shielded_pool deposit"); })())] : []),
    "--encrypted_note_payload_hash", bytesToCliHex(p.encryptedNotePayloadHashHex),
    "--policy_id", bytesToCliHex(p.policyIdHex),
    ...depositProofArgs
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

// ===========================================================================
// FIX6 (audit2): user-signed-burn inbound. The USER already burned on Arbitrum;
// the relayer validates that burn, then completes the Stellar side. No backend
// EVM key is used here.
// ===========================================================================

export type BurnValidation = {
  burnTxHash: string;
  sender: string;
  amount6: bigint;
  destinationDomain: number;
  mintRecipient: string;
  destinationCaller: string;
  burnToken: string;
  maxFee: bigint;
  minFinalityThreshold: number;
  hookData: string;
};

// Validate a user-submitted depositForBurnWithHook tx against the expected deposit
// terms. Throws on ANY mismatch. Returns the decoded burn params on success.
export async function validateInboundBurnTx(env: EnvMap, args: {
  burnTxHash: string; expectedSender: string; expectedAmount6: bigint; pool: string; expectedMaxFee6?: bigint; expectedFinality?: number;
}): Promise<BurnValidation> {
  const provider = new JsonRpcProvider(env.ARB_SEPOLIA_RPC_URL ?? "https://sepolia-rollup.arbitrum.io/rpc");
  const tx = await provider.getTransaction(args.burnTxHash);
  const receipt = await provider.getTransactionReceipt(args.burnTxHash);
  if (!tx || !receipt) throw new Error("burn tx not found on Arbitrum");
  if (receipt.status !== 1) throw new Error("burn tx reverted");
  if (tx.from.toLowerCase() !== args.expectedSender.toLowerCase()) throw new Error("burn sender != deposit user wallet");
  const tokenMessenger = (env.ARB_SEPOLIA_CCTP_TOKEN_MESSENGER ?? LOCKED_CCTP.arbitrumSepoliaTokenMessenger).toLowerCase();
  if ((tx.to ?? "").toLowerCase() !== tokenMessenger) throw new Error("burn tx target != CCTP TokenMessenger");
  const { Interface } = await import("ethers");
  const iface = new Interface([
    "function depositForBurnWithHook(uint256 amount,uint32 destinationDomain,bytes32 mintRecipient,address burnToken,bytes32 destinationCaller,uint256 maxFee,uint32 minFinalityThreshold,bytes calldata hookData)"
  ]);
  let d;
  try { d = iface.parseTransaction({ data: tx.data }); } catch { throw new Error("burn tx is not depositForBurnWithHook"); }
  if (!d) throw new Error("could not decode burn calldata");
  const forwarder = env.STELLAR_CCTP_FORWARDER_CONTRACT ?? LOCKED_CCTP.stellarCctpForwarder;
  const usdc = (env.ARB_SEPOLIA_USDC_ADDRESS ?? LOCKED_CCTP.arbitrumSepoliaUsdc).toLowerCase();
  const expMint = stellarContractToBytes32(forwarder).toLowerCase();
  const expHook = encodeStellarForwardHook(args.pool).toLowerCase();
  if (BigInt(d.args[0]) !== args.expectedAmount6) throw new Error("burn amount != deposit amount");
  if (Number(d.args[1]) !== LOCKED_CCTP.stellarDomain) throw new Error("burn destination domain != Stellar");
  if (String(d.args[2]).toLowerCase() !== expMint) throw new Error("burn mintRecipient != Stellar CCTP Forwarder");
  if (String(d.args[3]).toLowerCase() !== usdc) throw new Error("burn burnToken != expected USDC");
  if (String(d.args[4]).toLowerCase() !== expMint) throw new Error("burn destinationCaller != Stellar CCTP Forwarder");
  if (args.expectedMaxFee6 !== undefined && BigInt(d.args[5]) > args.expectedMaxFee6) throw new Error("burn maxFee exceeds prepared maxFee");
  // PART8: explicitly enforce the CCTP finality threshold (must match the value the
  // /v1/deposits/prepare burn request used; defaults to CONFIRMED for fast transfer).
  const expectedFinality = args.expectedFinality ?? (env.EXPECTED_CCTP_FINALITY_THRESHOLD ? Number(env.EXPECTED_CCTP_FINALITY_THRESHOLD) : FINALITY_THRESHOLD_CONFIRMED);
  if (Number(d.args[6]) !== expectedFinality) throw new Error(`burn minFinalityThreshold ${Number(d.args[6])} != expected ${expectedFinality}`);
  if (String(d.args[7]).toLowerCase() !== expHook) throw new Error("burn hookData forwardRecipient != ShadePool");
  return {
    burnTxHash: args.burnTxHash, sender: tx.from, amount6: BigInt(d.args[0]), destinationDomain: Number(d.args[1]),
    mintRecipient: String(d.args[2]), destinationCaller: String(d.args[4]), burnToken: String(d.args[3]),
    maxFee: BigInt(d.args[5]), minFinalityThreshold: Number(d.args[6]), hookData: String(d.args[7])
  };
}

export type PostUserBurnParams = {
  burnTxHash: string; pool: string; amount6: bigint; commitmentHex: string; encryptedNotePayloadHashHex: string;
  policyIdHex: string; newRootHex: string; coin?: GeneratedCoin; scratch?: string; poolId?: string; chainId?: string;
};

// After the user burn is validated: fetch the Circle attestation, mint_and_forward
// on Stellar, generate the DepositNoteMint proof, and receive_cctp_deposit. Returns
// real tx hashes. The coin opening (for the proof) is dev/test-supplied via scratch;
// the normal app supplies it through the prover path (gated, never logged).
export async function runPostUserBurnCctpInbound(env: EnvMap, p: PostUserBurnParams): Promise<InboundResult> {
  const forwarder = env.STELLAR_CCTP_FORWARDER_CONTRACT ?? LOCKED_CCTP.stellarCctpForwarder;
  const sac = need(env, "STELLAR_TESTNET_USDC_SAC_CONTRACT");
  const relayerSecret = need(env, "STELLAR_RELAYER_SECRET");
  const apiBase = env.CCTP_ATTESTATION_API_BASE ?? "https://iris-api-sandbox.circle.com";

  // 1) Circle attestation for the user's burn.
  const att = await pollAttestation(apiBase, LOCKED_CCTP.arbitrumSepoliaDomain, p.burnTxHash, {});
  const cctpNonceHex = keccak256(att.message);

  // 2) mint_and_forward into the pool.
  const before = sacBalance(env, sac, p.pool, relayerSecret);
  const mintForward = sorobanInvoke({
    contractId: forwarder, secret: relayerSecret, method: "mint_and_forward",
    args: ["--message", bytesToCliHex(att.message), "--attestation", bytesToCliHex(att.attestation)],
    rpcUrl: env.STELLAR_RPC_URL, passphrase: env.STELLAR_NETWORK_PASSPHRASE
  });
  let after = sacBalance(env, sac, p.pool, relayerSecret);
  for (let i = 0; i < 10 && after <= before; i++) { sleepSync(3000); after = sacBalance(env, sac, p.pool, relayerSecret); }
  const amount7 = after - before;
  if (amount7 <= 0n) throw new Error("mint_and_forward produced no pool USDC delta");

  // 3) DepositNoteMint proof (requires the note opening). Gated: dev/test supplies
  //    the coin; the proof binds the commitment to the CCTP message.
  if (!p.coin) throw new Error("coin opening required to build DepositNoteMint proof (supply via prover path)");
  const dep = buildDepositProof(p.coin, {
    sourceDomain: String(LOCKED_CCTP.arbitrumSepoliaDomain), destinationDomain: String(LOCKED_CCTP.stellarDomain),
    cctpNonceHex, burnTxHashHex: p.burnTxHash, amount6dp: p.amount6.toString(), amount7dp: amount7.toString(),
    assetStrkey: sac, poolStrkey: p.pool, encryptedNotePayloadHashHex: p.encryptedNotePayloadHashHex,
    policyIdHex: p.policyIdHex, poolId: p.poolId ?? "1", chainId: p.chainId ?? "148"
  }, p.scratch ?? ".scratch", "userburn");
  if (!dep.locallyVerified) throw new Error("DepositNoteMint proof failed local verification");

  // 4) receive_cctp_deposit (proof-bound).
  const receive = sorobanInvoke({
    contractId: p.pool, secret: relayerSecret, method: "receive_cctp_deposit",
    args: ["--source_domain", String(LOCKED_CCTP.arbitrumSepoliaDomain), "--cctp_nonce", bytesToCliHex(cctpNonceHex),
      "--asset", sac, "--amount", amount7.toString(), "--commitment", bytesToCliHex(p.commitmentHex),
      "--new_root", bytesToCliHex(p.newRootHex), "--encrypted_note_payload_hash", bytesToCliHex(p.encryptedNotePayloadHashHex),
      "--policy_id", bytesToCliHex(p.policyIdHex), "--proof_bytes", dep.proofHex, "--pub_signals_bytes", dep.publicHex],
    rpcUrl: env.STELLAR_RPC_URL, passphrase: env.STELLAR_NETWORK_PASSPHRASE
  });
  const leafIndex = receive.returnValue.replace(/"/g, "").trim();
  const rootRes = sorobanInvoke({ contractId: p.pool, secret: relayerSecret, method: "get_root", rpcUrl: env.STELLAR_RPC_URL, passphrase: env.STELLAR_NETWORK_PASSPHRASE, readOnly: true });
  return {
    burnTxHash: p.burnTxHash, message: att.message, attestation: att.attestation, cctpNonceHex,
    mintForwardTxHash: mintForward.txHash, vaultUsdcBefore: before.toString(), vaultUsdcAfter: after.toString(),
    receiveDepositTxHash: receive.txHash, leafIndex, root: rootRes.returnValue.replace(/"/g, "").trim(), amount7: amount7.toString()
  };
}
