"use client";
import { useState } from "react";
import { usePrivy, useWallets } from "@privy-io/react-auth";
import { createWalletClient, createPublicClient, custom, encodeFunctionData, parseAbi, type Hex } from "viem";
import { arbitrumSepolia } from "viem/chains";
import { generateNotePreimage, buildNoteCommitment, addNoteToVault } from "@shade/note-vault";
import { ApiClient } from "@/lib/api";
import { useAccessToken } from "@/lib/use-token";
import { getMemoryVault } from "@/lib/vault-store";

const ERC20_ABI = parseAbi(["function allowance(address,address) view returns (uint256)", "function approve(address,uint256) returns (bool)"]);
const TM_ABI = parseAbi(["function depositForBurnWithHook(uint256 amount,uint32 destinationDomain,bytes32 mintRecipient,address burnToken,bytes32 destinationCaller,uint256 maxFee,uint32 minFinalityThreshold,bytes hookData)"]);

type Stage = "idle" | "preparing_note" | "backup_check" | "approve_pending" | "burn_pending" | "burn_submitted" | "relayer_validating" | "stellar_completing" | "note_active" | "failed";

// FIX5: the deposit page signs approve + CCTP burn with the USER's wallet via viem.
// No prompt(), no backend EVM key.
export default function DepositPage() {
  const { authenticated } = usePrivy();
  const { wallets } = useWallets();
  const getToken = useAccessToken();
  const [amount, setAmount] = useState("1.0");
  const [vaultId, setVaultId] = useState("");
  const [stage, setStage] = useState<Stage>("idle");
  const [log, setLog] = useState<string[]>([]);
  const say = (m: string) => setLog((l) => [...l, m]);

  async function run() {
    setLog([]); setStage("preparing_note");
    try {
      const token = await getToken();
      if (!token) throw new Error("log in first");
      const evm = wallets.find((w) => w.address.startsWith("0x"));
      if (!evm) throw new Error("link an EVM wallet first");
      if (!vaultId) throw new Error("enter your verified vault id (see Dashboard)");

      // ensure the backend knows this wallet (FIX2 sync)
      await ApiClient.syncPrivyWallets(token, [{ wallet_type: "EVM", wallet_source: evm.walletClientType === "privy" ? "privy_embedded" : "external", chain: "arbitrum-sepolia", address: evm.address, privy_wallet_id: evm.address }]);

      // 1) generate the note locally
      const preimage = generateNotePreimage();
      const commitment = await buildNoteCommitment(preimage);
      const mem = getMemoryVault();
      if (mem) addNoteToVault(mem, { commitment, asset_id: "USDC", amount_7dp: String(Math.round(parseFloat(amount) * 1e7)), note_preimage: preimage, status: "prepared", created_at: new Date().toISOString() }, new Date().toISOString());
      say(`Generated note locally. Commitment ${commitment.slice(0, 18)}…`);

      // 2) prepare — backend returns approval + burn tx requests (gated on verified vault)
      setStage("backup_check");
      const amount6 = BigInt(Math.round(parseFloat(amount) * 1e6));
      const prep = await ApiClient.prepareDeposit(token, `dep-${commitment.slice(2, 18)}`, {
        amount_usdc_6dp: amount6.toString(), source_chain: "arbitrum-sepolia", source_wallet_address: evm.address,
        vault_id: vaultId, commitment, encrypted_note_payload_hash: commitment, policy_id: "shade:default-testnet-policy:v1"
      }) as {
        deposit_id: string; usdc_address: Hex; token_messenger_address: Hex;
        burn_tx_request: { args: [string, number, Hex, Hex, Hex, string, number, Hex] };
      };
      say(`Prepared deposit ${prep.deposit_id}.`);

      // 3) viem wallet client over the Privy provider
      const provider = await evm.getEthereumProvider();
      const account = evm.address as Hex;
      const walletClient = createWalletClient({ account, chain: arbitrumSepolia, transport: custom(provider) });
      const publicClient = createPublicClient({ chain: arbitrumSepolia, transport: custom(provider) });

      // 4) approve only if allowance insufficient
      const allowance = await publicClient.readContract({ address: prep.usdc_address, abi: ERC20_ABI, functionName: "allowance", args: [account, prep.token_messenger_address] }) as bigint;
      if (allowance < amount6) {
        setStage("approve_pending");
        say("Allowance insufficient — sending approve…");
        const approveHash = await walletClient.sendTransaction({ to: prep.usdc_address, data: encodeFunctionData({ abi: ERC20_ABI, functionName: "approve", args: [prep.token_messenger_address, amount6] }) });
        await publicClient.waitForTransactionReceipt({ hash: approveHash });
        say(`Approve confirmed: ${approveHash}`);
      } else { say("Allowance sufficient — skipping approve."); }

      // 5) CCTP burn from the user's wallet
      setStage("burn_pending");
      const a = prep.burn_tx_request.args;
      const burnHash = await walletClient.sendTransaction({
        to: prep.token_messenger_address,
        data: encodeFunctionData({ abi: TM_ABI, functionName: "depositForBurnWithHook", args: [BigInt(a[0]), a[1], a[2], a[3], a[4], BigInt(a[5]), a[6], a[7]] })
      });
      say(`CCTP burn sent: ${burnHash}`);
      await publicClient.waitForTransactionReceipt({ hash: burnHash });

      // 6) submit the burn hash automatically (NO prompt)
      setStage("burn_submitted");
      const sub = await ApiClient.burnSubmitted(token, prep.deposit_id, { burn_tx_hash: burnHash, source_chain: "arbitrum-sepolia", source_wallet_address: evm.address }) as { job_id: string };
      say(`Burn submitted to backend. Relayer job ${sub.job_id}.`);

      // 7) poll the relayer job through its states
      setStage("relayer_validating");
      for (let i = 0; i < 40; i++) {
        const j = await ApiClient.job(token, sub.job_id) as { status: string; result?: { state?: string; receiveDepositTxHash?: string } };
        say(`relayer: ${j.status}`);
        if (j.status === "broadcasting" || j.status === "completing_stellar_side") setStage("stellar_completing");
        if (j.result?.state === "active" || j.status === "ready") { setStage("note_active"); say(`Note ACTIVE. register tx ${j.result?.receiveDepositTxHash ?? "(see job)"}`); break; }
        if (j.status === "failed") { setStage("failed"); break; }
        await new Promise((r) => setTimeout(r, 4000));
      }
    } catch (e) { setStage("failed"); say(`Error: ${(e as Error).message}`); }
  }

  if (!authenticated) return <p>Please log in.</p>;
  const STAGES: Stage[] = ["preparing_note", "backup_check", "approve_pending", "burn_pending", "burn_submitted", "relayer_validating", "stellar_completing", "note_active"];
  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-bold">Deposit USDC → Shade</h1>
      <p className="text-sm text-neutral-400">Source: Arbitrum Sepolia · Destination: Stellar ShadePool (via CCTP). Your wallet signs approve + burn — the backend never holds your EVM key.</p>
      <label className="block text-sm">Amount (USDC)<input value={amount} onChange={(e) => setAmount(e.target.value)} className="ml-2 rounded bg-neutral-800 px-2 py-1" /></label>
      <label className="block text-sm">Verified vault id<input value={vaultId} onChange={(e) => setVaultId(e.target.value)} placeholder="vault-…" className="ml-2 w-96 rounded bg-neutral-800 px-2 py-1" /></label>
      <button onClick={run} disabled={stage !== "idle" && stage !== "failed" && stage !== "note_active"} className="rounded bg-violet-600 px-4 py-2">Prepare &amp; deposit</button>
      <div className="flex flex-wrap gap-2 text-xs">{STAGES.map((s) => <span key={s} className={`rounded px-2 py-1 ${stage === s ? "bg-violet-600" : "bg-neutral-800 text-neutral-400"}`}>{s}</span>)}</div>
      <pre className="overflow-auto rounded bg-neutral-900 p-3 text-xs">{log.join("\n")}</pre>
    </div>
  );
}
