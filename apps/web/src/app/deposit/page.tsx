"use client";
import { useEffect, useState } from "react";
import Link from "next/link";
import { usePrivy, useWallets } from "@privy-io/react-auth";
import { createWalletClient, createPublicClient, custom, encodeFunctionData, parseAbi, type Hex } from "viem";
import { arbitrumSepolia } from "viem/chains";
import { generateNotePreimage, buildNoteCommitment, addNoteToVault } from "@shade/note-vault";
import { ApiClient } from "@/lib/api";
import { useAccessToken } from "@/lib/use-token";
import { getMemoryVault } from "@/lib/vault-store";

const ERC20_ABI = parseAbi(["function allowance(address,address) view returns (uint256)", "function approve(address,uint256) returns (bool)"]);
const TM_ABI = parseAbi(["function depositForBurnWithHook(uint256 amount,uint32 destinationDomain,bytes32 mintRecipient,address burnToken,bytes32 destinationCaller,uint256 maxFee,uint32 minFinalityThreshold,bytes hookData)"]);

// Internal protocol stages (kept for the advanced drawer); the user sees the
// checkout steps below, not these.
type Stage = "idle" | "checking_vault" | "approve_pending" | "burn_pending" | "burn_submitted" | "relayer_validating" | "stellar_completing" | "note_active" | "failed";
type VaultSummary = { vault_id: string; backup_status: string; recovery_policy_status: string; created_at: string };
type VaultChoice =
  | { status: "loading" }
  | { status: "none" }
  | { status: "selected"; vault: VaultSummary }
  | { status: "multiple"; vaults: VaultSummary[]; selected: string };

const CHECKOUT = ["Secure vault", "Approve USDC", "Move USDC privately", "Private balance ready"] as const;
const STAGE_TO_STEP: Record<Stage, number> = { idle: 0, checking_vault: 0, approve_pending: 1, burn_pending: 2, burn_submitted: 2, relayer_validating: 2, stellar_completing: 2, note_active: 3, failed: -1 };

// PART6/7: deposit is a private checkout. The vault is auto-selected (no typing an
// id); the user just picks an amount and clicks Deposit Privately.
export default function DepositPage() {
  const { authenticated } = usePrivy();
  const { wallets } = useWallets();
  const getToken = useAccessToken();
  const [amount, setAmount] = useState("1.0");
  const [vault, setVault] = useState<VaultChoice>({ status: "loading" });
  const [stage, setStage] = useState<Stage>("idle");
  const [statusMsg, setStatusMsg] = useState("");
  const [details, setDetails] = useState<Record<string, string>>({});
  const [showAdvanced, setShowAdvanced] = useState(false);
  const detail = (k: string, v: string) => setDetails((d) => ({ ...d, [k]: v }));

  // Load + auto-select a verified, deposit-ready vault.
  useEffect(() => {
    (async () => {
      try {
        const token = await getToken();
        if (!token) return;
        const all = ((await ApiClient.listVaults(token)).vaults as VaultSummary[]);
        const ready = all.filter((v) => v.backup_status === "verified" && (v.recovery_policy_status === "sufficient" || v.recovery_policy_status === "strong"));
        if (ready.length === 0) setVault({ status: "none" });
        else if (ready.length === 1) setVault({ status: "selected", vault: ready[0] });
        else setVault({ status: "multiple", vaults: ready, selected: ready[0].vault_id });
      } catch { setVault({ status: "none" }); }
    })();
  }, [getToken, authenticated]);

  const selectedVaultId = vault.status === "selected" ? vault.vault.vault_id : vault.status === "multiple" ? vault.selected : null;

  async function deposit() {
    if (!selectedVaultId) return;
    setStage("checking_vault"); setStatusMsg("Checking vault…"); setDetails({});
    try {
      const token = await getToken();
      if (!token) throw new Error("please log in");
      const evm = wallets.find((w) => w.address.startsWith("0x"));
      if (!evm) throw new Error("connect an EVM wallet first");
      await ApiClient.syncPrivyWallets(token, [{ wallet_type: "EVM", wallet_source: evm.walletClientType === "privy" ? "privy_embedded" : "external", chain: "arbitrum-sepolia", address: evm.address, privy_wallet_id: evm.address }]);

      // generate the private receipt locally
      const preimage = generateNotePreimage();
      const commitment = await buildNoteCommitment(preimage);
      const mem = getMemoryVault();
      if (mem) addNoteToVault(mem, { commitment, asset_id: "USDC", amount_7dp: String(Math.round(parseFloat(amount) * 1e7)), note_preimage: preimage, status: "prepared", created_at: new Date().toISOString() }, new Date().toISOString());
      detail("Private receipt ID (commitment)", commitment);

      const amount6 = BigInt(Math.round(parseFloat(amount) * 1e6));
      const prep = await ApiClient.prepareDeposit(token, `dep-${commitment.slice(2, 18)}`, {
        amount_usdc_6dp: amount6.toString(), source_chain: "arbitrum-sepolia", source_wallet_address: evm.address,
        vault_id: selectedVaultId, commitment, encrypted_note_payload_hash: commitment, policy_id: "shade:default-testnet-policy:v1"
      }) as { deposit_id: string; usdc_address: Hex; token_messenger_address: Hex; burn_tx_request: { args: [string, number, Hex, Hex, Hex, string, number, Hex] } };
      detail("Deposit id", prep.deposit_id);

      // ensure Arbitrum Sepolia
      if (typeof evm.switchChain === "function") {
        try { await evm.switchChain(arbitrumSepolia.id); } catch (e) { throw new Error(`Wrong network. Switch to Arbitrum Sepolia: ${(e as Error).message}`); }
      }
      const provider = await evm.getEthereumProvider();
      const account = evm.address as Hex;
      const chainHex = await provider.request({ method: "eth_chainId" }) as string;
      if (parseInt(chainHex, 16) !== arbitrumSepolia.id) throw new Error("Wrong network. Switch to Arbitrum Sepolia.");
      const walletClient = createWalletClient({ account, chain: arbitrumSepolia, transport: custom(provider) });
      const publicClient = createPublicClient({ chain: arbitrumSepolia, transport: custom(provider) });

      // approve only if needed
      setStage("approve_pending"); setStatusMsg("Waiting for wallet approval…");
      const allowance = await publicClient.readContract({ address: prep.usdc_address, abi: ERC20_ABI, functionName: "allowance", args: [account, prep.token_messenger_address] }) as bigint;
      if (allowance < amount6) {
        const approveHash = await walletClient.sendTransaction({ to: prep.usdc_address, data: encodeFunctionData({ abi: ERC20_ABI, functionName: "approve", args: [prep.token_messenger_address, amount6] }) });
        detail("Approve tx", approveHash);
        await publicClient.waitForTransactionReceipt({ hash: approveHash });
      }

      // move USDC privately (CCTP burn)
      setStage("burn_pending"); setStatusMsg("Moving USDC through the private bridge…");
      const a = prep.burn_tx_request.args;
      const burnHash = await walletClient.sendTransaction({ to: prep.token_messenger_address, data: encodeFunctionData({ abi: TM_ABI, functionName: "depositForBurnWithHook", args: [BigInt(a[0]), a[1], a[2], a[3], a[4], BigInt(a[5]), a[6], a[7]] }) });
      detail("Move USDC (CCTP burn) tx", burnHash);
      await publicClient.waitForTransactionReceipt({ hash: burnHash });

      setStage("burn_submitted");
      const sub = await ApiClient.burnSubmitted(token, prep.deposit_id, { burn_tx_hash: burnHash, source_chain: "arbitrum-sepolia", source_wallet_address: evm.address }) as { job_id: string };
      detail("Network helper job id", sub.job_id);

      setStage("relayer_validating"); setStatusMsg("Creating your private receipt…");
      for (let i = 0; i < 40; i++) {
        const j = await ApiClient.job(token, sub.job_id) as { status: string; result?: { state?: string; receiveDepositTxHash?: string; mintForwardTxHash?: string } };
        if (j.result?.mintForwardTxHash) { setStage("stellar_completing"); detail("Bridge delivery tx", j.result.mintForwardTxHash); }
        // Only "ready" when the note is actually registered on-chain (PART9 honesty).
        if (j.result?.state === "active" && j.result.receiveDepositTxHash) {
          detail("Private vault funding tx", j.result.receiveDepositTxHash);
          setStage("note_active"); setStatusMsg("Private deposit ready."); break;
        }
        if (j.result?.state === "burn_validated") setStatusMsg("Your burn was validated. The private proof step is pending — this is not fully automated yet.");
        if (j.status === "failed") { setStage("failed"); setStatusMsg("Bridge transfer failed or is still finalizing. Please retry."); break; }
        await new Promise((r) => setTimeout(r, 4000));
      }
    } catch (e) {
      setStage("failed");
      const msg = (e as Error).message;
      setStatusMsg(/Wrong network/.test(msg) ? msg : /reject|denied/i.test(msg) ? "Wallet rejected the transaction." : /not verified|deposit-ready/i.test(msg) ? "Vault is not verified yet." : msg);
    }
  }

  if (!authenticated) return <p className="text-neutral-300">Please log in to deposit.</p>;

  const step = STAGE_TO_STEP[stage];
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Deposit USDC privately</h1>
        <p className="text-sm text-neutral-400">Your wallet will approve USDC and move it into your private Shade vault. Shade cannot see your private note secrets.</p>
      </div>

      {vault.status === "loading" && <p className="text-sm text-neutral-400">Loading your vault…</p>}
      {vault.status === "none" && (
        <div className="rounded-lg border border-amber-800 bg-amber-950/30 p-4 text-sm">
          <p>Create a private vault first.</p>
          <Link href="/vault" className="mt-2 inline-block rounded bg-violet-600 px-3 py-1">Go to Vault Setup</Link>
        </div>
      )}
      {vault.status === "selected" && <p className="text-sm">Using Private Vault · <span className="text-green-400">Ready</span> ({vault.vault.recovery_policy_status})</p>}
      {vault.status === "multiple" && (
        <label className="block text-sm">Vault:
          <select value={vault.selected} onChange={(e) => setVault({ ...vault, selected: e.target.value })} className="ml-2 rounded bg-neutral-800 px-2 py-1">
            {vault.vaults.map((v) => <option key={v.vault_id} value={v.vault_id}>{v.vault_id.slice(0, 14)}… · Ready · {v.recovery_policy_status}</option>)}
          </select>
        </label>
      )}

      {selectedVaultId && (
        <>
          <label className="block text-sm">Amount (USDC)<input value={amount} onChange={(e) => setAmount(e.target.value)} className="ml-2 w-28 rounded bg-neutral-800 px-2 py-1" /></label>
          <button onClick={deposit} disabled={stage !== "idle" && stage !== "failed" && stage !== "note_active"} className="rounded-lg bg-violet-600 px-5 py-3 font-medium">Deposit Privately</button>

          {/* checkout progress */}
          <ol className="flex flex-wrap gap-2 text-xs">
            {CHECKOUT.map((label, i) => (
              <li key={label} className={`rounded px-3 py-1 ${step > i ? "bg-green-700" : step === i && stage !== "idle" ? "bg-violet-600" : "bg-neutral-800 text-neutral-400"}`}>{i + 1}. {label}</li>
            ))}
          </ol>
          {statusMsg && <p className={`text-sm ${stage === "failed" ? "text-red-400" : stage === "note_active" ? "text-green-400" : "text-neutral-300"}`}>{statusMsg}</p>}
        </>
      )}

      <div>
        <button onClick={() => setShowAdvanced((v) => !v)} className="text-xs text-neutral-500 underline">Advanced details</button>
        {showAdvanced && (
          <div className="mt-2 space-y-1 rounded bg-neutral-900 p-3 text-xs text-neutral-400">
            {Object.entries(details).length === 0 ? <p>No details yet.</p> : Object.entries(details).map(([k, v]) => <p key={k}><span className="text-neutral-500">{k}:</span> {v}</p>)}
          </div>
        )}
      </div>
    </div>
  );
}
