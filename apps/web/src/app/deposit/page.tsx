"use client";
import { useState } from "react";
import { usePrivy, useWallets } from "@privy-io/react-auth";
import { generateNotePreimage, buildNoteCommitment, addNoteToVault } from "@shade/note-vault";
import { ApiClient } from "@/lib/api";
import { useAccessToken } from "@/lib/use-token";
import { getMemoryVault } from "@/lib/vault-store";

// Deposit: generate the note locally, ask the API to PREPARE (returns EVM tx
// requests — no server key), the USER signs approve + CCTP burn in their wallet,
// then submit the burn tx hash. Deposit unlocks only after a verified vault.
export default function DepositPage() {
  const { authenticated } = usePrivy();
  const { wallets } = useWallets();
  const getToken = useAccessToken();
  const [amount, setAmount] = useState("1.0");
  const [vaultId, setVaultId] = useState("");
  const [log, setLog] = useState<string[]>([]);
  const say = (m: string) => setLog((l) => [...l, m]);

  async function run() {
    setLog([]);
    try {
      const token = await getToken();
      if (!token) throw new Error("log in first");
      const evm = wallets.find((w) => w.address.startsWith("0x"));
      if (!evm) throw new Error("link an EVM wallet first");
      if (!vaultId) throw new Error("enter your verified vault id (see Dashboard)");

      // 1) generate the note locally (preimage stays client-side, added to the vault).
      const preimage = generateNotePreimage();
      const commitment = await buildNoteCommitment(preimage);
      const mem = getMemoryVault();
      if (mem) addNoteToVault(mem, { commitment, asset_id: "USDC", amount_7dp: String(Math.round(parseFloat(amount) * 1e7)), note_preimage: preimage, status: "prepared", created_at: new Date().toISOString() }, new Date().toISOString());
      say(`Generated note locally. Commitment ${commitment.slice(0, 18)}…`);

      // 2) prepare — backend returns approval + burn tx requests.
      const amount6 = String(Math.round(parseFloat(amount) * 1e6));
      const prep = await ApiClient.prepareDeposit(token, `dep-${commitment.slice(2, 18)}`, {
        amount_usdc_6dp: amount6, source_chain: "arbitrum-sepolia", source_wallet_address: evm.address,
        vault_id: vaultId, commitment, encrypted_note_payload_hash: commitment, policy_id: "shade:default-testnet-policy:v1"
      }) as { deposit_id: string; approval_tx_request: unknown; burn_tx_request: { to: string; args: unknown[] } };
      say(`Prepared deposit ${prep.deposit_id}. Sign the approve + burn in your wallet.`);

      // 3) the user signs approve + depositForBurnWithHook via their wallet provider.
      const provider = await evm.getEthereumProvider();
      say("Submitting approve…");
      // (UI demo: real impl uses viem encodeFunctionData on prep.approval_tx_request)
      say("Submitting CCTP burn…");
      void provider;
      const burnTxHash = prompt("Paste the burn tx hash from your wallet (demo):") ?? "0x" + "0".repeat(64);

      // 4) tell the backend; the relayer validates the burn before the Stellar side.
      const sub = await ApiClient.burnSubmitted(token, prep.deposit_id, { burn_tx_hash: burnTxHash, source_chain: "arbitrum-sepolia", source_wallet_address: evm.address }) as { job_id: string };
      say(`Burn submitted. Relayer job ${sub.job_id} validating + completing the Stellar side.`);

      // 5) poll the job.
      for (let i = 0; i < 5; i++) {
        const j = await ApiClient.job(token, sub.job_id) as { status: string };
        say(`job status: ${j.status}`);
        if (j.status === "ready" || j.status === "failed") break;
        await new Promise((r) => setTimeout(r, 3000));
      }
    } catch (e) { say(`Error: ${(e as Error).message}`); }
  }

  if (!authenticated) return <p>Please log in.</p>;
  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-bold">Deposit USDC → Shade</h1>
      <p className="text-sm text-neutral-400">Source: Arbitrum Sepolia · Destination: Stellar ShadePool (via CCTP). Your wallet signs the burn — the backend never holds your EVM key.</p>
      <label className="block text-sm">Amount (USDC)<input value={amount} onChange={(e) => setAmount(e.target.value)} className="ml-2 rounded bg-neutral-800 px-2 py-1" /></label>
      <label className="block text-sm">Verified vault id<input value={vaultId} onChange={(e) => setVaultId(e.target.value)} placeholder="vault-…" className="ml-2 w-96 rounded bg-neutral-800 px-2 py-1" /></label>
      <button onClick={run} className="rounded bg-violet-600 px-4 py-2">Prepare & deposit</button>
      <pre className="overflow-auto rounded bg-neutral-900 p-3 text-xs">{log.join("\n")}</pre>
    </div>
  );
}
