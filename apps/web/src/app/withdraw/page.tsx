"use client";
import { useState } from "react";
import { usePrivy } from "@privy-io/react-auth";
import { ApiClient } from "@/lib/api";
import { useAccessToken } from "@/lib/use-token";
import { connectFreighter, signWithdrawXdr } from "@/lib/stellar-signer";

// Withdraw (Path A): the backend builds the unsigned Soroban XDR, the user's
// Stellar wallet (Freighter) signs it, and the backend broadcasts the signed XDR.
// No user Stellar secret touches the backend (audit.md PHASE 7).
export default function WithdrawPage() {
  const { authenticated } = usePrivy();
  const getToken = useAccessToken();
  const [to, setTo] = useState("");
  const [proofHex, setProofHex] = useState("");
  const [publicHex, setPublicHex] = useState("");
  const [log, setLog] = useState<string[]>([]);
  const say = (m: string) => setLog((l) => [...l, m]);

  async function run() {
    setLog([]);
    try {
      const token = await getToken();
      if (!token) throw new Error("log in first");
      say("Requesting unsigned withdraw XDR from backend…");
      const { unsigned_xdr } = await ApiClient.buildWithdrawXdr(token, { to, proofHex, publicHex }) as { unsigned_xdr: string };
      const addr = await connectFreighter();
      say(`Signing with Freighter (${addr.slice(0, 8)}…)…`);
      const signedXdr = await signWithdrawXdr(unsigned_xdr, addr);
      say("Submitting signed XDR for broadcast…");
      const res = await ApiClient.submitWithdrawal(token, { signedXdr }) as { job_id: string };
      say(`Submitted. Relayer broadcast job ${res.job_id}.`);
    } catch (e) { say(`Error: ${(e as Error).message}`); }
  }

  if (!authenticated) return <p>Please log in.</p>;
  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-bold">Withdraw / Exit</h1>
      <p className="text-sm text-neutral-400">The contract requires your Stellar signature (Freighter). The backend only builds + broadcasts — it never holds your secret. (Proof-authorized no-wallet exits are a documented future path.)</p>
      <label className="block text-sm">Recipient (G…)<input value={to} onChange={(e) => setTo(e.target.value)} className="ml-2 w-96 rounded bg-neutral-800 px-2 py-1" /></label>
      <label className="block text-sm">proofHex<input value={proofHex} onChange={(e) => setProofHex(e.target.value)} className="ml-2 w-96 rounded bg-neutral-800 px-2 py-1" /></label>
      <label className="block text-sm">publicHex<input value={publicHex} onChange={(e) => setPublicHex(e.target.value)} className="ml-2 w-96 rounded bg-neutral-800 px-2 py-1" /></label>
      <button onClick={run} className="rounded bg-violet-600 px-4 py-2">Build → sign → broadcast</button>
      <pre className="overflow-auto rounded bg-neutral-900 p-3 text-xs">{log.join("\n")}</pre>
    </div>
  );
}
