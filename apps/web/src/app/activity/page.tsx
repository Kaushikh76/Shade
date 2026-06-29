"use client";
import { useEffect, useState } from "react";
import { usePrivy } from "@privy-io/react-auth";
import { ApiClient } from "@/lib/api";
import { useAccessToken } from "@/lib/use-token";

type Act = { event_type: string; entity_type?: string; entity_id?: string; tx_hash?: string; created_at: string };

// PART11/12: map internal event types to human-readable product language.
const EVENT_LABEL: Record<string, string> = {
  "auth.login": "Signed in",
  "wallet.add": "Wallet linked",
  "wallet.sync_privy": "Wallets synced",
  "vault.create": "Private vault created",
  "vault.backup_verified": "Vault backup verified",
  "vault.restored": "Vault restored successfully",
  "note.backup": "Private receipt backed up",
  "deposit.prepare": "Deposit started",
  "deposit.burn_submitted": "USDC burn confirmed",
  "withdrawal.prepare": "Withdrawal started",
  "rfq.settle": "Private swap settled",
  "cctp_exit.prepare": "Private exit started"
};
function labelFor(ev: string): string { return EVENT_LABEL[ev] ?? ev.replace(/[._]/g, " "); }

export default function ActivityPage() {
  const { authenticated } = usePrivy();
  const getToken = useAccessToken();
  const [acts, setActs] = useState<Act[]>([]);
  const [err, setErr] = useState("");

  useEffect(() => {
    let stop = false;
    const tick = async () => {
      try { const token = await getToken(); if (token) setActs(((await ApiClient.activity(token)).activity as Act[])); }
      catch (e) { setErr((e as Error).message); }
    };
    tick();
    const id = setInterval(() => { if (!stop) tick(); }, 4000); // live-ish; backend also offers SSE /v1/activity/stream
    return () => { stop = true; clearInterval(id); };
  }, [getToken]);

  if (!authenticated) return <p>Please log in.</p>;
  return (
    <div className="space-y-3">
      <h1 className="text-2xl font-bold">Activity</h1>
      {err && <p className="text-red-400">{err}</p>}
      <ul className="space-y-1 text-sm">
        {acts.map((a, i) => (
          <li key={i} className="rounded bg-neutral-900 px-3 py-2">
            <span className="text-violet-300">{labelFor(a.event_type)}</span>
            {a.tx_hash ? <span className="text-neutral-500"> · tx {a.tx_hash.slice(0, 12)}…</span> : ""}
            <span className="float-right text-neutral-500">{new Date(a.created_at).toLocaleString()}</span>
            <details className="mt-1"><summary className="cursor-pointer text-xs text-neutral-600">Advanced details</summary>
              <div className="text-xs text-neutral-500">{a.event_type}{a.entity_type ? ` · ${a.entity_type} ${a.entity_id}` : ""}{a.tx_hash ? ` · ${a.tx_hash}` : ""}</div>
            </details>
          </li>
        ))}
        {acts.length === 0 && <li className="text-neutral-500">No activity yet.</li>}
      </ul>
    </div>
  );
}
