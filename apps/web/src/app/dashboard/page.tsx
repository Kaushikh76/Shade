"use client";
import { useEffect, useState } from "react";
import Link from "next/link";
import { usePrivy, useWallets } from "@privy-io/react-auth";
import { ApiClient } from "@/lib/api";
import { useAccessToken } from "@/lib/use-token";

export default function Dashboard() {
  const { authenticated, user } = usePrivy();
  const { wallets } = useWallets();
  const getToken = useAccessToken();
  const [vaults, setVaults] = useState<unknown[]>([]);
  const [health, setHealth] = useState<unknown>(null);
  const [err, setErr] = useState<string>("");

  useEffect(() => {
    (async () => {
      try {
        setHealth(await ApiClient.health());
        const token = await getToken();
        if (!token) return;
        // FIX2: sync the user's Privy linked EVM/Stellar wallets into the backend.
        const toSync = wallets.map((w) => ({
          wallet_type: w.address.startsWith("0x") ? "EVM" : "STELLAR",
          wallet_source: w.walletClientType === "privy" ? "privy_embedded" : "external",
          chain: w.address.startsWith("0x") ? "arbitrum-sepolia" : "stellar-testnet",
          address: w.address, privy_wallet_id: w.address
        }));
        if (toSync.length) await ApiClient.syncPrivyWallets(token, toSync);
        setVaults((await ApiClient.listVaults(token)).vaults);
      } catch (e) { setErr((e as Error).message); }
    })();
  }, [getToken, authenticated, wallets]);

  if (!authenticated) return <p>Please log in.</p>;
  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Dashboard</h1>
      {err && <p className="text-red-400">{err}</p>}
      <section><h2 className="font-semibold">User</h2><p className="text-sm text-neutral-400">{user?.id}</p></section>
      <section>
        <h2 className="font-semibold">Connected wallets</h2>
        <ul className="text-sm text-neutral-400">{wallets.map((w) => {
          const id = Number((w.chainId ?? "").toString().replace("eip155:", "")) || 0;
          const onArb = id === 421614;
          return <li key={w.address}>{w.walletClientType}: {w.address} <span className={onArb ? "text-green-400" : "text-amber-400"}>· chain {id || "?"}{onArb ? " (Arbitrum Sepolia ✓)" : " (deposit needs 421614)"}</span></li>;
        })}</ul>
      </section>
      <section>
        <h2 className="font-semibold">Private vault</h2>
        {(() => {
          const ready = (vaults as Array<{ vault_id: string; backup_status: string; recovery_policy_status: string }>).filter((v) => v.backup_status === "verified" && (v.recovery_policy_status === "sufficient" || v.recovery_policy_status === "strong"));
          const onArb = wallets.some((w) => Number((w.chainId ?? "").toString().replace("eip155:", "")) === 421614);
          if (ready.length === 0) return <div className="text-sm"><p className="text-amber-400">Needs setup</p><p className="text-neutral-400">Next action: <Link href="/vault" className="text-violet-400 underline">Create your private vault</Link></p></div>;
          const strong = ready.some((v) => v.recovery_policy_status === "strong");
          return <div className="text-sm">
            <p className="text-green-400">Ready</p>
            <p className="text-neutral-400">Recovery: {strong ? "Strong" : "Basic"} · Wallet: {onArb ? "Connected (Arbitrum Sepolia)" : <span className="text-amber-400">Wrong network — switch to Arbitrum Sepolia</span>}</p>
            <p className="text-neutral-400">Next action: <Link href="/deposit" className="text-violet-400 underline">Deposit privately</Link> · <Link href="/restore" className="text-violet-400 underline">Restore</Link></p>
          </div>;
        })()}
      </section>
      <section>
        <details><summary className="cursor-pointer text-xs text-neutral-600">Advanced: system health</summary>
          <pre className="mt-2 overflow-auto rounded bg-neutral-900 p-3 text-xs text-neutral-500">{JSON.stringify(health, null, 2)}</pre>
        </details>
      </section>
    </div>
  );
}
