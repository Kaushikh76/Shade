"use client";
import { useEffect, useState } from "react";
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
        <ul className="text-sm text-neutral-400">{wallets.map((w) => <li key={w.address}>{w.walletClientType}: {w.address}</li>)}</ul>
      </section>
      <section>
        <h2 className="font-semibold">Note vaults ({vaults.length})</h2>
        <ul className="text-sm text-neutral-400">
          {vaults.map((v) => { const vv = v as { vault_id: string; backup_status: string; recovery_policy_status: string }; return (
            <li key={vv.vault_id}>{vv.vault_id.slice(0, 18)}… — backup: {vv.backup_status}, recovery: {vv.recovery_policy_status}</li>
          ); })}
          {vaults.length === 0 && <li>No vault yet — create one on the Vault page before depositing.</li>}
        </ul>
      </section>
      <section><h2 className="font-semibold">System health</h2><pre className="overflow-auto rounded bg-neutral-900 p-3 text-xs">{JSON.stringify(health, null, 2)}</pre></section>
    </div>
  );
}
