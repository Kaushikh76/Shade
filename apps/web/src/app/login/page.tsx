"use client";
import { usePrivy, useWallets } from "@privy-io/react-auth";

export default function LoginPage() {
  const { ready, authenticated, login, user } = usePrivy();
  const { wallets } = useWallets();
  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-bold">Login</h1>
      {!authenticated ? (
        <button onClick={() => login()} className="rounded bg-violet-600 px-4 py-2" disabled={!ready}>Connect EVM wallet & sign in</button>
      ) : (
        <div className="space-y-2 text-sm">
          <p>Signed in as <span className="text-violet-400">{user?.id}</span></p>
          <p className="text-neutral-400">Linked wallets:</p>
          <ul className="list-disc pl-6">{wallets.map((w) => <li key={w.address}>{w.walletClientType}: {w.address}</li>)}</ul>
          <p className="text-neutral-500">Optionally connect a Stellar wallet (Freighter) on the Vault page for recovery + spends.</p>
        </div>
      )}
    </div>
  );
}
