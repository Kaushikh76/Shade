"use client";
import Link from "next/link";
import { usePrivy } from "@privy-io/react-auth";

export default function Home() {
  const { ready, authenticated, login } = usePrivy();
  return (
    <div className="space-y-6">
      <h1 className="text-3xl font-bold">Shade Protocol <span className="text-violet-400">Testnet</span></h1>
      <p className="max-w-2xl text-neutral-300">
        Private cross-chain USDC settlement. Deposit USDC from Arbitrum Sepolia into a shielded pool on
        Stellar via Circle CCTP, hold it as a private note, and spend or exit with a zero-knowledge proof —
        all from your own wallets. Your note vault is encrypted in your browser and recoverable after a
        cache wipe; the backend never sees your note secrets or private keys.
      </p>
      <div className="flex gap-3">
        {ready && !authenticated && <button onClick={() => login()} className="rounded bg-violet-600 px-4 py-2">Connect wallet (Privy)</button>}
        {ready && authenticated && <Link href="/dashboard" className="rounded bg-violet-600 px-4 py-2">Go to dashboard</Link>}
      </div>
      <ul className="list-disc pl-6 text-sm text-neutral-400">
        <li>Privy identity · EVM funding wallet · optional Stellar wallet (Freighter)</li>
        <li>Random vault master key, wrapped by passkey / Stellar / recovery-kit</li>
        <li>No deposit until your vault backup is verified</li>
      </ul>
    </div>
  );
}
