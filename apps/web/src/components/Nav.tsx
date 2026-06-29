"use client";
import Link from "next/link";
import { usePrivy } from "@privy-io/react-auth";

const LINKS = [["/", "Home"], ["/dashboard", "Dashboard"], ["/vault", "Vault"], ["/deposit", "Deposit"], ["/restore", "Restore"], ["/withdraw", "Withdraw"], ["/activity", "Activity"]] as const;

export function Nav() {
  const { ready, authenticated, login, logout, user } = usePrivy();
  return (
    <nav className="flex flex-wrap items-center gap-3 border-b border-neutral-800 pb-3 text-sm">
      <span className="font-semibold text-violet-400">Shade</span>
      {LINKS.map(([href, label]) => (
        <Link key={href} href={href} className="text-neutral-300 hover:text-white">{label}</Link>
      ))}
      <span className="ml-auto">
        {ready && authenticated ? (
          <button onClick={() => logout()} className="rounded bg-neutral-800 px-3 py-1">
            {user?.email?.address ?? user?.id?.slice(0, 14) ?? "Account"} · Logout
          </button>
        ) : (
          <button onClick={() => login()} className="rounded bg-violet-600 px-3 py-1">Login with Privy</button>
        )}
      </span>
    </nav>
  );
}
