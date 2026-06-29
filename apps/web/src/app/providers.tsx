"use client";
import { PrivyProvider } from "@privy-io/react-auth";
import type { ReactNode } from "react";

// Privy is the canonical app identity. EVM is the funding wallet; Stellar (Freighter)
// is optional/fallback. Embedded wallets are enabled for users without one.
export function Providers({ children }: { children: ReactNode }) {
  const appId = process.env.NEXT_PUBLIC_PRIVY_APP_ID ?? "";
  return (
    <PrivyProvider
      appId={appId}
      config={{
        loginMethods: ["email", "wallet", "google"],
        appearance: { theme: "dark", accentColor: "#7c5cff" },
        embeddedWallets: { createOnLogin: "users-without-wallets" }
      }}
    >
      {children}
    </PrivyProvider>
  );
}
