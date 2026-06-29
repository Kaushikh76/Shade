import "./globals.css";
import type { ReactNode } from "react";
import { Providers } from "./providers";
import { Nav } from "@/components/Nav";

export const metadata = { title: "Shade Protocol — Testnet", description: "Private cross-chain USDC settlement" };

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>
        <Providers>
          <div className="mx-auto max-w-4xl px-4 py-6">
            <div className="mb-4 rounded bg-amber-900/40 px-3 py-2 text-sm text-amber-200">
              ⚠️ Testnet only — do not use real funds. Notes are private; back up your recovery vault before depositing.
            </div>
            <Nav />
            <main className="mt-6">{children}</main>
          </div>
        </Providers>
      </body>
    </html>
  );
}
