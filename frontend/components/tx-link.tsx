"use client"

import { stellarTx, arbTx, shortHash } from "@/lib/explorer"
import { ExternalLink } from "lucide-react"

// A 0x-prefixed hash is an Arbitrum (EVM) tx; anything else is a Stellar tx hash.
export function inferChain(hash: string): "stellar" | "arb" {
  return hash.startsWith("0x") ? "arb" : "stellar"
}

// Clickable, truncated tx hash -> explorer. Chain auto-inferred from the hash
// unless pinned via the `chain` prop.
export function TxLink({ hash, chain, label }: { hash?: string | null; chain?: "stellar" | "arb"; label?: string }) {
  if (!hash) return <span className="text-muted-foreground">—</span>
  const c = chain ?? inferChain(hash)
  const href = c === "arb" ? arbTx(hash) : stellarTx(hash)
  return (
    <a
      href={href}
      target="_blank"
      rel="noreferrer"
      className="inline-flex items-center gap-1 font-mono text-xs text-[#2563eb] hover:underline"
      title={hash}
    >
      {label ?? shortHash(hash)}
      <ExternalLink className="h-3 w-3" />
    </a>
  )
}
