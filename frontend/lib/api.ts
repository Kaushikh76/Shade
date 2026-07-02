// Typed client for the Shade backend API. Attaches the Privy Bearer token on every
// call and an idempotency-key header on resource-creating POSTs.
import { getAccessToken } from "./token"

const BASE = process.env.NEXT_PUBLIC_API_BASE ?? "http://localhost:8080"

export type ApiError = { status: number; error: string; details?: unknown }

export function newIdempotencyKey(): string {
  return (globalThis.crypto?.randomUUID?.() ?? `idem-${Date.now()}-${Math.random().toString(16).slice(2)}`).replace(/-/g, "")
}

async function req<T>(
  path: string,
  opts: { method?: string; body?: unknown; idempotencyKey?: string; auth?: boolean } = {},
): Promise<T> {
  const headers: Record<string, string> = {}
  // Only set JSON content-type when there's actually a body — Fastify rejects an
  // empty body when content-type is application/json (bodyless POSTs like /v1/notes/coin).
  if (opts.body !== undefined) headers["content-type"] = "application/json"
  if (opts.auth !== false) {
    const token = await getAccessToken()
    if (token) headers["authorization"] = `Bearer ${token}`
  }
  if (opts.idempotencyKey) headers["idempotency-key"] = opts.idempotencyKey

  const res = await fetch(`${BASE}${path}`, {
    method: opts.method ?? "GET",
    headers,
    credentials: "include",
    body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
  })

  const text = await res.text()
  const data = text ? safeJson(text) : null
  if (!res.ok) {
    const e: ApiError = { status: res.status, error: (data as { error?: string })?.error ?? res.statusText, details: (data as { details?: unknown })?.details }
    throw e
  }
  return data as T
}

function safeJson(t: string): unknown {
  try { return JSON.parse(t) } catch { return t }
}

export const api = {
  get: <T>(path: string, auth = true) => req<T>(path, { method: "GET", auth }),
  post: <T>(path: string, body?: unknown, idempotencyKey?: string) => req<T>(path, { method: "POST", body, idempotencyKey }),
  patch: <T>(path: string, body?: unknown) => req<T>(path, { method: "PATCH", body }),
  del: <T>(path: string) => req<T>(path, { method: "DELETE" }),
  base: BASE,
}

// ---- typed shapes (only what the UI uses; extend per phase) ----
export type Me = {
  id: string
  privy_user_id: string | null
  display_name: string | null
  email: string | null
  wallets: Array<{ id: string; wallet_type: string; chain: string; address: string; is_primary: boolean }>
}
export type Contracts = {
  shadePool: string
  nullifierRegistry: string
  verifierWithdraw: string
  verifierTransfer: string
  verifierDepositNoteMint: string
  cctpForwarder: string
  usdcSac: string
  xlmSac: string
}
export type HealthFull = { ok: boolean; db: boolean; pool: string | null; network: string }
export type SyncWalletInput = { wallet_type: "EVM" | "STELLAR"; wallet_source?: string; chain: string; address: string; privy_wallet_id?: string }
