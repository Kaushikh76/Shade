// Typed API client. Sends the Privy access token as a Bearer header on every
// user-owned request. Never stores secrets.

const API = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8080";

export type ApiOpts = { token?: string | null; idempotencyKey?: string; body?: unknown; method?: string };

export async function api<T = unknown>(path: string, opts: ApiOpts = {}): Promise<T> {
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (opts.token) headers.authorization = `Bearer ${opts.token}`;
  if (opts.idempotencyKey) headers["idempotency-key"] = opts.idempotencyKey;
  const res = await fetch(`${API}${path}`, {
    method: opts.method ?? (opts.body ? "POST" : "GET"),
    headers,
    body: opts.body ? JSON.stringify(opts.body) : undefined,
    credentials: "include"
  });
  const text = await res.text();
  const json = text ? JSON.parse(text) : {};
  if (!res.ok) throw new Error((json as { error?: string }).error ?? `API ${res.status}`);
  return json as T;
}

// Convenience wrappers used across pages.
export const ApiClient = {
  health: () => api("/v1/health/full"),
  contracts: () => api("/v1/contracts"),
  me: (token: string) => api("/v1/me", { token }),
  wallets: (token: string) => api<{ wallets: unknown[] }>("/v1/me/wallets", { token }),
  createVault: (token: string, envelope: unknown) => api("/v1/note-vaults", { token, body: { envelope } }),
  listVaults: (token: string) => api<{ vaults: unknown[] }>("/v1/note-vaults", { token }),
  getVault: (token: string, vaultId: string) => api(`/v1/note-vaults/${vaultId}`, { token }),
  verifyBackup: (token: string, vaultId: string, body: unknown) => api(`/v1/note-vaults/${vaultId}/verify-backup`, { token, body }),
  markRestored: (token: string, vaultId: string) => api(`/v1/note-vaults/${vaultId}/mark-restored`, { token, method: "POST" }),
  syncPrivyWallets: (token: string, wallets: unknown[]) => api<{ synced: number; wallets: unknown[] }>("/v1/me/wallets/sync-privy", { token, body: { wallets } }),
  prepareDeposit: (token: string, idem: string, body: unknown) => api("/v1/deposits/prepare", { token, idempotencyKey: idem, body }),
  burnSubmitted: (token: string, depositId: string, body: unknown) => api(`/v1/deposits/${depositId}/burn-submitted`, { token, body }),
  job: (token: string, jobId: string) => api(`/v1/jobs/${jobId}`, { token }),
  activity: (token: string) => api<{ activity: unknown[] }>("/v1/activity", { token }),
  buildWithdrawXdr: (token: string, body: unknown) => api("/v1/withdrawals/build-xdr", { token, body }),
  submitWithdrawal: (token: string, body: unknown) => api("/v1/withdrawals/submit", { token, body })
};
