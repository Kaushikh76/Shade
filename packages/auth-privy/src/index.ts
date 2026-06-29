// @shade/auth-privy — verify Privy access tokens (ES256 JWT) and enforce ownership.
//
// Privy access tokens are ES256 JWTs (iss=privy.io, aud=appId, sub=Privy DID).
// We verify them OFFLINE with the dashboard verification key (an EC P-256 SPKI
// public key) via WebCrypto — no network call, no SDK version coupling. The Privy
// DID (sub) is the canonical user identity; client-supplied ids are never trusted.

const subtle = globalThis.crypto.subtle;

export type PrivyClaims = { userId: string; appId: string; issuer: string; issuedAt: number; expiration: number; sessionId?: string };

// Minimal request shape (works with Fastify/Node req): headers map.
export type HeadersLike = { authorization?: string; cookie?: string; [k: string]: string | string[] | undefined };
export type RequestLike = { headers: HeadersLike };

// DB adapter the guards use — implemented by the API's Store. Keeps this package
// free of a direct DB dependency.
export type PrivyDbAdapter = {
  upsertUserByPrivyId(privyUserId: string, profile?: { email?: string; primaryAuthMethod?: string }): Promise<string>; // returns user_id
  userOwnsWallet(userId: string, address: string, chain?: string): Promise<boolean>;
  userOwnsVault(userId: string, vaultId: string): Promise<boolean>;
};

function b64urlToBytes(s: string): Uint8Array {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4);
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
const bs = (u: Uint8Array): BufferSource => u as unknown as BufferSource;

function pemToSpki(pem: string): Uint8Array {
  const body = pem.replace(/-----BEGIN [^-]+-----/, "").replace(/-----END [^-]+-----/, "").replace(/\s+/g, "");
  const bin = atob(body);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

let cachedKey: CryptoKey | null = null;          // test/PEM override key
const jwksCache = new Map<string, CryptoKey>();  // kid -> imported key

// Import the verification key. Priority: test-injected key > PEM env
// (PRIVY_JWT_VERIFICATION_KEY) > JWKS fetched from Privy by app id (PRIVY_APP_ID),
// selecting the JWK by the token header `kid`.
async function verificationKey(opts?: { pem?: string; appId?: string; kid?: string }): Promise<CryptoKey> {
  if (cachedKey) return cachedKey;
  const keyPem = opts?.pem ?? process.env.PRIVY_JWT_VERIFICATION_KEY;
  if (keyPem) {
    cachedKey = await subtle.importKey("spki", bs(pemToSpki(keyPem)), { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
    return cachedKey;
  }
  const appId = opts?.appId ?? process.env.PRIVY_APP_ID;
  if (!appId) throw new Error("provide PRIVY_JWT_VERIFICATION_KEY or PRIVY_APP_ID for token verification");
  const kid = opts?.kid ?? "default";
  const cacheKey = `${appId}:${kid}`;
  if (jwksCache.has(cacheKey)) return jwksCache.get(cacheKey)!;
  const url = process.env.PRIVY_JWKS_URL ?? `https://auth.privy.io/api/v1/apps/${appId}/jwks.json`;
  const resp = await fetch(url);
  if (!resp.ok) throw new Error(`failed to fetch Privy JWKS (${resp.status})`);
  const { keys } = (await resp.json()) as { keys: Array<JsonWebKey & { kid?: string }> };
  const jwk = (opts?.kid ? keys.find((k) => k.kid === opts.kid) : undefined) ?? keys[0];
  if (!jwk) throw new Error("no matching JWK for token kid");
  const key = await subtle.importKey("jwk", jwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
  jwksCache.set(cacheKey, key);
  return key;
}
// Test seam: inject a pre-imported key (used by unit tests with a local keypair).
export function __setVerificationKeyForTest(key: CryptoKey | null): void { cachedKey = key; }

// Extract the Privy access token from the privy-token cookie or Authorization header.
export function extractPrivyAccessToken(request: RequestLike): string | null {
  const auth = request.headers.authorization;
  if (typeof auth === "string" && auth.startsWith("Bearer ")) return auth.slice(7).trim();
  const cookie = request.headers.cookie;
  if (typeof cookie === "string") {
    for (const part of cookie.split(";")) {
      const [k, v] = part.trim().split("=");
      if (k === "privy-token" && v) return decodeURIComponent(v);
    }
  }
  return null;
}

// Verify an ES256 Privy access token. Returns claims or throws.
export async function verifyPrivyAccessToken(token: string, opts?: { appId?: string; pem?: string; nowSec?: number }): Promise<PrivyClaims> {
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("malformed JWT");
  const [headerB64, payloadB64, sigB64] = parts;
  const header = JSON.parse(new TextDecoder().decode(b64urlToBytes(headerB64))) as { alg: string; kid?: string };
  if (header.alg !== "ES256") throw new Error(`unexpected alg ${header.alg}`);
  const signingInput = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
  const sig = b64urlToBytes(sigB64); // ES256 = raw r||s (64 bytes)
  const key = await verificationKey({ pem: opts?.pem, appId: opts?.appId, kid: header.kid });
  const ok = await subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, bs(sig), bs(signingInput));
  if (!ok) throw new Error("invalid token signature");
  const payload = JSON.parse(new TextDecoder().decode(b64urlToBytes(payloadB64))) as { sub: string; aud: string; iss: string; iat: number; exp: number; sid?: string };
  const now = opts?.nowSec ?? Math.floor(Date.now() / 1000);
  if (payload.iss !== "privy.io") throw new Error("bad issuer");
  const appId = opts?.appId ?? process.env.PRIVY_APP_ID;
  if (appId && payload.aud !== appId) throw new Error("audience mismatch");
  if (payload.exp <= now) throw new Error("token expired");
  return { userId: payload.sub, appId: payload.aud, issuer: payload.iss, issuedAt: payload.iat, expiration: payload.exp, sessionId: payload.sid };
}

function unauthorized(msg: string): never {
  const e = new Error(msg) as Error & { statusCode: number };
  e.statusCode = 401;
  throw e;
}
function forbidden(msg: string): never {
  const e = new Error(msg) as Error & { statusCode: number };
  e.statusCode = 403;
  throw e;
}

// Verify the token, sync the Privy user into the DB, and return the local user_id.
export async function requirePrivyUser(db: PrivyDbAdapter, request: RequestLike, opts?: { appId?: string; pem?: string }): Promise<{ userId: string; privyUserId: string; claims: PrivyClaims }> {
  const token = extractPrivyAccessToken(request);
  if (!token) unauthorized("Privy authentication required");
  let claims: PrivyClaims;
  try { claims = await verifyPrivyAccessToken(token, opts); } catch (e) { unauthorized(`invalid Privy token: ${(e as Error).message}`); }
  const userId = await db.upsertUserByPrivyId(claims.userId);
  return { userId, privyUserId: claims.userId, claims };
}

export async function optionalPrivyUser(db: PrivyDbAdapter, request: RequestLike, opts?: { appId?: string; pem?: string }): Promise<{ userId: string; privyUserId: string } | null> {
  const token = extractPrivyAccessToken(request);
  if (!token) return null;
  try {
    const claims = await verifyPrivyAccessToken(token, opts);
    const userId = await db.upsertUserByPrivyId(claims.userId);
    return { userId, privyUserId: claims.userId };
  } catch { return null; }
}

// Sync helpers (called after verify; the privyUser object comes from the Privy
// server SDK / linked-accounts when available).
export async function syncPrivyUserToDb(db: PrivyDbAdapter, privyUser: { id: string; email?: string; primaryAuthMethod?: string }): Promise<string> {
  return db.upsertUserByPrivyId(privyUser.id, { email: privyUser.email, primaryAuthMethod: privyUser.primaryAuthMethod });
}

export async function requireUserOwnedWallet(db: PrivyDbAdapter, userId: string, walletAddress: string, chain?: string): Promise<void> {
  if (!(await db.userOwnsWallet(userId, walletAddress, chain))) forbidden("wallet is not linked to the authenticated user");
}
export async function requireUserOwnedVault(db: PrivyDbAdapter, userId: string, vaultId: string): Promise<void> {
  if (!(await db.userOwnsVault(userId, vaultId))) forbidden("vault does not belong to the authenticated user");
}
