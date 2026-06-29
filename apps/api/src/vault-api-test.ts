import "dotenv/config";
import { resolve } from "node:path";
process.env.PRIVY_APP_ID = "test-vault-app";
process.env.SHADE_NETWORK_MODE = "testnet";
import Fastify from "fastify";
import { registerRoutes } from "./routes.js";
import { JobQueue } from "@shade/queue";
import { __setVerificationKeyForTest } from "@shade/auth-privy";
import {
  generateVaultMasterKey, generateNotePreimage, buildNoteCommitment, createEmptyNoteVault, addNoteToVault,
  createVaultEnvelope, wrapVaultKeyWithStellarSignature, diagnosticWrapVaultKeyWithEvmSignature, randomBytes,
  type VaultNote, type EncryptedVaultEnvelope
} from "@shade/note-vault";

// PHASE 4 note-vault backend API test. Privy-authenticated (local P-256 key);
// drives create -> list -> verify-backup -> deposit-ready, recovery policy, plaintext
// rejection, and cross-user ownership. No network beyond the in-process Fastify.

const subtle = globalThis.crypto.subtle;
const APP_ID = "test-vault-app";
const ORIGIN = "https://app.shade.test";
const results: { name: string; ok: boolean; detail: string }[] = [];
const check = (name: string, ok: boolean, detail = "") => { results.push({ name, ok, detail }); console.log(`${ok ? "PASS" : "FAIL"}  ${name}${detail ? " — " + detail : ""}`); };
const b64url = (b: Uint8Array) => { let s = ""; for (const x of b) s += String.fromCharCode(x); return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); };
const bs = (u: Uint8Array) => u as unknown as BufferSource;
const json = (r: { json: () => unknown }) => r.json() as Record<string, unknown>;

let signKey: CryptoKey;
async function tokenFor(did: string): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const h = b64url(new TextEncoder().encode(JSON.stringify({ alg: "ES256", typ: "JWT" })));
  const p = b64url(new TextEncoder().encode(JSON.stringify({ sub: did, aud: APP_ID, iss: "privy.io", iat: now, exp: now + 3600 })));
  const sig = new Uint8Array(await subtle.sign({ name: "ECDSA", hash: "SHA-256" }, signKey, bs(new TextEncoder().encode(`${h}.${p}`))));
  return `${h}.${p}.${b64url(sig)}`;
}

async function makeEnvelope(privyUserId: string, evmOnly = false): Promise<{ env: EncryptedVaultEnvelope }> {
  const master = generateVaultMasterKey();
  const pre = generateNotePreimage();
  const note: VaultNote = { commitment: await buildNoteCommitment(pre), asset_id: "USDC", amount_7dp: "5000000", note_preimage: pre, status: "active", created_at: "2026-06-30T00:00:00Z" };
  const vault = addNoteToVault(createEmptyNoteVault(`vault-${randomBytes(4).join("")}`, "2026-06-30T00:00:00Z"), note, "2026-06-30T00:00:00Z");
  const wrappers = evmOnly
    ? [await diagnosticWrapVaultKeyWithEvmSignature(master, randomBytes(65), {})]
    : [await wrapVaultKeyWithStellarSignature(master, randomBytes(64), { stellar_address: "GTEST", wallet_source: "freighter" })];
  const env = await createVaultEnvelope({ vault, masterKey: master, privyUserId, origin: ORIGIN, wrappers });
  return { env };
}

(async () => {
  const app = Fastify({ logger: false });
  const queue = new JobQueue();
  try {
    const kp = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
    signKey = kp.privateKey;
    __setVerificationKeyForTest(kp.publicKey);
    await registerRoutes(app, undefined, queue);

    const tok = await tokenFor("did:privy:vaultuser");
    const authH = { authorization: `Bearer ${tok}` };

    // unauthenticated create rejected
    const { env } = await makeEnvelope("did:privy:vaultuser");
    check("POST /v1/note-vaults 401 without Privy token", (await app.inject({ method: "POST", url: "/v1/note-vaults", payload: { envelope: env } })).statusCode === 401);

    // create with Stellar wrapper -> sufficient
    const created = await app.inject({ method: "POST", url: "/v1/note-vaults", headers: authH, payload: { envelope: env } });
    const cj = json(created);
    check("create vault returns sufficient recovery policy", created.statusCode === 200 && cj.recovery_policy_status === "sufficient" && cj.backup_status === "created", `policy=${cj.recovery_policy_status}`);

    // list
    const list = json(await app.inject({ method: "GET", url: "/v1/note-vaults", headers: authH }));
    check("GET /v1/note-vaults lists the vault", Array.isArray(list.vaults) && (list.vaults as unknown[]).length >= 1);

    // before verify-backup: not deposit-ready
    const before = json(await app.inject({ method: "GET", url: `/v1/note-vaults/${env.vault_id}`, headers: authH }));
    check("vault not deposit-ready before verify-backup", before.backup_status === "created");

    // verify-backup -> ready
    const verified = json(await app.inject({ method: "POST", url: `/v1/note-vaults/${env.vault_id}/verify-backup`, headers: authH }));
    check("verify-backup -> verified + deposit ready", verified.backup_status === "verified" && verified.ready === true, `ready=${verified.ready}`);

    // EVM-only vault -> insufficient policy (cannot deposit)
    const { env: evmEnv } = await makeEnvelope("did:privy:vaultuser", true);
    const evmCreated = json(await app.inject({ method: "POST", url: "/v1/note-vaults", headers: authH, payload: { envelope: evmEnv } }));
    check("EVM-only vault is insufficient (deposit blocked)", evmCreated.recovery_policy_status === "insufficient");

    // plaintext envelope rejected
    const dirty = { ...env, ciphertext: env.ciphertext, wrappers: env.wrappers, note_preimage: { owner_secret: "leak" } } as unknown;
    const dirtyRes = await app.inject({ method: "POST", url: "/v1/note-vaults", headers: authH, payload: { envelope: dirty } });
    check("plaintext-field envelope rejected", dirtyRes.statusCode >= 400);

    // cross-user ownership: another DID cannot read this vault
    const otherTok = await tokenFor("did:privy:attacker");
    const cross = await app.inject({ method: "GET", url: `/v1/note-vaults/${env.vault_id}`, headers: { authorization: `Bearer ${otherTok}` } });
    check("another user cannot read the vault (404)", cross.statusCode === 404);
  } catch (e) {
    check("vault-api test harness", false, (e as Error).message.slice(0, 200));
  }
  await app.close();
  await queue.close();
  const failed = results.filter((r) => !r.ok);
  if (failed.length) { console.error(`\nVAULT API TESTS FAILED: ${failed.map((f) => f.name).join(", ")}`); process.exit(1); }
  console.log("\nVAULT API TESTS PASS");
  void resolve;
})();
