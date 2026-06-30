import "dotenv/config";
process.env.PRIVY_APP_ID = "test-deposit-app";
process.env.SHADE_NETWORK_MODE = "testnet";
// Deposit calldata needs the canonical pool id (public, not a secret).
process.env.SHIELDED_POOL_CONTRACT = process.env.SHIELDED_POOL_CONTRACT || "CDVEGBVXPIHKHCR7CJDJS4JVCMOVABEFBQ4HZQ7PKK6VIO3J3V5ZRTB5";
import Fastify from "fastify";
import { Wallet } from "ethers";
import { registerRoutes } from "./routes.js";
import { JobQueue } from "@shade/queue";
import { __setVerificationKeyForTest } from "@shade/auth-privy";
import {
  generateVaultMasterKey, generateNotePreimage, buildNoteCommitment, createEmptyNoteVault, addNoteToVault,
  createVaultEnvelope, wrapVaultKeyWithStellarSignature, randomBytes, type VaultNote, type EncryptedVaultEnvelope
} from "@shade/note-vault";

// PHASE 6 user-signed deposit API test. Asserts: prepare requires auth + verified
// vault + owned wallet, returns EVM tx requests (no server EVM key), and
// burn-submitted enqueues CCTP_INBOUND_AFTER_USER_BURN. No network.

const subtle = globalThis.crypto.subtle;
const APP_ID = "test-deposit-app";
const ORIGIN = "https://app.shade.test";
const results: { name: string; ok: boolean; detail: string }[] = [];
const check = (name: string, ok: boolean, detail = "") => { results.push({ name, ok, detail }); console.log(`${ok ? "PASS" : "FAIL"}  ${name}${detail ? " — " + detail : ""}`); };
const b64url = (b: Uint8Array) => { let s = ""; for (const x of b) s += String.fromCharCode(x); return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); };
const bs = (u: Uint8Array) => u as unknown as BufferSource;
const json = (r: { json: () => unknown }) => r.json() as Record<string, unknown>;
const toHexRun = (b: Uint8Array) => [...b].map((x) => x.toString(16).padStart(2, "0")).join("");

let signKey: CryptoKey;
async function tokenFor(did: string): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const h = b64url(new TextEncoder().encode(JSON.stringify({ alg: "ES256", typ: "JWT" })));
  const pl = b64url(new TextEncoder().encode(JSON.stringify({ sub: did, aud: APP_ID, iss: "privy.io", iat: now, exp: now + 3600 })));
  const sig = new Uint8Array(await subtle.sign({ name: "ECDSA", hash: "SHA-256" }, signKey, bs(new TextEncoder().encode(`${h}.${pl}`))));
  return `${h}.${pl}.${b64url(sig)}`;
}
async function makeVerifiedVault(app: ReturnType<typeof Fastify>, authH: Record<string, string>, privyUserId: string): Promise<string> {
  const master = generateVaultMasterKey();
  const pre = generateNotePreimage();
  const note: VaultNote = { commitment: await buildNoteCommitment(pre), asset_id: "USDC", amount_7dp: "5000000", note_preimage: pre, status: "prepared", created_at: "2026-06-30T00:00:00Z" };
  const vault = addNoteToVault(createEmptyNoteVault(`vault-${randomBytes(4).join("")}`, "2026-06-30T00:00:00Z"), note, "2026-06-30T00:00:00Z");
  const wrapper = await wrapVaultKeyWithStellarSignature(master, randomBytes(64), { stellar_address: "GTEST", wallet_source: "freighter" });
  const env: EncryptedVaultEnvelope = await createVaultEnvelope({ vault, masterKey: master, privyUserId, origin: ORIGIN, wrappers: [wrapper] });
  await app.inject({ method: "POST", url: "/v1/note-vaults", headers: authH, payload: { envelope: env } });
  await app.inject({ method: "POST", url: `/v1/note-vaults/${env.vault_id}/verify-backup`, headers: authH, payload: { verification: { vault_id: env.vault_id, decrypted_vault_hash: "0x" + "ab".repeat(16), commitments_hash: "0xcd", method: "stellar_ed25519_signature", verified_at_client: new Date().toISOString() } } });
  return env.vault_id;
}

(async () => {
  const app = Fastify({ logger: false });
  const queue = new JobQueue();
  try {
    const kp = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
    signKey = kp.privateKey;
    __setVerificationKeyForTest(kp.publicKey);
    await registerRoutes(app, undefined, queue);

    const did = "did:privy:depositor";
    const tok = await tokenFor(did);
    const authH = { authorization: `Bearer ${tok}` };
    const evmWallet = Wallet.createRandom().address;

    // link the EVM wallet (needs a signed nonce — but addWallet via the wallet route
    // requires a signature; for the test we link directly through the legacy path is
    // not available under Privy. Instead, link by adding a wallet row via /v1/me/wallets
    // requires signature. Use a Stellar-less direct approach: the deposit prepare
    // checks userOwnsWallet, so seed it through the note-vault user's wallet table.)
    // Simplest: add the wallet through the DB-backed addWallet via a nonce sign.
    const nonce = json(await app.inject({ method: "POST", url: "/v1/auth/nonce", payload: { wallet_type: "EVM", address: evmWallet } }));
    // (auth/nonce works without Privy; sign with a throwaway since we only need the row)
    // To own the wallet we must pass signature verification — use a real signer.
    const signer = Wallet.createRandom();
    const nonce2 = json(await app.inject({ method: "POST", url: "/v1/auth/nonce", payload: { wallet_type: "EVM", address: signer.address } }));
    const sig = await signer.signMessage(nonce2.message as string);
    const addRes = await app.inject({ method: "POST", url: "/v1/me/wallets", headers: authH, payload: { wallet_type: "EVM", address: signer.address, signature: sig, nonce: nonce2.nonce } });
    check("link EVM wallet to user", addRes.statusCode === 200 && !!json(addRes).wallet_id);
    void nonce;

    const vaultId = await makeVerifiedVault(app, authH, did);

    // prepare requires auth
    check("deposit prepare 401 without auth", (await app.inject({ method: "POST", url: "/v1/deposits/prepare", headers: { "idempotency-key": "k1234567" }, payload: {} })).statusCode === 401);

    // Unique commitment + idempotency key per run so the deterministic deposit_id
    // is fresh (avoids colliding with a prior run's row in the shared DB).
    const runTag = toHexRun(randomBytes(16));
    const prepBody = {
      amount_usdc_6dp: "1000000", source_chain: "arbitrum-sepolia", source_wallet_address: signer.address,
      vault_id: vaultId, commitment: "0x" + runTag + "ab".repeat(16), encrypted_note_payload_hash: "0x" + "cd".repeat(32), policy_id: "shade:default"
    };
    const prep = await app.inject({ method: "POST", url: "/v1/deposits/prepare", headers: { ...authH, "idempotency-key": `kdep-${runTag}` }, payload: prepBody });
    const pj = json(prep);
    check("prepare returns approval + burn tx requests (no server EVM key)", prep.statusCode === 200 && !!pj.approval_tx_request && !!pj.burn_tx_request && !!pj.mint_recipient, `status=${prep.statusCode}`);
    check("burn tx targets CCTP TokenMessenger, dest=Stellar", !!pj.token_messenger_address && pj.destination_domain === 27);

    // prepare with unowned wallet rejected
    const badWallet = await app.inject({ method: "POST", url: "/v1/deposits/prepare", headers: { ...authH, "idempotency-key": `kbad-${runTag}` }, payload: { ...prepBody, source_wallet_address: Wallet.createRandom().address } });
    check("prepare rejects unowned wallet (403)", badWallet.statusCode === 403);

    // prepare with unverified vault rejected
    const unverifiedVaultId = `vault-unverified-${randomBytes(4).join("")}`;
    // create but DON'T verify
    const m2 = generateVaultMasterKey();
    const pre2 = generateNotePreimage();
    const note2: VaultNote = { commitment: await buildNoteCommitment(pre2), asset_id: "USDC", amount_7dp: "5000000", note_preimage: pre2, status: "prepared", created_at: "2026-06-30T00:00:00Z" };
    const v2 = addNoteToVault(createEmptyNoteVault(unverifiedVaultId, "2026-06-30T00:00:00Z"), note2, "2026-06-30T00:00:00Z");
    const w2 = await wrapVaultKeyWithStellarSignature(m2, randomBytes(64), {});
    const env2 = await createVaultEnvelope({ vault: v2, masterKey: m2, privyUserId: did, origin: ORIGIN, wrappers: [w2] });
    await app.inject({ method: "POST", url: "/v1/note-vaults", headers: authH, payload: { envelope: env2 } });
    const unverifiedDep = await app.inject({ method: "POST", url: "/v1/deposits/prepare", headers: { ...authH, "idempotency-key": `kunv-${runTag}` }, payload: { ...prepBody, vault_id: unverifiedVaultId } });
    check("prepare rejects unverified vault (409)", unverifiedDep.statusCode === 409);

    // burn-submitted enqueues the validating relayer job
    const burnRes = await app.inject({ method: "POST", url: `/v1/deposits/${pj.deposit_id}/burn-submitted`, headers: authH, payload: { burn_tx_hash: "0x" + "11".repeat(32), source_chain: "arbitrum-sepolia", source_wallet_address: signer.address } });
    const bj = json(burnRes);
    check("burn-submitted enqueues relayer job", burnRes.statusCode === 200 && !!bj.job_id);
    const queued = await queue.getJob(bj.job_id as string);
    check("queued job is CCTP_INBOUND_AFTER_USER_BURN", queued?.job_type === "CCTP_INBOUND_AFTER_USER_BURN");
  } catch (e) {
    check("deposit-api test harness", false, (e as Error).message.slice(0, 200));
  }
  await app.close();
  await queue.close();
  const failed = results.filter((r) => !r.ok);
  if (failed.length) { console.error(`\nDEPOSIT API TESTS FAILED: ${failed.map((f) => f.name).join(", ")}`); process.exit(1); }
  console.log("\nDEPOSIT API TESTS PASS");
})();
