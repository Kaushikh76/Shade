import {
  extractPrivyAccessToken, verifyPrivyAccessToken, requirePrivyUser, optionalPrivyUser,
  requireUserOwnedVault, __setVerificationKeyForTest, type PrivyDbAdapter
} from "./index.js";

// PHASE 11 auth-privy tests. Mints a local ES256 token with a generated P-256 key
// (the same algorithm Privy uses) and verifies the offline verification path,
// rejection of bad/expired/wrong-audience tokens, and ownership guards. No network.

const subtle = globalThis.crypto.subtle;
const APP_ID = "test-app-id";
const results: { name: string; ok: boolean; detail: string }[] = [];
const check = (name: string, ok: boolean, detail = "") => { results.push({ name, ok, detail }); console.log(`${ok ? "PASS" : "FAIL"}  ${name}${detail ? " — " + detail : ""}`); };

function b64url(bytes: Uint8Array): string {
  let s = ""; for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
const bs = (u: Uint8Array) => u as unknown as BufferSource;

async function mintToken(claims: Record<string, unknown>, signingKey: CryptoKey): Promise<string> {
  const header = b64url(new TextEncoder().encode(JSON.stringify({ alg: "ES256", typ: "JWT" })));
  const payload = b64url(new TextEncoder().encode(JSON.stringify(claims)));
  const input = new TextEncoder().encode(`${header}.${payload}`);
  const sig = new Uint8Array(await subtle.sign({ name: "ECDSA", hash: "SHA-256" }, signingKey, bs(input)));
  return `${header}.${payload}.${b64url(sig)}`;
}

const db: PrivyDbAdapter = {
  async upsertUserByPrivyId(privyUserId: string) { return `user-for-${privyUserId}`; },
  async userOwnsWallet() { return true; },
  async userOwnsVault(_userId: string, vaultId: string) { return vaultId === "vault-owned"; }
};

(async () => {
  try {
    const kp = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
    __setVerificationKeyForTest(kp.publicKey);
    const now = Math.floor(Date.now() / 1000);

    // extraction
    check("extractPrivyAccessToken reads Bearer header", extractPrivyAccessToken({ headers: { authorization: "Bearer abc.def.ghi" } }) === "abc.def.ghi");
    check("extractPrivyAccessToken reads privy-token cookie", extractPrivyAccessToken({ headers: { cookie: "x=1; privy-token=tok123; y=2" } }) === "tok123");
    check("extractPrivyAccessToken null when absent", extractPrivyAccessToken({ headers: {} }) === null);

    // valid token verifies
    const good = await mintToken({ sub: "did:privy:alice", aud: APP_ID, iss: "privy.io", iat: now, exp: now + 3600, sid: "sess1" }, kp.privateKey);
    const claims = await verifyPrivyAccessToken(good, { appId: APP_ID });
    check("valid Privy token verifies; DID is userId", claims.userId === "did:privy:alice" && claims.sessionId === "sess1");

    // requirePrivyUser syncs to db
    const req = { headers: { authorization: `Bearer ${good}` } };
    const u = await requirePrivyUser(db, req, { appId: APP_ID });
    check("requirePrivyUser returns synced user_id + DID", u.userId === "user-for-did:privy:alice" && u.privyUserId === "did:privy:alice");

    // tampered signature rejected
    const tampered = good.slice(0, -4) + "AAAA";
    const tamperFails = await verifyPrivyAccessToken(tampered, { appId: APP_ID }).then(() => false).catch(() => true);
    check("tampered token rejected", tamperFails);

    // expired token rejected
    const expired = await mintToken({ sub: "did:privy:bob", aud: APP_ID, iss: "privy.io", iat: now - 7200, exp: now - 3600 }, kp.privateKey);
    const expFails = await verifyPrivyAccessToken(expired, { appId: APP_ID }).then(() => false).catch(() => true);
    check("expired token rejected", expFails);

    // wrong audience rejected
    const wrongAud = await mintToken({ sub: "did:privy:bob", aud: "other-app", iss: "privy.io", iat: now, exp: now + 3600 }, kp.privateKey);
    const audFails = await verifyPrivyAccessToken(wrongAud, { appId: APP_ID }).then(() => false).catch(() => true);
    check("wrong audience rejected", audFails);

    // wrong issuer rejected
    const wrongIss = await mintToken({ sub: "did:privy:bob", aud: APP_ID, iss: "evil.io", iat: now, exp: now + 3600 }, kp.privateKey);
    const issFails = await verifyPrivyAccessToken(wrongIss, { appId: APP_ID }).then(() => false).catch(() => true);
    check("wrong issuer rejected", issFails);

    // token signed by a DIFFERENT key rejected (forged)
    const evilKp = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
    const forged = await mintToken({ sub: "did:privy:attacker", aud: APP_ID, iss: "privy.io", iat: now, exp: now + 3600 }, evilKp.privateKey);
    const forgedFails = await verifyPrivyAccessToken(forged, { appId: APP_ID }).then(() => false).catch(() => true);
    check("token signed by foreign key rejected", forgedFails);

    // optionalPrivyUser returns null on no token, user on valid
    check("optionalPrivyUser null without token", (await optionalPrivyUser(db, { headers: {} }, { appId: APP_ID })) === null);
    check("optionalPrivyUser resolves with token", (await optionalPrivyUser(db, req, { appId: APP_ID }))?.privyUserId === "did:privy:alice");

    // ownership guard
    let ownFail = false;
    try { await requireUserOwnedVault(db, u.userId, "someone-elses-vault"); } catch { ownFail = true; }
    check("requireUserOwnedVault rejects unowned vault (403)", ownFail);
    let ownOk = true;
    try { await requireUserOwnedVault(db, u.userId, "vault-owned"); } catch { ownOk = false; }
    check("requireUserOwnedVault allows owned vault", ownOk);
  } catch (e) {
    check("auth test harness", false, (e as Error).message.slice(0, 200));
  }

  const failed = results.filter((r) => !r.ok);
  if (failed.length) { console.error(`\nAUTH-PRIVY TESTS FAILED: ${failed.map((f) => f.name).join(", ")}`); process.exit(1); }
  console.log("\nAUTH-PRIVY TESTS PASS");
})();
