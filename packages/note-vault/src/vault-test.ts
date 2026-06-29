import {
  generateVaultMasterKey, generateNotePreimage, buildNoteCommitment, createEmptyNoteVault, addNoteToVault,
  createVaultEnvelope, parseVaultEnvelope, decryptEnvelope, assertNoPlaintextNoteFields, redactVaultForLogs,
  wrapVaultKeyWithStellarSignature, unwrapVaultKeyWithStellarSignature,
  wrapVaultKeyWithRecoveryKitPassword, unwrapVaultKeyWithRecoveryKitPassword,
  wrapVaultKeyWithPasskeyPrf, unwrapVaultKeyWithPasskeyPrf,
  diagnosticWrapVaultKeyWithEvmSignature, diagnosticVerifyEvmSignatureStability,
  evaluateRecoveryPolicy, randomBytes, toHex, type VaultNote, type EncryptedVaultEnvelope
} from "./index.js";

// PHASE 11 note-vault unit tests — pure WebCrypto, no chain, no network.

const results: { name: string; ok: boolean; detail: string }[] = [];
const check = (name: string, ok: boolean, detail = "") => { results.push({ name, ok, detail }); console.log(`${ok ? "PASS" : "FAIL"}  ${name}${detail ? " — " + detail : ""}`); };
const eq = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((x, i) => x === b[i]);

const NOW = "2026-06-30T00:00:00.000Z";
const ORIGIN = "https://app.shade.test";
const PRIVY = "did:privy:testuser";

async function buildVaultEnvelope() {
  const master = generateVaultMasterKey();
  let vault = createEmptyNoteVault("vault-1", NOW);
  const preimage = generateNotePreimage();
  const note: VaultNote = { commitment: await buildNoteCommitment(preimage), asset_id: "USDC", amount_7dp: "5000000", note_preimage: preimage, status: "active", created_at: NOW };
  vault = addNoteToVault(vault, note, NOW);
  // a non-EVM wrapper (Stellar sig) so the envelope is restorable
  const stellarSig = randomBytes(64);
  const wrapper = await wrapVaultKeyWithStellarSignature(master, stellarSig, { stellar_address: "GTEST", wallet_source: "freighter" });
  const env = await createVaultEnvelope({ vault, masterKey: master, privyUserId: PRIVY, origin: ORIGIN, wrappers: [wrapper] });
  return { master, vault, note, env, stellarSig };
}

(async () => {
  try {
    const master = generateVaultMasterKey();
    check("generateVaultMasterKey is 32 random bytes", master.length === 32 && !eq(master, generateVaultMasterKey()));

    const { master: vmaster, vault, note, env, stellarSig } = await buildVaultEnvelope();

    // decrypt with a different (wrong) master key fails
    const restoredVault = await decryptEnvelope(env, generateVaultMasterKey()).catch(() => null);
    check("decrypt with WRONG master key fails", restoredVault === null);
    // decrypt with the correct master key succeeds
    const direct = await decryptEnvelope(env, vmaster);
    check("decrypt with correct master key restores vault", direct.notes[0]?.commitment === note.commitment);

    // correct roundtrip
    const { master: m2, env: env2, note: note2 } = await buildVaultEnvelope();
    const ok2 = await decryptEnvelope(env2, m2);
    check("encrypt/decrypt roundtrip restores the note", ok2.notes[0]?.commitment === note2.commitment && ok2.notes[0]?.note_preimage.owner_secret === note2.note_preimage.owner_secret);

    // wrapper unwrap roundtrip: unwrap master key with the Stellar sig, then decrypt
    const unwrapped = await unwrapVaultKeyWithStellarSignature(env.wrappers[0], stellarSig);
    const viaWrapper = await decryptEnvelope(env, unwrapped);
    check("unwrap via Stellar wrapper restores vault (cache-clear restore)", viaWrapper.notes[0]?.commitment === note.commitment);

    // wrong wrapper secret fails
    const wrongUnwrap = await unwrapVaultKeyWithStellarSignature(env.wrappers[0], randomBytes(64)).then(() => false).catch(() => true);
    check("wrong wrapper secret fails", wrongUnwrap);

    // corrupted ciphertext fails
    const corrupt: EncryptedVaultEnvelope = { ...env, ciphertext: env.ciphertext.slice(0, -4) + "AAAA" };
    const corruptFails = await decryptEnvelope(corrupt, vmaster).then(() => false).catch(() => true);
    check("corrupted ciphertext fails", corruptFails);

    // wrong AAD fails (tamper privy_user_id)
    const wrongAad: EncryptedVaultEnvelope = { ...env, aad: { ...env.aad, privy_user_id: "did:privy:attacker" } };
    const m3 = await unwrapVaultKeyWithStellarSignature(env.wrappers[0], stellarSig);
    const aadFails = await decryptEnvelope(wrongAad, m3).then(() => false).catch(() => true);
    check("wrong AAD (identity) fails", aadFails);

    // recovery-kit password wrapper roundtrip + wrong password fails
    const masterPw = generateVaultMasterKey();
    const pwWrapper = await wrapVaultKeyWithRecoveryKitPassword(masterPw, "correct horse battery staple", { file_id: "kit-1", created_at: NOW });
    const pwBack = await unwrapVaultKeyWithRecoveryKitPassword(pwWrapper, "correct horse battery staple");
    const pwWrong = await unwrapVaultKeyWithRecoveryKitPassword(pwWrapper, "wrong").then(() => false).catch(() => true);
    check("recovery-kit password wrapper roundtrip + wrong password fails", eq(pwBack, masterPw) && pwWrong);

    // passkey PRF wrapper (mock PRF output)
    const masterPrf = generateVaultMasterKey();
    const prfOut = randomBytes(32);
    const prfWrapper = await wrapVaultKeyWithPasskeyPrf(masterPrf, prfOut, { credential_id_hash: "h", backup_eligible: true, backup_state: true });
    const prfBack = await unwrapVaultKeyWithPasskeyPrf(prfWrapper, prfOut);
    check("passkey PRF wrapper roundtrip (mocked)", eq(prfBack, masterPrf) && prfWrapper.type === "passkey_prf");

    // EVM wrapper is diagnostic-only
    const evmWrapper = await diagnosticWrapVaultKeyWithEvmSignature(generateVaultMasterKey(), randomBytes(65), {});
    check("EVM signature wrapper marked diagnostic_only", evmWrapper.diagnostic_only === true && evmWrapper.metadata.diagnostic_only === true);
    const sig = randomBytes(65);
    check("diagnosticVerifyEvmSignatureStability detects (in)stability", diagnosticVerifyEvmSignatureStability(sig, sig) === true && diagnosticVerifyEvmSignatureStability(sig, randomBytes(65)) === false);

    // plaintext note fields rejected from an envelope-shaped object
    const dirty = { version: "shade-encrypted-vault-v1", owner_secret: "leak" };
    let rejected = false;
    try { assertNoPlaintextNoteFields(dirty); } catch { rejected = true; }
    check("assertNoPlaintextNoteFields rejects plaintext secret", rejected);
    // a clean envelope passes
    let clean = true;
    try { assertNoPlaintextNoteFields(env); } catch { clean = false; }
    check("clean envelope passes plaintext gate", clean);
    // parseVaultEnvelope validates + runs the gate
    check("parseVaultEnvelope roundtrips a clean envelope", parseVaultEnvelope(JSON.stringify(env)).vault_id === env.vault_id);

    // redaction hides ciphertext + wrapped keys
    const red = redactVaultForLogs(env) as EncryptedVaultEnvelope;
    check("redactVaultForLogs hides ciphertext + wrapped_key", (red.ciphertext as unknown) === "[REDACTED]" && (red.wrappers[0].wrapped_key as unknown) === "[REDACTED]");

    // recovery policy
    const stellarW = env.wrappers[0];
    check("EVM-only recovery rejected (insufficient)", evaluateRecoveryPolicy([evmWrapper], { mainnet: false, min: 1, allowEvmOnly: false }) === "insufficient");
    check("testnet: one non-EVM wrapper is sufficient", evaluateRecoveryPolicy([stellarW], { mainnet: false, min: 1, allowEvmOnly: false }) === "sufficient");
    check("mainnet: needs >=2 incl. strong wrapper", evaluateRecoveryPolicy([stellarW], { mainnet: true, min: 2, allowEvmOnly: false }) === "insufficient"
      && evaluateRecoveryPolicy([stellarW, pwWrapper], { mainnet: true, min: 2, allowEvmOnly: false }) === "strong");

    void toHex; void vault;
  } catch (e) {
    check("vault test harness", false, (e as Error).message.slice(0, 200));
  }

  const failed = results.filter((r) => !r.ok);
  if (failed.length) { console.error(`\nNOTE-VAULT TESTS FAILED: ${failed.map((f) => f.name).join(", ")}`); process.exit(1); }
  console.log("\nNOTE-VAULT TESTS PASS");
})();
