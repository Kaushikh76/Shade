// @shade/note-vault — browser-safe note vault crypto (WebCrypto only).
//
// Security model (see docs/note-vault-recovery.md):
//  - a random 256-bit `vault_master_key` (never derived from an EVM signature)
//    encrypts the note vault with AES-256-GCM bound to AAD;
//  - the master key is WRAPPED (not stored) by recovery methods (passkey PRF,
//    Stellar Ed25519 signature, recovery-kit passphrase; EVM is diagnostic-only);
//  - the backend stores only ciphertext + wrapped keys and must reject plaintext.
//
// No node:crypto. Uses globalThis.crypto.subtle (present in browsers and Node 18+).

const subtle = globalThis.crypto.subtle;
const te = new TextEncoder();
const td = new TextDecoder();
// WebCrypto's lib types want ArrayBuffer-backed BufferSource; our Uint8Arrays are
// always ArrayBuffer-backed at runtime, so this cast is safe and avoids the
// SharedArrayBuffer union in the strict lib typings.
const bs = (u?: Uint8Array): BufferSource | undefined => u as unknown as BufferSource;

// ---------- encoding helpers (browser + node safe) ----------
export function toB64(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}
export function fromB64(b64: string): Uint8Array {
  const s = atob(b64);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}
export function toHex(bytes: Uint8Array): string {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}
export function randomBytes(n: number): Uint8Array {
  const b = new Uint8Array(n);
  globalThis.crypto.getRandomValues(b);
  return b;
}

// ---------- types ----------
export type VaultMasterKey = Uint8Array; // 32 raw bytes
export type NotePreimage = {
  owner_secret: string;
  spend_secret: string;
  blinding: string;
  nonce: string;
  memo_commitment: string;
  compliance_tag: string;
  source_context: string;
};
export type VaultNote = {
  commitment: string;        // protocol (Poseidon) commitment supplied by the prover/coinutils
  asset_id: string;
  amount_7dp: string;
  note_preimage: NotePreimage;
  deposit_id?: string;
  status: "prepared" | "active" | "spent";
  created_at: string;
};
export type NoteVault = {
  version: "shade-note-vault-v1";
  vault_id: string;
  created_at: string;
  updated_at: string;
  notes: VaultNote[];
};
export type WrapperType = "passkey_prf" | "stellar_ed25519_signature" | "recovery_file_secret" | "recovery_kit_password" | "evm_signature";
export type VaultWrapper = {
  id: string;
  type: WrapperType;
  status: "active" | "revoked";
  kdf: "HKDF-SHA256" | "PBKDF2-SHA256";
  salt: string;              // base64
  wrapped_key: string;       // base64(iv(12) || aesgcm-ciphertext) of the master key
  diagnostic_only?: boolean; // true for the EVM wrapper
  metadata: Record<string, unknown>;
};
export type VaultAad = { app: string; origin: string; vault_id: string; privy_user_id: string; vault_version: number };
export type EncryptedVaultEnvelope = {
  version: "shade-encrypted-vault-v1";
  vault_id: string;
  privy_user_id: string;
  cipher: { name: "AES-256-GCM"; iv: string; tagLength: 128 };
  aad: VaultAad;
  ciphertext: string;        // base64
  wrappers: VaultWrapper[];
};

// ---------- core crypto ----------
async function aesKey(raw: Uint8Array): Promise<CryptoKey> {
  return subtle.importKey("raw", bs(raw)!, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}
// PART1 fix: build the AES-GCM params and ONLY include `additionalData` when an AAD
// is actually provided. Passing `additionalData: undefined` makes some browsers'
// SubtleCrypto throw "AeadParams: additionalData: Not a BufferSource", which crashed
// vault creation (the no-AAD wrapper encryption path).
function aesGcmParams(iv: Uint8Array, aad?: Uint8Array): AesGcmParams {
  const params: AesGcmParams = { name: "AES-GCM", iv: iv as unknown as BufferSource, tagLength: 128 };
  if (aad !== undefined) params.additionalData = aad as unknown as BufferSource;
  return params;
}
async function aesGcmEncrypt(rawKey: Uint8Array, plaintext: Uint8Array, aad?: Uint8Array): Promise<{ iv: Uint8Array; ct: Uint8Array }> {
  const iv = randomBytes(12);
  const key = await aesKey(rawKey);
  const ct = new Uint8Array(await subtle.encrypt(aesGcmParams(iv, aad), key, bs(plaintext)!));
  return { iv, ct };
}
async function aesGcmDecrypt(rawKey: Uint8Array, iv: Uint8Array, ct: Uint8Array, aad?: Uint8Array): Promise<Uint8Array> {
  const key = await aesKey(rawKey);
  return new Uint8Array(await subtle.decrypt(aesGcmParams(iv, aad), key, bs(ct)!));
}
async function hkdf(ikm: Uint8Array, salt: Uint8Array, info: string): Promise<Uint8Array> {
  const base = await subtle.importKey("raw", bs(ikm)!, "HKDF", false, ["deriveBits"]);
  return new Uint8Array(await subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: bs(salt)!, info: bs(te.encode(info))! }, base, 256));
}
async function pbkdf2(password: string, salt: Uint8Array, iterations: number): Promise<Uint8Array> {
  const base = await subtle.importKey("raw", bs(te.encode(password))!, "PBKDF2", false, ["deriveBits"]);
  return new Uint8Array(await subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: bs(salt)!, iterations }, base, 256));
}
async function sha256Hex(bytes: Uint8Array): Promise<string> {
  return toHex(new Uint8Array(await subtle.digest("SHA-256", bs(bytes)!)));
}

// ---------- vault construction ----------
export function generateVaultMasterKey(): VaultMasterKey {
  return randomBytes(32);
}
export function generateNotePreimage(): NotePreimage {
  const h = () => toHex(randomBytes(31));
  return { owner_secret: h(), spend_secret: h(), blinding: h(), nonce: h(), memo_commitment: h(), compliance_tag: h(), source_context: h() };
}
// Vault-local integrity commitment (sha256 of the preimage). NOT the on-chain
// Poseidon protocol commitment — that is computed by the prover/coinutils and
// supplied as VaultNote.commitment. Used to detect vault tampering on restore.
export async function buildNoteCommitment(preimage: NotePreimage): Promise<string> {
  return "0x" + (await sha256Hex(te.encode(JSON.stringify(preimage))));
}
export function createEmptyNoteVault(vaultId: string, now: string): NoteVault {
  return { version: "shade-note-vault-v1", vault_id: vaultId, created_at: now, updated_at: now, notes: [] };
}
export function addNoteToVault(vault: NoteVault, note: VaultNote, now: string): NoteVault {
  return { ...vault, updated_at: now, notes: [...vault.notes.filter((n) => n.commitment !== note.commitment), note] };
}

const AAD_BYTES = (aad: VaultAad) => te.encode(JSON.stringify(aad));

export async function encryptNoteVault(vault: NoteVault, masterKey: VaultMasterKey, aad: VaultAad): Promise<{ ciphertext: string; iv: string }> {
  const { iv, ct } = await aesGcmEncrypt(masterKey, te.encode(JSON.stringify(vault)), AAD_BYTES(aad));
  return { ciphertext: toB64(ct), iv: toB64(iv) };
}
export async function decryptNoteVault(ciphertext: string, iv: string, masterKey: VaultMasterKey, aad: VaultAad): Promise<NoteVault> {
  const pt = await aesGcmDecrypt(masterKey, fromB64(iv), fromB64(ciphertext), AAD_BYTES(aad));
  return JSON.parse(td.decode(pt)) as NoteVault;
}

export async function createVaultEnvelope(args: {
  vault: NoteVault; masterKey: VaultMasterKey; privyUserId: string; origin: string; wrappers: VaultWrapper[];
}): Promise<EncryptedVaultEnvelope> {
  const aad: VaultAad = { app: "Shade Protocol", origin: args.origin, vault_id: args.vault.vault_id, privy_user_id: args.privyUserId, vault_version: 1 };
  const { ciphertext, iv } = await encryptNoteVault(args.vault, args.masterKey, aad);
  return {
    version: "shade-encrypted-vault-v1", vault_id: args.vault.vault_id, privy_user_id: args.privyUserId,
    cipher: { name: "AES-256-GCM", iv, tagLength: 128 }, aad, ciphertext, wrappers: args.wrappers
  };
}
export function parseVaultEnvelope(json: string): EncryptedVaultEnvelope {
  const env = JSON.parse(json) as EncryptedVaultEnvelope;
  validateVaultEnvelope(env);
  return env;
}
export function validateVaultEnvelope(env: EncryptedVaultEnvelope): void {
  if (env?.version !== "shade-encrypted-vault-v1") throw new Error("bad envelope version");
  if (!env.vault_id || !env.privy_user_id || !env.ciphertext || env.cipher?.name !== "AES-256-GCM") throw new Error("malformed envelope");
  if (!Array.isArray(env.wrappers)) throw new Error("envelope missing wrappers");
  assertNoPlaintextNoteFields(env);
}

// Decrypt the vault directly from an envelope given the master key.
export async function decryptEnvelope(env: EncryptedVaultEnvelope, masterKey: VaultMasterKey): Promise<NoteVault> {
  return decryptNoteVault(env.ciphertext, env.cipher.iv, masterKey, env.aad);
}

// ---------- security gates ----------
const PLAINTEXT_FORBIDDEN = ["owner_secret", "spend_secret", "blinding", "nonce", "note_preimage", "vault_master_key", "raw_signature", "private_key", "secret"];
export function assertNoPlaintextNoteFields(obj: unknown): void {
  const walk = (v: unknown): void => {
    if (Array.isArray(v)) { v.forEach(walk); return; }
    if (v && typeof v === "object") {
      for (const [k, val] of Object.entries(v as Record<string, unknown>)) {
        if (PLAINTEXT_FORBIDDEN.includes(k)) throw new Error(`plaintext note field "${k}" is forbidden in stored/transmitted vault data`);
        walk(val);
      }
    }
  };
  walk(obj);
}
export function redactVaultForLogs(obj: unknown): unknown {
  const walk = (v: unknown): unknown => {
    if (Array.isArray(v)) return v.map(walk);
    if (v && typeof v === "object") {
      const out: Record<string, unknown> = {};
      for (const [k, val] of Object.entries(v as Record<string, unknown>)) {
        out[k] = PLAINTEXT_FORBIDDEN.includes(k) || k === "wrapped_key" || k === "ciphertext" ? "[REDACTED]" : walk(val);
      }
      return out;
    }
    return v;
  };
  return walk(obj);
}

// ---------- recovery wrappers ----------
async function wrapWithKey(wrappingKey: Uint8Array, masterKey: VaultMasterKey): Promise<string> {
  const { iv, ct } = await aesGcmEncrypt(wrappingKey, masterKey);
  const blob = new Uint8Array(iv.length + ct.length);
  blob.set(iv, 0); blob.set(ct, iv.length);
  return toB64(blob);
}
async function unwrapWithKey(wrappingKey: Uint8Array, wrappedKeyB64: string): Promise<VaultMasterKey> {
  const blob = fromB64(wrappedKeyB64);
  return aesGcmDecrypt(wrappingKey, blob.slice(0, 12), blob.slice(12));
}

// Passkey PRF: prfOutput is the 32-byte WebAuthn PRF result (results.first).
export async function wrapVaultKeyWithPasskeyPrf(masterKey: VaultMasterKey, prfOutput: Uint8Array, metadata: Record<string, unknown>): Promise<VaultWrapper> {
  const salt = randomBytes(16);
  const wk = await hkdf(prfOutput, salt, "shade-vault-passkey-prf");
  return { id: toHex(randomBytes(8)), type: "passkey_prf", status: "active", kdf: "HKDF-SHA256", salt: toB64(salt), wrapped_key: await wrapWithKey(wk, masterKey), metadata };
}
export async function unwrapVaultKeyWithPasskeyPrf(wrapper: VaultWrapper, prfOutput: Uint8Array): Promise<VaultMasterKey> {
  const wk = await hkdf(prfOutput, fromB64(wrapper.salt), "shade-vault-passkey-prf");
  return unwrapWithKey(wk, wrapper.wrapped_key);
}
export function isPasskeyPrfAvailable(): boolean {
  return typeof globalThis !== "undefined" && "PublicKeyCredential" in globalThis && !!(globalThis.navigator && "credentials" in globalThis.navigator);
}

// Stellar Ed25519: signatureBytes is the 64-byte signature over a fixed challenge
// (deterministic for ed25519), produced by Freighter signMessage / Privy raw sign.
export async function wrapVaultKeyWithStellarSignature(masterKey: VaultMasterKey, signatureBytes: Uint8Array, metadata: Record<string, unknown>): Promise<VaultWrapper> {
  const salt = randomBytes(16);
  const wk = await hkdf(signatureBytes, salt, "shade-vault-stellar-ed25519");
  return { id: toHex(randomBytes(8)), type: "stellar_ed25519_signature", status: "active", kdf: "HKDF-SHA256", salt: toB64(salt), wrapped_key: await wrapWithKey(wk, masterKey), metadata };
}
export async function unwrapVaultKeyWithStellarSignature(wrapper: VaultWrapper, signatureBytes: Uint8Array): Promise<VaultMasterKey> {
  const wk = await hkdf(signatureBytes, fromB64(wrapper.salt), "shade-vault-stellar-ed25519");
  return unwrapWithKey(wk, wrapper.wrapped_key);
}

// Recovery-kit passphrase: PBKDF2-SHA256 (WebCrypto; Argon2id/scrypt are documented
// alternatives but not native to WebCrypto).
const PBKDF2_ITERS = 310_000;
export async function wrapVaultKeyWithRecoveryKitPassword(masterKey: VaultMasterKey, password: string, metadata: Record<string, unknown>): Promise<VaultWrapper> {
  const salt = randomBytes(16);
  const wk = await pbkdf2(password, salt, PBKDF2_ITERS);
  return { id: toHex(randomBytes(8)), type: "recovery_kit_password", status: "active", kdf: "PBKDF2-SHA256", salt: toB64(salt), wrapped_key: await wrapWithKey(wk, masterKey), metadata };
}
export async function unwrapVaultKeyWithRecoveryKitPassword(wrapper: VaultWrapper, password: string): Promise<VaultMasterKey> {
  const wk = await pbkdf2(password, fromB64(wrapper.salt), PBKDF2_ITERS);
  return unwrapWithKey(wk, wrapper.wrapped_key);
}

// Emergency recovery file (PART5): a high-entropy secret generated in the browser
// wraps the master key via HKDF. The secret is written into the DOWNLOADED file
// only — never the backend. To restore, the user supplies the file (which carries
// both the secret and the wrapped key); the backend stores only the wrapped key.
export type RecoveryFile = {
  version: "shade-recovery-file-v1";
  vault_id: string;
  created_at: string;
  app: "Shade Protocol";
  warning: string;
  recovery_file_secret: string; // base64 — lives ONLY in this file, never on the backend
  wrapper: VaultWrapper;        // the same wrapper stored in the envelope (no secret)
};
export function generateRecoveryFileSecret(): Uint8Array {
  return randomBytes(32);
}
export async function wrapVaultKeyWithRecoveryFileSecret(masterKey: VaultMasterKey, secret: Uint8Array, metadata: Record<string, unknown>): Promise<VaultWrapper> {
  const salt = randomBytes(16);
  const wk = await hkdf(secret, salt, "shade-vault-recovery-file");
  return { id: toHex(randomBytes(8)), type: "recovery_file_secret", status: "active", kdf: "HKDF-SHA256", salt: toB64(salt), wrapped_key: await wrapWithKey(wk, masterKey), metadata };
}
export async function unwrapVaultKeyWithRecoveryFileSecret(wrapper: VaultWrapper, secret: Uint8Array): Promise<VaultMasterKey> {
  const wk = await hkdf(secret, fromB64(wrapper.salt), "shade-vault-recovery-file");
  return unwrapWithKey(wk, wrapper.wrapped_key);
}
export function buildRecoveryFile(vaultId: string, secret: Uint8Array, wrapper: VaultWrapper, now: string): RecoveryFile {
  return {
    version: "shade-recovery-file-v1", vault_id: vaultId, created_at: now, app: "Shade Protocol",
    warning: "Keep this file safe. It can help restore your private vault. Anyone with this file can decrypt your vault.",
    recovery_file_secret: toB64(secret), wrapper
  };
}

// EVM signature wrapper — DIAGNOSTIC ONLY. Marked diagnostic_only:true; cannot
// satisfy the recovery policy by itself.
export async function diagnosticWrapVaultKeyWithEvmSignature(masterKey: VaultMasterKey, signatureBytes: Uint8Array, metadata: Record<string, unknown>): Promise<VaultWrapper> {
  const salt = randomBytes(16);
  const wk = await hkdf(signatureBytes, salt, "shade-vault-evm-diagnostic");
  return { id: toHex(randomBytes(8)), type: "evm_signature", status: "active", kdf: "HKDF-SHA256", salt: toB64(salt), wrapped_key: await wrapWithKey(wk, masterKey), diagnostic_only: true, metadata: { ...metadata, diagnostic_only: true } };
}
// EVM signatures over the same message are NOT guaranteed stable across wallets
// (some add entropy); this checks two signatures match before trusting the wrapper.
export function diagnosticVerifyEvmSignatureStability(sigA: Uint8Array, sigB: Uint8Array): boolean {
  return sigA.length === sigB.length && sigA.every((b, i) => b === sigB[i]);
}

// ---------- recovery policy ----------
export type RecoveryPolicyStatus = "insufficient" | "sufficient" | "strong";
export function evaluateRecoveryPolicy(wrappers: VaultWrapper[], opts: { mainnet: boolean; min: number; allowEvmOnly: boolean }): RecoveryPolicyStatus {
  const active = wrappers.filter((w) => w.status === "active");
  const nonEvm = active.filter((w) => w.type !== "evm_signature" && !w.diagnostic_only);
  const strong = active.some((w) => w.type === "passkey_prf" || w.type === "stellar_ed25519_signature");
  if (!opts.allowEvmOnly && nonEvm.length === 0) return "insufficient";
  if (nonEvm.length < opts.min) return "insufficient";
  if (opts.mainnet) return nonEvm.length >= 2 && strong ? "strong" : "insufficient";
  return strong && nonEvm.length >= 2 ? "strong" : "sufficient";
}
