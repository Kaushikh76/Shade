// Local vault cache: ENCRYPTED-only in IndexedDB; the decrypted vault lives in
// memory for the session. Plaintext note secrets are NEVER written to localStorage
// (ALLOW_PLAINTEXT_NOTE_CACHE defaults off). See docs/note-vault-recovery.md.
import type { NoteVault, EncryptedVaultEnvelope } from "@shade/note-vault";

const DB_NAME = "shade-vault";
const STORE = "encrypted-envelopes";

// In-memory decrypted vault (cleared on tab close / cache clear).
let memoryVault: NoteVault | null = null;
export function setMemoryVault(v: NoteVault | null): void { memoryVault = v; }
export function getMemoryVault(): NoteVault | null { return memoryVault; }

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(STORE, { keyPath: "vault_id" });
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

// Cache only the ENCRYPTED envelope locally (safe — no plaintext).
export async function cacheEnvelope(env: EncryptedVaultEnvelope): Promise<void> {
  const db = await openDb();
  await new Promise<void>((resolve, reject) => {
    const tx = db.transaction(STORE, "readwrite");
    tx.objectStore(STORE).put(env);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}
export async function loadCachedEnvelope(vaultId: string): Promise<EncryptedVaultEnvelope | null> {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, "readonly");
    const req = tx.objectStore(STORE).get(vaultId);
    req.onsuccess = () => resolve((req.result as EncryptedVaultEnvelope) ?? null);
    req.onerror = () => reject(req.error);
  });
}
// Simulate a cache clear (the /restore page uses this to prove recovery works).
export async function clearLocalCache(): Promise<void> {
  memoryVault = null;
  const db = await openDb();
  await new Promise<void>((resolve, reject) => {
    const tx = db.transaction(STORE, "readwrite");
    tx.objectStore(STORE).clear();
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}
