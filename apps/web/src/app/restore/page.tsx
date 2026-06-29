"use client";
import { useState } from "react";
import { usePrivy } from "@privy-io/react-auth";
import {
  validateVaultEnvelope, decryptEnvelope, unwrapVaultKeyWithStellarSignature,
  unwrapVaultKeyWithRecoveryFileSecret, unwrapVaultKeyWithRecoveryKitPassword,
  fromB64, type EncryptedVaultEnvelope, type RecoveryFile
} from "@shade/note-vault";
import { ApiClient } from "@/lib/api";
import { useAccessToken } from "@/lib/use-token";
import { clearLocalCache, setMemoryVault, cacheEnvelope } from "@/lib/vault-store";
import { connectFreighter, stellarRecoverySignature } from "@/lib/stellar-signer";

type Method = "freighter" | "file" | "password";

// PART11: restore with passkey/Freighter/recovery-file/advanced-password. The
// recovery file path needs no typing — the user just picks their downloaded file.
export default function RestorePage() {
  const { authenticated } = usePrivy();
  const getToken = useAccessToken();
  const [log, setLog] = useState<string[]>([]);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const say = (m: string) => setLog((l) => [...l, m]);

  async function fetchEnvelope(token: string, vaultId: string): Promise<EncryptedVaultEnvelope> {
    const res = await ApiClient.getVault(token, vaultId) as { envelope: EncryptedVaultEnvelope };
    const env = res.envelope;
    validateVaultEnvelope(env);
    return env;
  }

  async function finish(token: string, env: EncryptedVaultEnvelope, master: Uint8Array) {
    const vault = await decryptEnvelope(env, master);
    if (vault.vault_id !== env.vault_id) throw new Error("restored vault id mismatch");
    setMemoryVault(vault);
    await cacheEnvelope(env);
    say(`Vault restored — ${vault.notes.length} private receipt(s) recovered.`);
    vault.notes.forEach((n) => say(`  receipt ${n.commitment.slice(0, 18)}… (${n.status})`));
    await ApiClient.markRestored(token, env.vault_id);
    say("Vault restored successfully. No plaintext ever left your browser.");
  }

  // Restore from the downloaded recovery file (passwordless).
  async function restoreFromFile(file: File) {
    setLog([]);
    try {
      const token = await getToken(); if (!token) throw new Error("log in first");
      const rf = JSON.parse(await file.text()) as RecoveryFile;
      if (rf.version !== "shade-recovery-file-v1") throw new Error("not a Shade recovery file");
      await clearLocalCache();
      say("Cleared local cache (simulating a fresh device).");
      const env = await fetchEnvelope(token, rf.vault_id);
      const w = env.wrappers.find((x) => x.type === "recovery_file_secret");
      if (!w) throw new Error("this vault has no recovery-file method");
      const master = await unwrapVaultKeyWithRecoveryFileSecret(w, fromB64(rf.recovery_file_secret));
      await finish(token, env, master);
    } catch (e) { say(`Error: ${(e as Error).message}`); }
  }

  async function restoreWith(method: Exclude<Method, "file">, vaultId: string) {
    setLog([]);
    try {
      const token = await getToken(); if (!token) throw new Error("log in first");
      if (!vaultId) throw new Error("enter your vault id (or use the recovery file)");
      await clearLocalCache();
      say("Cleared local cache (simulating a fresh device).");
      const env = await fetchEnvelope(token, vaultId);
      let master: Uint8Array;
      if (method === "freighter") {
        const addr = await connectFreighter();
        const sig = await stellarRecoverySignature(addr);
        const w = env.wrappers.find((x) => x.type === "stellar_ed25519_signature");
        if (!w) throw new Error("this vault has no Stellar wallet method");
        master = await unwrapVaultKeyWithStellarSignature(w, sig);
      } else {
        const pw = prompt("Recovery passphrase:") ?? "";
        const w = env.wrappers.find((x) => x.type === "recovery_kit_password");
        if (!w) throw new Error("this vault has no password method");
        master = await unwrapVaultKeyWithRecoveryKitPassword(w, pw);
      }
      await finish(token, env, master);
    } catch (e) { say(`Error: ${(e as Error).message}`); }
  }

  const [vaultId, setVaultId] = useState("");
  if (!authenticated) return <p className="text-neutral-300">Please log in to restore your vault.</p>;

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-2xl font-bold">Restore your vault</h1>
        <p className="text-sm text-neutral-400">Recover your private receipts on a new device. The backend only ever held encrypted data.</p>
      </div>

      <div className="rounded-lg border border-neutral-800 bg-neutral-900 p-4">
        <h3 className="font-medium">Restore from recovery file</h3>
        <p className="text-xs text-neutral-400">Pick the emergency recovery file you downloaded when you created the vault. No password needed.</p>
        <input type="file" accept="application/json" onChange={(e) => e.target.files?.[0] && restoreFromFile(e.target.files[0])} className="mt-2 text-sm" />
      </div>

      <div className="rounded-lg border border-neutral-800 bg-neutral-900 p-4 space-y-2">
        <h3 className="font-medium">Restore with your Stellar wallet</h3>
        <p className="text-xs text-neutral-400">Use Freighter to sign and unlock your vault.</p>
        <input value={vaultId} onChange={(e) => setVaultId(e.target.value)} placeholder="vault id" className="w-80 rounded bg-neutral-800 px-2 py-1 text-sm" />
        <button onClick={() => restoreWith("freighter", vaultId)} className="ml-2 rounded bg-violet-600 px-3 py-1 text-sm">Restore with Freighter</button>
      </div>

      <div>
        <button onClick={() => setShowAdvanced((v) => !v)} className="text-xs text-neutral-500 underline">Advanced: password recovery</button>
        {showAdvanced && (
          <div className="mt-2 rounded-lg border border-neutral-800 bg-neutral-900 p-4">
            <button onClick={() => restoreWith("password", vaultId)} className="rounded bg-neutral-800 px-3 py-1 text-sm">Restore with password</button>
          </div>
        )}
      </div>

      <pre className="overflow-auto rounded bg-neutral-900 p-3 text-xs text-neutral-400">{log.join("\n")}</pre>
    </div>
  );
}
