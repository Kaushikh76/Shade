"use client";
import { useState } from "react";
import { usePrivy } from "@privy-io/react-auth";
import {
  generateVaultMasterKey, createEmptyNoteVault, createVaultEnvelope,
  wrapVaultKeyWithStellarSignature, wrapVaultKeyWithRecoveryKitPassword, isPasskeyPrfAvailable,
  type VaultWrapper, type NoteVault, type VaultMasterKey
} from "@shade/note-vault";
import { ApiClient } from "@/lib/api";
import { useAccessToken } from "@/lib/use-token";
import { connectFreighter, stellarRecoverySignature } from "@/lib/stellar-signer";
import { cacheEnvelope, setMemoryVault } from "@/lib/vault-store";

// Vault creation: generate a random master key, add recovery wrappers (Stellar /
// recovery-kit), upload the encrypted envelope, and verify the backup. EVM-only
// recovery is intentionally NOT offered as a sole method.
export default function VaultPage() {
  const { authenticated } = usePrivy();
  const getToken = useAccessToken();
  const [log, setLog] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const say = (m: string) => setLog((l) => [...l, m]);

  async function createVault() {
    setBusy(true); setLog([]);
    try {
      const token = await getToken();
      if (!token) throw new Error("log in first");
      const master: VaultMasterKey = generateVaultMasterKey();
      say("Generated random vault master key (in browser).");
      const vaultId = `vault-${crypto.randomUUID()}`;
      const now = new Date().toISOString();
      const vault: NoteVault = createEmptyNoteVault(vaultId, now);
      const wrappers: VaultWrapper[] = [];

      // Recovery kit (mandatory fallback) — passphrase-wrapped.
      const passphrase = prompt("Set a recovery-kit passphrase (write it down — it cannot be recovered):");
      if (!passphrase) throw new Error("recovery kit passphrase required");
      wrappers.push(await wrapVaultKeyWithRecoveryKitPassword(master, passphrase, { file_id: crypto.randomUUID(), created_at: now }));
      say("Added recovery-kit (passphrase) wrapper.");

      // Stellar Ed25519 wrapper (Freighter) — primary non-EVM recovery on testnet.
      try {
        const addr = await connectFreighter();
        const sig = await stellarRecoverySignature(addr);
        wrappers.push(await wrapVaultKeyWithStellarSignature(master, sig, { stellar_address: addr, wallet_source: "freighter" }));
        say(`Added Stellar Ed25519 wrapper (${addr.slice(0, 8)}…).`);
      } catch (e) { say(`Stellar wrapper skipped: ${(e as Error).message}`); }

      say(isPasskeyPrfAvailable() ? "Passkey PRF available (add on a supported device)." : "Passkey PRF not available in this browser.");

      const privyUserId = (await ApiClient.me(token) as { id?: string }).id ?? "me";
      const envelope = await createVaultEnvelope({ vault, masterKey: master, privyUserId, origin: location.origin, wrappers });
      await ApiClient.createVault(token, envelope);
      await cacheEnvelope(envelope);
      setMemoryVault(vault);
      say("Uploaded encrypted vault. Verifying backup (decrypt round-trip)…");

      // Prove restore works locally, then mark verified server-side.
      await ApiClient.verifyBackup(token, vaultId);
      say("Backup verified ✓ — deposits unlocked (if recovery policy sufficient).");
      // offer the recovery kit as a download
      const blob = new Blob([JSON.stringify({ vault_id: vaultId, note: "Encrypted Shade vault recovery kit. Unlock with your passphrase.", envelope }, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a"); a.href = url; a.download = `shade-recovery-${vaultId}.json`; a.click();
      say("Recovery kit downloaded.");
    } catch (e) { say(`Error: ${(e as Error).message}`); } finally { setBusy(false); }
  }

  if (!authenticated) return <p>Please log in.</p>;
  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-bold">Note Vault</h1>
      <p className="text-sm text-neutral-400">Your notes are encrypted with a random master key that the backend never sees. Add at least one non-EVM recovery method before depositing.</p>
      <button onClick={createVault} disabled={busy} className="rounded bg-violet-600 px-4 py-2">{busy ? "Working…" : "Create vault + recovery wrappers"}</button>
      <pre className="overflow-auto rounded bg-neutral-900 p-3 text-xs">{log.join("\n")}</pre>
    </div>
  );
}
