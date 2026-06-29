"use client";
import { useState } from "react";
import { usePrivy } from "@privy-io/react-auth";
import { parseVaultEnvelope, decryptEnvelope, unwrapVaultKeyWithStellarSignature, unwrapVaultKeyWithRecoveryKitPassword, type EncryptedVaultEnvelope } from "@shade/note-vault";
import { ApiClient } from "@/lib/api";
import { useAccessToken } from "@/lib/use-token";
import { clearLocalCache, setMemoryVault } from "@/lib/vault-store";
import { connectFreighter, stellarRecoverySignature } from "@/lib/stellar-signer";

// Restore flow: simulate a cache clear, fetch the encrypted envelope from the
// backend, unlock the master key with a recovery wrapper, decrypt, and verify the
// note commitments match — proving notes survive a browser wipe.
export default function RestorePage() {
  const { authenticated } = usePrivy();
  const getToken = useAccessToken();
  const [vaultId, setVaultId] = useState("");
  const [log, setLog] = useState<string[]>([]);
  const say = (m: string) => setLog((l) => [...l, m]);

  async function restore(method: "stellar" | "kit") {
    setLog([]);
    try {
      const token = await getToken();
      if (!token) throw new Error("log in first");
      await clearLocalCache();
      say("Simulated cache clear (IndexedDB + memory cleared).");
      const env = parseVaultEnvelope(JSON.stringify(await ApiClient.getVault(token, vaultId) as { envelope: EncryptedVaultEnvelope })["envelope"]);
      say("Fetched encrypted vault envelope from backend.");

      let master: Uint8Array;
      if (method === "stellar") {
        const addr = await connectFreighter();
        const sig = await stellarRecoverySignature(addr);
        const w = env.wrappers.find((x) => x.type === "stellar_ed25519_signature");
        if (!w) throw new Error("no Stellar wrapper on this vault");
        master = await unwrapVaultKeyWithStellarSignature(w, sig);
        say("Unlocked master key via Stellar Ed25519 wrapper.");
      } else {
        const pw = prompt("Recovery-kit passphrase:") ?? "";
        const w = env.wrappers.find((x) => x.type === "recovery_kit_password");
        if (!w) throw new Error("no recovery-kit wrapper on this vault");
        master = await unwrapVaultKeyWithRecoveryKitPassword(w, pw);
        say("Unlocked master key via recovery-kit passphrase.");
      }
      const vault = await decryptEnvelope(env, master);
      setMemoryVault(vault);
      say(`Decrypted vault — ${vault.notes.length} note(s) restored to memory.`);
      vault.notes.forEach((n) => say(`  note ${n.commitment.slice(0, 18)}… (${n.status})`));
      await ApiClient.markRestored(token, vaultId);
      say("Marked restored ✓. Notes are available without any plaintext leaving the browser.");
    } catch (e) { say(`Error: ${(e as Error).message}`); }
  }

  if (!authenticated) return <p>Please log in.</p>;
  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-bold">Restore Vault</h1>
      <p className="text-sm text-neutral-400">Recover your private notes after a cache wipe using a recovery wrapper. The backend only ever held ciphertext.</p>
      <label className="block text-sm">Vault id<input value={vaultId} onChange={(e) => setVaultId(e.target.value)} placeholder="vault-…" className="ml-2 w-96 rounded bg-neutral-800 px-2 py-1" /></label>
      <div className="flex gap-3">
        <button onClick={() => restore("stellar")} className="rounded bg-violet-600 px-4 py-2">Restore via Stellar</button>
        <button onClick={() => restore("kit")} className="rounded bg-neutral-700 px-4 py-2">Restore via recovery kit</button>
      </div>
      <pre className="overflow-auto rounded bg-neutral-900 p-3 text-xs">{log.join("\n")}</pre>
    </div>
  );
}
