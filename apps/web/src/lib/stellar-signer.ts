// Freighter Stellar signer (the active client-side Stellar signer; Privy Stellar
// is Tier 2 / TODO). Used to (a) sign withdraw XDR and (b) produce the Stellar
// Ed25519 recovery-wrapper signature. No secret ever leaves the wallet.
import {
  isConnected, requestAccess, getAddress, getNetworkDetails, signTransaction, signMessage
} from "@stellar/freighter-api";

export async function freighterAvailable(): Promise<boolean> {
  try { return (await isConnected()).isConnected; } catch { return false; }
}
export async function connectFreighter(): Promise<string> {
  const r = await requestAccess();
  if (r.error) throw new Error(r.error.message ?? "Freighter access denied");
  return r.address;
}
export async function freighterAddress(): Promise<string | null> {
  try { const r = await getAddress(); return r.error ? null : r.address; } catch { return null; }
}
export async function signWithdrawXdr(unsignedXdr: string, address: string): Promise<string> {
  const net = await getNetworkDetails();
  const r = await signTransaction(unsignedXdr, { networkPassphrase: net.networkPassphrase, address });
  if (r.error) throw new Error(r.error.message ?? "sign failed");
  return r.signedTxXdr;
}
// Deterministic Stellar signature over a fixed challenge → recovery wrapper key.
export async function stellarRecoverySignature(address: string): Promise<Uint8Array> {
  const challenge = "shade-vault-recovery-v1";
  const r = await signMessage(challenge, { address });
  if (r.error || !r.signedMessage) throw new Error(r.error?.message ?? "signMessage failed");
  // signedMessage may be base64; normalize to bytes.
  const s = r.signedMessage;
  const bin = atob(typeof s === "string" ? s : Buffer.from(s).toString("base64"));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
