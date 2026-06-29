import { access } from "node:fs/promises";

export async function requireProofStack(): Promise<void> {
  const provingKey = process.env.PROVING_KEY_PATH;
  const verifyingKey = process.env.VERIFYING_KEY_PATH;
  const circuitBuild = process.env.CIRCUIT_BUILD_DIR;
  if (!process.env.PROOF_SYSTEM) throw new Error("PROOF_SYSTEM is required");
  if (!provingKey || !verifyingKey || !circuitBuild) {
    throw new Error("PROVING_KEY_PATH, VERIFYING_KEY_PATH, and CIRCUIT_BUILD_DIR are required");
  }
  await Promise.all([access(provingKey), access(verifyingKey), access(circuitBuild)]);
}

export function redactSecrets(input: string): string {
  return input.replace(/0x[a-fA-F0-9]{64}/g, "0x[REDACTED_32_BYTES]").replace(/S[A-Z2-7]{55}/g, "S[REDACTED_STELLAR_SECRET]");
}
