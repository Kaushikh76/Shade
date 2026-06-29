import { StrKey } from "@stellar/stellar-sdk";

export const LOCKED_CCTP = {
  cctpVersion: "v2",
  arbitrumSepoliaDomain: 3,
  stellarDomain: 27,
  arbitrumSepoliaUsdc: "0x75faf114eafb1BDbe2F0316DF893fd58CE46AA4d",
  arbitrumSepoliaTokenMessenger: "0x8FE6B999Dc680CcFDD5Bf7EB0974218be2542DAA",
  arbitrumSepoliaMessageTransmitter: "0xE737e5cEBEEBa77EFE34D4aa090756590b1CE275",
  stellarCctpForwarder: "CA66Q2WFBND6V4UEB7RD4SAXSVIWMD6RA4X3U32ELVFGXV5PJK4T4VSZ",
  stellarMessageTransmitter: "CBJ6MTCKKZG73PMDZCJMSFRD7DQEMI4FKDH7CGDSV4W6FHCRBCQAVVJY",
  stellarTokenMessengerMinter: "CDNG7HXAPBWICI2E3AUBP3YZWZELJLYSB6F5CC7WLDTLTHVM74SLRTHP",
  stellarUsdcAsset: "USDC-GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5"
} as const;

export type CctpInboundRoute = {
  destinationDomain: number;
  mintRecipient: string;
  destinationCaller: string;
  forwardRecipient: string;
};

export function stellarContractToBytes32(contractId: string): `0x${string}` {
  if (!StrKey.isValidContract(contractId)) {
    throw new Error(`Expected Stellar contract strkey, got ${contractId}`);
  }
  return `0x${Buffer.from(StrKey.decodeContract(contractId)).toString("hex")}`;
}

export function validateInboundRoute(route: CctpInboundRoute, expectedForwarder = LOCKED_CCTP.stellarCctpForwarder): void {
  if (route.destinationDomain !== LOCKED_CCTP.stellarDomain) {
    throw new Error(`wrong destination domain: expected ${LOCKED_CCTP.stellarDomain}`);
  }
  if (!StrKey.isValidContract(route.mintRecipient)) {
    throw new Error("mintRecipient must be a Stellar C contract");
  }
  if (!StrKey.isValidContract(route.destinationCaller)) {
    throw new Error("destinationCaller must be a Stellar C contract");
  }
  if (route.mintRecipient !== expectedForwarder) {
    throw new Error("mintRecipient must equal CctpForwarder");
  }
  if (route.destinationCaller !== expectedForwarder) {
    throw new Error("destinationCaller must equal CctpForwarder");
  }
  if (!StrKey.isValidContract(route.forwardRecipient)) {
    throw new Error("forwardRecipient must be the ShadeVault C contract");
  }
}

export function encodeStellarForwardHook(forwardRecipient: string): `0x${string}` {
  if (!StrKey.isValidContract(forwardRecipient)) {
    throw new Error("forwardRecipient must be a Stellar C contract");
  }
  const prefix = Buffer.alloc(24, 0);
  const reserved = Buffer.alloc(4, 0);
  const recipient = Buffer.from(forwardRecipient, "utf8");
  const len = Buffer.alloc(4);
  len.writeUInt32BE(recipient.length);
  return `0x${Buffer.concat([prefix, reserved, len, recipient]).toString("hex")}`;
}

export function usdc6ToStellar7(amount6: bigint): bigint {
  return amount6 * 10n;
}

export function stellar7ToUsdc6(amount7: bigint): bigint {
  if (amount7 % 10n !== 0n) throw new Error("Stellar 7dp amount cannot be represented exactly as CCTP 6dp");
  return amount7 / 10n;
}

// --- CCTP V2 burn (Arbitrum Sepolia) -----------------------------------------
// TokenMessengerV2.depositForBurnWithHook, verified against
// circlefin/evm-cctp-contracts master src/v2/TokenMessengerV2.sol
export const TOKEN_MESSENGER_V2_ABI = [
  "function depositForBurnWithHook(uint256 amount,uint32 destinationDomain,bytes32 mintRecipient,address burnToken,bytes32 destinationCaller,uint256 maxFee,uint32 minFinalityThreshold,bytes calldata hookData) external",
  "function depositForBurn(uint256 amount,uint32 destinationDomain,bytes32 mintRecipient,address burnToken,bytes32 destinationCaller,uint256 maxFee,uint32 minFinalityThreshold) external"
] as const;

export const ERC20_ABI = [
  "function balanceOf(address) view returns (uint256)",
  "function allowance(address owner,address spender) view returns (uint256)",
  "function approve(address spender,uint256 value) returns (bool)",
  "function transfer(address to,uint256 value) returns (bool)"
] as const;

// src/v2/FinalityThresholds.sol
export const FINALITY_THRESHOLD_FINALIZED = 2000;
export const FINALITY_THRESHOLD_CONFIRMED = 1000;

export type CctpAttestation = {
  status: string;
  message: `0x${string}`;
  attestation: `0x${string}`;
  eventNonce?: string;
  cctpVersion?: number;
};

// Circle Iris V2 message lookup by source tx hash.
// https://developers.circle.com/cctp  (sandbox base for testnet)
export async function fetchAttestationByTx(
  apiBase: string,
  sourceDomain: number,
  burnTxHash: string
): Promise<CctpAttestation | null> {
  const url = `${apiBase.replace(/\/$/, "")}/v2/messages/${sourceDomain}?transactionHash=${burnTxHash}`;
  const res = await fetch(url);
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`Iris lookup failed ${res.status}: ${await res.text()}`);
  const body = (await res.json()) as { messages?: Array<Record<string, unknown>> };
  const msg = body.messages?.[0];
  if (!msg) return null;
  return {
    status: String(msg.status),
    message: msg.message as `0x${string}`,
    attestation: msg.attestation as `0x${string}`,
    eventNonce: msg.eventNonce ? String(msg.eventNonce) : undefined,
    cctpVersion: typeof msg.cctpVersion === "number" ? msg.cctpVersion : undefined
  };
}

export async function pollAttestation(
  apiBase: string,
  sourceDomain: number,
  burnTxHash: string,
  opts: { intervalMs?: number; timeoutMs?: number; onTick?: (status: string) => void } = {}
): Promise<CctpAttestation> {
  const intervalMs = opts.intervalMs ?? 8000;
  const timeoutMs = opts.timeoutMs ?? 20 * 60 * 1000;
  const start = Date.now();
  for (;;) {
    const att = await fetchAttestationByTx(apiBase, sourceDomain, burnTxHash);
    const status = att?.status ?? "pending";
    opts.onTick?.(status);
    const attStr = att?.attestation as string | undefined;
    if (att && status === "complete" && attStr && attStr !== "0x" && attStr !== "PENDING") {
      return att;
    }
    if (Date.now() - start > timeoutMs) {
      throw new Error(`attestation timed out after ${Math.round((Date.now() - start) / 1000)}s (last status: ${status})`);
    }
    await new Promise((r) => setTimeout(r, intervalMs));
  }
}
