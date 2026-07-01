// IntentClient — submits private RFQ intents to the Shade API and tracks lifecycle.
// Uses fetch (browser-native). Pass an authToken from Privy for authenticated routes.

import type { CommitteeNodeInfo, EncryptedAmountShare } from "./mpc.js";
import { splitAndEncryptAmount, buildAmountCommitment, buildValueCommitment, randomBlinding } from "./mpc.js";

// Re-exported for callers who import solely from @shade/sdk.
export type { CommitteeNodeInfo } from "./mpc.js";

// EncryptedShare — per-node Shamir ciphertext (same shape as EncryptedAmountShare).
export type EncryptedShare = {
  nodeId: string;
  ciphertext: string;
  nonce: string;
  senderPubkey: string;
};

// Blinding values retained by the client after buildPrivateIntent().
// Required for Phase C ZK proof (proves amount_commitment = hash(amount, blinding)).
export type IntentBlindings = {
  amountBlinding: string;
  minOutputBlinding: string;
  destinationBlinding: string;
};

export type IntentParams = {
  inputAsset: string;
  outputAsset: string;
  amountMode: "exact_in" | "exact_out" | "max_in";
  amount7dp: string;           // plaintext 7dp or amount_commitment when built via buildPrivateIntent()
  minOutput7dp: string;
  expiryLedger: number;
  noteCommitment: string;      // 0x.. Poseidon commitment of the deposited input note
  destination: string;         // EVM address (Path A) or output commitment (MPC path)
  policyId?: string;

  // MPC private matching path — supply all four to enable private routing.
  // When present, POST /v1/intents forwards to the committee and
  // POST /v1/rfq/settle requires a confirmed MPC match before settlement.
  noteNullifier?: string;
  recipientCommitment?: string;
  encryptedShares?: EncryptedShare[];
};

// Parameters for the full private-intent construction pipeline.
// The plaintext amount never leaves buildPrivateIntent() — only commitments
// and encrypted Shamir shares are included in the submitted payload.
export type PrivateIntentBuildParams = {
  amount7dp: bigint;
  minOutput7dp: bigint;
  noteCommitment: string;      // Poseidon commitment of the input note
  noteNullifier: string;       // nullifier of the input note (hex)
  recipientCommitment: string; // output note commitment for the counterparty
  destinationAddress: string;  // EVM address that will receive the payout
  inputAsset: string;
  outputAsset: string;
  expiryLedger: number;
  policyId?: string;
  signature?: string;          // user signature over the intent hash (hex)
};

export type QuoteResult = {
  quoteId: string;
  solverPubkey: string;
  netOutput7dp: string;        // net payout to the user in 7dp
  fee7dp: string;
  validUntilLedger: number;
  settlementMethod: string;
};

export type SettlementStatus = {
  state: "pending" | "filled" | "settled" | "expired" | "failed";
  txHash?: string;
  detail?: string;
};

export type DepositStatus = {
  state: "pending" | "attesting" | "forwarded" | "registered" | "failed";
  leafIndex?: number;
  root?: string;
  burnTxHash?: string;
  stellarTxHash?: string;
};

export class IntentClient {
  constructor(
    private readonly apiBase: string,
    private readonly authToken?: string
  ) {}

  private get headers(): Record<string, string> {
    return {
      "Content-Type": "application/json",
      ...(this.authToken ? { Authorization: `Bearer ${this.authToken}` } : {})
    };
  }

  private async post<T>(path: string, body: unknown): Promise<T> {
    const res = await fetch(`${this.apiBase}${path}`, {
      method: "POST",
      headers: this.headers,
      body: JSON.stringify(body)
    });
    if (!res.ok) throw new Error(`POST ${path}: ${res.status} ${await res.text()}`);
    return res.json() as Promise<T>;
  }

  private async get<T>(path: string): Promise<T> {
    const res = await fetch(`${this.apiBase}${path}`, { headers: this.headers });
    if (!res.ok) throw new Error(`GET ${path}: ${res.status} ${await res.text()}`);
    return res.json() as Promise<T>;
  }

  // Fetch the MPC committee's public keys. Required before buildPrivateIntent().
  async fetchCommittee(): Promise<CommitteeNodeInfo[]> {
    const data = await this.get<{ nodes: CommitteeNodeInfo[] }>("/v1/mpc/committee");
    return data.nodes;
  }

  /**
   * Full private-intent construction pipeline.
   *
   * The plaintext amount never leaves this method — only SHA-256 commitments
   * (amount_commitment, min_output_commitment, destination_commitment) and
   * per-node Shamir ciphertext (encrypted_shares) are included in the payload.
   *
   * Callers should store the returned `blindings` alongside the local note; they
   * are required for Phase C ZK proof generation.
   *
   * Usage:
   *   const { payload, blindings } = await client.buildPrivateIntent({ ... });
   *   const result = await client.submit(payload);
   */
  async buildPrivateIntent(p: PrivateIntentBuildParams): Promise<{
    payload: IntentParams;
    blindings: IntentBlindings;
  }> {
    const nodes = await this.fetchCommittee();

    // Three independent random blindings — one per committed value.
    const amountBlinding = randomBlinding();
    const minOutputBlinding = randomBlinding();
    const destinationBlinding = randomBlinding();

    const [amountCommitment, minOutputCommitment, destinationCommitment] = await Promise.all([
      buildAmountCommitment(p.amount7dp, amountBlinding),
      buildAmountCommitment(p.minOutput7dp, minOutputBlinding),
      buildValueCommitment(p.destinationAddress, destinationBlinding)
    ]);

    // Amount is Shamir-split and encrypted per node. No plaintext amount in payload.
    const encryptedShares = splitAndEncryptAmount(p.amount7dp, nodes);

    return {
      payload: {
        inputAsset: p.inputAsset,
        outputAsset: p.outputAsset,
        amountMode: "exact_in",
        amount7dp: amountCommitment,      // commitment travels, not plaintext
        minOutput7dp: minOutputCommitment,
        expiryLedger: p.expiryLedger,
        noteCommitment: p.noteCommitment,
        destination: destinationCommitment,
        policyId: p.policyId,
        noteNullifier: p.noteNullifier,
        recipientCommitment: p.recipientCommitment,
        encryptedShares
      },
      blindings: { amountBlinding, minOutputBlinding, destinationBlinding }
    };
  }

  // Submit a private RFQ intent. Returns intentHash + optional mpc_session_id.
  // When encryptedShares + noteNullifier are provided, the API automatically routes
  // the intent to the MPC committee for private matching. Settlement then requires
  // all three: RFQ lifecycle verified + MPC match confirmed + ZK proof valid.
  async submit(p: IntentParams): Promise<{ intentId: string; intentHash: string; mpc_routed?: boolean; mpc_session_id?: string }> {
    const mpcFields = p.encryptedShares?.length && p.noteNullifier
      ? {
          note_nullifier: p.noteNullifier,
          note_commitment: p.noteCommitment,
          recipient_commitment: p.recipientCommitment,
          encrypted_shares: p.encryptedShares
        }
      : {};

    return this.post("/v1/intents", {
      intent_type: "PRIVATE_RFQ",
      version: "1.0",
      user_pubkey_commitment: p.noteCommitment,
      input_asset: p.inputAsset,
      output_asset: p.outputAsset,
      amount_mode: p.amountMode,
      amount_commitment: p.amount7dp,
      min_output_commitment: p.minOutput7dp,
      expiry_ledger: p.expiryLedger,
      allowed_solvers_root: "0x" + "00".repeat(32),
      compliance_policy_id: p.policyId ?? "shade:default-testnet-policy:v1",
      destination_commitment: p.destination,
      replay_domain: "shade:stellar:testnet:rfq:v1" as const,
      signature: "0x" + "00".repeat(64), // placeholder — user signs off-chain
      ...mpcFields
    });
  }

  // Poll for a solver quote until one arrives or the timeout expires.
  async pollQuote(
    intentId: string,
    opts: { timeoutMs?: number; intervalMs?: number } = {}
  ): Promise<QuoteResult> {
    const { timeoutMs = 60_000, intervalMs = 2_000 } = opts;
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      try {
        const data = await this.get<{ quotes?: QuoteResult[] }>(`/v1/intents/${intentId}/quotes`);
        if (data.quotes?.[0]) return data.quotes[0];
      } catch { /* not ready yet */ }
      await delay(intervalMs);
    }
    throw new Error(`pollQuote: no quote after ${timeoutMs}ms for intent ${intentId}`);
  }

  async acceptQuote(quoteId: string): Promise<{ accepted: boolean }> {
    return this.post(`/v1/quotes/${quoteId}/accept`, {});
  }

  // Poll intent state until settled/failed/expired or timeout.
  async trackSettlement(
    intentId: string,
    opts: { timeoutMs?: number; intervalMs?: number } = {}
  ): Promise<SettlementStatus> {
    const { timeoutMs = 300_000, intervalMs = 5_000 } = opts;
    const deadline = Date.now() + timeoutMs;
    const terminal = new Set(["settled", "failed", "expired"]);
    while (Date.now() < deadline) {
      try {
        const data = await this.get<{ state?: string; tx_hash?: string }>(`/v1/intents/${intentId}`);
        if (data.state && terminal.has(data.state)) {
          return { state: data.state as SettlementStatus["state"], txHash: data.tx_hash };
        }
      } catch { /* transient */ }
      await delay(intervalMs);
    }
    return { state: "pending", detail: `not settled after ${timeoutMs}ms` };
  }

  // Poll a CCTP deposit job until the note is registered in the pool.
  async trackDeposit(
    depositId: string,
    opts: { timeoutMs?: number; intervalMs?: number } = {}
  ): Promise<DepositStatus> {
    const { timeoutMs = 600_000, intervalMs = 8_000 } = opts;
    const deadline = Date.now() + timeoutMs;
    const terminal = new Set(["registered", "failed"]);
    while (Date.now() < deadline) {
      try {
        const data = await this.get<DepositStatus>(`/v1/deposits/${depositId}`);
        if (data.state && terminal.has(data.state)) return data;
      } catch { /* transient */ }
      await delay(intervalMs);
    }
    return { state: "pending" };
  }
}

function delay(ms: number): Promise<void> {
  return new Promise(r => setTimeout(r, ms));
}
