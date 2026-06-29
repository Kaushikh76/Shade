import pg from "pg";
import type { StateTransition } from "@shade/shared-types";

const { Pool } = pg;

export class Store {
  private readonly pool: pg.Pool;

  constructor(databaseUrl = process.env.DATABASE_URL ?? "postgres://shade:shade@localhost:5432/shade") {
    if (!databaseUrl) throw new Error("DATABASE_URL is required for persistent state");
    this.pool = new Pool({ connectionString: databaseUrl });
  }

  async health(): Promise<void> {
    await this.pool.query("select 1");
  }

  async transition(transition: StateTransition): Promise<void> {
    await this.pool.query(
      `insert into state_transitions(entity_type, entity_id, from_state, to_state, reason, tx_hash, metadata)
       values ($1,$2,$3,$4,$5,$6,$7)`,
      [
        transition.entityType,
        transition.entityId,
        transition.fromState ?? null,
        transition.toState,
        transition.reason ?? null,
        transition.txHash ?? null,
        transition.metadata ?? {}
      ]
    );
  }

  async upsertDeposit(input: {
    depositId: string;
    idempotencyKey: string;
    sourceDomain: number;
    destinationDomain: number;
    assetId: string;
    amount6: string;
    amount7: string;
    commitment: string;
    encryptedNotePayloadHash: string;
    policyId: string;
    state: string;
  }): Promise<void> {
    await this.pool.query(
      `insert into cctp_deposits(
        deposit_id, idempotency_key, source_domain, destination_domain, asset_id,
        amount_usdc_6dp, amount_usdc_7dp, commitment, encrypted_note_payload_hash, policy_id, state
      ) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
      on conflict (idempotency_key) do nothing`,
      [
        input.depositId,
        input.idempotencyKey,
        input.sourceDomain,
        input.destinationDomain,
        input.assetId,
        input.amount6,
        input.amount7,
        input.commitment,
        input.encryptedNotePayloadHash,
        input.policyId,
        input.state
      ]
    );
  }

  async getById<T>(table: string, idColumn: string, id: string): Promise<T | null> {
    const allowedTables = new Set([
      "cctp_deposits",
      "proof_jobs",
      "withdrawals",
      "intents",
      "quotes",
      "settlements",
      "cctp_exits",
      "note_commitments"
    ]);
    if (!allowedTables.has(table)) throw new Error(`unsafe table ${table}`);
    const result = await this.pool.query(`select * from ${table} where ${idColumn} = $1`, [id]);
    return (result.rows[0] as T | undefined) ?? null;
  }

  async insertGeneric(table: string, row: Record<string, unknown>): Promise<void> {
    const allowedTables = new Set(["proof_jobs", "withdrawals", "intents", "quotes", "quote_acceptances", "solver_inventory_locks", "fills", "settlements", "cctp_exits"]);
    if (!allowedTables.has(table)) throw new Error(`unsafe table ${table}`);
    const keys = Object.keys(row);
    const placeholders = keys.map((_, i) => `$${i + 1}`).join(",");
    await this.pool.query(
      `insert into ${table}(${keys.join(",")}) values (${placeholders}) on conflict do nothing`,
      Object.values(row)
    );
  }
}
