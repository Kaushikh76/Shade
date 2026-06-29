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

  // C7: count unresolved ROOT_MISMATCH_CRITICAL findings from the root auditor
  // (P1.9). The API refuses spends while any exist. Tolerates a missing table
  // (migration 002 not yet applied) by treating it as "no findings".
  async criticalRootMismatchCount(): Promise<number> {
    try {
      const r = await this.pool.query<{ n: string }>(
        "select count(*)::text as n from root_audit_findings where code = 'ROOT_MISMATCH_CRITICAL'"
      );
      return Number(r.rows[0]?.n ?? "0");
    } catch {
      return 0;
    }
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

  // ---- Privy identity (auth-privy adapter) ----

  // Find or create the user for a Privy DID; bump last_login; ensure a profile.
  async upsertUserByPrivyId(privyUserId: string, profile?: { email?: string; primaryAuthMethod?: string }): Promise<string> {
    const existing = await this.pool.query<{ id: string }>("select id from users where privy_user_id=$1", [privyUserId]);
    if (existing.rows[0]) {
      await this.pool.query("update users set last_login_at=now(), updated_at=now() where id=$1", [existing.rows[0].id]);
      return existing.rows[0].id;
    }
    const u = await this.pool.query<{ id: string }>(
      "insert into users(privy_user_id, email, primary_auth_method, last_login_at) values ($1,$2,$3,now()) returning id",
      [privyUserId, profile?.email ?? null, profile?.primaryAuthMethod ?? "privy"]
    );
    await this.pool.query("insert into user_profiles(user_id) values ($1) on conflict do nothing", [u.rows[0].id]);
    return u.rows[0].id;
  }

  async userOwnsWallet(userId: string, address: string, chain?: string): Promise<boolean> {
    const params: unknown[] = [userId, address];
    let q = "select 1 from user_wallets where user_id=$1 and lower(address)=lower($2)";
    if (chain) { params.push(chain); q += " and chain=$3"; }
    const r = await this.pool.query(q, params);
    return (r.rowCount ?? 0) > 0;
  }

  async userOwnsVault(userId: string, vaultId: string): Promise<boolean> {
    const r = await this.pool.query("select 1 from note_vaults where user_id=$1 and vault_id=$2", [userId, vaultId]);
    return (r.rowCount ?? 0) > 0;
  }

  // ---- PHASE 2 auth / users ----

  async createNonce(walletType: string, address: string, nonce: string, message: string, expiresAt: Date): Promise<void> {
    await this.pool.query(
      "insert into auth_nonces(wallet_type, address, nonce, message, expires_at) values ($1,$2,$3,$4,$5)",
      [walletType, address, nonce, message, expiresAt]
    );
  }

  // Consume a nonce: returns the signed message if it exists, is unconsumed and
  // unexpired; marks it consumed atomically.
  async consumeNonce(walletType: string, address: string, nonce: string): Promise<string | null> {
    const { rows } = await this.pool.query<{ message: string }>(
      `update auth_nonces set consumed_at = now()
       where id = (select id from auth_nonces
         where wallet_type=$1 and address=$2 and nonce=$3 and consumed_at is null and expires_at > now()
         order by created_at desc for update skip locked limit 1)
       returning message`,
      [walletType, address, nonce]
    );
    return rows[0]?.message ?? null;
  }

  // Find or create the user owning this wallet; bump last_login; ensure a profile.
  async upsertUserByWallet(walletType: string, chain: string, address: string): Promise<string> {
    const existing = await this.pool.query<{ user_id: string }>("select user_id from user_wallets where wallet_type=$1 and address=$2", [walletType, address]);
    if (existing.rows[0]) {
      await this.pool.query("update users set last_login_at=now(), updated_at=now() where id=$1", [existing.rows[0].user_id]);
      return existing.rows[0].user_id;
    }
    const user = await this.pool.query<{ id: string }>("insert into users(last_login_at) values (now()) returning id");
    const userId = user.rows[0].id;
    await this.pool.query("insert into user_profiles(user_id) values ($1) on conflict do nothing", [userId]);
    await this.pool.query(
      "insert into user_wallets(user_id, wallet_type, chain, address, is_primary, verified_at) values ($1,$2,$3,$4,true,now())",
      [userId, walletType, chain, address]
    );
    return userId;
  }

  async createSession(userId: string, sessionHash: string, expiresAt: Date): Promise<void> {
    await this.pool.query("insert into user_sessions(user_id, session_hash, expires_at) values ($1,$2,$3)", [userId, sessionHash, expiresAt]);
  }

  async userIdForSession(sessionHash: string): Promise<string | null> {
    const { rows } = await this.pool.query<{ user_id: string }>(
      "select user_id from user_sessions where session_hash=$1 and revoked_at is null and expires_at > now()",
      [sessionHash]
    );
    return rows[0]?.user_id ?? null;
  }

  async revokeSession(sessionHash: string): Promise<void> {
    await this.pool.query("update user_sessions set revoked_at=now() where session_hash=$1", [sessionHash]);
  }

  async getUser(userId: string): Promise<Record<string, unknown> | null> {
    const { rows } = await this.pool.query(
      `select u.id, u.display_name, u.email, u.avatar_url, u.testnet_only, u.created_at, u.last_login_at,
              p.preferences, p.risk_flags
       from users u left join user_profiles p on p.user_id = u.id where u.id=$1`,
      [userId]
    );
    return rows[0] ?? null;
  }

  async updateUser(userId: string, fields: { display_name?: string; email?: string; avatar_url?: string; preferences?: unknown }): Promise<void> {
    const sets: string[] = [];
    const vals: unknown[] = [];
    for (const k of ["display_name", "email", "avatar_url"] as const) {
      if (fields[k] !== undefined) { vals.push(fields[k]); sets.push(`${k}=$${vals.length + 1}`); }
    }
    if (sets.length) { vals.unshift(userId); await this.pool.query(`update users set ${sets.join(",")}, updated_at=now() where id=$1`, [userId, ...vals.slice(1)]); }
    if (fields.preferences !== undefined) {
      await this.pool.query("update user_profiles set preferences=$2, updated_at=now() where user_id=$1", [userId, fields.preferences]);
    }
  }

  async listWallets(userId: string): Promise<Array<Record<string, unknown>>> {
    const { rows } = await this.pool.query("select id, wallet_type, chain, address, is_primary, verified_at, created_at from user_wallets where user_id=$1 order by created_at asc", [userId]);
    return rows;
  }

  async addWallet(userId: string, walletType: string, chain: string, address: string): Promise<string> {
    const { rows } = await this.pool.query<{ id: string }>(
      `insert into user_wallets(user_id, wallet_type, chain, address) values ($1,$2,$3,$4)
       on conflict (wallet_type, address) do update set chain=excluded.chain returning id`,
      [userId, walletType, chain, address]
    );
    return rows[0].id;
  }

  async deleteWallet(userId: string, walletId: string): Promise<boolean> {
    const r = await this.pool.query("delete from user_wallets where id=$1 and user_id=$2 and is_primary=false", [walletId, userId]);
    return (r.rowCount ?? 0) > 0;
  }

  async logActivity(userId: string | null, event: { event_type: string; entity_type?: string; entity_id?: string; tx_hash?: string; metadata?: unknown }): Promise<void> {
    await this.pool.query(
      "insert into user_activity(user_id, event_type, entity_type, entity_id, tx_hash, metadata) values ($1,$2,$3,$4,$5,$6)",
      [userId, event.event_type, event.entity_type ?? null, event.entity_id ?? null, event.tx_hash ?? null, event.metadata ?? {}]
    );
  }

  async listActivity(userId: string, limit = 100): Promise<Array<Record<string, unknown>>> {
    const { rows } = await this.pool.query("select event_type, entity_type, entity_id, tx_hash, metadata, created_at from user_activity where user_id=$1 order by created_at desc limit $2", [userId, limit]);
    return rows;
  }

  // List a user's rows from a user-owned table (user_id column).
  async listByUser(table: string, userId: string): Promise<Array<Record<string, unknown>>> {
    const allowed = new Set(["cctp_deposits", "note_commitments", "withdrawals", "intents", "settlements", "cctp_exits", "encrypted_note_backups"]);
    if (!allowed.has(table)) throw new Error(`unsafe table ${table}`);
    const { rows } = await this.pool.query(`select * from ${table} where user_id=$1 order by created_at desc limit 200`, [userId]);
    return rows;
  }

  async addNoteBackup(userId: string, commitment: string, encryptedPayload: string, version: string): Promise<void> {
    await this.pool.query(
      `insert into encrypted_note_backups(user_id, commitment, encrypted_payload, encryption_version) values ($1,$2,$3,$4)
       on conflict (user_id, commitment) do update set encrypted_payload=excluded.encrypted_payload`,
      [userId, commitment, encryptedPayload, version]
    );
  }

  async listQuotesByIntent(intentHash: string): Promise<Array<Record<string, unknown>>> {
    const { rows } = await this.pool.query("select quote_id, intent_hash, quote_hash, solver_id, payload, valid_until_ledger, state from quotes where intent_hash=$1 order by created_at asc", [intentHash]);
    return rows;
  }

  // Mark a fill executed with its destination tx hash.
  async executeFill(fillId: string, destinationTxHash: string): Promise<boolean> {
    const r = await this.pool.query("update fills set destination_tx_hash=$2, state='EXECUTED' where fill_id=$1", [fillId, destinationTxHash]);
    return (r.rowCount ?? 0) > 0;
  }

  // Tag a just-created protocol row with the owning user (best-effort).
  async setRowUser(table: string, idColumn: string, id: string, userId: string): Promise<void> {
    const allowed = new Set(["cctp_deposits", "withdrawals", "intents", "settlements", "cctp_exits"]);
    if (!allowed.has(table)) return;
    await this.pool.query(`update ${table} set user_id=$2 where ${idColumn}=$1`, [id, userId]);
  }
}
