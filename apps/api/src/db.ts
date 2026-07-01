import pg from "pg";
import type { StateTransition } from "@shade/shared-types";

const { Pool } = pg;

export class Store {
  readonly pool: pg.Pool;

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

  // ---- PHASE 6 user-signed deposit ----

  async createUserDeposit(input: {
    depositId: string; idempotencyKey: string; userId: string; sourceChain: string; sourceWalletAddress: string;
    vaultId: string; sourceDomain: number; destinationDomain: number; assetId: string; amount6: string; amount7Max: string;
    commitment: string; encryptedNotePayloadHash: string; policyId: string;
  }): Promise<void> {
    await this.pool.query(
      `insert into cctp_deposits(deposit_id, idempotency_key, user_id, source_chain, source_wallet_address, vault_id,
        source_domain, destination_domain, asset_id, amount_usdc_6dp, amount_usdc_7dp, commitment,
        encrypted_note_payload_hash, policy_id, state)
       values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,'prepared')
       on conflict (deposit_id) do nothing`,
      [input.depositId, input.idempotencyKey, input.userId, input.sourceChain, input.sourceWalletAddress, input.vaultId,
       input.sourceDomain, input.destinationDomain, input.assetId, input.amount6, input.amount7Max, input.commitment,
       input.encryptedNotePayloadHash, input.policyId]
    );
  }

  async getDepositForUser(userId: string, depositId: string): Promise<Record<string, unknown> | null> {
    const { rows } = await this.pool.query("select * from cctp_deposits where deposit_id=$1 and user_id=$2", [depositId, userId]);
    return rows[0] ?? null;
  }

  async setDepositBurnTx(depositId: string, burnTxHash: string): Promise<void> {
    await this.pool.query("update cctp_deposits set source_tx_hash=$2, state='burn_submitted', updated_at=now() where deposit_id=$1", [depositId, burnTxHash]);
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

  // ---- Note vaults (PHASE 4) ----

  async createNoteVault(input: { userId: string; privyUserId: string; vaultId: string; envelope: unknown; ciphertext: string; aad: unknown; recoveryPolicyStatus: string }): Promise<void> {
    await this.pool.query(
      `insert into note_vaults(user_id, privy_user_id, vault_id, envelope, ciphertext, aad, backup_status, recovery_policy_status)
       values ($1,$2,$3,$4,$5,$6,'created',$7)
       on conflict (vault_id) do update set envelope=excluded.envelope, ciphertext=excluded.ciphertext, aad=excluded.aad,
         recovery_policy_status=excluded.recovery_policy_status, updated_at=now()`,
      [input.userId, input.privyUserId, input.vaultId, input.envelope, input.ciphertext, input.aad, input.recoveryPolicyStatus]
    );
  }

  async listNoteVaults(userId: string): Promise<Array<Record<string, unknown>>> {
    const { rows } = await this.pool.query(
      "select vault_id, backup_status, recovery_policy_status, last_backup_verified_at, last_restored_at, created_at, updated_at from note_vaults where user_id=$1 order by created_at desc",
      [userId]
    );
    return rows;
  }

  async getNoteVault(userId: string, vaultId: string): Promise<Record<string, unknown> | null> {
    const { rows } = await this.pool.query("select * from note_vaults where user_id=$1 and vault_id=$2", [userId, vaultId]);
    return rows[0] ?? null;
  }

  async updateNoteVault(userId: string, vaultId: string, input: { envelope: unknown; ciphertext: string; aad: unknown; recoveryPolicyStatus: string }): Promise<boolean> {
    const r = await this.pool.query(
      "update note_vaults set envelope=$3, ciphertext=$4, aad=$5, recovery_policy_status=$6, updated_at=now() where user_id=$1 and vault_id=$2",
      [userId, vaultId, input.envelope, input.ciphertext, input.aad, input.recoveryPolicyStatus]
    );
    return (r.rowCount ?? 0) > 0;
  }

  async setVaultBackupStatus(userId: string, vaultId: string, status: "verified" | "restored" | "failed"): Promise<boolean> {
    const col = status === "verified" ? "last_backup_verified_at" : status === "restored" ? "last_restored_at" : null;
    const set = col ? `, ${col}=now()` : "";
    const r = await this.pool.query(`update note_vaults set backup_status=$3${set}, updated_at=now() where user_id=$1 and vault_id=$2`, [userId, vaultId, status]);
    return (r.rowCount ?? 0) > 0;
  }

  // FIX3: mark verified AND persist the client's proof-of-decrypt verification.
  async setVaultBackupVerified(userId: string, vaultId: string, verification: unknown): Promise<boolean> {
    const r = await this.pool.query(
      "update note_vaults set backup_status='verified', last_backup_verified_at=now(), last_backup_verification=$3, updated_at=now() where user_id=$1 and vault_id=$2",
      [userId, vaultId, verification]
    );
    return (r.rowCount ?? 0) > 0;
  }

  async setVaultRecoveryPolicy(vaultId: string, status: string): Promise<void> {
    await this.pool.query("update note_vaults set recovery_policy_status=$2, updated_at=now() where vault_id=$1", [vaultId, status]);
  }

  // Vault deposit-readiness: backup verified AND recovery policy sufficient/strong.
  async vaultDepositReady(userId: string, vaultId: string): Promise<{ ready: boolean; backup_status: string; recovery_policy_status: string } | null> {
    const { rows } = await this.pool.query<{ backup_status: string; recovery_policy_status: string }>(
      "select backup_status, recovery_policy_status from note_vaults where user_id=$1 and vault_id=$2",
      [userId, vaultId]
    );
    if (!rows[0]) return null;
    const ready = rows[0].backup_status === "verified" && (rows[0].recovery_policy_status === "sufficient" || rows[0].recovery_policy_status === "strong");
    return { ready, ...rows[0] };
  }

  async addVaultWrapper(userId: string, vaultId: string, wrapperType: string, metadata: unknown): Promise<string> {
    const { rows } = await this.pool.query<{ id: string }>(
      "insert into note_vault_wrappers(vault_id, user_id, wrapper_type, metadata) values ($1,$2,$3,$4) returning id",
      [vaultId, userId, wrapperType, metadata ?? {}]
    );
    return rows[0].id;
  }

  async deleteVaultWrapper(userId: string, vaultId: string, wrapperId: string): Promise<boolean> {
    const r = await this.pool.query("delete from note_vault_wrappers where id=$1 and vault_id=$2 and user_id=$3", [wrapperId, vaultId, userId]);
    return (r.rowCount ?? 0) > 0;
  }

  async listVaultWrappers(vaultId: string): Promise<Array<{ wrapper_type: string; wrapper_status: string; metadata: Record<string, unknown> }>> {
    const { rows } = await this.pool.query("select wrapper_type, wrapper_status, metadata from note_vault_wrappers where vault_id=$1", [vaultId]);
    return rows as Array<{ wrapper_type: string; wrapper_status: string; metadata: Record<string, unknown> }>;
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
      `select u.id, u.privy_user_id, u.display_name, u.email, u.avatar_url, u.testnet_only,
              u.created_at, u.last_login_at, p.preferences, p.risk_flags
       from users u left join user_profiles p on p.user_id = u.id where u.id=$1`,
      [userId]
    );
    if (!rows[0]) return null;
    return { ...rows[0], wallets: await this.listWallets(userId) };
  }

  // FIX2: sync Privy linked wallets into user_wallets for the authenticated user.
  async syncPrivyWallets(userId: string, privyUserId: string, wallets: Array<{ wallet_type: string; wallet_source?: string; chain: string; address: string; privy_wallet_id?: string }>): Promise<number> {
    let n = 0;
    for (const w of wallets) {
      await this.pool.query(
        `insert into user_wallets(user_id, privy_user_id, wallet_type, wallet_source, chain, address, privy_wallet_id, verified_at)
         values ($1,$2,$3,$4,$5,$6,$7, now())
         on conflict (wallet_type, address) do update set
           user_id=excluded.user_id, privy_user_id=excluded.privy_user_id,
           wallet_source=excluded.wallet_source, chain=excluded.chain,
           privy_wallet_id=excluded.privy_wallet_id, verified_at=now()`,
        [userId, privyUserId, w.wallet_type, w.wallet_source ?? "external", w.chain, w.address, w.privy_wallet_id ?? null]
      );
      n++;
    }
    return n;
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

  async listNoteVaultsForRecovery(userId: string, vaultId?: string): Promise<Array<Record<string, unknown>>> {
    const filter = vaultId ? " and vault_id=$2" : "";
    const params: unknown[] = vaultId ? [userId, vaultId] : [userId];
    const { rows } = await this.pool.query(
      `select vault_id, envelope, ciphertext, aad, backup_status, recovery_policy_status, created_at, updated_at
       from note_vaults where user_id=$1${filter} order by created_at desc`,
      params
    );
    return rows;
  }

  async addNoteBackup(userId: string, commitment: string, encryptedPayload: string, version: string): Promise<void> {
    await this.pool.query(
      `insert into encrypted_note_backups(user_id, commitment, encrypted_payload, encryption_version) values ($1,$2,$3,$4)
       on conflict (user_id, commitment) do update set encrypted_payload=excluded.encrypted_payload`,
      [userId, commitment, encryptedPayload, version]
    );
  }

  // PHASE 8: gather the full RFQ lifecycle state for a settlement request.
  async rfqLifecycle(intentHash: string, quoteId: string): Promise<{
    intent: { intent_hash: string; user_id: string | null; expiry_ledger: number } | null;
    quote: { quote_id: string; intent_hash: string; quote_hash: string; solver_id: string; state: string; valid_until_ledger: number } | null;
    accepted: boolean;
    fill: { fill_id: string; quote_id: string; fill_receipt_hash: string; state: string; destination_tx_hash: string | null } | null;
  }> {
    const intent = (await this.pool.query("select intent_hash, user_id, expiry_ledger from intents where intent_hash=$1", [intentHash])).rows[0] ?? null;
    const quote = (await this.pool.query("select quote_id, intent_hash, quote_hash, solver_id, state, valid_until_ledger from quotes where quote_id=$1", [quoteId])).rows[0] ?? null;
    const accepted = ((await this.pool.query("select 1 from quote_acceptances where quote_id=$1", [quoteId])).rowCount ?? 0) > 0;
    const fill = (await this.pool.query("select fill_id, quote_id, fill_receipt_hash, state, destination_tx_hash from fills where quote_id=$1 order by created_at desc limit 1", [quoteId])).rows[0] ?? null;
    return { intent, quote, accepted, fill };
  }

  async isNullifierSpent(nullifier: string): Promise<boolean> {
    try {
      const r = await this.pool.query("select 1 from nullifier_spends where nullifier=$1", [nullifier]);
      return (r.rowCount ?? 0) > 0;
    } catch { return false; }
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

  // P2 #13 Shade View: fetch only the settlements/commitments the user owns —
  // silently drops ids that don't belong to them or don't exist, rather than
  // erroring, so a report never leaks another user's data through an id guess.
  async getOwnedSettlements(userId: string, settlementIds: string[]): Promise<Array<Record<string, unknown>>> {
    if (settlementIds.length === 0) return [];
    const { rows } = await this.pool.query(
      `select settlement_id, intent_hash, quote_id, nullifier, stellar_tx_hash, state, created_at
       from settlements where user_id=$1 and settlement_id = ANY($2)`,
      [userId, settlementIds]
    );
    return rows;
  }

  async getOwnedNoteCommitments(userId: string, commitments: string[]): Promise<Array<Record<string, unknown>>> {
    if (commitments.length === 0) return [];
    const { rows } = await this.pool.query(
      `select commitment, policy_id, amount_usdc_7dp, status, created_at
       from note_commitments where user_id=$1 and commitment = ANY($2)`,
      [userId, commitments]
    );
    return rows;
  }

  // Anchor transaction ids linked to the given settlements (SEP-31 payout id).
  async getAnchorIdsForSettlements(settlementIds: string[]): Promise<string[]> {
    if (settlementIds.length === 0) return [];
    const { rows } = await this.pool.query<{ anchor_transaction_id: string }>(
      `select distinct anchor_transaction_id from anchor_payouts
       where settlement_id = ANY($1) and anchor_transaction_id is not null`,
      [settlementIds]
    );
    return rows.map(r => r.anchor_transaction_id);
  }

  async insertViewKeyReport(row: {
    reportId: string; userId: string; timeRangeFrom?: string; timeRangeTo?: string;
    noteCommitments: string[]; disclosedNullifiers: string[]; quoteId?: string;
    policyId?: string; anchorId?: string; amountDisclosed: boolean; proofLinks: string[];
    servicePubkey: string; serviceSignature: string; encryptedAttachment?: unknown;
  }): Promise<void> {
    await this.pool.query(
      `insert into view_key_reports
         (report_id, user_id, time_range_from, time_range_to, note_commitments, disclosed_nullifiers,
          quote_id, policy_id, anchor_id, amount_disclosed, proof_links, service_pubkey, service_signature, encrypted_attachment)
       values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
      [
        row.reportId, row.userId, row.timeRangeFrom ?? null, row.timeRangeTo ?? null,
        JSON.stringify(row.noteCommitments), JSON.stringify(row.disclosedNullifiers),
        row.quoteId ?? null, row.policyId ?? null, row.anchorId ?? null, row.amountDisclosed,
        JSON.stringify(row.proofLinks), row.servicePubkey, row.serviceSignature,
        row.encryptedAttachment ? JSON.stringify(row.encryptedAttachment) : null
      ]
    );
  }

  async getViewKeyReport(userId: string, reportId: string): Promise<Record<string, unknown> | null> {
    const { rows } = await this.pool.query(
      "select * from view_key_reports where report_id=$1 and user_id=$2",
      [reportId, userId]
    );
    return rows[0] ?? null;
  }
}
