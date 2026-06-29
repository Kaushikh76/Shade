import pg from "pg";

// PHASE 2: a durable Postgres-backed job queue. The API enqueues jobs; prover and
// relayer workers claim them atomically with FOR UPDATE SKIP LOCKED so concurrent
// workers never double-process. No external broker (Redis/BullMQ) needed — the
// `service_jobs` table is the queue (see db/migrations/003).

export type QueueName = "prover" | "relayer";

export type ServiceJob = {
  job_id: string;
  job_type: string;
  queue: QueueName;
  idempotency_key: string | null;
  payload: Record<string, unknown>;
  status: string;
  attempts: number;
  max_attempts: number;
  result: Record<string, unknown> | null;
  error: string | null;
};

export class JobQueue {
  private readonly pool: pg.Pool;

  constructor(databaseUrl = process.env.DATABASE_URL ?? "postgres://shade:shade@localhost:5432/shade") {
    this.pool = new pg.Pool({ connectionString: databaseUrl });
  }

  async close(): Promise<void> {
    await this.pool.end();
  }

  // Enqueue a job. If idempotencyKey is supplied and a job already exists for it,
  // the existing job is returned (no duplicate work).
  async enqueue(queue: QueueName, jobType: string, payload: Record<string, unknown>, idempotencyKey?: string): Promise<ServiceJob> {
    if (idempotencyKey) {
      const existing = await this.pool.query<ServiceJob>("select * from service_jobs where idempotency_key = $1", [idempotencyKey]);
      if (existing.rows[0]) return existing.rows[0];
    }
    const { rows } = await this.pool.query<ServiceJob>(
      `insert into service_jobs(job_type, queue, idempotency_key, payload, status)
       values ($1,$2,$3,$4,'queued') returning *`,
      [jobType, queue, idempotencyKey ?? null, payload]
    );
    await this.event(rows[0].job_id, "queued", `enqueued ${jobType}`);
    return rows[0];
  }

  // Atomically claim the oldest available job for a queue (optionally filtered by
  // job types). Returns null if the queue is empty. Increments attempts.
  async claimNext(queue: QueueName, jobTypes?: string[]): Promise<ServiceJob | null> {
    const typeFilter = jobTypes && jobTypes.length ? "and job_type = any($2)" : "";
    const params: unknown[] = [queue];
    if (jobTypes && jobTypes.length) params.push(jobTypes);
    const { rows } = await this.pool.query<ServiceJob>(
      `update service_jobs set status='claimed', attempts=attempts+1, claimed_at=now(), updated_at=now()
       where job_id = (
         select job_id from service_jobs
         where queue=$1 and status in ('queued','failed_retry') and available_at <= now() ${typeFilter}
         order by created_at asc
         for update skip locked
         limit 1
       )
       returning *`,
      params
    );
    return rows[0] ?? null;
  }

  // Advance a job's status (one of the in-progress states) + log an event.
  async setStatus(jobId: string, status: string, detail?: string): Promise<void> {
    await this.pool.query("update service_jobs set status=$2, updated_at=now() where job_id=$1", [jobId, status]);
    await this.event(jobId, status, detail);
  }

  async complete(jobId: string, result: Record<string, unknown>, status = "ready"): Promise<void> {
    await this.pool.query("update service_jobs set status=$2, result=$3, error=null, updated_at=now() where job_id=$1", [jobId, status, result]);
    await this.event(jobId, status, "completed");
  }

  // Mark failed. If attempts remain, requeue with a backoff (status failed_retry);
  // otherwise terminal 'failed'.
  async fail(jobId: string, error: string, backoffSeconds = 10): Promise<void> {
    const { rows } = await this.pool.query<{ attempts: number; max_attempts: number }>(
      "select attempts, max_attempts from service_jobs where job_id=$1",
      [jobId]
    );
    const j = rows[0];
    const terminal = !j || j.attempts >= j.max_attempts;
    if (terminal) {
      await this.pool.query("update service_jobs set status='failed', error=$2, updated_at=now() where job_id=$1", [jobId, error.slice(0, 2000)]);
      await this.event(jobId, "failed", error.slice(0, 500));
    } else {
      await this.pool.query(
        `update service_jobs set status='failed_retry', error=$2, available_at=now() + ($3 || ' seconds')::interval, updated_at=now() where job_id=$1`,
        [jobId, error.slice(0, 2000), String(backoffSeconds)]
      );
      await this.event(jobId, "failed_retry", error.slice(0, 500));
    }
  }

  async event(jobId: string, status: string, detail?: string): Promise<void> {
    await this.pool.query("insert into service_events(job_id, status, detail) values ($1,$2,$3)", [jobId, status, detail ?? null]);
  }

  async getJob(jobId: string): Promise<ServiceJob | null> {
    const { rows } = await this.pool.query<ServiceJob>("select * from service_jobs where job_id=$1", [jobId]);
    return rows[0] ?? null;
  }

  async getEvents(jobId: string): Promise<Array<{ status: string; detail: string | null; created_at: string }>> {
    const { rows } = await this.pool.query("select status, detail, created_at from service_events where job_id=$1 order by created_at asc", [jobId]);
    return rows as Array<{ status: string; detail: string | null; created_at: string }>;
  }
}
