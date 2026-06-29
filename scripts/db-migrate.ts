import "dotenv/config";
import { readFile } from "node:fs/promises";
import pg from "pg";

const databaseUrl = process.env.DATABASE_URL ?? "postgres://shade:shade@localhost:5432/shade";
const sql = await readFile("db/migrations/001_initial.sql", "utf8");
const pool = new pg.Pool({ connectionString: databaseUrl });

try {
  await pool.query(sql);
  console.log("Database migration PASS: db/migrations/001_initial.sql");
} finally {
  await pool.end();
}
