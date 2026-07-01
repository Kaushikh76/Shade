import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";

// Runs the Rust contract test matrix. The soroban workspace pins soroban-sdk 23,
// while `lean_imt` deliberately tracks soroban-sdk 25 as a standalone crate, so it
// is NOT a workspace member and must be tested with its own `cargo test`.
const cargoEnv = {
  ...process.env,
  PATH: `${process.env.HOME}/.cargo/bin:${process.env.PATH ?? ""}`
};

const suites: Array<{ name: string; cwd: string; args: string[] }> = [
  { name: "stellar workspace", cwd: "contracts/stellar", args: ["test", "--workspace"] },
  { name: "lean_imt (standalone crate)", cwd: "contracts/stellar/lean_imt", args: ["test"] }
];

let failed = false;
for (const suite of suites) {
  if (!existsSync(`${suite.cwd}/Cargo.toml`)) {
    console.error(`SKIP ${suite.name}: no Cargo.toml at ${suite.cwd}`);
    continue;
  }
  console.log(`\n=== cargo ${suite.args.join(" ")} (${suite.name}) ===`);
  const result = spawnSync("cargo", suite.args, { stdio: "inherit", cwd: suite.cwd, env: cargoEnv });
  if ((result.status ?? 1) !== 0) failed = true;
}

process.exit(failed ? 1 : 0);
