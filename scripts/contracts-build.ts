import { spawnSync } from "node:child_process";
import { appendFile } from "node:fs/promises";

const cli = spawnSync("stellar", ["--version"], { encoding: "utf8" });
if (cli.status !== 0) {
  await appendFile("docs/blockers.md", "\n\nObserved again: `stellar --version` failed during `npm run contracts:build`.\n");
  throw new Error("Stellar CLI is required. Install with `brew install stellar-cli`.");
}
const build = spawnSync("stellar", ["contract", "build"], {
  stdio: "inherit",
  cwd: "contracts/stellar",
  env: {
    ...process.env,
    PATH: `${process.env.HOME}/.cargo/bin:${process.env.PATH ?? ""}`
  }
});
process.exit(build.status ?? 1);
