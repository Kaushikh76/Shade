import { spawnSync } from "node:child_process";
const result = spawnSync("cargo", ["test", "--workspace"], {
  stdio: "inherit",
  cwd: "contracts/stellar",
  env: {
    ...process.env,
    PATH: `${process.env.HOME}/.cargo/bin:${process.env.PATH ?? ""}`
  }
});
process.exit(result.status ?? 1);
