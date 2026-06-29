import { spawnSync } from "node:child_process";
import { appendFile } from "node:fs/promises";

const commands = [
  ["setup:testnet", ["run", "setup:testnet"]],
  ["contracts:init:stellar", ["run", "contracts:init:stellar"]],
  ["cctp:inbound:e2e", ["run", "cctp:inbound:e2e"]],
  ["zk:withdraw:e2e", ["run", "zk:withdraw:e2e"]],
  ["rfq:e2e", ["run", "rfq:e2e"]],
  ["cctp:outbound:e2e", ["run", "cctp:outbound:e2e"]]
] as const;

const results: string[] = [];
let failed = false;
for (const [name, args] of commands) {
  const result = spawnSync("npm", args, { encoding: "utf8", stdio: "pipe" });
  const ok = result.status === 0;
  failed ||= !ok;
  results.push(`- ${name}: ${ok ? "PASS" : "FAIL"}`);
  process.stdout.write(result.stdout);
  process.stderr.write(result.stderr);
}

await appendFile("docs/test-report.md", `\n## E2E All Aggregate\n\n${results.join("\n")}\n`);
if (failed) {
  throw new Error(`E2E aggregate failed:\n${results.join("\n")}`);
}
