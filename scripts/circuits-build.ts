import { appendFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { spawnSync } from "node:child_process";

type Check = { name: string; ok: boolean; detail: string };

const checks: Check[] = [];
const noirVersion = npmView("@noir-lang/noir_js");
const bbVersion = npmView("@aztec/bb.js");
checks.push({ name: "@noir-lang/noir_js availability", ok: !!noirVersion, detail: noirVersion || "not available" });
checks.push({ name: "@aztec/bb.js availability", ok: !!bbVersion, detail: bbVersion || "not available" });
checks.push({
  name: "circuit source files",
  ok: false,
  detail: "only circuit README specs exist; no Noir/Circom circuit source files have been authored yet"
});
checks.push({
  name: "Soroban verifier compatibility",
  ok: false,
  detail: "current local soroban-sdk exposes BLS12-381 helpers; architecture asks for BN254/Poseidon private-note verifier path, so verifier implementation must be selected before keys are generated"
});
checks.push({
  name: "proving artifacts",
  ok: existsSync("proof-artifacts"),
  detail: existsSync("proof-artifacts") ? "present" : "missing proof-artifacts directory"
});

await appendFile("docs/test-report.md", `\n## Circuit Build Audit\n\n${checks.map((c) => `- ${c.name}: ${c.ok ? "PASS" : "FAIL"} - ${c.detail}`).join("\n")}\n`);
const failed = checks.filter((check) => !check.ok);
if (failed.length) {
  throw new Error(failed.map((check) => `${check.name}: ${check.detail}`).join("\n"));
}

function npmView(pkg: string): string {
  const result = spawnSync("npm", ["view", pkg, "version"], { encoding: "utf8" });
  return result.status === 0 ? result.stdout.trim() : "";
}
