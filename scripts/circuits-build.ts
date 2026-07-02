import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { beginReport, writeCheckReport, failIfAny, type CheckResult } from "../apps/cli/src/lib/report.js";

// C1: real Circom build pipeline. Compiles every Shade circuit to r1cs+wasm, runs
// the Groth16 trusted setup (reusing ptau), and exports the verification key.
// Idempotent: skips setup if output/main_final.zkey already exists
// (rerun with CIRCUITS_FORCE_SETUP=1 to regenerate keys).
// BLS12-381 Circom circuits verified on Soroban.

const SHADE_ROOT = process.env.SHADE_ROOT ?? process.cwd();
const CIRCUITS_DIR = resolve(SHADE_ROOT, "circuits");
// Default ptau: dev-generated in .zk-ref/circuits/; override with SHADE_PTAU env.
// PTAU must be an absolute path — snarkjs runs in the circuit cwd, so relative paths break.
const PTAU = resolve(
  SHADE_ROOT,
  process.env.SHADE_PTAU ??
  (existsSync(resolve(SHADE_ROOT, ".zk-ref/circuits/pot16_final.ptau"))
    ? ".zk-ref/circuits/pot16_final.ptau"
    : ".zk-ref/soroban-examples/privacy-pools/circuits/pot15_final.ptau")
);
const FORCE = process.env.CIRCUITS_FORCE_SETUP === "1";

// circom binary: prefer CIRCOM_BIN env, then PATH, then temp download location.
const CIRCOM_BIN =
  process.env.CIRCOM_BIN ??
  (existsSync("C:/Users/clats/AppData/Local/Temp/circom.exe")
    ? "C:/Users/clats/AppData/Local/Temp/circom.exe"
    : "circom");

// name -> nPublic (output signals + declared public inputs in component main)
const CIRCUITS: { name: string; nPublic: number }[] = [
  { name: "withdraw_public",   nPublic: 18 }, // 1 output + 16 inputs + Phase 2 assetId
  { name: "private_transfer",  nPublic: 9  }, // hidden-amount transfer + ASP + Phase 2 in/out assetId
  { name: "deposit_note_mint", nPublic: 14 }, // 1 output + 13 inputs (assetIdHash already public)
  { name: "proof_of_fill_claim", nPublic: 11 }, // 1 output (claimId) + 10 public inputs
  { name: "mpc_settlement",    nPublic: 12 }, // 4 outputs + 7 public inputs + Phase 2/5 assetId
];

const checks: CheckResult[] = [];
const home = process.env.HOME ?? process.env.USERPROFILE ?? "";
const PATH_VAR = home
  ? `${home}/.cargo/bin:${process.env.PATH ?? ""}`
  : (process.env.PATH ?? "");
const env = { ...process.env, PATH: PATH_VAR, NODE_OPTIONS: "--max-old-space-size=8192" };

function circomlibPath(): string {
  const r = spawnSync("npm", ["root", "-g"], { encoding: "utf8", shell: true });
  const root = r.stdout?.trim();
  if (root && existsSync(resolve(root, "circomlib/circuits"))) {
    return resolve(root, "circomlib/circuits");
  }
  return "";
}

const ptauExists = existsSync(PTAU);
if (!ptauExists) {
  checks.push({ name: "powers-of-tau", ok: false, detail: `missing ${PTAU} — run: npx snarkjs powersoftau new bls12-381 16 .zk-ref/circuits/pot16_0000.ptau && npx snarkjs ptb .zk-ref/circuits/pot16_0000.ptau .zk-ref/circuits/pot16_beacon.ptau <hash> 10 && npx snarkjs pt2 .zk-ref/circuits/pot16_beacon.ptau .zk-ref/circuits/pot16_final.ptau` });
} else {
  checks.push({ name: "powers-of-tau", ok: true, detail: PTAU });
  const CIRCOMLIB = circomlibPath();
  const libArgs = CIRCOMLIB ? ["-l", ".", "-l", CIRCOMLIB] : ["-l", "."];

  for (const c of CIRCUITS) {
    const dir = resolve(CIRCUITS_DIR, c.name);
    if (!existsSync(dir)) {
      checks.push({ name: `circuit ${c.name}`, ok: false, detail: `directory not found: ${dir}` });
      continue;
    }
    try {
      mkdirSync(resolve(dir, "build"), { recursive: true });
      mkdirSync(resolve(dir, "output"), { recursive: true });

      // Compile circom -> r1cs + wasm
      execFileSync(
        CIRCOM_BIN,
        ["main.circom", "--r1cs", "--wasm", "--sym", "-o", "build", ...libArgs, "--prime", "bls12381"],
        { cwd: dir, env, encoding: "utf8", timeout: 120_000 }
      );

      const wasm = resolve(dir, "build/main_js/main.wasm");
      const r1cs  = resolve(dir, "build/main.r1cs");
      if (!existsSync(wasm) || !existsSync(r1cs)) throw new Error("compile produced no wasm/r1cs");

      const zkey0 = resolve(dir, "output/main_0000.zkey");
      const zkey  = resolve(dir, "output/main_final.zkey");
      const vk    = resolve(dir, "output/main_verification_key.json");

      if (FORCE || !existsSync(zkey)) {
        // Phase 1: Groth16 setup from r1cs + ptau
        execFileSync("npx", ["--yes", "snarkjs", "groth16", "setup", r1cs, PTAU, zkey0], { cwd: dir, env, timeout: 300_000, shell: true });

        // Phase 2: zkey contribute — use -e flag for non-interactive entropy
        execFileSync(
          "npx",
          ["--yes", "snarkjs", "zkey", "contribute", zkey0, zkey,
           `-n=shade-${c.name}`, `-e=shade-build-${c.name}-2026`],
          { cwd: dir, env, timeout: 300_000, shell: true }
        );
      }

      if (!existsSync(vk) || FORCE) {
        execFileSync("npx", ["--yes", "snarkjs", "zkey", "export", "verificationkey", zkey, vk], { cwd: dir, env, timeout: 60_000, shell: true });
      }

      const vkJson = JSON.parse(readFileSync(vk, "utf8"));
      const ok = vkJson.nPublic === c.nPublic;
      checks.push({
        name: `circuit ${c.name} (nPublic=${vkJson.nPublic})`,
        ok,
        detail: ok ? "compiled + zkey + vk OK" : `expected nPublic=${c.nPublic}, got ${vkJson.nPublic}`
      });
    } catch (e) {
      checks.push({ name: `circuit ${c.name} build`, ok: false, detail: (e as Error).message.slice(0, 300) });
    }
  }
}

beginReport({ title: "Circuit Build" });
await writeCheckReport("Circuit Build (Circom BLS12-381)", checks);
for (const c of checks) console.log(`${c.ok ? "PASS" : "FAIL"}  ${c.name}${c.detail ? " — " + c.detail : ""}`);
failIfAny(checks);
console.log("circuits:build PASS");
