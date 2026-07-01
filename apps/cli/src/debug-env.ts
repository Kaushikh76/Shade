import { loadRuntimeEnv } from "./lib/env.js";
import { spawnSync } from "node:child_process";

const env = await loadRuntimeEnv();
const relayerSecret = env["STELLAR_RELAYER_SECRET"];
const pool = env["SHIELDED_POOL_CONTRACT"];

console.log("relayerSecret first5:", relayerSecret?.substring(0,5));
console.log("relayerSecret length:", relayerSecret?.length);
console.log("pool first8:", pool?.substring(0,8));
console.log("process.env.STELLAR_ACCOUNT:", process.env["STELLAR_ACCOUNT"] ?? "<unset>");

const cargoPath = `${process.env["HOME"]}/.cargo/bin;${process.env["PATH"]}`;
const r = spawnSync("stellar", [
  "contract", "invoke",
  "--id", pool!,
  "--source-account", relayerSecret!,
  "--rpc-url", "https://soroban-testnet.stellar.org",
  "--network-passphrase", "Test SDF Network ; September 2015",
  "--", "get_root"
], {
  encoding: "utf8",
  env: { ...process.env, PATH: cargoPath }
});
console.log("status:", r.status);
console.log("stdout:", r.stdout?.trim().substring(0,100));
console.log("stderr:", r.stderr?.trim().substring(0,200));
