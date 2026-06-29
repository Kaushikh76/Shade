import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { config } from "dotenv";

export type EnvMap = Record<string, string>;

export async function loadRuntimeEnv(): Promise<EnvMap> {
  for (const path of [process.env.SHADE_ENV_FILE ?? ".env", ".env", ".env.generated", "../.env"]) {
    if (existsSync(path)) config({ path, override: false });
  }
  const env: EnvMap = { ...process.env } as EnvMap;
  if (existsSync(".env.generated")) {
    const generated = await readFile(".env.generated", "utf8");
    for (const line of generated.split("\n")) {
      if (!line.includes("=") || line.trimStart().startsWith("#")) continue;
      const index = line.indexOf("=");
      env[line.slice(0, index)] = line.slice(index + 1);
    }
  }
  return env;
}

export function requireKeys(env: EnvMap, keys: string[]): string[] {
  return keys.filter((key) => !env[key]);
}
