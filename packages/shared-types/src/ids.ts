import { createHash } from "node:crypto";
import type { DeterministicIdInput } from "./index.js";

export function deterministicId({ namespace, parts }: DeterministicIdInput): string {
  const hash = createHash("sha256")
    .update(namespace)
    .update("\0")
    .update(parts.join("\0"))
    .digest("hex");
  return `${namespace}_${hash.slice(0, 32)}`;
}

export function hashJson(value: unknown): string {
  return `0x${createHash("sha256").update(stableStringify(value)).digest("hex")}`;
}

export function stableStringify(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  const entries = Object.entries(value as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b));
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${stableStringify(v)}`).join(",")}}`;
}
