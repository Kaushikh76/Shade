import { appendFile } from "node:fs/promises";

export type CheckResult = {
  name: string;
  ok: boolean;
  detail: string;
};

export async function writeCheckReport(title: string, results: CheckResult[]): Promise<void> {
  const lines = ["", `## ${title}`, "", ...results.map((r) => `- ${r.name}: ${r.ok ? "PASS" : "FAIL"} - ${r.detail}`)];
  await appendFile("docs/test-report.md", `${lines.join("\n")}\n`);
}

export function failIfAny(results: CheckResult[]): void {
  const failed = results.filter((result) => !result.ok);
  if (failed.length) {
    throw new Error(failed.map((result) => `${result.name}: ${result.detail}`).join("\n"));
  }
}
