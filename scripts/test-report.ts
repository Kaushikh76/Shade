import { readFile } from "node:fs/promises";

const report = await readFile("docs/test-report.md", "utf8");
console.log(report);
