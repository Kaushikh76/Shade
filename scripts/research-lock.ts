import { access } from "node:fs/promises";

await access("docs/research-lock.md");
console.log("Research lock exists: docs/research-lock.md");
