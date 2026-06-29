import "dotenv/config";
import { requireProofStack } from "@shade/proof-utils";

await requireProofStack();
console.log("Proof stack inputs are present");
