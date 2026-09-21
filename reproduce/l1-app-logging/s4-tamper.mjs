// S4 — alter the record of S3 using credentials the operator legitimately holds.
// For L1 those credentials are: write access to the log file. That is all.

import { readFileSync, writeFileSync, statSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const LOG = resolve(dirname(fileURLToPath(import.meta.url)), "output", "app.log.jsonl");

console.log("=== L1 S4: tamper with the DENY record ===\n");
const before = readFileSync(LOG, "utf8").trim().split("\n");
console.log(`before: ${before.length} lines`);
console.log(`S3 record before: ${before.find((l) => l.includes('"S3"'))}\n`);

// The operator deletes the denial outright.
const after = before.filter((l) => !l.includes('"S3"'));
writeFileSync(LOG, after.join("\n") + "\n");

console.log(`after:  ${after.length} lines`);
console.log(`S3 record after:  ${after.find((l) => l.includes('"S3"')) ?? "<gone>"}\n`);

console.log("--- can an outside party detect this? ---");
console.log(`file mtime is the only residue:  ${statSync(LOG).mtime.toISOString()}`);
console.log("no sequence numbers  -> a removed line leaves no hole");
console.log("no hash chain        -> remaining lines still 'agree' with each other");
console.log("no external anchor   -> nothing off-box ever saw the original");
console.log("\nDETECTABLE BY OUTSIDE PARTY: NO");
