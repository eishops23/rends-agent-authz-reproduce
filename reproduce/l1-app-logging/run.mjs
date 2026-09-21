// L1 — application logging only. The naive baseline.
//
// The agent consults the policy in its own process, calls the tool, and writes
// a structured JSON line AFTER execution. Nothing outside the agent enforces
// anything. This stack exists to establish the floor.

import { appendFileSync, writeFileSync, readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { transfer_funds, resetLedger, readLedger } from "../../harness/ledger.mjs";
import { SCENARIOS, decide, AGENT_PRINCIPAL, DELEGATED_HUMAN } from "../../harness/scenarios.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const OUT = resolve(HERE, "output");
const LEDGER = resolve(OUT, "ledger.json");
const LOG = resolve(OUT, "app.log.jsonl");

function log(rec) {
  appendFileSync(LOG, JSON.stringify(rec) + "\n");
}

resetLedger(LEDGER);
writeFileSync(LOG, "");

console.log("=== L1: application logging only ===\n");

for (const s of SCENARIOS) {
  const d = decide(s.args);
  let result = null;

  if (d.decision === "ALLOW") {
    result = transfer_funds(s.args, LEDGER);
  } else if (d.decision === "ESCALATE") {
    // The approval is a variable in this process. Nothing binds it to the action.
    const approved = true;
    if (approved) result = transfer_funds(s.args, LEDGER);
  }
  // DENY: the tool is simply not called. Note what that means for evidence.

  log({
    scenario: s.id,
    agent: AGENT_PRINCIPAL,
    user: DELEGATED_HUMAN,
    action: "transfer_funds",
    args: s.args,
    decision: d.decision,
    clause: d.clause,
    executed: Boolean(result),
    at: new Date().toISOString(),
  });
  console.log(`${s.id} (${s.label}): decision=${d.decision} executed=${Boolean(result)}`);
}

// --- Axis 2: can the agent bypass the control? TEST it, do not assume. ---
console.log("\n--- bypass test: call the tool directly, skipping the policy ---");
const before = readLedger(LEDGER);
const bypass = transfer_funds(
  { from: "ACCT-A", to: "ACCT-SANCTIONED-9", amount: 27500.0, currency: "USD" },
  LEDGER,
);
const after = readLedger(LEDGER);
console.log(`bypass executed: ${bypass.executed}`);
console.log(`ledger moved:    ${before["ACCT-A"]} -> ${after["ACCT-A"]}`);
console.log(`log lines:       ${readFileSync(LOG, "utf8").trim().split("\n").length} (bypass wrote none)`);
