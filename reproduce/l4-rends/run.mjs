// L4 — Rends standalone, on the current production path. No special-casing.
//
// Usage (Fed runs this; it WRITES to the production audit chain):
//   AC_ENDPOINT=http://localhost:4000 AC_API_KEY=<key> \
//   ORG_ID=<uuid> AGENT_ID=<uuid> \
//   node /home/ubuntu/agent-authz-evidence/reproduce/l4-rends/run.mjs
//
// ⛔ WHAT THIS WRITES. Each check-action call is a /v1/ request, so the gateway
// audits it, and comply writes its own rows. These are WORM and permanent. That
// is the production path — the brief forbids special-casing — and the cost is
// stated rather than hidden.
//
// ⛔ RAW vs REDACTED (ruling 2026-09-13). Raw responses go to
// /home/ubuntu/agent-authz-raw/ (outside the public tree). A redacted copy goes
// to ./output/ and ships public.

import { writeFileSync, appendFileSync, mkdirSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { transfer_funds, resetLedger, readLedger } from "../../harness/ledger.mjs";
import { SCENARIOS, AGENT_PRINCIPAL, DELEGATED_HUMAN } from "../../harness/scenarios.mjs";
import { redact, redactorSelfTest } from "../../harness/redact.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const OUT = resolve(HERE, "output");
const RAW = "/home/ubuntu/agent-authz-raw/l4-rends";
const LEDGER = resolve(OUT, "ledger.json");

const ENDPOINT = process.env.AC_ENDPOINT ?? "http://localhost:4000";
const KEY = process.env.AC_API_KEY;
const ORG_ID = process.env.ORG_ID;
const AGENT_ID = process.env.AGENT_ID;

for (const [k, v] of [["AC_API_KEY", KEY], ["ORG_ID", ORG_ID], ["AGENT_ID", AGENT_ID]]) {
  if (!v) {
    console.error(`REFUSING TO START — ${k} is not set. This stack talks to production; it does not guess.`);
    process.exit(2);
  }
}

// ⛔ The redactor must be proven able to see a secret before anything is written
// through it. A redactor that silently matches nothing produces a "redacted"
// file identical to the raw one.
const self = redactorSelfTest();
if (!self.ok) {
  console.error("REFUSING TO START — redactor self-test FAILED:", JSON.stringify(self));
  process.exit(2);
}

mkdirSync(OUT, { recursive: true });
mkdirSync(RAW, { recursive: true });
resetLedger(LEDGER);

const rawLines = [];
const pubLines = [];
function record(label, obj) {
  const raw = JSON.stringify({ label, ...obj });
  rawLines.push(raw);
  pubLines.push(redact(raw).text);
}

async function checkAction(s) {
  // ⚠️ The amount can only travel as text — see POLICY-ENCODING.md. This is the
  // limitation under test, encoded exactly as the product would force a caller to.
  const body = {
    orgId: ORG_ID,
    agentId: AGENT_ID,
    actionType: "financial_transaction",
    actionName: "transfer_funds",
    resourceType: "account",
    input_summary:
      `from=${s.args.from} to=${s.args.to} amount=${s.args.amount.toFixed(2)} currency=${s.args.currency}`,
  };
  const t0 = Date.now();
  const res = await fetch(`${ENDPOINT}/v1/compliance/check-action`, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${KEY}` },
    body: JSON.stringify(body),
  });
  const ms = Date.now() - t0;
  const text = await res.text();
  let parsed = null;
  try { parsed = JSON.parse(text); } catch { /* keep the raw text */ }
  return { status: res.status, ms, body, response: parsed ?? text };
}

console.log("=== L4: Rends standalone, production path ===\n");
console.log(`endpoint ${ENDPOINT}  org ${ORG_ID}  agent ${AGENT_ID}\n`);

for (const s of SCENARIOS) {
  const r = await checkAction(s);
  // The product returns {blocked, violations[...]} — NOT allow/deny/escalate.
  // Mapping it to the spec's vocabulary is an interpretation, so it is recorded
  // as one, beside the raw response.
  const blocked = r.response && typeof r.response === "object" ? Boolean(r.response.blocked ?? r.response.data?.blocked) : null;
  record(s.id, { scenario: s.id, expected: s.expect.decision, http: r.status, latency_ms: r.ms, request: r.body, response: r.response, interpreted_blocked: blocked });
  console.log(`${s.id} (${s.label}): http=${r.status} blocked=${blocked} latency=${r.ms}ms`);
}

// ── Axis 2. TEST the bypass; do not assume it. ────────────────────────────────
// Path A is advisory: it returns a decision and does not stand between the agent
// and the tool. If that is true, this call succeeds and moves real money in the
// ledger with no check-action having been made at all.
console.log("\n--- bypass test: call the tool directly, never calling check-action ---");
const before = readLedger(LEDGER);
const bypass = transfer_funds({ from: "ACCT-A", to: "ACCT-SANCTIONED-9", amount: 27500.0, currency: "USD" }, LEDGER);
const after = readLedger(LEDGER);
console.log(`bypass executed: ${bypass.executed}`);
console.log(`ledger moved:    ${before["ACCT-A"]} -> ${after["ACCT-A"]}`);
console.log(`sanctioned acct: ${after["ACCT-SANCTIONED-9"] ?? 0}`);
record("BYPASS", { note: "tool called directly; no check-action issued", executed: bypass.executed, ledger_before: before["ACCT-A"], ledger_after: after["ACCT-A"] });

writeFileSync(resolve(RAW, "run.raw.jsonl"), rawLines.join("\n") + "\n");
writeFileSync(resolve(OUT, "run.redacted.jsonl"), pubLines.join("\n") + "\n");
console.log(`\nraw      -> ${RAW}/run.raw.jsonl   (NOT public)`);
console.log(`redacted -> ${OUT}/run.redacted.jsonl (public tree)`);
console.log(`\nprincipals recorded: agent=${AGENT_PRINCIPAL} delegated_human=${DELEGATED_HUMAN}`);
console.log("⚠️  axis 4: check-action's body carries agentId but NO delegated human field — see POLICY-ENCODING.md");
