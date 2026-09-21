#!/usr/bin/env node
/**
 * ⭐⭐ L5 DECISION ADAPTER — OBSERVATION POINT B.
 *
 * Reads `AgentCore.Policy.AuthorizeAction` spans out of the `aws/spans` CloudWatch log group and
 * commits each into a SHA-512 hash chain, producing a bundle a second party verifies offline with
 * `verify-seal.mjs` — the same envelope F-12's config seal uses, so the verifier extends, not forks.
 *
 * ⭐⭐ WHY THIS IS WORTH ANYTHING: the record is emitted by AWS, not by the vendor's client. A
 * suppressed client-side call yields no decision at all; a suppressed gateway call still emits AWS's
 * own span. That is the entire difference between point B and point A.
 *
 * ⛔⛔ AND THE HALF THAT MUST TRAVEL WITH IT — see WHAT_THIS_DOES_NOT_PROVE below. It proves a
 * decision happened, which policy decided, and what it decided. It proves NOTHING about who asked or
 * what they asked for, and it never will on this source. `authz_evidence` carries no principal and
 * no arguments; axes 4 and 5 stay unmet and shipping this does not move them.
 *
 * ⛔ READ-ONLY. Creates no AWS resource, deletes nothing, and does not touch the gateway.
 *
 * usage: node ingest-decisions.mjs [--since-min N] [--out FILE] [--log-group NAME] [--force]
 *
 * ⛔⛔ THIS SCRIPT REFUSES TO OVERWRITE AN EXISTING BUNDLE. A bundle is the only copy of a capture
 * that can never be taken again — the window has passed and the spans have aged out. Re-running with
 * the default --out once destroyed nothing only because nobody re-ran it. Use --force to mean it.
 */
import { execFileSync } from "node:child_process";
import { writeFileSync, mkdirSync, existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { computeHash, canonicalJSON } from "../../harness/chain.mjs";
// ⛔⛔ F-18: the span→record mapping lives in its own module so a TEST can reach it.
//    This file calls AWS at its top level, so anything defined here is untestable.
import { SPAN_NAME, toDecisionRecord } from "./decision-record.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const BUNDLE_KIND = "agentcore-decision-capture";
const BUNDLE_VERSION = 1;

/**
 * ⛔⛔ VERBATIM FROM PROPOSAL-L5 §2. The verifier prints these ON SUCCESS, because a bundle that
 * verifies is exactly when a reader is most likely to over-read it.
 */
const WHAT_THIS_DOES_NOT_PROVE = [
  "WHO ASKED. The span carries no principal — no agent identity, no delegated human identity. Axis 4 is unmet and this bundle does not move it.",
  "WHAT THEY ASKED FOR. No arguments. amount, to and from appear nowhere in the decision span. Axis 5 is unmet and this bundle does not move it.",
  "WHICH VERSION OF THE RULE. The deciding policy is named by id, not by version. Axis 6 stays half-met.",
  "THAT NOTHING WAS OMITTED. A suppressed call that never reaches the gateway emits no span, so it cannot appear here and its absence is indistinguishable from it never having happened.",
  "THAT THE CAPTURE WAS HONEST. Without external anchoring this proves internal consistency of a capture the operator produced. Same custody ceiling as the config seal.",
];

const WHAT_THIS_PROVES = [
  "That a specific authorization decision was made by AWS Bedrock AgentCore, at a stated time, by a named policy engine, in a stated enforcement mode.",
  "Which Cedar policy determined the outcome, by id, and what the outcome was (ALLOW or DENY).",
  "That the set of decisions in this bundle has not been altered or reduced since capture: every entry is SHA-512 linked and the final manifest makes an omission detectable.",
];

function arg(name, fallback) {
  const i = process.argv.indexOf(name);
  return i !== -1 && process.argv[i + 1] ? process.argv[i + 1] : fallback;
}

const sinceMin = Number(arg("--since-min", "60"));
const logGroup = arg("--log-group", "aws/spans");
const startedAtMs = Date.now();
const outPath = resolve(arg("--out", `${HERE}/output/decision-capture.latest.json`));
const cursorPath = arg("--cursor", null);
const force = process.argv.includes("--force");

/**
 * ⭐ A CURSOR MAKES THE WINDOW AUTOMATIC. IT DOES NOT MAKE CAPTURE RESUMABLE.
 * ⛔⛔ SAY IT THAT WAY EVERY TIME. With --cursor the next run starts where the last one ended, so
 * windows stop being chosen by hand and gaps/overlaps stop being invisible. What it does NOT do is
 * link the bundles: run N and run N+1 remain two INDEPENDENT bundles with two different roots, and
 * nothing in either commits to the other. A reader who sees "it can run twice" and concludes "it
 * resumes" has concluded something false. Bundle-to-bundle linkage is a separate, unbuilt thing.
 */
function readCursor() {
  if (!cursorPath || !existsSync(cursorPath)) return null;
  try {
    const c = JSON.parse(readFileSync(cursorPath, "utf8"));
    return Number.isFinite(c.next_start_ms) ? c : null;
  } catch { return null; }
}
const cursor = readCursor();

/**
 * ⛔⛔ REFUSE-BEFORE-READ. This runs BEFORE any AWS call, on purpose: a capture that cannot be written
 * should not be taken at all, and failing after the read would tempt the operator to re-run with
 * --force to "not waste it" — which is exactly the decision this guard exists to slow down.
 */
if (existsSync(outPath) && !force) {
  console.error(`⛔ REFUSING TO OVERWRITE: ${outPath}`);
  console.error("");
  console.error("   That file is a capture. The window it covers has passed and cannot be re-read,");
  console.error("   so overwriting it destroys evidence rather than refreshing it.");
  console.error("");
  console.error("   Write a new bundle instead:");
  console.error(`     node ingest-decisions.mjs --out output/decision-capture.$(date -u +%Y%m%dT%H%M%SZ).json`);
  console.error("");
  console.error("   Or, if you have decided the existing bundle is worth less than this run:");
  console.error("     node ingest-decisions.mjs --force");
  process.exit(2);
}

/**
 * ⛔ Read-only. filter-log-events is a read; no resource is created.
 *
 * ⛔⛔ PAGINATION IS DONE HERE, EXPLICITLY, AND THAT IS THE POINT. This used to rely on the AWS CLI's
 * default paginator — which works, but is a DEFAULT, not a guarantee: `max_items` in ~/.aws/config,
 * AWS_MAX_ITEMS, or a stray --no-paginate would silently truncate the read and the script could not
 * tell a short set from a complete one.
 *
 * ⭐ MEASURED 2026-09-16, and this is not hypothetical: over a 7-day window this log group returns
 * FOUR pages (0, 17, 17, 0 events). The FIRST PAGE IS EMPTY while a nextToken is present — so a
 * single-page read returns ZERO from a group that holds data. That is DEBT 1's shape exactly, and it
 * is the second time that shape has been logged.
 *
 * ⇒ We now loop on nextToken ourselves and COUNT the pages. A short set is impossible without an
 * explicit error, because the loop only ends when AWS stops returning a token.
 */
let maxEventMs = 0;
function fetchSpans() {
  const startTime = String(cursor ? cursor.next_start_ms : Date.now() - sinceMin * 60_000);
  if (cursor) console.log(`cursor: resuming the WINDOW from ${new Date(cursor.next_start_ms).toISOString()} (written by a previous run)`);
  const messages = [];
  let token = null;
  let pages = 0;
  for (;;) {
    const args = [
      "logs", "filter-log-events",
      "--log-group-name", logGroup,
      "--start-time", startTime,
      "--filter-pattern", "AuthorizeAction",
      "--no-paginate",                 // ⭐ we page deliberately; the CLI must not do it for us
      "--output", "json",
    ];
    if (token) args.push("--next-token", token);
    const page = execFileSync("aws", args,
      { encoding: "utf8", maxBuffer: 64 * 1024 * 1024, timeout: 120_000 });
    let parsed;
    try { parsed = JSON.parse(page); }
    catch (err) {
      console.error(`⛔ page ${pages + 1} was not parseable JSON — refusing to treat it as empty`);
      throw err;
    }
    pages += 1;
    for (const e of parsed.events ?? []) {
      if (e.message) messages.push(e.message);
      if (Number.isFinite(e.timestamp) && e.timestamp > maxEventMs) maxEventMs = e.timestamp;
    }
    token = parsed.nextToken ?? null;
    if (!token) break;
    if (pages > 500) throw new Error("refusing to page past 500 pages — nextToken is not terminating");
  }
  console.log(`pages read: ${pages}  (messages: ${messages.length})`);
  const raw = JSON.stringify(messages);
  return JSON.parse(raw);
}

/**
 * ⛔⛔ `toDecisionRecord` MOVED TO `./decision-record.mjs` — F-18, 2026-09-16.
 *
 * ⭐⭐ AND THE SENTENCE THAT USED TO STAND HERE CAME OUT. It read:
 *   "EVERY field is copied from the span; nothing is derived, defaulted or inferred."
 * ⛔ It was FALSE — `authorization_reason` and `mismatched_policies` were in the span and not in
 *   the record — and it was false in the reassuring direction, because it sat above a named list
 *   of deliberate absences, and a named list reads as exhaustive.
 * ⇒ ⛔⛔ THE CHOICE WAS "make the list exhaustive and enforced, or drop the sentence." BOTH were
 *   done: the sentence is gone, and `decision-record.mjs` now carries COPIED / DECLINED maps that
 *   `undeclaredAttributes()` enforces against REAL SPANS in
 *   `harness/__tests__/decision-record.test.mjs`.
 * ⭐ A sentence in a header cannot fail. A test can.
 */

const messages = fetchSpans();
const records = [];
const seen = new Set();
for (const m of messages) {
  let span;
  try { span = JSON.parse(m); } catch { continue; }
  const rec = toDecisionRecord(span);
  if (!rec) continue;
  // ⭐ A span can be delivered more than once. De-duplicate on span id, not request id: one request
  // can legitimately produce several spans, and collapsing on request id would silently drop them.
  const key = `${rec.span_id}`;
  if (seen.has(key)) continue;
  seen.add(key);
  records.push(rec);
}

records.sort((x, y) => Number(x.start_time_unix_nano ?? 0) - Number(y.start_time_unix_nano ?? 0));

// ── chain ────────────────────────────────────────────────────────────────────
const entries = [];
let prev = null;
for (const data of records) {
  const hash = computeHash(data, prev);
  entries.push({ data, previousHash: prev, hash });
  prev = hash;
}

// ⭐ Manifest as the FINAL entry — this is what makes an omission detectable. Removing a decision
// from the middle re-links nothing; removing the last one before the manifest changes the count.
// ⭐ Each item pins index, type, id AND the entry's own hash — so reordering, substitution and
// removal are all detectable, not just a count change.
const manifest = {
  kind: "manifest",
  item_count: records.length,
  items: records.map((r, i) => ({ index: i, type: r.type, id: r.id, decision: r.decision, hash: entries[i].hash })),
};
const manifestHash = computeHash(manifest, prev);
entries.push({ data: manifest, previousHash: prev, hash: manifestHash });

const bundle = {
  seal_version: BUNDLE_VERSION,
  kind: BUNDLE_KIND,
  what_this_proves: WHAT_THIS_PROVES,
  what_this_does_not_prove: WHAT_THIS_DOES_NOT_PROVE,
  captured_at_unsealed: new Date().toISOString(),
  source: { log_group: logGroup, span_name: SPAN_NAME, window_minutes: sinceMin },
  // ⛔⛔ SCOPED 2026-09-16. This note used to end "so there is nothing to redact", which is true of
  //    principal and arguments and NOT true of every value the project's redactor is configured to
  //    mask: `harness/redact.mjs` has a rule for the AWS account id, and that id appears in
  //    `policy_engine_arn` and `gateway_arn` on EVERY record. The 09-16 capture carries 104 of them.
  // ⭐ ARNs are carried deliberately — an ARN is the identity of the thing the evidence is about,
  //    and masking it would make a capture unverifiable against the account it describes.
  // ⚠️ The field now says what it means: no redaction pass was run, and the claim is about the two
  //    axes named, not about values present.
  redaction: {
    applied: false,
    scope: "This statement is about redactions PERFORMED and about the two axes named below. It is NOT a claim that no maskable value is present.",
    note: "Decision spans carry no principal and no arguments, so no redaction was applied on those axes. That is a limitation of the source, not a privacy property.",
    values_present: "AWS resource identifiers are carried verbatim, including the account id inside policy_engine_arn and gateway_arn on every record. No credential of any kind is present.",
  },
  root: manifestHash,
  entry_count: entries.length,
  entries,
};

mkdirSync(dirname(outPath), { recursive: true });
// ⛔ Re-checked at the write: the guard above ran before a multi-second AWS read, and a concurrent
// run could have created the file in between. Cheap, and the failure it prevents is unrecoverable.
if (existsSync(outPath) && !force) {
  console.error(`⛔ REFUSING TO OVERWRITE (appeared during the read): ${outPath}`);
  process.exit(2);
}
writeFileSync(outPath, `${JSON.stringify(bundle, null, 2)}\n`);

const allow = records.filter((r) => r.decision === "ALLOW").length;
const deny = records.filter((r) => r.decision === "DENY").length;
console.log(`decisions captured: ${records.length}  (ALLOW ${allow} · DENY ${deny})`);
console.log(`root:  ${manifestHash}`);
console.log(`out:   ${outPath}`);
if (cursorPath) {
  const next = (maxEventMs > 0 ? maxEventMs + 1 : Number(startedAtMs));
  writeFileSync(cursorPath, `${JSON.stringify({ next_start_ms: next, written_at: new Date().toISOString(), decisions_in_this_run: records.length }, null, 2)}\n`);
  console.log(`cursor: next window starts ${new Date(next).toISOString()}  → ${cursorPath}`);
}

if (records.length === 0 && cursor) {
  console.log("");
  console.log("⭐ ZERO NEW DECISIONS since the cursor. With a cursor in use this is the EXPECTED");
  console.log("   result when nothing has happened — it is not the 'zero' that means a broken query.");
} else if (records.length === 0) {
  console.log("");
  console.log("⛔ ZERO DECISIONS. This is not a pass. Either the window is wrong, or trace delivery");
  console.log("   is not active — and vended delivery takes MINUTES to activate (F-14 §2).");
  process.exitCode = 2;
}
