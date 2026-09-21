/**
 * ⭐⭐ OFFLINE SEAL VERIFIER.
 *
 *   node reproduce/l5-adapter/verify-seal.mjs <bundle.json>
 *
 * ⛔ NO NETWORK. NO AWS. NO DATABASE. NO ACCOUNT. NO RENDS.
 * The only inputs are the file you pass and `node:crypto`. That is deliberate: the brief's axis-14
 * test is "can the record be verified after the vendor is gone", and a verifier that phones home
 * answers it with "no".
 *
 * ⛔⛔ WHAT A PASS MEANS: the sealed CONTEXT is intact — the gateway configuration and every
 * policy's Cedar text are exactly as captured. IT DOES NOT MEAN ANY DECISION IS PROVEN. There is
 * no AgentCore-originated decision record to verify (F-11). The bundle says so itself, in
 * `what_this_does_not_prove`, and this tool prints it.
 *
 * ⭐⭐ THREE STATES, NOT TWO:
 *   VERIFIED + WITNESSED ... the root is intact AND a third party attests it existed at time T
 *   VERIFIED, UNWITNESSED .. the root is intact; only the operator's own clock says when
 *   FAILED ................. the root does not verify
 * ⛔ ANY doubt about a receipt resolves to UNWITNESSED. A receipt that cannot be checked here is
 * not a witness, and printing it as one would be worse than shipping no receipt at all.
 *
 * Exit codes: 0 = verified (witnessed or not) · 1 = FAILED · 2 = usage/parse error.
 */
import { readFileSync } from "node:fs";

import { computeHash, verifyChain } from "../../harness/chain.mjs";
import { verifyTimestamp } from "../../harness/rfc3161.mjs";

const BOLD = "\u001b[1m";
const DIM = "\u001b[2m";
const RED = "\u001b[31m";
const GREEN = "\u001b[32m";
const YELLOW = "\u001b[33m";
const OFF = "\u001b[0m";

const path = process.argv[2];
if (!path) {
  console.error("usage: node verify-seal.mjs <bundle.json>");
  process.exit(2);
}

let bundle;
try {
  bundle = JSON.parse(readFileSync(path, "utf8"));
} catch (err) {
  console.error(`${RED}cannot read or parse ${path}: ${err.message}${OFF}`);
  process.exit(2);
}

const fail = (msg) => {
  console.log(`${RED}${BOLD}FAILED${OFF} — ${msg}`);
  process.exit(1);
};

// ⭐ Two bundle kinds share this envelope, so the verifier extends rather than forking:
//   config-seal       — what the gateway was CONFIGURED to enforce   (F-12)
//   decision-capture  — what it ACTUALLY allowed or denied           (L5 point B)
// ⛔ They answer different questions and neither substitutes for the other. A config seal carries a
// policy's exact Cedar text and survives the operator deleting it; a decision record names which
// policy decided and what it decided, but not its text. Together they answer "what was the rule, and
// did it fire" — which neither answers alone.
const KINDS = {
  "agentcore-gateway-config-seal": "Config-seal",
  "agentcore-decision-capture": "Decision-capture",
};
if (!(bundle.kind in KINDS)) {
  fail(`unexpected bundle kind: ${JSON.stringify(bundle.kind)}`);
}
const isDecision = bundle.kind === "agentcore-decision-capture";
const NOUN = isDecision ? "decision record" : "context";

console.log("");
console.log(`${BOLD}${KINDS[bundle.kind] ?? "Bundle"} verification${OFF}  ${DIM}${path}${OFF}`);
console.log(`${DIM}offline: no network, no AWS, no database, no Rends account${OFF}`);
console.log("");

const entries = bundle.entries;
if (!Array.isArray(entries) || entries.length === 0) fail("bundle has no entries");

// ── 1. the chain itself ─────────────────────────────────────────────────────
const chain = verifyChain(entries);
if (!chain.valid) {
  const e = entries[chain.brokenAt];
  const label = e?.data?.kind === "manifest" ? "manifest" : `${e?.data?.type}/${e?.data?.id}`;
  console.log(`  chain ............. ${RED}BROKEN at entry ${chain.brokenAt} (${label})${OFF}`);
  console.log(`  reason ............ ${RED}${chain.reason}${OFF}`);
  fail(`entry ${chain.brokenAt} does not verify`);
}
console.log(`  chain ............. ${GREEN}OK${OFF}  ${DIM}${entries.length} entries, SHA-512 linked${OFF}`);

// ── 2. the manifest — this is what catches an OMISSION ───────────────────────
const last = entries[entries.length - 1];
if (last?.data?.kind !== "manifest") {
  fail("the final entry is not a manifest — an item could have been removed without trace");
}
const manifest = last.data;
const sealed = entries.slice(0, -1);

if (manifest.item_count !== sealed.length) {
  console.log(`  manifest count .... ${RED}MISMATCH: manifest says ${manifest.item_count}, bundle carries ${sealed.length}${OFF}`);
  fail("an item was added or removed");
}
if (!Array.isArray(manifest.items) || manifest.items.length !== sealed.length) {
  fail("manifest item list does not match the bundle");
}
for (let i = 0; i < sealed.length; i++) {
  const m = manifest.items[i];
  const e = sealed[i];
  if (m.index !== i || m.type !== e.data.type || m.id !== e.data.id || m.hash !== e.hash) {
    console.log(`  manifest[${i}] ...... ${RED}MISMATCH${OFF}`);
    console.log(`      manifest: ${m.type}/${m.id} ${String(m.hash).slice(0, 16)}…`);
    console.log(`      bundle  : ${e.data.type}/${e.data.id} ${e.hash.slice(0, 16)}…`);
    fail(`item ${i} does not match the manifest`);
  }
}
console.log(`  manifest .......... ${GREEN}OK${OFF}  ${DIM}${manifest.item_count} items pinned by index, type, id and hash${OFF}`);

// ── 3. the declared root ────────────────────────────────────────────────────
if (bundle.root !== last.hash) {
  console.log(`  root .............. ${RED}MISMATCH${OFF}`);
  console.log(`      declared : ${bundle.root}`);
  console.log(`      computed : ${last.hash}`);
  fail("the declared root is not the manifest's hash");
}
const recomputedRoot = computeHash(manifest, last.previousHash);
if (recomputedRoot !== bundle.root) fail("the root does not recompute from the manifest");
console.log(`  root .............. ${GREEN}OK${OFF}  ${DIM}${bundle.root.slice(0, 32)}…${OFF}`);

// ── 4. what was sealed ──────────────────────────────────────────────────────
// ⭐ The gate names four things explicitly — policy engine, enforcement mode, role and authorizer.
// They are covered by the hash either way, but a relying party should not have to open the JSON to
// read the posture they came here to check, so surface them.
const gwItem = sealed.find((e) => e.data.type === "gateway");
const engineItem = sealed.find((e) => e.data.type === "policy-engine");
if (gwItem) {
  const g = gwItem.data.config ?? {};
  console.log("");
  console.log(`${BOLD}Sealed gateway posture${OFF}`);
  console.log(`  gateway .............. ${g.gatewayId ?? "(absent)"}  ${DIM}status ${g.status ?? "?"}${OFF}`);
  console.log(`  ${BOLD}enforcement mode${OFF} ..... ${BOLD}${g.policyEngineConfiguration?.mode ?? "(absent)"}${OFF}`);
  console.log(`  policy engine ........ ${engineItem?.data?.config?.policyEngineId ?? g.policyEngineConfiguration?.arn ?? "(absent)"}`);
  console.log(`  role ................. ${g.roleArn ?? "(absent)"}`);
  console.log(`  authorizer ........... ${g.authorizerType ?? "(absent)"}`);
}

console.log("");
if (isDecision) {
  // ⭐ A decision bundle's payload IS the list, so print the decision and the policy that made it.
  const allow = sealed.filter((e) => e.data.decision === "ALLOW").length;
  const deny = sealed.filter((e) => e.data.decision === "DENY").length;
  console.log(`${BOLD}Decisions captured${OFF}  ${DIM}${allow} ALLOW · ${deny} DENY${OFF}`);
  for (const e of sealed) {
    const d = e.data;
    const mark = d.decision === "DENY" ? `${RED}DENY ${OFF}` : `${GREEN}ALLOW${OFF}`;
    console.log(`  ${mark}  ${DIM}${d.id}${OFF}`);
    console.log(`         policy ${(d.determining_policies ?? []).join(", ") || "(none named)"}  ${DIM}mode ${d.enforcement_mode ?? "?"}${OFF}`);
    // ⛔⛔ F-18, 2026-09-16. WITHOUT THIS LINE A READER SEES "(none named)" AND NOTHING ELSE, AND
    //    CANNOT TELL A CEDAR DEFAULT-DENY FROM A POLICY EVALUATION ERROR. Both are DENY with an
    //    empty determining_policies; only the reason separates them. Fixing the RECORD was not
    //    enough — the record held the cause and the reader was still not shown it, which is the
    //    same shape as the finding itself.
    // ⭐ Printed only when the span carried one. A record without a reason renders EXACTLY as
    //    before, so every bundle captured before this change is unaffected in the output a second
    //    party reads. An ALLOW span carries no reason at all; that is real, not a dropped field.
    if (d.authorization_reason) {
      const [first, ...rest] = String(d.authorization_reason).split("\n");
      console.log(`         ${DIM}reason ${first}${OFF}`);
      for (const line of rest) console.log(`                ${DIM}${line}${OFF}`);
    }
  }
} else {
  console.log(`${BOLD}Sealed configuration${OFF}`);
  for (const e of sealed) {
    console.log(`  [${String(e.data.index).padStart(2)}] ${e.data.type.padEnd(21)} ${String(e.data.id).slice(0, 54)}`);
    const cedar = e.data.config?.definition?.cedar?.statement;
    if (cedar) console.log(`       ${DIM}${cedar.replace(/\s+/g, " ").slice(0, 150)}${OFF}`);
  }
}

// ── 5. the witness ──────────────────────────────────────────────────────────
// ⭐ RFC-3161. Checked with `openssl ts -verify`, which validates the TSA signature AND that the
// token's imprint is the hash of this bundle's `root` — both, in one call, with no network.
const w = bundle.witness;
let witnessState = "unwitnessed";
let witnessReason = "no witness receipt is attached — only the operator's own clock says when this was captured";
if (w && w.token_der_base64) {
  const r = verifyTimestamp(bundle.root, Buffer.from(w.token_der_base64, "base64"));
  witnessState = r.state;
  witnessReason = r.reason;
} else if (w && w.ok === false) {
  witnessReason = `a witness was attempted and did not succeed: ${w.reason}`;
}

console.log("");
console.log(`${BOLD}Witness${OFF}`);
if (witnessState === "witnessed") {
  console.log(`  ${GREEN}RFC-3161 receipt verifies${OFF}  ${DIM}${w.tsa}${OFF}`);
  console.log(`  asserted time ........ ${BOLD}${w.asserted_time}${OFF}  ${DIM}(the TSA's clock, not ours)${OFF}`);
  console.log(`  serial ............... ${DIM}${w.serial}${OFF}`);
  console.log(`  ${DIM}The receipt commits to this bundle's root, so the root existed at that time.${OFF}`);
} else {
  console.log(`  ${YELLOW}not witnessed${OFF} — ${DIM}${witnessReason}${OFF}`);
}

// ── 6. the disclaimer travels with the artifact ─────────────────────────────
console.log("");
if (witnessState === "witnessed") {
  console.log(`${GREEN}${BOLD}VERIFIED + WITNESSED${OFF} — the captured ${BOLD}${NOUN}${OFF} is intact, and a third party attests it existed at ${BOLD}${w.asserted_time}${OFF}.`);
} else {
  console.log(`${GREEN}${BOLD}VERIFIED${OFF}, ${YELLOW}${BOLD}UNWITNESSED${OFF} — the captured ${BOLD}${NOUN}${OFF} is intact; nothing outside the operator attests when it was captured.`);
}
console.log("");
if (isDecision) {
  // ⛔⛔ The config seal's line — "this is context, not a decision" — is exactly backwards here, and
  // the opposite overclaim is the one this bundle invites: "Rends verifies AgentCore decisions" is
  // literally true of it and badly misleading. So the headline names the reduction, not the capability.
  console.log(`${YELLOW}${BOLD}This is a decision record: that it happened, and which policy decided.${OFF}`);
  console.log(`${YELLOW}${BOLD}It is NOT a record of who asked or what they asked for.${OFF}`);
} else {
  console.log(`${YELLOW}${BOLD}This is context, not a decision.${OFF}`);
}
for (const line of bundle.what_this_proves ?? ["(bundle declared no scope — treat with suspicion)"]) {
  console.log(`${DIM}  · ${line}${OFF}`);
}
console.log("");
console.log(`${YELLOW}What it does NOT prove:${OFF}`);
for (const line of bundle.what_this_does_not_prove ?? ["(bundle declared none — treat with suspicion)"]) {
  console.log(`${DIM}  · ${line}${OFF}`);
}
console.log("");
if (bundle.captured_at_unsealed) {
  console.log(`${DIM}Captured at ${bundle.captured_at_unsealed} — UNSEALED, from the operator's own clock.${OFF}`);
}
if (typeof bundle.redaction === "string") {
  console.log(`${DIM}${bundle.redaction}${OFF}`);
} else if (bundle.redaction && typeof bundle.redaction === "object") {
  const r = bundle.redaction;
  console.log(`${DIM}redaction: ${r.applied ? "applied" : "none"}${r.note ? ` — ${r.note}` : ""}${OFF}`);
}
console.log("");
process.exit(0);
