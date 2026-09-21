/**
 * ⭐⭐ CONFIG SEALER — L5, option 2 (RULED by Fed 2026-09-13).
 *
 *   node reproduce/l5-adapter/seal-config.mjs
 *        [--region R] [--gateway ID] [--engine ID] [--role NAME]
 *        [--out-dir DIR] [--raw-dir DIR] [--tsa URL] [--no-witness] [--force]
 *
 * ⭐ Every parameter DEFAULTS to the value hardcoded before 2026-09-16, so a bare run is the run it
 * always was. Env fallbacks: SEAL_REGION, SEAL_GATEWAY_ID, SEAL_ENGINE_ID, SEAL_GATEWAY_ROLE,
 * SEAL_OUT_DIR, SEAL_RAW_DIR.
 *
 * ⛔⛔ PARAMETERISED IN FORM, NOT DEMONSTRATED AGAINST A SECOND RIG. At the time of this change the
 * account held exactly ONE gateway and ONE policy engine, so "it works on another target" is
 * untested. What IS proven: the parameters reach the API call rather than being shadowed by the old
 * constants. Do not describe this as portability demonstrated.
 *
 * ⛔⛔ WHAT THIS SEALS, AND SAY IT THIS WAY EVERY TIME:
 *     IT SEALS THE **CONTEXT** OF A DECISION. IT DOES NOT SEAL THE DECISION.
 *
 * F-11 established that the AgentCore Gateway emits no per-decision span, and that a DENIAL emits
 * nothing at all. There is therefore no AgentCore-originated decision record to seal, and any tool
 * claiming to seal one would be lying. What AgentCore *does* expose, read-only and in full, is the
 * CONFIGURATION that governed decisions: the gateway, its role, the policy engine, and every
 * policy's exact Cedar text.
 *
 * ⭐ WHY THAT IS WORTH SEALING — F-07. The operator deleted the Cedar policy that produced a DENY.
 * The CloudWatch counter survived (`DenyDecisions = 1.0, Policy = L2_C3_forbid_v2-e6bergdd8o`) and
 * became a dangling reference to an object nobody can read. The fact of the denial was
 * tamper-resistant; its MEANING was fully mutable. Sealing the configuration at capture time is
 * what preserves the meaning, and it works in the flattering direction too — an operator can no
 * longer quietly delete a permissive policy after it allowed something.
 *
 * ⛔ WHAT A SEAL CANNOT TELL YOU:
 *   · that any particular action was allowed or denied      — there is no decision record (F-11)
 *   · that the config was unchanged BETWEEN two seals       — only that each seal is intact
 *   · that the capture was honest at capture time           — that is external anchoring, P4 axis 1
 *
 * ⭐ REDACT-THEN-SEAL. The seal is computed over the REDACTED projection, which is what ships
 * publicly and what a third party actually receives. Sealing the raw capture and publishing a
 * redacted one would hand out a bundle that cannot verify. The raw capture is kept outside the
 * public tree per the redaction ruling.
 */
import { execFileSync } from "node:child_process";
import { mkdirSync, writeFileSync, existsSync } from "node:fs";

import { computeHash, verifyChain } from "../../harness/chain.mjs";
import { DEFAULT_TSA, requestTimestamp } from "../../harness/rfc3161.mjs";
import { redact, redactorSelfTest } from "../../harness/redact.mjs";

/** ⭐ Resolution order: --flag, then env, then the pre-2026-09-16 hardcoded value. */
function arg(flag, envName, fallback) {
  const i = process.argv.indexOf(flag);
  if (i !== -1 && process.argv[i + 1]) return process.argv[i + 1];
  return process.env[envName] || fallback;
}

const REGION = arg("--region", "SEAL_REGION", "us-west-2");
const GATEWAY_ID = arg("--gateway", "SEAL_GATEWAY_ID", "authz-evidence-gw-dr3quovzsv");
const ENGINE_ID = arg("--engine", "SEAL_ENGINE_ID", "authz_evidence_engine-p2kixx62xj");
const GATEWAY_ROLE = arg("--role", "SEAL_GATEWAY_ROLE", "authz-evidence-gateway-role");

const RAW_DIR = arg("--raw-dir", "SEAL_RAW_DIR", "/home/ubuntu/agent-authz-raw/l5-adapter");
const OUT_DIR = arg("--out-dir", "SEAL_OUT_DIR", new URL("./output/", import.meta.url).pathname)
  .replace(/\/?$/, "/");

/**
 * ⭐ TSA list, tried in order. Comma-separated via --tsa or SEAL_TSA.
 * ⛔⛔ WHAT A FALLBACK BUYS, AND WHAT IT DOES NOT. It buys OPERATOR independence — one TSA down,
 * rate-limiting, retiring, or with an expired signing cert. It does NOT buy NETWORK independence:
 * every entry goes out through this host's egress, DNS and curl, so a local outage fails all of them
 * identically. Redundancy in form is not redundancy in fact unless the failure modes differ.
 * ⭐ WHY IT IS STILL WORTH IT, NARROWLY: a failed witness is normally recoverable by re-running —
 * EXCEPT when the subject is about to disappear. You cannot re-seal a deleted policy, so a TSA
 * outage at that one moment is PERMANENT — which is exactly the case this component exists for.
 * The fallback automates, inside the same run, a retry the operator would otherwise have to notice.
 */
const TSA_LIST = arg("--tsa", "SEAL_TSA", DEFAULT_TSA).split(",").map((x) => x.trim()).filter(Boolean);
const force = process.argv.includes("--force");

/**
 * ⛔⛔ REFUSE-BEFORE-READ — the same guard and the same reasoning as ingest-decisions.mjs. It runs
 * BEFORE any AWS call on purpose: a seal that cannot be written should not be taken at all, and
 * failing after the reads would tempt a --force re-run to "not waste it", which is the decision this
 * guard exists to slow down.
 *
 * ⚠️ ONE SHAPE DIFFERENCE, DELIBERATE. ingest-decisions.mjs writes ONE file and guards one path.
 * This writes THREE, and the timestamped name is not known until after the reads — so the guard
 * covers the two FIXED paths, which are the two that can destroy something: latest.json is the
 * witnessed seal, and config.raw.json sits in the held raw directory.
 */
const GUARDED = [`${OUT_DIR}config-seal.latest.json`, `${RAW_DIR}/config.raw.json`];
function refuseIfPresent(when) {
  for (const target of GUARDED) {
    if (existsSync(target) && !force) {
      console.error(`⛔ REFUSING TO OVERWRITE${when}: ${target}`);
      console.error("");
      console.error("   Sealing writes over this file. If it is the witnessed seal, its RFC-3161");
      console.error("   receipt cannot be recovered once the bundle it commits to is gone.");
      console.error("");
      console.error("   Seal somewhere else instead:");
      console.error("     node seal-config.mjs --out-dir /tmp/seal-run --raw-dir /tmp/seal-run/raw");
      console.error("");
      console.error("   Or, if the existing file is worth less than this run:  --force");
      process.exit(2);
    }
  }
}
refuseIfPresent("");

const SEAL_VERSION = "1";

function aws(args) {
  const out = execFileSync("aws", [...args, "--region", REGION, "--output", "json"], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
  return JSON.parse(out);
}

/** IAM is global; the CLI still accepts --region but these reads are account-wide. */
function iam(args) {
  return aws(args);
}

/* ── 1. CAPTURE ───────────────────────────────────────────────────────────── */

function capture() {
  const items = [];
  const add = (type, id, data) => items.push({ type, id, data });

  const caller = aws(["sts", "get-caller-identity"]);
  add("capture-context", "caller", {
    account: caller.Account,
    capturedByArn: caller.Arn,
    region: REGION,
    // ⛔ NO TIMESTAMP IN A SEALED ITEM. It goes in the unsealed header instead — see the note in
    // buildSeal(). A clock the operator controls is not evidence, and putting it inside the chain
    // would dress it up as though it were.
  });

  const gw = aws(["bedrock-agentcore-control", "get-gateway", "--gateway-identifier", GATEWAY_ID]);
  add("gateway", gw.gatewayId, gw);

  const role = iam(["iam", "get-role", "--role-name", GATEWAY_ROLE]);
  add("gateway-role-trust", GATEWAY_ROLE, role.Role.AssumeRolePolicyDocument);

  const attached = iam(["iam", "list-attached-role-policies", "--role-name", GATEWAY_ROLE]);
  add("gateway-role-attached", GATEWAY_ROLE, attached.AttachedPolicies);

  const inlineNames = iam(["iam", "list-role-policies", "--role-name", GATEWAY_ROLE]).PolicyNames;
  for (const name of inlineNames) {
    const doc = iam(["iam", "get-role-policy", "--role-name", GATEWAY_ROLE, "--policy-name", name]);
    add("gateway-role-inline", `${GATEWAY_ROLE}/${name}`, doc.PolicyDocument);
  }

  const engine = aws(["bedrock-agentcore-control", "get-policy-engine", "--policy-engine-id", ENGINE_ID]);
  add("policy-engine", engine.policyEngineId, engine);

  // ⭐⭐ THE PAYLOAD. Each policy's exact Cedar statement — the thing F-07 proved is destructible.
  const policies = aws([
    "bedrock-agentcore-control", "list-policies", "--policy-engine-id", ENGINE_ID,
  ]).policies;
  for (const p of policies) {
    const full = aws([
      "bedrock-agentcore-control", "get-policy",
      "--policy-engine-id", ENGINE_ID, "--policy-id", p.policyId,
    ]);
    add("policy", full.policyId, full);
  }

  const targets = aws([
    "bedrock-agentcore-control", "list-gateway-targets", "--gateway-identifier", GATEWAY_ID,
  ]).items ?? [];
  for (const t of targets) {
    const full = aws([
      "bedrock-agentcore-control", "get-gateway-target",
      "--gateway-identifier", GATEWAY_ID, "--target-id", t.targetId,
    ]);
    add("gateway-target", full.targetId, full);
  }

  return items;
}

/* ── 2. SEAL ──────────────────────────────────────────────────────────────── */

/** Deterministic order — the seal must not depend on the order AWS happened to answer in. */
function sortItems(items) {
  return [...items].sort((a, b) =>
    `${a.type} ${a.id}` < `${b.type} ${b.id}` ? -1 : `${a.type} ${a.id}` > `${b.type} ${b.id}` ? 1 : 0,
  );
}

function buildSeal(redactedItems) {
  const sorted = sortItems(redactedItems);
  const entries = [];
  let previousHash = null;

  for (let i = 0; i < sorted.length; i++) {
    const it = sorted[i];
    const data = { index: i, type: it.type, id: it.id, config: it.data };
    const hash = computeHash(data, previousHash);
    entries.push({ data, hash, previousHash });
    previousHash = hash;
  }

  // ⭐⭐ THE MANIFEST IS THE LAST ENTRY, AND IT IS WHAT MAKES AN OMISSION VISIBLE.
  // A chain alone detects EDITING. It does not detect a bundle that was published one item
  // SHORTER — re-chaining a truncated list produces a perfectly valid chain. The manifest pins
  // the count and every item's (index, type, id, hash), so removing, adding or reordering an item
  // contradicts it. This is the gap-evidence property from P4 axis 2, applied to config.
  const manifest = {
    kind: "manifest",
    item_count: sorted.length,
    items: entries.map((e, i) => ({ index: i, type: e.data.type, id: e.data.id, hash: e.hash })),
  };
  const manifestHash = computeHash(manifest, previousHash);
  entries.push({ data: manifest, hash: manifestHash, previousHash });

  return { entries, root: manifestHash };
}

/* ── 3. MAIN ──────────────────────────────────────────────────────────────── */

const selfTest = redactorSelfTest();
if (!selfTest.ok) {
  console.error("⛔ redactor self-test FAILED — refusing to write anything.");
  process.exit(2);
}
console.log("redactor self-test: OK");

mkdirSync(RAW_DIR, { recursive: true });
mkdirSync(OUT_DIR, { recursive: true });

console.log(`capturing gateway configuration from ${REGION} …`);
const rawItems = capture();
console.log(`captured ${rawItems.length} configuration items`);

// Raw, unredacted — OUTSIDE the public tree, per the redaction ruling.
// ⛔ Re-checked at the write: the guard above ran before multi-second AWS reads, and a concurrent
// run could have created the file in between. Same reasoning as ingest-decisions.mjs.
refuseIfPresent(" (appeared during the reads)");
writeFileSync(`${RAW_DIR}/config.raw.json`, JSON.stringify(rawItems, null, 2));

// ⭐ REDACT, THEN SEAL. Redaction runs over the canonical serialization of each item so that what
// is hashed and what is published are the same bytes.
let totalHits = {};
const redactedItems = rawItems.map((it) => {
  const r = redact(JSON.stringify(it.data));
  for (const [k, v] of Object.entries(r.hits)) totalHits[k] = (totalHits[k] ?? 0) + v;
  const idR = redact(it.id);
  return { type: it.type, id: idR.text, data: JSON.parse(r.text) };
});
console.log("redaction hits:", JSON.stringify(totalHits));

const { entries, root } = buildSeal(redactedItems);

// ⭐⭐ THE WITNESS — RFC-3161, ruled for config seals 2026-09-13.
// ⛔ Requested AFTER the root exists and attached as an UNSEALED SIBLING. It cannot go inside the
// chain: the receipt is derived FROM the root, so sealing it would change the root that produced
// it. That is not a limitation to work around, it is the shape of the thing.
// ⚠️ Only the SHA-512 of the root leaves this machine. The TSA cannot learn what was sealed.
const wantWitness = !process.argv.includes("--no-witness");
let witness = null;
if (wantWitness) {
  let t = null;
  const attempts = [];
  for (const tsa of TSA_LIST) {
    console.log(`requesting an RFC-3161 timestamp over the root from ${tsa} …`);
    const r = requestTimestamp(root, tsa);
    attempts.push({ tsa, ok: r.ok, reason: r.ok ? undefined : String(r.reason).slice(0, 200) });
    if (r.ok) { t = { ...r, tsa }; break; }
    console.log(`  ⚠️ ${tsa} did not witness: ${String(r.reason).slice(0, 110)}`);
  }
  if (!t) t = { ok: false, reason: `all ${TSA_LIST.length} TSA(s) failed`, tsa: TSA_LIST[0] };
  t.attempts = attempts;
  if (t.ok) {
    witness = {
      type: "rfc3161",
      note:
        "UNSEALED SIBLING. A receipt is derived from the root, so it cannot be inside the chain " +
        "the root commits to. Verify it against `root` with: openssl ts -verify -data <root> -in <token>.",
      tsa: t.tsa,
      fallback_used: attempts.length > 1,
      hash_algorithm: t.hashAlgorithm,
      imprint_over: "the `root` field of this bundle, as a UTF-8 string with no trailing newline",
      asserted_time: t.info.asserted_time,
      policy_oid: t.info.policy_oid,
      serial: t.info.serial,
      token_der_base64: t.token.toString("base64"),
    };
    console.log(`  witnessed: ${t.info.asserted_time}  (serial ${t.info.serial})`);
  } else {
    // ⛔ A FAILED WITNESS IS RECORDED, NOT SWALLOWED. A bundle that silently lost its receipt is
    // indistinguishable from one that never asked for a witness.
    witness = { type: "rfc3161", attempted: true, ok: false, tsa: t.tsa, reason: t.reason, attempts: t.attempts };
    console.log(`  ⛔ NOT witnessed: ${t.reason}`);
  }
}

// ⛔ Verify what we just built before writing it. A sealer that emits an unverifiable seal is worse
// than no sealer, because the failure surfaces at the relying party.
const selfCheck = verifyChain(entries);
if (!selfCheck.valid) {
  console.error("⛔ self-check FAILED:", JSON.stringify(selfCheck), "— refusing to write the bundle.");
  process.exit(3);
}
console.log(`self-check: chain of ${entries.length} entries verifies`);

const bundle = {
  seal_version: SEAL_VERSION,
  kind: "agentcore-gateway-config-seal",
  // ⛔⛔ THE DISCLAIMER TRAVELS WITH THE ARTIFACT. A relying party must not have to read our repo
  // to learn what this does not prove.
  what_this_proves:
    "The exact AgentCore gateway CONFIGURATION captured at the stated time — the gateway, its " +
    "execution role, the policy engine, and every policy's exact Cedar text — has not been " +
    "altered, removed or reordered since capture.",
  what_this_does_not_prove: [
    "That any particular action was allowed or denied. There is no AgentCore-originated " +
      "per-decision record to seal: the gateway emits no decision span, and a denial emits " +
      "nothing at all (F-11).",
    "That the configuration was unchanged BETWEEN two captures. A seal proves each capture is " +
      "intact, not that nothing happened in the gap.",
    "That the capture reflects reality — a seal proves the bytes were captured and not altered " +
      "since, not that the operator captured honestly. An RFC-3161 receipt, when present, attests " +
      "only that this root EXISTED at the stated time; it says nothing about whether the " +
      "configuration it describes was the one actually running.",
    "That this receipt is portable to a customer's own seal. The seal here is computed over the " +
      "REDACTED projection, because this repository ships public. A customer sealing their own " +
      "configuration would not redact, so their root differs and a receipt over ours does not " +
      "transfer. (Axis-1 Q7, recorded as a scope limit rather than solved.)",
  ],
  // ⚠️ UNSEALED ON PURPOSE. This timestamp comes from the operator's clock. It is recorded because
  // it is useful and excluded from the chain because it is not evidence.
  captured_at_unsealed: new Date().toISOString(),
  redaction:
    "The seal is computed over the REDACTED projection — the bytes published here. The raw " +
    "capture is retained outside the public tree and is NOT what this root covers.",
  root,
  witness,
  entry_count: entries.length,
  entries,
};

const stamp = bundle.captured_at_unsealed.replace(/[:.]/g, "-");
const outPath = `${OUT_DIR}config-seal.${stamp}.json`;
writeFileSync(outPath, JSON.stringify(bundle, null, 2));
writeFileSync(`${OUT_DIR}config-seal.latest.json`, JSON.stringify(bundle, null, 2));

console.log("");
console.log("sealed items:");
for (const e of entries.slice(0, -1)) {
  console.log(`  [${String(e.data.index).padStart(2)}] ${e.data.type.padEnd(21)} ${String(e.data.id).slice(0, 52).padEnd(52)} ${e.hash.slice(0, 16)}…`);
}
console.log(`  [manifest] ${entries.length - 1} items pinned`);
console.log("");
console.log(`root:     ${root}`);
console.log(`raw:      ${RAW_DIR}/config.raw.json   (unredacted, outside the public tree)`);
console.log(`bundle:   ${outPath}`);
console.log(`verify:   node reproduce/l5-adapter/verify-seal.mjs ${outPath}`);
