/**
 * ⭐⭐ THE SPAN → DECISION-RECORD MAPPING, AND THE CONTRACT THAT GOVERNS IT.
 *
 * ⛔⛔ WHY THIS IS ITS OWN MODULE. It used to live inside `ingest-decisions.mjs`, whose top level
 * calls AWS the moment it is imported — so the mapping could not be tested without a live capture,
 * and it was never tested. F-18 was the result: two denials with OPPOSITE causes produced records
 * that differed only in their ids. ⭐ Extracted so `__tests__/decision-record.test.mjs` exercises
 * THE FUNCTION THE ADAPTER ACTUALLY USES — not a copy of it that can drift.
 *
 * ⛔⛔ AND THE ASYMMETRY THAT F-18 IS REALLY ABOUT:
 *   the old header said "EVERY field is copied from the span; nothing is derived, defaulted or
 *   inferred", and listed three deliberate absences. ⭐ That guard was written against INVENTING a
 *   field. ⛔ It said nothing about LOSING one — and a named list of omissions reads as complete,
 *   so the loss was invisible. `authorization_reason` was in the span, absent from the record, and
 *   absent from the list.
 * ⇒ ⭐⭐ THE SENTENCE IS GONE. It is replaced by a contract a TEST enforces, below, because a
 *   sentence in a header cannot fail and a test can.
 */

export const SPAN_NAME = "AgentCore.Policy.AuthorizeAction";

/**
 * ⭐⭐ THE GOVERNED NAMESPACE. Every span attribute beginning with this prefix carries DECISION
 * SEMANTICS — what was decided, by what, and why — and must have an explicit disposition below.
 * ⛔ Attributes outside it (`aws.local.*`, `aws.remote.*`, `rpc.*`, `http.*`, `telemetry.*`,
 * `PlatformType`, `aws.span.kind`, `aws.xray.origin`) are transport and infrastructure. They are
 * deliberately out of scope, and that is a scope statement, not an omission.
 * ⚠️ `aws.request.id` and `aws.resource.arn` sit outside the prefix but ARE copied — identity, not
 * semantics. They are listed in COPIED anyway so the mapping is readable in one place.
 */
export const GOVERNED_PREFIX = "aws.agentcore.";

/** ⭐ span attribute → record field. */
export const COPIED = Object.freeze({
  "aws.request.id": "id",
  "aws.resource.arn": "gateway_arn",
  "aws.agentcore.policy.authorization_decision": "decision",
  "aws.agentcore.policy.authorization_reason": "authorization_reason",
  "aws.agentcore.policy.determining_policies": "determining_policies",
  "aws.agentcore.policy.mismatched_policies": "mismatched_policies",
  "aws.agentcore.policy.types": "policy_types",
  "aws.agentcore.policy.target_resource.id": "target_resource_id",
  "aws.agentcore.gateway.policy.arn": "policy_engine_arn",
  "aws.agentcore.gateway.policy.mode": "enforcement_mode",
});

/**
 * ⛔ span attribute → WHY IT IS NOT COPIED. An entry here is a RECORDED DECISION, reviewable in a
 * diff. ⚠️ The bar for adding one is that the field does not bear on which policy decided or why —
 * ⛔⛔ and F-18 exists because a field that DID bear on why was never written down at all.
 */
export const DECLINED = Object.freeze({
  "aws.agentcore.policy.temporal.evaluation_invoked":
    "A temporal-policy evaluation flag, observed as false on every span captured to date. It does " +
    "not name a policy and does not state a cause. ⚠️ Surfaced by this contract on 2026-09-16 — it " +
    "is DECLINED rather than copied so the omission is a decision on the record, and it is Fed's to " +
    "overturn.",
});

/**
 * ⛔⛔ THE GUARD F-18 EARNED. Returns every governed attribute a span carries that is neither copied
 * nor explicitly declined. ⭐ A non-empty result means AWS is emitting decision semantics this
 * adapter silently drops — which is exactly the failure the old header could not express.
 * ⚠️ It is driven by REAL SPANS, so it also catches a field AWS adds later that nobody has read yet.
 */
export function undeclaredAttributes(span) {
  const a = span?.attributes ?? {};
  return Object.keys(a)
    .filter((k) => k.startsWith(GOVERNED_PREFIX))
    .filter((k) => !(k in COPIED) && !(k in DECLINED))
    .sort();
}

/**
 * ⭐ Normalise one span to a decision record. Nothing is derived, defaulted or inferred: a field
 * absent from the span is `null` in the record, never a plausible substitute.
 * ⛔ An adapter that fills a gap with something reasonable is the thing this exercise exists to
 * refuse — and an adapter that quietly drops a field is the thing F-18 caught it also doing.
 */
export function toDecisionRecord(span) {
  const a = span?.attributes ?? {};
  if (span?.name !== SPAN_NAME) return null;
  const decision = a["aws.agentcore.policy.authorization_decision"];
  if (decision === undefined) return null;

  return {
    type: "authorization_decision",
    id: a["aws.request.id"],                                   // ⭐ unique per decision
    decision,                                                   // ALLOW | DENY
    // ⭐⭐ F-18: WITHOUT THESE TWO, A DEFAULT-DENY AND AN EVALUATION ERROR ARE THE SAME RECORD.
    // Both are decision=DENY with determining_policies=[]; only these say which happened.
    authorization_reason: a["aws.agentcore.policy.authorization_reason"] ?? null,
    mismatched_policies: a["aws.agentcore.policy.mismatched_policies"] ?? null,
    determining_policies: a["aws.agentcore.policy.determining_policies"] ?? null,
    policy_types: a["aws.agentcore.policy.types"] ?? null,
    policy_engine_arn: a["aws.agentcore.gateway.policy.arn"] ?? null,
    enforcement_mode: a["aws.agentcore.gateway.policy.mode"] ?? null,
    target_resource_id: a["aws.agentcore.policy.target_resource.id"] ?? null,
    gateway_arn: a["aws.resource.arn"] ?? null,
    trace_id: span.traceId ?? null,
    span_id: span.spanId ?? null,
    start_time_unix_nano: span.startTimeUnixNano ?? null,
    // ⛔ Absent because the SPAN does not carry them, not because they were dropped:
    //    principal, arguments, policy version. See WHAT_THIS_DOES_NOT_PROVE in ingest-decisions.mjs.
    // ⛔ Absent by recorded decision: see DECLINED above.
  };
}
