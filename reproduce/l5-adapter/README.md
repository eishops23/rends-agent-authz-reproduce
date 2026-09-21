# L5 — the config sealer

> ## It seals the **context** of a decision. It does **not** seal the decision.

Say it that way every time. F-11 established that an AgentCore Gateway emits no per-decision span,
and that a **denial emits nothing at all** — no span, no trace, no log line, only a counter
increment. There is therefore no AgentCore-originated decision record to seal, and a tool claiming
to seal one would be lying.

What AgentCore *does* expose, read-only and in full, is the **configuration** that governed
decisions. That is what this seals.

```bash
node reproduce/l5-adapter/seal-config.mjs                       # capture + seal (needs AWS read access)
node reproduce/l5-adapter/verify-seal.mjs <bundle.json>         # verify (needs NOTHING)
```

## Why configuration is worth sealing — F-07

The operator deleted the Cedar policy that produced a DENY. The CloudWatch counter survived —
`DenyDecisions = 1.0, Policy = L2_C3_forbid_v2-e6bergdd8o` — and became a dangling reference to an
object nobody can read. **The fact of the denial was tamper-resistant; its meaning was fully
mutable.** An outside party learns "one thing was denied by a policy you cannot read", which is not
evidence about an event.

The inverse is worse: an operator can delete a *permissive* policy after it allowed something,
leaving `AllowDecisions = 1.0` against an unreadable dimension. A reviewer cannot distinguish
"allowed by a narrow, careful rule" from "allowed by a rule that permitted everything".

Sealing the configuration is what preserves the meaning, in both directions.

## Demonstrated, not asserted

Run on 2026-09-13 against the live gateway:

| step | result |
|---|---|
| create an inert throwaway policy, seal with it present | root `ac41207a…`, **11 items** |
| operator deletes it with credentials they legitimately hold | `get-policy` ⇒ `ResourceNotFoundException` |
| verify the **pre-deletion** seal, afterwards | **VERIFIED**, and it still carries the policy's exact Cedar text, name, status, `enforcementMode` and `createdAt` |
| seal again, after the deletion | root `7639e427…`, **10 items** — different root, and a diff names exactly which item disappeared |

The post-deletion root is byte-identical to the seal taken *before* the probe policy existed, which
also confirms the sealing is deterministic rather than time-dependent.

## What is in a seal

Ten items on the current rig, in a deterministic order (sorted by type then id), each hashed into a
SHA-512 chain, with a **manifest** as the final entry:

```
capture-context        caller identity, account, region
gateway                the full gateway resource
gateway-role-trust     the execution role's trust policy
gateway-role-attached  its attached managed policies
gateway-role-inline    each inline policy document, in full
policy-engine          the policy engine resource
policy                 EVERY policy's exact Cedar statement   ← the F-07 payload
gateway-target         each target
```

### The manifest is the part that catches an omission

A hash chain detects **editing**. It does not detect a bundle published one item **shorter** —
re-chaining a truncated list produces a perfectly valid chain. The manifest pins the item count and
every item's `(index, type, id, hash)`, so removing, adding or reordering an item contradicts it.
This is the gap-evidence property from P4 axis 2, applied to configuration.

Verified against five tamper shapes, each of which must go red:

| tamper | caught by | diagnosis |
|---|---|---|
| edit a Cedar statement (`forbid` → `permit`) | chain | `hash does not match the recomputed hash of its own data` |
| remove an item | chain | `previousHash does not point at the preceding entry` |
| **remove an item and re-chain the rest** | **manifest** | `manifest says 10, bundle carries 9` |
| reorder two items | chain | `previousHash does not point at the preceding entry` |
| swap the declared root | root check | `the declared root is not the manifest's hash` |

The third is the one a naive chain misses.

## The verifier is genuinely offline

`verify-seal.mjs` imports `node:fs` and `harness/chain.mjs`, and `harness/chain.mjs` imports
`node:crypto` and a pure serializer. **No network, no AWS, no database, no Rends account, no build
step.** The brief's axis-14 test is "can the record be verified after the vendor is gone", and a
verifier that phones home answers it with "no".

⚠️ This does **not** close P4 axis 3. Axis 3 asks for an offline verifier against an exported
**Rends audit-trail bundle**; this verifies a **config seal**, which is a different artifact. The
audit doc's warning stands: a verifier that has never seen a real bundle of the relevant shape is
an assertion, not a capability.

## Redact, then seal

The seal is computed over the **redacted projection** — the bytes published here. Sealing the raw
capture and publishing a redacted one would hand out a bundle that cannot verify. The raw capture
is retained at `/home/ubuntu/agent-authz-raw/l5-adapter/` per the redaction ruling, and is **not**
what the root covers. The bundle says so in its own `redaction` field.

## The copied primitives

`harness/canonical-json.mjs` and `harness/chain.mjs` are verbatim ports of the product's
`shared/src/audit/{canonical-json,hash-chain}.ts`, so a seal produced here is checkable by the
product's own `verifyChain` and vice versa. A copy drifts, and canonicalization is exactly where
the subtle bugs live, so `harness/__tests__/canonical-json-parity.test.mjs` runs **both**
implementations over the same probes and asserts byte-identical output:

```bash
node --test harness/__tests__/canonical-json-parity.test.mjs
```

It fails loudly rather than skipping if the reference is absent. A skipped parity test must never
read as a passing one.

## What a seal cannot tell you

- **That any particular action was allowed or denied.** There is no decision record (F-11).
- **That the configuration was unchanged between two captures.** A seal proves each capture is
  intact, not that nothing happened in the gap. Two seals with different roots prove drift; two
  with the same root prove the endpoints matched, not the middle.
- **That the capture was honest at capture time.** Nothing here is counter-signed by a party
  outside the operator's control. That is external anchoring — P4 axis 1 — and it is **not part of
  this seal**. Without it, a sealed bundle proves internal consistency of a capture the operator
  produced.

All three travel inside every bundle, in `what_this_does_not_prove`, and the verifier prints them
on success. A relying party should not have to read this repo to learn what the artifact does not
mean.
