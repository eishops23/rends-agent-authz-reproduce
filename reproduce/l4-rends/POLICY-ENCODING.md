# L4 — the policy of `POLICY-SPEC.md`, encoded natively in Rends

Traceability: every clause below maps to a clause id in `../../policy/POLICY-SPEC.md`.
Anything that could **not** be encoded natively is recorded here as a limit, not omitted.

---

## ⛔⛔ FINDING BEFORE ANY SCENARIO RUNS: THE AMOUNT NEVER REACHES THE EVALUATOR

Measured in the production source, 2026-09-13:

| where | what it admits |
|---|---|
| `services/comply/src/routes/real-time.ts:9-16` — `checkActionBodySchema` | `orgId`, `agentId`, `actionType`, `actionName`, `resourceType`, `input_summary`. **No typed arguments field.** |
| `shared/src/types/comply.types.ts:134-148` — `RuleContext` | the same six, plus `agentConfig`, `industry`, `jurisdictions`, `documents` |
| `services/comply/src/engine/rules-engine.ts:58-83` — `buildEvaluationRoot` | flattens to roots `org` and `agent` plus the four action strings |

The rules engine **does** implement numeric comparison — `gt` / `lt` / `gte` / `lte`, with
`Number()` coercion and a `Number.isFinite` guard (`rules-engine.ts:176-186`). The operator set
is not the limitation.

> ### ⇒ **`amount` HAS NO ROUTE INTO THE EVALUATION ROOT.**
> C1 and C2 are amount-threshold clauses. Through the production pre-action check they can only be
> expressed by **pattern-matching a number out of `input_summary`**, which the type declares as
> *"Redacted or summarized input for condition evaluation."*
>
> ⛔ This is a loss against Cedar, which evaluates typed context attributes, and it is recorded as
> one. It belongs in D3 and it must not be smoothed over in D1.

**The honest encoding therefore uses a `regex` leaf for the threshold clauses and states that it
does.** A reader comparing L2 and L4 on axis 5 should see *typed numeric comparison* on one side and
*regex over a summary string* on the other.

---

## ⚠️ AND THERE ARE TWO PRODUCTION PATHS, NOT ONE

Rends decides in two different places, and they answer different axes. The matrix must say which
produced each decision rather than presenting "Rends" as one thing.

| path | mechanism | which clause it can carry |
|---|---|---|
| **A — pre-action check** `POST /v1/compliance/check-action` | comply rules engine → `{blocked, violations[]}` | C3 natively (destination is a string); C1/C2 only by regex |
| **B — permission gate** `govern.agent_permissions.requires_approval` → `deploy` orchestrator hold | the escalation the demo's Scene 4 exercises | C2's *escalation*, natively — but with **no numeric threshold** |

⛔⛔ **Path A is ADVISORY.** It returns a decision; it does not stand between the agent and the tool.
The caller is expected to honour it. That is the same structural position as L1's in-process check,
and **axis 2 must be tested against it, not assumed** — see `run.mjs`'s bypass step.
⭐ **Path B is ENFORCING** — the orchestrator holds the execution at `awaiting_approval` and the tool
call does not happen. That is Rends' real answer to axis 1, and it is narrower than "Rends enforces".

---

## Clause encodings

### C3 — DENY to a restricted destination  *(path A, native)*

```json
{
  "name": "L4-C3-restricted-destination",
  "rule_type": "prohibition",
  "priority": 100,
  "conditions": {
    "all_of": [
      { "field": "agent.action_name", "operator": "eq", "value": "transfer_funds" },
      { "field": "agent.input_summary", "operator": "contains", "value": "ACCT-SANCTIONED-9" }
    ]
  },
  "actions": { "decision": "BLOCK", "reason": "C3 restricted destination" }
}
```
⭐ Native: the destination is a string and `contains` is a string operator.
⚠️ Limit: it matches the destination **as text inside a summary**, so it is defeated by any caller
that words the summary differently. Cedar would match a typed `resource` attribute.

### C2 — ESCALATE above $10,000  *(path A regex + path B enforcement)*

```json
{
  "name": "L4-C2-escalate-above-10k",
  "rule_type": "obligation",
  "priority": 90,
  "conditions": {
    "all_of": [
      { "field": "agent.action_name", "operator": "eq", "value": "transfer_funds" },
      { "field": "agent.input_summary", "operator": "regex",
        "value": "amount=(1[0-9]{4,}|[2-9][0-9]{4,})\\\\.00" }
    ]
  },
  "actions": { "decision": "ESCALATE", "reason": "C2 above 10000 requires approval" }
}
```
⛔⛔ **THE REGEX IS THE FINDING.** It approximates `10000 < amount <= 50000` by matching digit
shape. It does **not** implement the upper bound, it breaks on formatting (`27,500`, `27500`,
`2.75e4`), and it is not the clause — it is a lexical proxy for the clause. **Recorded as such.**
⭐ The *enforcement* of the escalation is path B, which is real.

### C1 — ALLOW at or below $10,000  *(default)*

No rule. Default-permit in path A: absent a matching prohibition, `blocked` is false.
⛔⛔ **This is the opposite of Cedar's model.** `POLICY-SPEC.md` states default-**deny**, "matching
Cedar's evaluation model". Path A is **default-allow** — an action with no matching rule is not
blocked. That is a structural difference in the evaluation model and belongs in D1 on axis 1.

---

## Regulation choice — FIXTURE, and the reason is the global-rules defect

⭐ **Picked: a fixture regulation row** (`e0000000-…-e001`, *"Evidence Challenge Fixture — Funds
Transfer Authorization"*), not a real one.

⚠️ Two real regulations fit genuinely — **NY DFS Part 504 (AML transaction monitoring)**, which is
almost exactly C2's threshold review plus C3's sanctioned-destination filtering, and **FinCEN AML
Program Requirements (BSA)**. Part 504 is named here as the **real-world analogue: cited, not wired.**

⛔ **The reason for the fixture is not tidiness.** `comply.rules` has **no `org_id`**, so attaching
synthetic test rules to a real regulation row would put them in **every tenant's** rule set under a
real citation — a compliance view grouping rules by regulation would show L4 test artifacts under
NY DFS Part 504 to a real bank. The fixture keeps them attributable and greppable.
⚠️ **Cost, stated:** C2 and C3 lose their real-world citation inside the artifact. Carried as prose
here instead.

---

## ⛔⛔ Isolation is BY PREDICATE, not by scope — and one typo defeats it

**Measured:** `comply.rules` has no `org_id` column, and `findApplicableRules`
(`rules-engine.ts:88-99`) selects **every enabled, in-date rule** with no tenant clause, then
evaluates each against whichever org is calling.

> ### ⇒ **A RULE WRITTEN FOR L4 IS EVALUATED FOR EVERY TENANT, INCLUDING APEX.**

⭐ **Accepted for this test, on Fed's ruling 2026-09-13**, given the constraint. The containment is
the **first condition of each rule**:

```json
{ "field": "agent.action_name", "operator": "eq", "value": "transfer_funds" }
```

No real tenant emits `action_name = "transfer_funds"`, so the rules evaluate to false for real
traffic and cost one predicate comparison each.

> ### ⛔⛔ **BUT THIS IS CONTAINMENT BY STRING EQUALITY, AND IT IS ONE TYPO FROM FAILING.**
> ⚠️ If that gate is mistyped, widened, or dropped in a later edit — `contains` instead of `eq`, a
> truncated value, a refactor that reorders `all_of` — **these rules begin firing against real
> tenants' production traffic**, and C3's second condition is a `contains` over a free-text summary,
> which is exactly the kind of predicate that matches by accident.
> ⭐ **Nothing in the schema prevents this. There is no scope to fall back on.** The `§VERIFY` block
> in `setup.sql` asserts both rules still carry the gate; that check is the only guard there is, and
> it is a check, not a constraint.

⇒ **This is recorded as a PRODUCT finding in its own right, separately from the evidence-challenge
findings** — see `findings/F-03-rules-are-global-no-tenant-predicate.md`. It is load-bearing for
anything sold to a regulated institution, and it belongs in **D3 stated plainly, not as a footnote.**

---

## What this encoding does not claim

- It does **not** claim Rends cannot express amount thresholds — only that **this production path**
  cannot receive an amount. A typed-argument surface is a build, not an impossibility (§7's third
  category: not architecturally impossible).
- It does **not** claim path A is useless. It is the pre-action check the product ships and the
  demo exercises; it is advisory, and the artifact says advisory.
- The bypass result in `run.mjs` is the measurement for axis 2. Nothing here predicts it.
