# ⛔⛔ REDACTION NOTE — sibling to `decision-capture.20260916T152000Z.json`

⭐ **Added by ADDITION, 2026-09-16.** ⛔⛔ **The bundle is NOT modified and must not be. Its `root`
commits to its exact bytes; editing it to improve its own description would destroy the only property
that makes it evidence.** ⇒ ⭐ **The correction lives beside it.**

---

# 1 — ⛔ WHAT THE BUNDLE SAYS ABOUT ITSELF
```json
"redaction": {
  "applied": false,
  "note": "Decision spans carry no principal and no arguments, so there is nothing to redact.
           That is a limitation, not a privacy property."
}
```

# 2 — ⛔⛔ **WHY THAT SENTENCE IS INCOMPLETE**

⭐ **Measured in this bundle:**
```
raw occurrences of AWS account id 168866076232 ............ 104
  policy_engine_arn ...... 52   (one per decision)
  gateway_arn ............ 52   (one per decision)
for comparison, decision-capture.latest.json (09-14) ......   4
```
⛔⛔ **And `harness/redact.mjs` carries a rule for exactly that value** —
`[/\b168866076232\b/g, "<AWS_ACCOUNT_ID>"]`.
> ### ⇒ ⛔⛔ ***"THERE IS NOTHING TO REDACT"* IS TRUE OF PRINCIPAL AND ARGUMENTS. IT IS NOT TRUE OF
> ### EVERY VALUE THE PROJECT'S OWN REDACTOR IS CONFIGURED TO MASK.**

## ⭐ THE CLAIM'S ACTUAL SCOPE
⭐ **`applied: false` is accurate**: no redaction pass was run over this bundle.
⛔ **The `note` is scoped to REDACTIONS PERFORMED and to the two axes it names — principal and
arguments — NOT to values PRESENT in the capture.** ⚠️ **Read as a statement about values present, it
is wrong**, and a reader has every reason to read it that way, because that is what a field called
`redaction` appears to be about.

# 3 — ⭐ WHAT IS ACTUALLY IN THE BUNDLE, STATED PLAINLY

| | |
|---|---|
| ⭐ **absent, and it is a limitation** | **no principal** — no agent identity, no delegated human · **no arguments** — `amount`, `to`, `from` appear nowhere. ⛔ **Axes 4 and 5 unmet.** This half of the note is correct and is the important half |
| ⛔ **present, by convention** | **AWS account id `168866076232`**, inside `policy_engine_arn` and `gateway_arn` on every decision record |
| ⭐ **present** | policy ids, gateway id, engine id, request ids, trace and span ids, timestamps |
| ⛔ **not present** | no access key, no bearer token, no credential of any kind |

## ⚠️ "BY CONVENTION" — **AND THE CONVENTION IS REAL, NOT AN EXCUSE**
⭐ The split this repo actually operates:
- ⭐ **L2 RUN CAPTURES go through `redact()`** — `rig/l2-agentcore/output/*.redacted.jsonl` carry
  `<AWS_ACCOUNT_ID>`, and the redactor self-test runs before every capture.
- ⛔ **BUNDLES AND ANALYSIS PROSE DO NOT.** Gateway and engine ARNs are carried verbatim, because the
  ARN **is** the identity of the thing the evidence is about, and masking it would make a sealed
  configuration unverifiable against the account it describes.
⭐ **This predates the bundle:** `decision-capture.latest.json` shipped on 09-14 with 4 occurrences,
and **six committed files** already carry AWS access key IDs in prose.
⇒ ⭐ **The convention was already chosen and consistently applied. What was missing was the bundle
saying so about itself.**

# 4 — ⛔ WHAT A SKEPTICAL READER SHOULD TAKE FROM THIS

> ### ⭐⭐ **THE BUNDLE CONTAINS NO PRINCIPAL AND NO ARGUMENTS — THAT IS TRUE, AND IT IS A LIMITATION
> ### OF THE SOURCE, NOT A PRIVACY FEATURE WE BUILT.**
> ### ⛔ **IT DOES CONTAIN AWS RESOURCE IDENTIFIERS, INCLUDING THE ACCOUNT ID, 104 TIMES.**
⚠️ **Neither fact is hidden and neither should be inferred from the `redaction` field alone**, which
is the reason this note exists.

# 5 — ⛔⛝ **WHAT WAS DELIBERATELY NOT DONE**
| | |
|---|---|
| ⛔⛝ **the bundle was not edited** | its `root` is the point of it. ⭐ **A capture that can be improved after the fact is not a capture** |
| ⛔⛝ **the generator's note text was not changed** | `ingest-decisions.mjs` will emit the same incomplete sentence into the NEXT bundle. ⚠️ **That is a reader-facing string on a published artifact** ⇒ ⛔ **flagged for Fed, not changed here** |
| ⛔⛝ **no re-capture** | the bundle verifies at exit 0 and nothing about it is wrong — **only its self-description was incomplete** |

## Status
⭐ **Correction by ADDITION. The artifact is untouched and still verifies.**
⛔ **`applied: false` accurate · the `note` scoped to principal and arguments, not to values present ·
104 account-id occurrences recorded here by measurement.**
⚠️ **RECURS on the next capture until the generator's string is ruled on.**
