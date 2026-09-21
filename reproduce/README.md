# ⭐⭐ `reproduce/` — **RUN THIS. NO AWS ACCOUNT. NO MONEY. NO RIG.**
**Cost to run: a machine with `node` and `bash`.** ⛔ **Nothing here calls AWS.**

⭐ **Start with `l5-adapter/decision-acceptance.sh`** — it is the strongest artifact in D2.
**5 cases, and THREE OF THEM MUST FAIL.** A suite where everything passes cannot tell a live
verifier from `exit 0`.

| | | |
|---|---|---|
| `l5-adapter/` | ⭐⭐ decision-capture seal + verifier | **offline by construction** |
| `l1-app-logging/` | the L1 baseline and its S4 tamper | offline |
| `l4-rends/` | the Rends stack | ⚠️ **needs a running Rends**, not AWS |
| `l2-agentcore/lambda/` | the tool target the gateway invokes | ⚠️ a handler, not an entry point |

⚠️ **`../harness/` is at the repo root, not in here.** ⭐ **Deliberate:** every stack reaches it as
`../../harness/…`, and **moving it is the one change that would break all ten of those imports.**
⛔ **It is tier A — offline — and it stays at root so the imports resolve unchanged.**
⚠️ **`rfc3161.mjs` in the harness reaches a public timestamp authority. Not AWS, but not airgapped.**
