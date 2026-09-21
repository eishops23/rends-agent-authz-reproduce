-- ============================================================================
-- L4 SETUP — the dedicated tenant, the fixture regulation, and the C2/C3 rules.
--
-- ⛔ DRAFTED. Fed runs it. It WRITES to the production database.
--
-- Run with the Keycloak group's id supplied as a variable — there is no
-- placeholder to hand-edit, because a hand-edited placeholder is how the wrong
-- id reaches production:
--
--   sudo -u postgres psql -v ON_ERROR_STOP=1 -d agentcompliant \
--     -v kc_org_id="'org_authz_evidence_XXXX'" \
--     -f /home/ubuntu/agent-authz-evidence/reproduce/l4-rends/setup.sql
--
-- ⚠️ VERIFY IN A SEPARATE INVOCATION. A block that checks its own post-state
-- inside its own transaction proves intent, not durability — see §VERIFY.
-- ============================================================================

\if :{?kc_org_id}
\else
  \echo '⛔ REFUSING: -v kc_org_id=... was not supplied. This creates a production tenant; it does not guess.'
  \quit
\endif

BEGIN;

-- ── 1. THE TENANT ───────────────────────────────────────────────────────────
-- Same columns any tenant gets. No fixture shortcut, no special-casing.
--
-- purpose = 'production' per Fed's ruling ("a dedicated production org … same
-- code surface as any other tenant"). ⚠️ CONSEQUENCE, STATED: org-purge and
-- every other purpose-keyed behaviour will treat this as a real tenant. The
-- CHECK also admits 'demo' and 'ci-harness'; 'production' is the instruction
-- and it is the honest one for an artifact that claims to use the real path.
--
-- allow_wildcard_scope is left at the column DEFAULT (true). ⛔ It is true on
-- all fourteen existing orgs. Setting it false here would be a hardening no
-- real tenant gets, i.e. special-casing in the flattering direction.
-- ⚠️ It is also the over-grant default `finding-api-key-scope-picker-over-grant`
-- already records — inherited deliberately, not endorsed.
INSERT INTO platform.organizations
  (clerk_org_id, name, slug, industry, jurisdictions,
   external_org_id, external_provider, purpose, settings, onboarding_completed)
VALUES
  (:kc_org_id,
   'Agent Authorization Evidence',
   'agent-authz-evidence',
   'financial_services',
   ARRAY['US-FED','US-NY']::text[],
   :kc_org_id,
   'keycloak',
   'production',
   '{"evidence_challenge": true, "brief": "CC-BRIEF-agent-authorization-evidence.md"}'::jsonb,
   true)
ON CONFLICT (clerk_org_id) DO NOTHING;

-- industry + jurisdictions are set because buildEvaluationRoot puts BOTH in the
-- evaluation root (rules-engine.ts:58-83). Leaving them null would give the
-- engine a narrower context than a real tenant has, which would make L4's
-- result unrepresentative in our own favour.

-- ── 2. THE FIXTURE REGULATION ───────────────────────────────────────────────
-- ⭐ RULED: a FIXTURE row, not a real regulation. Reason recorded in
-- POLICY-ENCODING.md §Regulation choice, and it follows from comply.rules having
-- NO org_id: rules are GLOBAL. Attaching synthetic test rules to
-- 'NY DFS Part 504 — AML Transaction Monitoring' would put them in every
-- tenant's rule set under a real citation, so a compliance view grouping by
-- regulation would show L4 test artifacts to a real bank.
-- ⚠️ Part 504 remains the real-world ANALOGUE and is named as prose in
-- POLICY-ENCODING.md — cited, not wired.
INSERT INTO comply.regulations
  (id, name, short_name, jurisdiction, jurisdiction_name, category, status,
   effective_date, summary, enforcement_agency,
   applicable_industries, applicable_agent_action_types, metadata, source_type)
VALUES
  ('e0000000-0000-4000-8000-00000000e001',
   'Evidence Challenge Fixture — Funds Transfer Authorization',
   'EC-FIXTURE',
   'US-FED',
   'United States (fixture)',
   'fixture',
   'active',
   DATE '2026-09-01',
   'NOT A REAL REGULATION. A fixture row carrying the three-clause policy of '
   || 'CC-BRIEF-agent-authorization-evidence.md for the L4 stack. Real-world '
   || 'analogue: NY DFS Part 504 (AML transaction monitoring) and FinCEN BSA '
   || 'program requirements. Cited as analogue, deliberately not wired to them.',
   'none (fixture)',
   ARRAY['financial_services']::text[],
   ARRAY['financial_transaction']::text[],
   '{"fixture": true, "evidence_challenge": true}'::jsonb,
   'fixture')
ON CONFLICT (id) DO NOTHING;

-- ── 3. C3 — DENY to a restricted destination ────────────────────────────────
-- ⛔⛔ ISOLATION IS BY PREDICATE, NOT BY SCOPE. comply.rules has no org_id and
-- findApplicableRules has no tenant clause (rules-engine.ts:88-99), so every
-- enabled in-date rule is evaluated for EVERY tenant. The FIRST condition below
-- is what keeps this rule off real traffic. See POLICY-ENCODING.md §Isolation.
INSERT INTO comply.rules
  (id, regulation_id, name, description, rule_type, priority, conditions, actions,
   enabled, version, effective_from)
VALUES
  ('e0000000-0000-4000-8000-00000000c003',
   'e0000000-0000-4000-8000-00000000e001',
   'L4-C3-restricted-destination',
   'POLICY-SPEC C3: transfers to a restricted destination are denied unconditionally.',
   'prohibition',
   100,
   '{"all_of":[
       {"field":"agent.action_name","operator":"eq","value":"transfer_funds"},
       {"field":"agent.input_summary","operator":"contains","value":"ACCT-SANCTIONED-9"}
     ]}'::jsonb,
   '{"decision":"BLOCK","clause":"C3","reason":"C3 restricted destination"}'::jsonb,
   true, 1, DATE '2026-09-01')
ON CONFLICT (id) DO NOTHING;

-- ── 4. C2 — ESCALATE above $10,000 ──────────────────────────────────────────
-- ⛔⛔ THE REGEX IS A LEXICAL PROXY FOR THE CLAUSE, NOT THE CLAUSE. The amount
-- cannot reach the evaluator (POLICY-ENCODING.md §finding), so this matches the
-- DIGIT SHAPE of a five-or-more-figure amount in the summary string. It does NOT
-- implement C2's upper bound of 50000 and it breaks on '27,500' or '2.75e4'.
-- Recorded here so the SQL cannot be read as implementing the clause.
INSERT INTO comply.rules
  (id, regulation_id, name, description, rule_type, priority, conditions, actions,
   enabled, version, effective_from)
VALUES
  ('e0000000-0000-4000-8000-00000000c002',
   'e0000000-0000-4000-8000-00000000e001',
   'L4-C2-escalate-above-10k',
   'POLICY-SPEC C2: transfers above 10000 require a human approval bound to the '
   || 'action. LEXICAL PROXY — matches digit shape in input_summary; does not '
   || 'implement the 50000 upper bound.',
   'obligation',
   90,
   '{"all_of":[
       {"field":"agent.action_name","operator":"eq","value":"transfer_funds"},
       {"field":"agent.input_summary","operator":"regex","value":"amount=[1-9][0-9]{4,}\\.[0-9]{2}"}
     ]}'::jsonb,
   '{"decision":"ESCALATE","clause":"C2","reason":"C2 above 10000 requires approval"}'::jsonb,
   true, 1, DATE '2026-09-01')
ON CONFLICT (id) DO NOTHING;

-- ── C1 has NO rule, deliberately ────────────────────────────────────────────
-- Path A is default-ALLOW: absent a matching prohibition, `blocked` is false.
-- ⛔ POLICY-SPEC states default-DENY "matching Cedar's evaluation model". That
-- difference is an axis-1 evaluation-model finding for D1, not a gap to paper
-- over by inventing a permit rule the product does not have.

COMMIT;

-- ============================================================================
-- §VERIFY — RUN AS ITS OWN INVOCATION, NOT INSIDE THE TRANSACTION ABOVE.
--
--  /usr/bin/psql -h 127.0.0.1 -U cc_readonly -d agentcompliant -tAF' | ' -c "SELECT (SELECT count(*) FROM platform.organizations WHERE slug='agent-authz-evidence') AS org, (SELECT count(*) FROM comply.regulations WHERE id='e0000000-0000-4000-8000-00000000e001') AS fixture_reg, (SELECT count(*) FROM comply.rules WHERE regulation_id='e0000000-0000-4000-8000-00000000e001' AND enabled) AS rules_enabled;"
--
-- PASS: org = 1 | fixture_reg = 1 | rules_enabled = 2
--
-- ⛔⛔ AND THE ISOLATION CHECK, which matters more than the counts. Confirm the
-- new rules cannot fire for a real tenant's traffic: every one must carry the
-- action_name gate.
--
--  /usr/bin/psql -h 127.0.0.1 -U cc_readonly -d agentcompliant -tAF' | ' -c "SELECT name, (conditions::jsonb #>> '{all_of,0,value}') AS first_gate FROM comply.rules WHERE regulation_id='e0000000-0000-4000-8000-00000000e001' ORDER BY name;"
--
-- PASS: BOTH rows show first_gate = transfer_funds. Anything else means a rule
-- is loose in every tenant's evaluation.
-- ============================================================================
