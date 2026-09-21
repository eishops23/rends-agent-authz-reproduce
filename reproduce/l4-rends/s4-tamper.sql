-- ============================================================================
-- L4 S4 — TAMPER WITH THE DENY RECORD, using credentials the operator
-- legitimately holds.
--
-- ⭐⭐ RULED 2026-09-13: ROLLBACK-WRAPPED. Fed runs it.
--
-- ⛔ WHY WRAPPED, AND WHAT THAT COSTS. If the WORM trigger refuses, the refusal
-- IS the answer and a rollback changes nothing about it. If the trigger does NOT
-- refuse, this tells us the tamper would have succeeded WITHOUT destroying a row
-- of the production audit chain. The cost is stated rather than hidden: in the
-- second case we learn the mutation is possible but cannot then measure
-- outside-party detectability against a really-mutated chain — that half would
-- have to be argued from chain structure and must be labelled as argued, not
-- measured.
--
-- ⛔ RUN AS THE APPLICATION ROLE, NOT AS postgres. The question is what the
-- OPERATOR can do with the credentials they legitimately hold in normal
-- operation. Running as a superuser answers a different and easier question, and
-- would make the result flattering and wrong.
--
--   psql "$DATABASE_URL" -v ON_ERROR_STOP=0 \
--     -f /home/ubuntu/agent-authz-evidence/reproduce/l4-rends/s4-tamper.sql \
--     2>&1 | tee /home/ubuntu/agent-authz-raw/l4-rends/s4.raw.txt
--
-- ⚠️ ON_ERROR_STOP=0 deliberately: a refusal is a RESULT, not a reason to abort.
-- Every statement must get its chance to fail on the record.
-- ============================================================================

\echo '=== L4 S4: tamper with the DENY record (ROLLBACK-wrapped) ==='
\echo ''
\echo '--- who am I? (must NOT be a superuser, or the test is meaningless) ---'
SELECT current_user,
       (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) AS is_superuser;

\echo ''
\echo '--- the target row: the most recent transfer_funds DENY on this chain ---'
SELECT id, created_at, actor_type, action,
       left(details::text, 160) AS details_head
  FROM comply.audit_trail
 WHERE action ILIKE '%check-action%'
    OR details::text ILIKE '%transfer_funds%'
 ORDER BY created_at DESC
 LIMIT 5;

BEGIN;

\echo ''
\echo '=== ATTEMPT 1 — UPDATE the decision in place ==='
UPDATE comply.audit_trail
   SET details = jsonb_set(details::jsonb, '{blocked}', 'false'::jsonb)
 WHERE id = (SELECT id FROM comply.audit_trail
              WHERE details::text ILIKE '%ACCT-SANCTIONED-9%'
              ORDER BY created_at DESC LIMIT 1);

\echo ''
\echo '=== ATTEMPT 2 — DELETE the row outright ==='
DELETE FROM comply.audit_trail
 WHERE id = (SELECT id FROM comply.audit_trail
              WHERE details::text ILIKE '%ACCT-SANCTIONED-9%'
              ORDER BY created_at DESC LIMIT 1);

\echo ''
\echo '=== ATTEMPT 3 — TRUNCATE the table (the blunt instrument) ==='
TRUNCATE comply.audit_trail;

\echo ''
\echo '=== ATTEMPT 4 — disable the guard, then delete (the informed operator) ==='
\echo '--- an operator who READ the schema would try this first ---'
ALTER TABLE comply.audit_trail DISABLE TRIGGER USER;

ROLLBACK;

\echo ''
\echo '=== POST-STATE — proves the rollback held and nothing was destroyed ==='
SELECT count(*) AS rows_still_present FROM comply.audit_trail;

\echo ''
\echo '=== WHAT TO RECORD ==='
\echo 'For each attempt: did it RAISE, and with what message?'
\echo '  raised  -> the guard refused; that refusal is the evidence'
\echo '  silent  -> the mutation would have COMMITTED. Record that, and do NOT'
\echo '             re-run it unwrapped to "confirm" - the wrapped run already'
\echo '             answered the question.'
\echo ''
\echo 'Then axis 13: could an OUTSIDE party detect it without the operator?'
\echo 'That depends on external anchoring (P4 axis 1) and per-agent sequence'
\echo 'numbers (P4 axis 2). F-02 already records anchoring as ABSENT.'
