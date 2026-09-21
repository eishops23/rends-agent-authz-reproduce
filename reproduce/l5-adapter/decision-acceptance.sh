#!/usr/bin/env bash
# ⭐⭐ L5 DECISION ADAPTER — ACCEPTANCE, IN THE F-12 SHAPE.
# ⛔ A suite where every case passes cannot tell a live verifier from `exit 0`. Three of these five
#    MUST FAIL, and the run is a failure if they do not.
set -uo pipefail
cd "$(dirname "$0")"
BUNDLE="${1:-output/decision-capture.latest.json}"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
pass=0; fail=0
ok()   { echo "  PASS  $1"; pass=$((pass+1)); }
bad()  { echo "  FAIL  $1"; fail=$((fail+1)); }
# expect_ok / expect_fail invert deliberately: a tamper case that VERIFIES is the bug.
expect_ok()   { if node verify-seal.mjs "$1" >/dev/null 2>&1; then ok "$2"; else bad "$2 (expected verify OK, got failure)"; fi; }
expect_fail() { if node verify-seal.mjs "$1" >/dev/null 2>&1; then bad "$2 (TAMPER VERIFIED — the verifier is blind)"; else ok "$2"; fi; }

echo "L5 decision-capture acceptance"
echo

# ── 1. POSITIVE CONTROL ──────────────────────────────────────────────────────
expect_ok "$BUNDLE" "positive control — the real captured bundle verifies"

# ── 2. it actually contains both outcomes, or it proves nothing about DENY ────
A=$(python3 -c "import json;d=json.load(open('$BUNDLE'));print(sum(1 for e in d['entries'] if e['data'].get('decision')=='ALLOW'))")
D=$(python3 -c "import json;d=json.load(open('$BUNDLE'));print(sum(1 for e in d['entries'] if e['data'].get('decision')=='DENY'))")
if [ "$A" -ge 1 ] && [ "$D" -ge 1 ]; then ok "corpus carries a real ALLOW and a real DENY ($A/$D)"
else bad "corpus lacks one outcome (ALLOW=$A DENY=$D) — a DENY claim needs a captured DENY"; fi

# ── 3. TAMPER: flip a decision ───────────────────────────────────────────────
python3 -c "
import json;d=json.load(open('$BUNDLE'))
for e in d['entries']:
    if e['data'].get('decision')=='DENY': e['data']['decision']='ALLOW'; break
json.dump(d,open('$WORK/flip.json','w'))"
expect_fail "$WORK/flip.json" "tamper — a DENY rewritten to ALLOW is rejected"

# ── 4. TAMPER: drop a decision entirely ──────────────────────────────────────
python3 -c "
import json;d=json.load(open('$BUNDLE'))
d['entries']=[d['entries'][0]]+d['entries'][2:]
json.dump(d,open('$WORK/drop.json','w'))"
expect_fail "$WORK/drop.json" "tamper — a removed decision is rejected"

# ── 5. TAMPER: drop a decision AND re-chain, the sophisticated case ──────────
# ⭐ This is the one the manifest exists for. Re-linking hides the gap from the chain check; only the
#    manifest's pinned item list still remembers what was there.
python3 - <<PY
import json,hashlib,sys
sys.path.insert(0,'.')
d=json.load(open('$BUNDLE'))
kept=[e for e in d['entries'][:-1]][1:]          # drop the first decision
man=d['entries'][-1]['data']
def canon(v):
    return json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False)
def h(data,prev):
    return hashlib.sha512((canon(data)+(prev or '')).encode()).hexdigest()
ents=[];prev=None
for e in kept:
    hh=h(e['data'],prev); ents.append({'data':e['data'],'previousHash':prev,'hash':hh}); prev=hh
man['item_count']=len(kept)                      # attacker fixes the count too
mh=h(man,prev); ents.append({'data':man,'previousHash':prev,'hash':mh})
d['entries']=ents; d['root']=mh
json.dump(d,open('$WORK/rechain.json','w'))
PY
expect_fail "$WORK/rechain.json" "tamper — removal + full re-chain + corrected count is STILL rejected"

echo
echo "  $pass passed, $fail failed"
[ "$fail" -eq 0 ] || exit 1
