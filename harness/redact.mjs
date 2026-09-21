// Redaction, per the 2026-09-13 ruling: redacted artifacts in the public tree,
// raw unredacted captures outside it (/home/ubuntu/agent-authz-raw/).
//
// ⛔ WHAT IS REDACTED AND WHY. This repo ships PUBLIC (R2). The scenarios use
// fixture accounts and a fixture human, so the ARGUMENTS are safe to publish and
// MUST be — axis 5 is "exact arguments as evaluated", and redacting them would
// destroy the artifact. What is redacted is infrastructure identity: account
// ids, bearer tokens, key prefixes, internal host names, AWS account numbers.
//
// ⚠️ Redaction is STRUCTURED, not a regex sweep over prose: each rule names what
// it replaces and leaves a typed placeholder, so a reader can see that a value
// was present and what kind it was. A silently-deleted field would make the
// published artifact weaker evidence than the raw one in a way nobody could see.

const RULES = [
  [/\bac_live_[A-Za-z0-9_-]{4,}/g, "<RENDS_API_KEY>"],
  [/\bAKIA[0-9A-Z]{16}\b/g, "<AWS_ACCESS_KEY_ID>"],
  [/\b168866076232\b/g, "<AWS_ACCOUNT_ID>"],
  [/\bBearer\s+[A-Za-z0-9._~+/-]+=*/g, "Bearer <TOKEN>"],
  [/\binstance-\d{8}-\d{4}\b/g, "<HOST>"],
  [/\b\d{1,3}(?:\.\d{1,3}){3}\b/g, "<IP>"],
];

/** Redact a string. Returns { text, hits } so a caller can assert redaction happened. */
export function redact(text) {
  let out = String(text);
  const hits = {};
  for (const [re, repl] of RULES) {
    const m = out.match(re);
    if (m) hits[repl] = (hits[repl] ?? 0) + m.length;
    out = out.replace(re, repl);
  }
  return { text: out, hits };
}

/** ⛔ POSITIVE CONTROL for the caller: prove the redactor can actually see a secret shape. */
export function redactorSelfTest() {
  // ⛔ EVERY VALUE HERE IS SYNTHETIC EXCEPT THE ACCOUNT ID, WHICH IS RULED PUBLISHABLE.
  // Until 2026-09-21 this probe used the REAL host name. It matched the rule's shape and therefore
  // tested nothing the synthetic one does not, while putting our hostname in a file destined for a
  // public mirror. A fixture that leaks is not a fixture — and the first draft of THIS comment
  // named the old value, which is the same mistake one line further down.
  const probe = "key=ac_live_ABCDEFGH acct=168866076232 host=instance-19990101-0000";
  const { text, hits } = redact(probe);
  const ok = !text.includes("ac_live_ABCDEFGH") && !text.includes("168866076232") && Object.keys(hits).length === 3;
  return { ok, text, hits };
}
