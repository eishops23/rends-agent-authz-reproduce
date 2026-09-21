/**
 * Hash-chain primitives — a VERBATIM PORT of `agentcompliant:shared/src/audit/hash-chain.ts`.
 *
 * SHA-512 over `canonicalJSON(data) + previousHash`. Same algorithm, same digest, same linkage
 * rules, so a seal produced here is checkable by the product's own `verifyChain` and vice versa.
 * ⛔ Pinned by `__tests__/canonical-json-parity.test.mjs` — see the note in `canonical-json.mjs`.
 *
 * ⭐ Nothing in this file touches the network, a database, the filesystem or the environment.
 * That is the axis-3 property the brief asks for, and it is why the verifier can be run by someone
 * who has never heard of Rends.
 */
import { createHash } from "node:crypto";

import { canonicalJSON } from "./canonical-json.mjs";

export { canonicalJSON };

/** SHA-512 of canonicalJSON(data) concatenated with previousHash ("" when null). */
export function computeHash(data, previousHash) {
  const serialized = canonicalJSON(data);
  const prev = previousHash ?? "";
  return createHash("sha512").update(`${serialized}${prev}`, "utf8").digest("hex");
}

/**
 * Validate that each entry's `hash` matches computeHash(data, previousHash), and that
 * `previousHash` matches the prior entry's `hash` (genesis uses null).
 * Returns { valid, brokenAt?, reason? }.
 */
export function verifyChain(entries) {
  if (!Array.isArray(entries)) return { valid: false, brokenAt: 0, reason: "entries is not an array" };
  if (entries.length === 0) return { valid: true };

  for (let i = 0; i < entries.length; i += 1) {
    const entry = entries[i];
    if (!entry) return { valid: false, brokenAt: i, reason: "entry is missing" };

    const expected = computeHash(entry.data, entry.previousHash);
    if (expected !== entry.hash) {
      return { valid: false, brokenAt: i, reason: "hash does not match the recomputed hash of its own data" };
    }
    if (i > 0) {
      const prev = entries[i - 1];
      if (!prev || entry.previousHash !== prev.hash) {
        return { valid: false, brokenAt: i, reason: "previousHash does not point at the preceding entry" };
      }
    } else if (entry.previousHash !== null) {
      return { valid: false, brokenAt: i, reason: "the first entry must have previousHash null" };
    }
  }
  return { valid: true };
}
