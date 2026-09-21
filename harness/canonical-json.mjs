/**
 * JCS-style canonical JSON — a VERBATIM PORT of
 * `agentcompliant:shared/src/audit/canonical-json.ts` with the TypeScript annotations removed.
 *
 * ⛔ WHY A COPY AND NOT AN IMPORT. This repo ships PUBLIC (R2) and must run standalone — `node`,
 * no build step, no dependency on a private repo. Importing the original would make the public
 * reproduction unrunnable for anyone outside this machine, which is the whole point of D2.
 *
 * ⛔⛔ AND A COPY DRIFTS. That is not a hypothetical: the product's own comment records that the
 * `created_at::text` export defect was a CANONICALIZATION mismatch, not a digest one. So this file
 * is pinned by `__tests__/canonical-json-parity.test.mjs`, which runs BOTH implementations over the
 * same probes and asserts byte-identical output. ⭐ If you edit this file, run that test.
 *
 * Keys sorted recursively, undefined/function/symbol members dropped, arrays preserved in order.
 */
export function canonicalJSON(value) {
  if (value === null) return "null";
  const t = typeof value;
  if (t === "string") return JSON.stringify(value);
  if (t === "number") {
    if (!Number.isFinite(value)) return "null";
    return JSON.stringify(value);
  }
  if (t === "boolean") return value ? "true" : "false";
  if (t === "undefined" || t === "function" || t === "symbol") return "null";
  if (t === "bigint") return value.toString();

  if (value instanceof Date) return JSON.stringify(value.toISOString());

  if (Array.isArray(value)) {
    const parts = value.map((v) => {
      if (v === undefined || typeof v === "function" || typeof v === "symbol") return "null";
      return canonicalJSON(v);
    });
    return `[${parts.join(",")}]`;
  }

  if (t === "object") {
    const obj = value;
    const keys = Object.keys(obj)
      .filter((k) => {
        const v = obj[k];
        return v !== undefined && typeof v !== "function" && typeof v !== "symbol";
      })
      .sort();
    const parts = keys.map((k) => `${JSON.stringify(k)}:${canonicalJSON(obj[k])}`);
    return `{${parts.join(",")}}`;
  }

  return "null";
}
