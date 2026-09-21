/**
 * ⭐⭐ RFC-3161 TIMESTAMPING — the witness for a config seal. Ruled by Fed 2026-09-13.
 *
 * ⛔⛔ ZERO NPM DEPENDENCIES, DELIBERATELY. Gate 1 was passed by measuring that the verifier runs in
 * a clean room with no `node_modules` and no `package.json`. Adding an ASN.1 library to parse a
 * timestamp token would break the property the gate certifies. So this module shells out to
 * `openssl`, which is a system binary present in that clean room's PATH — **not a Rends dependency,
 * and not something a relying party has to install from us.**
 *
 * ⚠️ `openssl ts -verify` EXITS 0 EVEN WHEN VERIFICATION FAILS. It prints the failure and returns
 * success. So this module parses stdout for the literal `Verification: OK` and never trusts the
 * exit code. Getting that wrong would turn every forged token into a pass.
 *
 * ⭐ WHY RFC-3161 FOR SEALS SPECIFICALLY (axis-1 amendment): a config seal is EPISODIC — one root
 * per capture — so the hardest question in the witness options, *"what does a missed anchor mean"*,
 * largely dissolves. A seal either carries a receipt or it does not, and the verifier says which.
 * There is no continuous history for a gap to hide in. That is not true of the audit chain, which
 * is why the audit chain is on hold.
 */
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

/** Public, free, no registration. DigiCert's TSA is widely trusted by auditors. */
export const DEFAULT_TSA = "http://timestamp.digicert.com";

/** Candidate CA bundles, in order. A relying party on another distro may need to pass their own. */
const CA_CANDIDATES = [
  "/etc/ssl/certs/ca-certificates.crt",
  "/etc/pki/tls/certs/ca-bundle.crt",
  "/etc/ssl/cert.pem",
];

function have(bin) {
  try {
    execFileSync("which", [bin], { stdio: ["ignore", "pipe", "ignore"] });
    return true;
  } catch {
    return false;
  }
}

export function opensslAvailable() {
  return have("openssl");
}

export function findCaBundle() {
  for (const c of CA_CANDIDATES) {
    try {
      readFileSync(c);
      return c;
    } catch {
      /* next */
    }
  }
  return null;
}

function withTempDir(fn) {
  const dir = mkdtempSync(join(tmpdir(), "rfc3161-"));
  try {
    return fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/**
 * ⭐ Request a timestamp token over `rootHex`.
 *
 * ⛔ WHAT LEAVES THIS MACHINE: the SHA-512 of the seal root string, and nothing else. Not the
 * configuration, not the Cedar text, not an account id. A TSA cannot learn what was sealed.
 * ⚠️ It CAN learn that someone timestamped something at that moment — that is inherent to using an
 * external witness and is the point.
 *
 * Returns { ok, token (Buffer), tsa, hashAlgorithm, info } or { ok:false, reason }.
 */
export function requestTimestamp(rootHex, tsaUrl = DEFAULT_TSA, timeoutMs = 30_000) {
  if (!opensslAvailable()) return { ok: false, reason: "openssl not available" };
  return withTempDir((dir) => {
    const dataFile = join(dir, "root.txt");
    const reqFile = join(dir, "req.tsq");
    const respFile = join(dir, "resp.tsr");
    // ⛔ The imprint is over the root STRING exactly as it appears in the bundle — no newline, no
    // JSON wrapper. The verifier reconstructs the same bytes, so any difference here is a silent
    // permanent mismatch.
    writeFileSync(dataFile, rootHex, "utf8");

    try {
      execFileSync("openssl", ["ts", "-query", "-data", dataFile, "-sha512", "-cert", "-no_nonce", "-out", reqFile], {
        stdio: ["ignore", "ignore", "pipe"],
      });
    } catch (err) {
      return { ok: false, reason: `could not build the request: ${String(err).slice(0, 120)}` };
    }

    try {
      execFileSync(
        "curl",
        ["-sS", "--max-time", String(Math.ceil(timeoutMs / 1000)), "-H", "Content-Type: application/timestamp-query",
         "-H", "Accept: application/timestamp-reply", "--data-binary", `@${reqFile}`, "-o", respFile, tsaUrl],
        { stdio: ["ignore", "ignore", "pipe"] },
      );
    } catch (err) {
      return { ok: false, reason: `TSA unreachable: ${String(err).slice(0, 120)}` };
    }

    let text;
    try {
      text = execFileSync("openssl", ["ts", "-reply", "-in", respFile, "-text"], {
        encoding: "utf8",
        stdio: ["ignore", "pipe", "ignore"],
      });
    } catch (err) {
      return { ok: false, reason: `TSA reply is not a parseable timestamp response` };
    }
    if (!/Status:\s*Granted/i.test(text)) {
      return { ok: false, reason: `TSA did not grant: ${(text.match(/Status.*/) ?? ["?"])[0]}` };
    }

    return {
      ok: true,
      token: readFileSync(respFile),
      tsa: tsaUrl,
      hashAlgorithm: "sha512",
      info: {
        asserted_time: (text.match(/Time stamp:\s*(.+)/) ?? [null, null])[1]?.trim() ?? null,
        policy_oid: (text.match(/Policy OID:\s*(.+)/) ?? [null, null])[1]?.trim() ?? null,
        serial: (text.match(/Serial number:\s*(.+)/) ?? [null, null])[1]?.trim() ?? null,
      },
    };
  });
}

/**
 * ⭐⭐ Verify a token against `rootHex`. **OFFLINE** — `openssl ts -verify` performs no network I/O.
 *
 * ⭐ This checks BOTH things that matter in one call: that the TSA's signature is valid and chains
 * to a trusted root, AND that the token's message imprint is the hash of `rootHex`. A token that
 * verifies against different data fails here.
 *
 * Returns { state: "witnessed" | "unwitnessed", reason }.
 * ⛔ ANY doubt resolves to `unwitnessed`. A receipt we cannot check is not a witness, and reporting
 * it as one would be worse than having no receipt at all.
 */
export function verifyTimestamp(rootHex, tokenBuf, caFile = null) {
  if (!opensslAvailable()) {
    return { state: "unwitnessed", reason: "receipt present but openssl is unavailable here, so it could not be checked" };
  }
  const ca = caFile ?? findCaBundle();
  if (!ca) {
    return { state: "unwitnessed", reason: "receipt present but no CA bundle was found to anchor the TSA certificate" };
  }
  return withTempDir((dir) => {
    const dataFile = join(dir, "root.txt");
    const tokFile = join(dir, "token.tsr");
    writeFileSync(dataFile, rootHex, "utf8");
    writeFileSync(tokFile, tokenBuf);

    let out = "";
    try {
      out = execFileSync("openssl", ["ts", "-verify", "-data", dataFile, "-in", tokFile, "-CAfile", ca], {
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
      });
    } catch (err) {
      out = `${err.stdout ?? ""}${err.stderr ?? ""}`;
    }
    // ⛔⛔ PARSE THE OUTPUT, NEVER THE EXIT CODE. `openssl ts -verify` exits 0 on failure.
    if (/Verification:\s*OK/.test(out)) {
      return { state: "witnessed", reason: null };
    }
    const why =
      /message imprint mismatch/i.test(out) ? "the receipt does not commit to this root — it timestamps different bytes"
      : /bad signature|RSA lib/i.test(out) ? "the receipt's signature is invalid"
      : /unable to get local issuer|certificate verify failed|self.signed/i.test(out) ? "the TSA certificate does not chain to a trusted root on this machine"
      : `verification did not report OK: ${out.replace(/\s+/g, " ").slice(0, 140)}`;
    return { state: "unwitnessed", reason: why };
  });
}
