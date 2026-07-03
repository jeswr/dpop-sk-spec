// AUTHORED-BY Claude Fable 5
// Generates every computed value in the DPoP-SK spec's worked example (Appendix A),
// so the example is execution-verified rather than hand-written.
//
//   node tools/compute-examples.mjs
//
// Deterministic: all inputs are fixed constants below. Uses only node:crypto.
// Self-check: the JWK thumbprint (jkt) of the RFC 9449 example public key is
// asserted against the `jkt` value RFC 9449 §6.1 itself publishes.

import { createHash, createHmac, hkdfSync } from "node:crypto";
import { strict as assert } from "node:assert";

const b64u = (buf) => Buffer.from(buf).toString("base64url");
const sha256 = (data) => createHash("sha256").update(data).digest();

// ---------------------------------------------------------------------------
// Fixed example inputs
// ---------------------------------------------------------------------------

// Illustrative DPoP-bound access token (opaque to this profile; only its ASCII
// bytes matter, via ath). Not a verifiable JWT — establishment examples elide
// the issuer side.
const accessToken =
  "eyJhbGciOiJFUzI1NiIsInR5cCI6ImF0K2p3dCJ9.eyJpc3MiOiJodHRwczovL2lkcC5leGFt" +
  "cGxlIiwic3ViIjoiaHR0cHM6Ly9pZC5leGFtcGxlL2FsaWNlI21lIn0.EXAMPLE-AS-SIGNATURE";

// The P-256 public key used throughout RFC 9449's own examples (§4.1).
const dpopJwk = {
  crv: "P-256",
  kty: "EC",
  x: "l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs",
  y: "9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA",
};

// The jkt RFC 9449 §6.1 publishes for that key — used as a self-check.
const RFC9449_JKT = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I";

// Fixed 128-bit session id (base64url of bytes 00..0f) — clearly example-only.
const sessionId = b64u(Buffer.from("000102030405060708090a0b0c0d0e0f", "hex"));

// cb=none flavour: the server-generated 32-byte session key (bytes 10..2f).
const kNone = Buffer.from(
  "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
  "hex",
);

// cb=tls-exporter flavour: an EXAMPLE 32-byte EKM. In reality this comes from
// the TLS stack: TLS-Exporter("EXPERIMENTAL-dpop-sk-v1", "", 32) per RFC 8446 §7.5.
const ekm = Buffer.from(
  "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
  "hex",
);

// ---------------------------------------------------------------------------
// Derived values
// ---------------------------------------------------------------------------

// ath — RFC 9449 §4.2: base64url(SHA-256(ASCII(access token))).
const ath = b64u(sha256(Buffer.from(accessToken, "ascii")));

// jkt — RFC 7638 JWK SHA-256 thumbprint: SHA-256 over the JSON object with
// REQUIRED members only, lexicographically ordered, no whitespace.
const thumbprintInput = JSON.stringify({
  crv: dpopJwk.crv,
  kty: dpopJwk.kty,
  x: dpopJwk.x,
  y: dpopJwk.y,
});
const jkt = b64u(sha256(Buffer.from(thumbprintInput, "utf8")));
assert.equal(jkt, RFC9449_JKT, "jkt must match the RFC 9449 §6.1 example value");

// K (tls-exporter flavour) — HKDF-SHA256 per the spec §6:
//   PRK = HKDF-Extract(salt = ASCII(session_id), IKM = EKM)
//   K   = HKDF-Expand(PRK, info = "dpop-sk/v1" || 0x00 || ASCII(ath) || 0x00 || ASCII(jkt), 32)
const info = Buffer.concat([
  Buffer.from("dpop-sk/v1", "ascii"),
  Buffer.from([0]),
  Buffer.from(ath, "ascii"),
  Buffer.from([0]),
  Buffer.from(jkt, "ascii"),
]);
const kExporter = Buffer.from(
  hkdfSync("sha256", ekm, Buffer.from(sessionId, "ascii"), info, 32),
);

// Key-confirmation value (tls-exporter flavour):
//   confirm = base64url(HMAC-SHA256(K, "dpop-sk/v1 confirm" || 0x00 || ASCII(session_id)))
const confirm = b64u(
  createHmac("sha256", kExporter)
    .update(Buffer.from("dpop-sk/v1 confirm", "ascii"))
    .update(Buffer.from([0]))
    .update(Buffer.from(sessionId, "ascii"))
    .digest(),
);

// ---------------------------------------------------------------------------
// Per-request attestation (cb=none flavour, key kNone) — RFC 9421
// ---------------------------------------------------------------------------

const created = 1720000000;
const nonce = "1";
const method = "GET";
const targetUri = "https://pod.example/alice/private/doc";
const authorization = `DPoP ${accessToken}`;

// The inner-list serialization, exactly as it appears in Signature-Input.
const sigParams =
  `("@method" "@target-uri" "authorization")` +
  `;created=${created};keyid="${sessionId}";alg="hmac-sha256";nonce="${nonce}";tag="dpop-sk"`;

// Signature base per RFC 9421 §2.5 (LF-separated; params line last, no trailing LF).
const signatureBase = [
  `"@method": ${method}`,
  `"@target-uri": ${targetUri}`,
  `"authorization": ${authorization}`,
  `"@signature-params": ${sigParams}`,
].join("\n");

// hmac-sha256 per RFC 9421 §3.3.3; Signature field value is an RFC 8941 Byte
// Sequence, i.e. standard base64 between colons.
const signature = createHmac("sha256", kNone)
  .update(Buffer.from(signatureBase, "ascii"))
  .digest()
  .toString("base64");

// ---------------------------------------------------------------------------
// Drift guard: every computed value published in index.html (Appendix A) is
// asserted here, so editing an input without updating the spec (or vice
// versa) makes this script exit non-zero instead of silently diverging.
// ---------------------------------------------------------------------------

const PUBLISHED = {
  ath: "WKXpcs5xM2Dyko2M0gv0NC8vjApybvIBdn17lZ7izG0",
  jkt: RFC9449_JKT,
  sessionId: "AAECAwQFBgcICQoLDA0ODw",
  keyNone: "EBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8",
  ekmExample: "QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl8",
  kExporter: "B2D8_PhuOLMzvM9-ND2aVCXoz8ADWeTfhqiZV3yUvD4",
  confirm: "gvocwuudE9yiXXU5jINFTekorDybyEj_tQWPljW8eRA",
  signature: "hPkuPd32xbb4hUjR/hjbj0Cp445ZfWoOgrcq8+f3I3g=",
};
assert.equal(ath, PUBLISHED.ath, "ath drifted from the published example");
assert.equal(sessionId, PUBLISHED.sessionId, "session_id drifted");
assert.equal(b64u(kNone), PUBLISHED.keyNone, "cb=none key drifted");
assert.equal(b64u(ekm), PUBLISHED.ekmExample, "example EKM drifted");
assert.equal(b64u(kExporter), PUBLISHED.kExporter, "derived K drifted");
assert.equal(confirm, PUBLISHED.confirm, "confirm value drifted");
assert.equal(signature, PUBLISHED.signature, "HMAC signature drifted");

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

const out = {
  accessToken,
  ath,
  jkt,
  sessionId,
  cbNone: { key: b64u(kNone) },
  cbTlsExporter: {
    exporterLabel: "EXPERIMENTAL-dpop-sk-v1",
    exporterContext: "(zero-length)",
    ekmExample: b64u(ekm),
    hkdfSaltAscii: sessionId,
    hkdfInfoHex: info.toString("hex"),
    K: b64u(kExporter),
    confirm,
  },
  request: {
    method,
    targetUri,
    signatureInput: `sig=${sigParams}`,
    signatureBase,
    signature: `sig=:${signature}:`,
  },
};

console.log(JSON.stringify(out, null, 2));
