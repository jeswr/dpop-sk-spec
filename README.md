<!-- AUTHORED-BY Claude Fable 5 -->
# DPoP-SK: Negotiated Symmetric Session Keys for DPoP-Bound Requests

An **unofficial editor's draft** (W3C Solid CG-shaped, no standing) specifying **DPoP-SK** — a
negotiated, optional fast path for Solid-OIDC resource servers that preserves proof-of-possession
while amortizing DPoP's per-request asymmetric signature verification:

1. **Establish once**: the client presents one ordinary RFC 9449 DPoP proof to a session
   establishment endpoint; both sides obtain a 32-byte symmetric session key — derived from TLS
   Exported Keying Material (RFC 8446 §7.5, exporter label `EXPERIMENTAL-dpop-sk-v1`) for native
   clients, or server-generated and TLS-delivered once for browsers.
2. **Attest per request**: an RFC 9421 HTTP Message Signature (`hmac-sha256`, tag `dpop-sk`) over
   `("@method" "@target-uri" "authorization")` plus a counter — no fresh asymmetric operation.
3. **Anti-replay**: an RFC 4303 §3.4.3-style sliding window (verify-then-mark, atomic),
   tolerant of HTTP/2 out-of-order completion.
4. **Never a downgrade**: DPoP remains the mandatory, always-accepted Solid-OIDC baseline; the
   profile is advertised via RFC 9728 Protected Resource Metadata, is invisible without opt-in,
   and a token is never accepted bare.

The spec is [`index.html`](./index.html) (ReSpec; view rendered at
`https://jeswr.github.io/dpop-sk-spec/` once published, or open locally — ReSpec loads from
w3.org). It graduates §4–§6 of the reviewed design proposal
[high-throughput-pop-auth](https://github.com/jeswr/solid-server-rs/blob/main/docs/design/high-throughput-pop-auth.md)
into normative text, with an adversarial review pass recorded in the spec's Appendix B — which
found and fixed one genuine design-basis flaw (the proposal derived the session key from the
RFC 9266 channel-binding value, which RFC 9266 itself forbids using as a secret key; the spec
mints a dedicated exporter label instead).

## Status

- **No implementations exist.** This document deliberately precedes code (the design proposal's
  own graduation condition). The reference implementation is the planned `solid-server-rs`
  Tier-2 work item.
- Not a W3C Solid CG work item; published to solicit review.
- The `https://w3id.org/jeswr/dpop-sk/v1` profile URI needs a w3id redirect (pending).

## Repository contents

| File | What |
|---|---|
| `index.html` | The specification (ReSpec) |
| `DECISIONS.md` | Numbered design decisions + rationale, incl. divergences from the design proposal |
| `tools/compute-examples.mjs` | Generates every computed value in the spec's worked example (`node tools/compute-examples.mjs`; Node ≥ 20, stdlib only; self-checks the `jkt` against RFC 9449 §6.1's published value) |
| `spec.statements.ttl` | Machine-readable normative-statement companion (Turtle sidecar): every normative statement as an anchored `spec:Requirement` with a verbatim quote, RFC 2119 level, conformance-class binding, testability tag and honest test-gap accounting. COMPLEMENTARY — `index.html` remains the sole normative text. Format/shapes/validator: [jeswr/spec-companion](https://github.com/jeswr/spec-companion); validate with `node <spec-companion>/tools/validate.mjs spec.statements.ttl --spec-html index.html` |

## Provenance

Drafted with AI assistance (**Claude Fable 5**, Anthropic), from the cited design proposal and
primary sources (RFC 9449, RFC 9421, RFC 8446/5705/9266, RFC 4303, RFC 9728, RFC 5869,
Solid-OIDC 0.1.0), each verified against the primary text during drafting. Awaiting review by the
human editor (Jesse Wright). See the spec's SOTD.
