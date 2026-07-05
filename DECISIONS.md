<!-- AUTHORED-BY Claude Fable 5 -->
# DECISIONS — dpop-sk-spec

Numbered, durable design decisions for the DPoP-SK profile draft. The design basis is
[`solid-server-rs/docs/design/high-throughput-pop-auth.md`](https://github.com/jeswr/solid-server-rs/blob/main/docs/design/high-throughput-pop-auth.md)
(§4 establishment/attestation/lifetime, §5 security analysis, §6 negotiation); divergences from
it are marked **[DIVERGENCE]** and cross-referenced from the spec's Appendix C.

## D1. [DIVERGENCE] Dedicated exporter label, not the RFC 9266 channel-binding value

The design proposal derived the session key from
`EKM = export_keying_material(32, "EXPORTER-Channel-Binding", ∅)` per RFC 9266. Verifying
RFC 9266 against the primary text during drafting showed this is **nonconforming**: RFC 9266's
Security Considerations say "The derived data MUST NOT be used for any purpose other than channel
bindings as described in [RFC5056]. In particular, implementations MUST NOT use channel binding
as a secret key to protect privileged information", the registry entry marks the value
"Channel-binding is secret: no", and applications "MUST NOT use the channel binding for more than
one authentication mechanism instance on a given TLS connection". Using that value as HKDF IKM is
exactly the forbidden secret-key use.

**Decision:** mint a dedicated label `EXPERIMENTAL-dpop-sk-v1`. RFC 5705 §4: labels beginning
"EXPERIMENTAL" MAY be used for private use without registration (all others require
Specification Required registration). On standards adoption, a registered `EXPORTER-`-prefixed
label replaces it as a versioned breaking change. This was the adversarial pass's one genuine
finding against the design basis (spec Appendix B, A14) and should be fed back to
`high-throughput-pop-auth.md` §4.1.

## D2. [DIVERGENCE] TLS 1.3 REQUIRED for the `tls-exporter` flavour

Exporter constructions below TLS 1.3 are only sound with unique master secrets — extended master
secret (RFC 7627) and no renegotiation (RFC 9266 §§1,4). Rather than import those preconditions,
the flavour requires TLS 1.3 outright (rustls/modern stacks make this a non-restriction for the
native/service clients the flavour targets). `cb=none` has no TLS-version constraint beyond the
server's normal policy.

## D3. Exporter context zero-length; uniqueness bound in HKDF

RFC 8446 §7.5: "New uses of exporters SHOULD provide a context in all exporter computations,
though the value could be empty." We provide an explicit zero-length context and bind
per-session uniqueness in HKDF instead: salt = ASCII(session_id), info =
`"dpop-sk/v1" || 0x00 || ASCII(ath) || 0x00 || ASCII(jkt)`. Rationale: one derivation formula
regardless of TLS library context-handling quirks; the 0x00 separator is injective because
base64url excludes NUL; the version string in `info` domain-separates future profile versions.

## D4. [DIVERGENCE] Establishment `cb` is an exact requirement, not a capability offer

The design's request member was a client capability ("cb": what the client can do), leaving the
server free to answer with less. That is a downgrade surface (spec Appendix B, A6). Decision: the
client states the flavour it REQUIRES; the server honours it exactly or refuses with 400; the
client MUST discard a session whose response `cb` differs. A client willing to accept either
flavour simply retries with `cb=none` by its own explicit policy.

## D5. [DIVERGENCE] `confirm` key-confirmation member (tls-exporter responses)

Added so a derivation mismatch (buggy stack, unexpected intermediary) is detected before any
attested request, as a clean abort instead of a confusing 401-and-retry loop (Appendix B, A22).
`confirm = base64url(HMAC-SHA256(K, "dpop-sk/v1 confirm" || 0x00 || ASCII(session_id)))` — a
fixed-message HMAC discloses nothing useful about K.

## D6. Keep the `Authorization: DPoP <token>` scheme, replace only the proof

Inside a session, attested requests present the token under the unchanged `DPoP` scheme with no
`DPoP` proof header. Deliberate deviation from RFC 9449 §7.1 mechanics, chosen over minting a new
auth scheme because: (a) the token's `cnf` semantics are unchanged; (b) a non-implementing server
rejects the proof-less request with its normal DPoP challenge, which is precisely the fallback
signal the client needs; (c) no new scheme registration.

## D7. Signature parameters and covered components

Minimum covered set `("@method" "@target-uri" "authorization")` — target binding server-derived
(stronger than DPoP's client-asserted htm/htu), token bound into the base. REQUIRED params:
`created`, `keyid` (session id), `nonce` (decimal counter in RFC 9421's String-typed nonce
param), `tag="dpop-sk"`. `alg` OPTIONAL because the session fixes the algorithm; the verifier
uses the session's algorithm unconditionally (RFC 9421 §7.3.4 mixup guidance) and rejects a
mismatching `alg`. `content-digest` coverage is MAY, not MUST: within the threat model a body
swap requires K anyway (Appendix B, A11), and mandating RFC 9530 everywhere would tax the hot
path this profile exists to lighten.

## D8. Counter in `nonce`, window ≥128 / RECOMMENDED 1024

RFC 9421 has no integer-typed replay parameter; the String `nonce` carries the decimal counter
(64-bit bound, parse-time rejection of oversized values). Window floor raised from RFC 4303's
32/64 (sized for IPsec) to 128 minimum / 1024 recommended, sized for HTTP/2 concurrent-stream
out-of-order completion. Verify-then-mark ordering adopted verbatim from RFC 4303 §3.4.3 ("the
receive window is updated only if the integrity verification succeeds"); atomicity of
verify+mark is normative.

## D9. Lifetime cap and revocation story

`expires_in` MUST ≤ remaining token lifetime, SHOULD ≤ 300 s — the same revocation-propagation
window the reference server's verified-token cache uses; re-establishment re-runs the full
verifier, so issuer-side revocation propagates within one window. No in-place rekey in v1:
rotation = re-establishment (one DPoP round), keeping the state machine two-state.

## D10. Failure signalling is the generic DPoP challenge

All per-request failures yield 401 + the standard `WWW-Authenticate: DPoP` challenge, optionally
with RFC 9728 `resource_metadata`. No DPoP-SK-specific error code: avoids minting into the
IANA-controlled OAuth error registry, keeps the failure path identical to plain DPoP, and
withholds oracle detail (Appendix B, A18).

## D11. Metadata member `pop_session`; profile URI `w3id.org/jeswr/dpop-sk/v1` [DIVERGENCE in URI]

Member name kept from the design (§6) so the eventual three-part umbrella ("PoP negotiation":
RFC 9728 metadata + RFC 8705 profile + DPoP-SK) can share one member. The profile URI names THIS
spec (`dpop-sk/v1`) rather than the design's sketched `pop-session/v1`, since this document
stands alone as the DPoP-SK part. w3id redirect = pending (needs:user class).

## D12. ReSpec `CG-DRAFT`-shaped, unofficial, AI disclosure

Follows the `solid-webauthn-reauth-spec` precedent exactly: `specStatus: "CG-DRAFT"` +
`group: "cg/solid"` for CG styling, with an SOTD stating no standing whatsoever, plus the
drafting disclosure naming Claude Fable 5 and the awaiting-human-editor-review status.

## D13. Worked example is execution-verified

`tools/compute-examples.mjs` (Node stdlib only) generates every computed value (ath, jkt, HKDF
outputs, confirm, signature base, HMAC) and asserts the computed `jkt` of the RFC 9449 example
key equals the value RFC 9449 §6.1 itself publishes (`0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I`)
— a cross-check that the thumbprint code path matches the primary source. The establishment DPoP
proof's ES256 signature is elided (any §4.3-valid proof; ECDSA is randomized so a baked example
signature would not be reproducible).

## D14. No package.json / no build

The repo is a spec + one stdlib script: no dependencies, no lockfile, no dist, nothing for
`ignore-scripts` to guard (an `.npmrc` is present anyway, defensively). Gates: roborev on every
commit; `node tools/compute-examples.mjs` must exit 0 (the assert is the test).

## D15. LWS alignment: auth-layer profile on a JLWS realm, RFC 9728-negotiated; no new members

Alignment with the JLWS clean-slate Linked Web Storage draft (`jeswr/lws-spec`; its
DECISIONS.md D21 / `docs/alignment/dpop-sk.md` is the composition design). JLWS names
DPoP-SK as the second of its two negotiated PoP presentation profiles and discovers its
auth surface through the same RFC 9728 protected resource metadata this profile negotiates
through, so the composition costs **zero new mechanism**: `pop_session` sits beside JLWS's
`jlws_storage_description` in the realm's PRM, and the attested token is the
realm-audienced single-`aud` token of JLWS's RFC 8693 exchange (attestation scope =
audience containment ∘ per-request `@method`/`@target-uri` binding). The spec gains an
informative *Relationship to Linked Web Storage (JLWS)* subsection with two scoping notes:
(a) the never-bare rule is a property of `cnf`-bound tokens — JLWS's Bearer baseline (its
D9/S2) is out of this profile's scope and unweakened by it; (b) a PoP-required JLWS realm
signals with RFC 9728's registered `dpop_bound_access_tokens_required: true`, which covers
DPoP-SK too because every session is established from a DPoP-bound token — this profile
deliberately mints **no separate required-member** (the JLWS-side alignment fixed a JLWS
sentence that assumed one existed). Detail + vector homing in `docs/lws-alignment.md`; the
8 DPoP-SK×JLWS server-surface vectors home in `lws-spec/test-vectors/vectors/dpop-sk/`
(only the `channel_bindings: none` flavour is deterministic; `tls-exporter` stays in that
suite's GAPS.md). **Rejected:** a `pop_session.required` member (redundant with the
registered RFC 9728 member; two switches for one property invites disagreement).
