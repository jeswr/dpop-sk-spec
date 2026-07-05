<!-- AUTHORED-BY Claude Fable 5 -->

# LWS alignment — how DPoP-SK binds to a JLWS realm

**Substrate:** [JLWS — Linked Web Storage, clean-slate editor's draft](https://github.com/jeswr/lws-spec)
(`index.html`). The composition design this document lands is the sibling half of
`lws-spec/docs/alignment/dpop-sk.md` (JLWS DECISIONS.md D21); the spec edit itself is the
*Relationship to Linked Web Storage (JLWS)* subsection of this profile's Relationship
section.

## Verdict: an auth-layer PoP presentation profile, negotiated via RFC 9728

DPoP-SK is a **token-presentation** profile: it changes how an already-issued,
already-DPoP-bound access token is presented (one DPoP proof establishes a session key;
each request then carries an RFC 9421 `hmac-sha256` attestation — `#overview`,
`#attestation`). JLWS names it as the second of its two negotiated PoP profiles:

- JLWS core, *Proof-of-possession profiles*: "**DPoP-SK** — the negotiated symmetric fast
  path: one DPoP proof establishes a short-lived session key; each request carries an
  RFC 9421 `hmac-sha256` message signature with sliding-window replay protection. Its
  negotiation is already RFC 9728-based and composes here without change."
- JLWS core, *Authorization server discovery*: when a PoP presentation profile is offered,
  "the DPoP-SK members defined by [DPOP-SK]" appear in the protected resource metadata,
  beside JLWS's `jlws_storage_description` extension member.

It is **not** a storage-description capability: PoP profiles are a property of the realm's
auth surface, discovered where the rest of that surface is discovered — the RFC 9728 PRM
(this profile's `#discovery` defines the `pop_session` member for exactly this).

## The PRM contract on a JLWS realm

| PRM member | Meaning on the realm |
|---|---|
| `dpop_bound_access_tokens_required: true` | PoP required (Bearer refused) — covers DPoP **and** DPoP-SK |
| `dpop_signing_alg_values_supported` | DPoP offered (RFC 9449) |
| `pop_session {endpoint, algs, channel_bindings, profile}` | DPoP-SK offered (this profile, `#discovery`) |
| `jlws_storage_description` | JLWS storage description URI (JLWS core, *Authorization server discovery*) |

No separate DPoP-SK required-member exists or is needed: a DPoP-SK session is established
**from** a DPoP-bound access token (one full RFC 9449 proof at establishment,
`#establishment`), so RFC 9728's registered `dpop_bound_access_tokens_required` already
governs it; DPoP-SK *availability* is signalled by `pop_session`'s presence (this
profile's own PRM example carries both members together). The JLWS core's
*Proof-of-possession profiles* section states the same rule from its side.

## The session-key attestation over the LWS resource audience

The token a DPoP-SK session presents on a JLWS realm is the realm-audienced access token
JLWS obtains by RFC 8693 token exchange (JLWS core, *Token exchange*): its **single**
`aud` value equals the 401 challenge's `realm`, and the storage server accepts it only for
target resources that audience **logically contains** — same origin, ancestor path on
complete `/`-delimited segment boundaries (JLWS core, *Validation by the storage server*,
step 3). Composition consequences:

- A DPoP-SK session's usable scope is exactly the resources of **one JLWS realm** — the
  session key attests possession for requests inside the token's audience; requests
  outside it fail token validation regardless of the attestation.
- The attestation's covered components (`#attestation`) bind method + target URI per
  request, so a valid attestation for one resource cannot be replayed against another —
  complementing (not replacing) the audience-containment check.
- Within its lifetime the session inherits the token's temporal bounds: JLWS access
  tokens are short-lived (the exchange chain's design point is ≤300 s — JLWS DECISIONS.md
  S1), and this profile's session lifetime and `ath` binding (`#lifetime`,
  `#attestation-verification`) mean a rotated token requires re-establishment.

## Scoping against JLWS's Bearer baseline

JLWS's baseline presentation is **Bearer** (JLWS core, *Token presentation*; its
DECISIONS.md D9/S2 — the deliberate no-DPoP baseline), unlike Solid-OIDC. This profile's
never-bare rule is a property of **DPoP-bound tokens**: the tokens this profile operates on
always carry `cnf`, and a JLWS server already refuses any `cnf`-bound token presented bare
(JLWS core, *Validation by the storage server*, step 5: "when the token is PoP-bound
(`cnf` present), the corresponding proof MUST be validated per the profile in use, and the
token MUST NOT be accepted bare"). Bearer tokens without `cnf` on a Bearer-baseline realm
are outside this profile's scope — for a non-opting client, a JLWS server is observed
unchanged, exactly as this profile already promises for Solid servers.

No normative change to establishment, key derivation, attestation, anti-replay, lifetime,
or downgrade rules (`#establishment` … `#downgrade`) results from the composition: they
transfer verbatim.

## Conformance vectors (homing)

Per the homing rule of `lws-spec/docs/alignment/conformance-vectors.md` (server/AS surface
→ `lws-spec/test-vectors/`; pure agent-layer functions → `agentic-solid-conformance`), the
DPoP-SK×JLWS vectors are **server-surface** and home in
`lws-spec/test-vectors/vectors/dpop-sk/`: PRM shape (3 cases: `pop_session` +
`jlws_storage_description` coexistence, unknown-profile fail-closed, PoP-required
single-member), establishment with `channel_bindings: none` (deterministic HKDF from
committed TEST-ONLY material), and attestation accept / bad-signature / replay / expired
(8 cases, specified in `lws-spec/docs/alignment/dpop-sk.md` §3). The `tls-exporter`
flavour remains un-vectorable (it needs a live TLS exporter interface) and stays in that
suite's GAPS.md.
