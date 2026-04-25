# Verifier public-key sourcing

## Overview

To validate an SD-JWT-VC, the verifier needs the issuer's signing public key. Several mechanisms coexist for the verifier to obtain that key, each with different operational properties. This document describes the main approaches neutrally.

What the JWT carries differs across approaches:

- sometimes only **identifiers** that the verifier resolves out-of-band: `iss` (payload) plus `kid` (header) for JWKS lookup in Approach 1, or `iss` and/or a `kid` carrying a DID URL in Approach 4;
- sometimes the **certificate material itself**: embedded in the header (Approach 2, `x5c`) or referenced by a URL in the header (Approach 3, `x5u`), from which the public key is extracted.

In every case, the **trust anchor** — root certificate, trust-list entry, DID controller policy, or accepted `iss` URL prefix — lives outside the JWT and must be configured by the verifier in advance.

Two distinct concerns are at play and should not be conflated:

- **Key discovery** — turning the header information into a candidate public key.
- **Trust validation** — deciding whether that candidate key is authoritative for the issuer.

This document focuses on the discovery mechanics. The trust side (anchor sources, profile policies, threat assumptions) is profile- and deployment-specific and is referenced only where it directly shapes what the verifier must implement.

The verifier's job, in each case, is:

1. Interpret the relevant header values (and sometimes a claim in the payload).
2. Fetch, look up, or extract the candidate public key.
3. Verify that the key is trusted (i.e. traceable to a trust anchor the verifier has configured).
4. Use the key to validate the JWT signature.

Conceptually, every approach below maps to the same chain:

```
JWT header values → resolution / extraction → candidate key → trust-anchor check → signature verification
```

What differs between approaches is the *resolution / extraction* step and the shape of the *trust-anchor check*.

## Approach 1 — JWKS via issuer URL

The JWT identifies its issuer through the `iss` claim. RFC 7519 defines `iss` as a `StringOrURI` identifier; SD-JWT-VC narrows this convention to a resolvable HTTPS URL controlled by the issuer, from which a public-keyset can be fetched.

```json
{
  "alg": "ES256",
  "typ": "vc+sd-jwt",
  "kid": "issuer-key-2026-01"
}
```

**What the issuer must expose**

- The `iss` claim in the JWT payload, matching a URL the issuer controls.
- A JWKS document published at a well-known path derived from `iss`, per the URL resolution rules in the current SD-JWT-VC draft (section "JWT VC Issuer Metadata"). The JWKS lists active signing keys with a `kid` for each.
- Previously active signing keys need to remain published in the JWKS as long as any non-expired credentials were signed with them; otherwise their signatures become unverifiable.
- Optional: an HTTP `Cache-Control` header, and a key-rotation policy consistent with the caching window.

**What the verifier needs to implement**

- Trust-anchor list: the set of `iss` URL prefixes the verifier is willing to honor.
- HTTP client fetching the well-known JWKS endpoint and parsing the JWKS document.
- JWK selection by `kid` header, or by `alg` + iteration if `kid` is absent.
- Signature verification against the selected JWK.

**Operational notes**

- Requires network access at verification time unless the JWKS is cached.
- The verifier may cache the JWKS with a TTL; the cache should expect multiple keys to coexist during rotation windows.
- CORS restrictions apply if verification runs client-side in a browser.

## Approach 2 — X.509 certificate chain embedded in the header (`x5c`)

The issuer embeds the full X.509 certificate chain inside the JWT header. The verifier validates the chain up to a configured trust anchor.

```json
{
  "alg": "ES256",
  "typ": "vc+sd-jwt",
  "x5c": ["MIIB...leaf", "MIIB...intermediate"]
}
```

**What the issuer must expose**

- An `x5c` array in the JWT header containing the issuer's leaf certificate first, then each intermediate, in chain order.
- Optionally `x5t` / `x5t#S256` header fingerprints.
- Out-of-band distribution of the issuer's root or intermediate certificate(s), e.g. via a trust list, a governmental or federation registry, or direct configuration, so verifiers can provision trust anchors.

**What the verifier needs to implement**

- Trust-anchor store: root and intermediate certificates the verifier considers authoritative.
- Chain validation, applied to each certificate in the chain: signature against the parent, validity period, Extended Key Usage constraints, basic constraints, path-length constraints.
- Revocation checking for each certificate in the chain (CRL distribution point or OCSP), not just the leaf. The configured trust anchor itself follows its own out-of-band lifecycle.
- Public key extraction from the leaf certificate after chain validation passes.

**Operational notes**

- The signing material travels with every token — no fetch needed for the keys themselves — but revocation lookups (CRL or OCSP) typically still require network access at verification time, with stapling or caching as latency mitigations.
- Larger JWTs compared to identifier-based approaches (the certificates travel with every token, instead of just an identifier or URL).
- New credentials are signed under whichever certificate chain is current at issuance; previously issued credentials remain valid under their original chain until they expire or are revoked. Mass re-issuance is only required if a private key is compromised — which forces re-issuance regardless of the sourcing scheme.

## Approach 3 — X.509 certificate by reference (`x5u`)

Instead of embedding the chain, the JWT header carries a URL pointing to a PEM-encoded certificate (or chain) hosted by the issuer. The verifier fetches the certificate at that URL and proceeds as in Approach 2 for chain validation. Optionally, an `x5t#S256` header pins the leaf certificate to a specific SHA-256 thumbprint, so the verifier can detect substitution at the URL.

`x5u` and `x5t#S256` are standard JOSE headers from RFC 7515 (§4.1.5 and §4.1.8 respectively).

```json
{
  "alg": "ES256",
  "typ": "vc+sd-jwt",
  "x5u": "https://issuer.example.com/certs/issuer-2026.pem",
  "x5t#S256": "Xr8k9m...base64url(SHA-256 of leaf cert DER)..."
}
```

**What the issuer must expose**

- An `x5u` header in the JWT, an HTTPS URL pointing to the PEM-encoded certificate or chain. Per RFC 7515 §4.1.5, the leaf certificate (whose key signs the JWS) MUST be the first certificate in the concatenation.
- The endpoint MUST be served over TLS, with a server identity that the verifier can validate (RFC 7515 §4.1.5 references RFC 6125 for the identity check).
- A stable, cacheable URL; it should remain valid for as long as credentials signed by that key are in circulation.
- Optionally `x5t#S256` (base64url-encoded SHA-256 of the leaf certificate DER) in the header, allowing the verifier to pin the fetched certificate to a specific thumbprint.
- Out-of-band trust anchor distribution, as in Approach 2.

**What the verifier needs to implement**

- HTTPS fetch of the `x5u` URL with TLS server-identity validation (RFC 6125), and parsing of the PEM-encoded certificate or chain.
- If `x5t#S256` is present: SHA-256 over the DER form of the fetched leaf certificate, compared to the header value; reject on mismatch.
- Chain validation, including revocation checking for each certificate in the chain, as in Approach 2.
- Public key extraction from the validated leaf certificate.

**Operational notes**

- Smaller JWTs than `x5c` (only the URL travels with the token), at the cost of an HTTPS dependency at verification time.
- The hosted certificate should be cacheable so verifiers can apply HTTP cache semantics. `x5t#S256`, when present, is an orthogonal integrity check: it allows the verifier to detect substitution at the URL but does not replace caching.
- Trust does not flow from the URL itself: serving HTTPS does not make the certificate authoritative. The trust anchor check is the same as for `x5c`.

> **Note on a related but distinct mechanism.** OID4VP §5.9.3 (referenced by HAIP §5.2.3) defines a `client_id_prefix: x509_hash` Client Identifier Prefix in the signed *authorization request* (JAR) layer. That mechanism authenticates the *verifier* to the *wallet* in the presentation protocol, not the *issuer* of an SD-JWT-VC to a *verifier*. It is a different layer of the protocol stack and is out of scope for this document on issuer key sourcing.

## Approach 4 — DID resolution

The issuer identifies itself through a Decentralized Identifier (`did:*`). The verifier resolves the DID to a DID Document, extracts the verification method corresponding to the JWT's `kid`, and uses the embedded public key.

```json
{
  "alg": "ES256",
  "typ": "vc+sd-jwt",
  "kid": "did:web:issuer.example.com#key-2026-01"
}
```

**What the issuer must expose**

- An `iss` claim containing a DID, or a `kid` header that is itself a DID URL (as in the example above), resolvable via the appropriate DID method.
- A DID Document listing one or more verification methods (`JsonWebKey2020`, `EcdsaSecp256k1VerificationKey2019`, etc.) with stable `id` values the issuer can reference via `kid`.

**What the verifier needs to implement**

- A DID resolver supporting the DID method(s) used by trusted issuers.
- Trust policy expressed in DID-native terms (trusted DID prefixes, delegation graph, controller relationships).
- Verification method selection by `kid` pointing into the DID Document.
- Signature verification with the resolved public key.

**Operational notes**

- Trust semantics differ from the X.509 PKI world: revocation is handled through DID Document updates (or per-method flags), not CRL/OCSP.
- Trust models vary substantially across DID methods (`did:web` relies on DNS, `did:key` has no external root, `did:ebsi` uses a governmental trust list, etc.). Method-specific resolution, verification, and revocation details belong in the corresponding DID method specifications and in deployment-profile documentation; they are out of scope here.

## Cross-cutting operational concerns

These apply regardless of the sourcing scheme above.

**JWKS and certificate caching**

Cache the resolved keyset or certificate with a TTL. Respect any `Cache-Control` or `Expires` the issuer publishes. On cache miss or signature failure, re-fetching once before surfacing an error limits the blast radius when the issuer rotates keys without explicit coordination.

**Key rotation**

Expect multiple active keys to coexist during a rotation window. Verify against the `kid` (or other identifier) referenced in the JWT; do not assume a single current key. Cache old keys until their removal is signaled — by absence from the published keyset (Approaches 1 and 4) or by certificate revocation via CRL/OCSP (Approaches 2 and 3).

**Clock skew**

JWTs include `iat` and sometimes `exp` / `nbf`. Certificates include `notBefore` / `notAfter`. Allow a small skew window (for example 60-300 seconds) to tolerate clock drift between issuer and verifier.

**Rate limiting**

Fetching JWKS or `x5u` resources per presentation concentrates load on the issuer endpoint. Production verifiers typically introduce a caching layer and exponential backoff on fetch errors, so that a transient issuer outage does not cascade into a verification outage at scale.

**Trust anchor bootstrapping**

All four approaches ultimately reduce to "do I trust this key?". Document the source of truth for your trust anchors — a hand-curated list, a published trust list (e.g. national or federation lists), or a policy file — and the rotation procedure when anchors are added or removed.
