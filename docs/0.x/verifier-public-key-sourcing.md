# Verifier public-key sourcing

## Overview

To validate an SD-JWT-VC, the verifier needs the issuer's signing public key. The key itself is not transported inside the JWT payload — the JWT header carries a *pointer* (or fingerprint) to the key. Several pointer schemes coexist in the SD-JWT-VC ecosystem, each with different operational properties. This document describes the main approaches neutrally.

Two distinct concerns are at play and should not be conflated:

- **Key discovery** — turning the pointer into a candidate public key.
- **Trust validation** — deciding whether that candidate key is authoritative for the issuer.

This document focuses on the discovery mechanics. The trust side (anchor sources, profile policies, threat assumptions) is profile- and deployment-specific and is referenced only where it directly shapes what the verifier must implement.

The verifier's job, in each case, is:

1. Interpret the pointer in the JWT header (and sometimes a claim in the payload).
2. Fetch or look up the candidate public key via the pointer.
3. Verify that the key is trusted (i.e. traceable to a trust anchor the verifier has configured).
4. Use the key to validate the JWT signature.

Conceptually, every approach below maps to the same chain:

```
JWT header pointer → resolution mechanism → candidate key → trust-anchor check → signature verification
```

What differs between approaches is the *resolution mechanism* and the shape of the *trust-anchor check*.

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
- Optional: an HTTP `Cache-Control` header, and a key-rotation policy consistent with the caching window.

**What the verifier needs to implement**

- Trust-anchor list: the set of `iss` URL prefixes the verifier is willing to honor.
- HTTP client fetching the well-known JWKS endpoint and parsing the JWKS document.
- JWK selection by `kid` header, or by `alg` + iteration if `kid` is absent.
- Signature verification against the selected JWK.

**Operational notes**

- Requires network access at verification time unless the JWKS is cached.
- Key rotation is driven by the issuer; the verifier may cache the JWKS with a TTL.
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
- Chain validation: signature, validity period, Extended Key Usage constraints, path constraints.
- Revocation checking strategy (CRL distribution point, OCSP, or an explicit policy when neither is available).
- Public key extraction from the leaf certificate after chain validation passes.

**Operational notes**

- Self-contained: no runtime network dependency if revocation is skipped or cached.
- Larger JWTs compared to key-pointer approaches (the certificates travel with every token).
- Key rotation requires re-issuing credentials with the updated chain.

## Approach 3 — X.509 certificate by reference

Instead of embedding the chain, only a reference to the certificate travels with the request. The certificate itself is retrieved out-of-band, usually provisioned ahead of time. The reference may be a hash (HAIP `x509_hash`), a URI, or a registry identifier.

> **Context note.** This pattern is most commonly encountered in the surrounding protocols that transport or authenticate SD-JWT-VC credentials — notably in the OID4VP authorization request (JAR) where the verifier's own certificate can be referenced via `client_id_prefix: x509_hash`. The same pattern applies to any context where a certificate set is known in advance and embedding the chain on every token is undesirable. Less common directly in an SD-JWT-VC issuer header, more common in the enclosing presentation protocol.

Example of a hash-based reference inside an enclosing JAR (HAIP 1.0 Final context):

```text
client_id = "x509_hash:Xr8k9m...base64url(SHA-256(leaf_cert))..."
```

**What the issuer (or party whose cert is referenced) must expose**

- A base64url-encoded SHA-256 fingerprint of the leaf certificate — or another stable reference type — carried in the protocol element that identifies the signer.
- A published endpoint, trust list, or provisioning step through which the full certificate can be retrieved and pinned by verifiers.

**What the verifier needs to implement**

- Out-of-band retrieval of the full certificate, e.g. from a trust-list endpoint, a local provisioning step, or a registered certificate store.
- Hash (or equivalent) computation on the retrieved certificate, matched against the reference.
- Once the match is confirmed, the verifier proceeds as in Approach 2 (chain validation, trust anchors, key extraction).

**Operational notes**

- Smaller requests than full chain embedding — only the reference travels.
- Adds a provisioning step: the verifier needs to have the certificate before verification, not at verification time.
- Common in High-Assurance Interoperability Profile (HAIP) deployments and in profile-locked contexts where the relying-party / issuer certificate set is known in advance.
- A referenced-certificate pattern with a URI instead of a hash is also emerging; see in-flight profile drafts for exact semantics.

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

- An `iss` claim (or dedicated header) containing a DID resolvable via the appropriate DID method.
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

Expect multiple active keys in the issuer's keyset. Verify against the `kid` referenced in the JWT; do not assume a single current key. Cache old keys until their removal is signaled (absent from the published keyset).

**Clock skew**

JWTs include `iat` and sometimes `exp` / `nbf`. Certificates include `notBefore` / `notAfter`. Allow a small skew window (for example 60-300 seconds) to tolerate clock drift between issuer and verifier.

**Rate limiting**

Fetching JWKS per presentation concentrates load on the issuer endpoint. Production verifiers typically introduce a caching layer and exponential backoff on fetch errors, so that a transient issuer outage does not cascade into a verification outage at scale.

**Trust anchor bootstrapping**

All four approaches ultimately reduce to "do I trust this key?". Document the source of truth for your trust anchors — a hand-curated list, a published trust list (e.g. national or federation lists), or a policy file — and the rotation procedure when anchors are added or removed.
