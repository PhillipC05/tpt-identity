# tpt-identity — Build Checklist

## Phase 1 — Crypto & Key Foundation
- [x] `go.mod` — initialise module `github.com/PhillipC05/tpt-identity`
- [x] `pkg/crypto/sign.go` — Ed25519 sign / verify
- [x] `pkg/crypto/encrypt.go` — X25519 ECDH + NaCl secretbox
- [x] `pkg/crypto/hash.go` — canonical hashing utilities
- [x] `pkg/keystore/keystore.go` — AES-256-GCM encrypted PEM, PBKDF2, Ed25519 + X25519
- [ ] `pkg/keystore/keystore.go` — replace PBKDF2 with Argon2id; `golang.org/x/crypto/argon2`, params: 64MB / 3 iterations / 4 threads (GPU-resistant key derivation for identity key material)

## Phase 2 — DID Layer
- [x] `pkg/did/method.go` — `DIDMethod` interface + `RegisterMethod()` registry
- [x] `pkg/did/document.go` — W3C DID Document types (verification methods, services, context)
- [x] `pkg/did/web.go` — did:web: create, resolve via HTTPS `/.well-known/did.json`
- [x] `pkg/did/key.go` — did:key: derive DID from Ed25519 pubkey, offline resolve
- [x] `pkg/did/peer.go` — did:peer: pairwise DIDs, no public resolution
- [x] `pkg/did/ion.go` — did:ion: Bitcoin/Sidetree (build tag `ion`, optional)
- [x] `internal/resolver/resolver.go` — DID resolver with TTL caching, routes by prefix
- [ ] `internal/resolver/resolver.go` — SSRF hardening on did:web fetches: configurable domain allowlist, max 1 redirect, 5s timeout, block RFC-1918 IP ranges
- [ ] `pkg/did/key.go` — enforce usage constraint: did:key is ephemeral/offline only; reject did:key as issuer DID for any persistent credential (key rotation is structurally impossible for did:key)

## Phase 3 — Credential Schema Taxonomy
- [x] `pkg/schema/registry.go` — `RegisterSchema()`, `RegisterCategory()`, lookup helpers
- [ ] `pkg/schema/registry.go` — add version identifiers to all schemas (e.g. `nhi-credential-v1`); issued VCs must reference the versioned schema ID
- [ ] `pkg/schema/validate.go` — rewrite using embedded JSON Schema files + `github.com/santhosh-tekuri/jsonschema/v6`; Go structs become typed wrappers, not custom validation logic
- [x] `pkg/schema/core/identity.go` — schemas: legal-name, dob, address, passport, drivers-licence, nhi, ird-number
- [x] `pkg/schema/core/healthcare.go` — schemas: gp-records, specialist, pharmacy, allergies, immunisation, radiology, pathology, dental, acc-injury, disability + extra-sensitive: mental-health, sexual-health, reproductive-health, addiction
- [x] `pkg/schema/core/finance.go` — schemas: bank-account, income, tax-records, credit-history, benefits, insurance-policies, investments, property-ownership
- [x] `pkg/schema/core/professional.go` — schemas: qualifications, registrations, employment, practising-certificates
- [x] `pkg/schema/core/education.go` — schemas: enrolments, transcripts, qualifications, nzqa
- [x] `pkg/schema/core/legal.go` — schemas: court-orders, poa, will-estate, immigration-status + extra-sensitive: criminal-record
- [x] `pkg/schema/core/property.go` — schemas: real-estate, vehicles, assets
- [x] `pkg/schema/core/civic.go` — schemas: electoral-roll, benefits-entitlements, tax-filing, business-registration
- [x] `pkg/schema/core/social.go` — schemas: verified-contacts, social-graph, reputation
- [x] `pkg/schema/core/travel.go` — schemas: passport, visas, vaccination-certs, travel-insurance
- [x] `pkg/schema/core/insurance.go` — schemas: health, life, vehicle, home, business
- [x] `pkg/schema/validate.go` — validate VC claims against schema definitions

## Phase 4 — Verifiable Credentials
- [x] `pkg/vc/credential.go` — W3C VC Data Model 2.0 types (VerifiableCredential, VerifiablePresentation)
- [x] `pkg/vc/issue.go` — sign a VC with issuer DID (Ed25519Signature2020)
- [ ] `pkg/vc/issue.go` — replace Ed25519Signature2020 (deprecated) with DataIntegrityProof + eddsa-jcs-2022 cryptosuite; add `github.com/gowebpki/jcs` for JSON Canonicalization
- [x] `pkg/vc/verify.go` — resolve issuer DID, verify signature, check expiry
- [ ] `pkg/vc/verify.go` — update to verify DataIntegrityProof; also check `credentialStatus` if present
- [x] `pkg/vc/presentation.go` — Verifiable Presentations (holder proves possession)
- [ ] `pkg/vc/presentation.go` — add `challenge` + `domain` to `CreatePresentation()`; validate both in `VerifyPresentation()` (anti-replay)
- [ ] `pkg/vc/status.go` — BitstringStatusList credential status: `RevokeCredential()` flips a bit in a published status list VC; issued VCs carry a `credentialStatus` pointer to the list

## Phase 5 — Consent & Trust
- [x] `pkg/consent/policy.go` — sharing policy: schema-level grants, category grants (extra confirmation), extra-sensitive exclusions
- [ ] `pkg/consent/policy.go` — add `ExpiresAt` (optional) and `RevokedAt` to grants; withdrawal sets `RevokedAt`, never hard-deletes (preserve audit trail for NZ Privacy Act 2020 compliance)
- [x] `pkg/consent/receipt.go` — cryptographically signed consent receipts (who, schema, when, legal basis)
- [ ] `pkg/consent/receipt.go` — add `ExpiresAt` field; consent withdrawal reflected via `RevokedAt` flag, not deletion
- [ ] `pkg/trust/permit.go` — JWT permits (Ed25519-signed, short-lived) — port from tpt-email
- [ ] `pkg/trust/reputation.go` — federated reputation DNS queries — port from tpt-email

## Phase 6 — Storage
- [x] `internal/store/store.go` — `Store` interface defining all operations
- [x] `internal/store/sqlite.go` — SQLite implementation (pure-Go modernc, PostgreSQL-compatible schema)
- [ ] `internal/store/migrations/` — SQL migration files via `golang-migrate/migrate` with embedded FS; add `migrate up` / `migrate down` CLI subcommands

## Phase 7 — OIDC Provider
- [x] `oidc/discovery.go` — `GET /.well-known/openid-configuration`
- [x] `oidc/provider.go` — authorization code flow: `/authorize`, `/token`, `/userinfo`
- [x] `oidc/jwt.go` — ID token + access token issuance (Ed25519-signed JWTs, DID as `sub`)
- [ ] `oidc/provider.go` — security audit: PKCE enforced on all auth code flows, token comparison is timing-safe, state parameter validated
- [ ] `oidc/registration.go` — `POST /oidc/register` RFC 7591 Dynamic Client Registration (downstream TPT modules self-register)
- [ ] `oidc/revocation.go` — `POST /oidc/revoke` RFC 7009 token revocation

## Phase 8 — REST API
- [x] `api/server.go` — wire routes, middleware (auth, logging)
- [ ] `api/server.go` — add: structured audit logging middleware (who/action/resource/timestamp → append-only store, separate from request logs), rate limiting middleware (`golang.org/x/time/rate`)
- [ ] `api/status.go` — `GET /api/v1/status/:listId` serve BitstringStatusList VCs for credential revocation checks
- [ ] `api/health.go` — `GET /healthz` (liveness) and `GET /readyz` (readiness + DB connectivity check)
- [x] `api/identity.go` — `POST /api/v1/identities`, `GET /api/v1/identities/:did`
- [x] `api/credentials.go` — `POST /api/v1/credentials`, `POST /api/v1/credentials/verify`, list, delete
- [x] `api/consents.go` — grants CRUD, receipts list, session delete, schema list

## Phase 9 — CLI & Server Binary
- [x] `cmd/tpt-identity/main.go` — cobra root entry point
- [x] `cmd/tpt-identity/cmd/root.go` — root command + subcommand wiring
- [x] `cmd/tpt-identity/cmd/serve.go` — start HTTP server
- [x] `cmd/tpt-identity/cmd/keygen.go` — generate keypair, output DID
- [x] `cmd/tpt-identity/cmd/resolve.go` — resolve any DID
- [x] `cmd/tpt-identity/cmd/issue_vc.go` — issue a VC from CLI
- [x] `cmd/tpt-identity/cmd/verify_vc.go` — verify a VC from CLI
- [x] `config.yaml.example` — annotated example config

## Phase 10 — Tests
- [ ] `pkg/crypto/` — unit tests; fuzz tests for sign/verify and encrypt/decrypt (`go test -fuzz`)
- [ ] `pkg/did/` — unit tests for all methods; SSRF prevention test for did:web resolver
- [ ] `pkg/vc/` — issue → verify → revoke → re-verify round-trip; anti-replay presentation test; DataIntegrityProof compliance test
- [ ] `pkg/consent/` — policy enforcement: expiry, withdrawal/revocation, extra-sensitive exclusion, category grant confirmation
- [ ] `pkg/schema/` — registry versioning tests, JSON Schema validation tests
- [ ] `oidc/` — full authorization code flow with PKCE; token revocation (RFC 7009); dynamic client registration (RFC 7591)
- [ ] `api/` — HTTP handler integration tests; rate limiting; audit log entries; health check responses

## Phase 11 — Documentation
- [ ] `README.md` — overview, quickstart, architecture diagram
- [ ] `PROTOCOL.md` — DID methods spec, VC profiles, OIDC flows, consent model
- [ ] `SCHEMA.md` — full credential taxonomy reference

## Future (post-MVP)
- [ ] `pkg/trust/permit.go` + `pkg/trust/reputation.go` — port from tpt-email
- [ ] tpt-email migration — swap `internal/identity`, `internal/keystore`, `pkg/tfep/` for tpt-identity imports
- [ ] `GET /.well-known/jwks.json` — JWKS endpoint for OIDC token verification by third parties
- [ ] Prometheus metrics endpoint
- [ ] `POST /api/v1/consents/receipts` — relying party submits a receipt after access
- [ ] did:ion production hardening (Sidetree node, IPFS anchoring)
- [ ] Selective disclosure: evaluate SD-JWT (`draft-ietf-oauth-selective-disclosure-jwt`) first — no ZK proofs required, solid Go support, wider real-world deployment than BBS+; only proceed to BBS+ if ZK proofs are a hard requirement
- [ ] BBS+ (if required): Go ecosystem is thin; implement via WASM compiled from Rust `bbs` crate, not a pure-Go implementation
- [ ] Mobile SDK (Swift / Kotlin) wrapping the REST API
- [ ] NZ government integration: RealMe bridge, Te Whatu Ora FHIR identity, ACC API auth
