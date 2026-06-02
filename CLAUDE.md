# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Build
go build ./cmd/tpt-identity/...

# Build with optional features
go build -tags "ion,saml,ldap" ./cmd/tpt-identity/...

# Run all tests
go test ./...

# Run tests in one package
go test -v ./pkg/vc/...
go test -v ./oidc/...

# Run a single test function
go test -v -run TestIssueVerifyRoundTrip ./pkg/vc/...
go test -v -run TestPKCEVerification ./oidc/...

# Test with coverage
go test -cover ./...

# Run the server
go run ./cmd/tpt-identity serve --config config.yaml

# Key management
go run ./cmd/tpt-identity keygen --method web --domain example.com \
  --out-sign keys/ed25519.pem --out-enc keys/x25519.pem --passphrase ""

# Database migrations
go run ./cmd/tpt-identity migrate up
go run ./cmd/tpt-identity migrate version

# Issue a credential
go run ./cmd/tpt-identity issue-vc \
  --issuer did:web:example.com --key ed25519.pem \
  --subject did:peer:xyz --schema identity.legal-name \
  --claim givenNames=Alice --claim familyName=Smith --valid-for 8760h

# Resolve a DID
go run ./cmd/tpt-identity resolve "did:web:example.com"
```

## Architecture

### Module

`github.com/PhillipC05/tpt-identity` — Go 1.22, pure-Go SQLite (`modernc.org/sqlite`, no CGo).

### Request flow

```
HTTP request
  → api/server.go (rateLimit → audit → auth middleware)
  → handler (api/*.go)
  → oidc/ or pkg/ for domain logic
  → internal/store/ for persistence
```

The `api.Server` struct carries all runtime dependencies: `store.Store`, `oidc.Provider`, `bridge.Manager`, `bridge.Mapper`, `events.Bus`, `authn.LockoutManager`. These are wired in `cmd/tpt-identity/cmd/serve.go`.

### Cryptography invariants

- **Ed25519** for all signing (credentials, JWTs, consent receipts).
- **X25519 + NaCl secretbox** for encryption at rest and DIDComm.
- **Argon2id** (64 MB / 3 iterations / 4 threads) for every key derivation from a passphrase — this is the same constant in both `pkg/keystore/keystore.go` and `internal/authn/totp.go`; keep them in sync.
- **`did:key` may never be an issuer** of persistent credentials — `pkg/vc/issue.go` returns `ErrEphemeralIssuer` if you try. Bridge-created identities use `did:key` only as a stable identifier; auth is via the external provider.
- Proof algorithm: **DataIntegrityProof / eddsa-jcs-2022**. `pkg/crypto/hash.go` provides JCS canonicalization. The signing pipeline is `JCS(proofOptions) ‖ JCS(document) → SHA-256 → Ed25519.Sign`.

### DID methods

Registered at `init()` time via `pkg/did/method.go`'s global registry. The four methods (`web`, `key`, `peer`, and optionally `ion` under build tag) each live in their own file. `did:web` resolution fetches `https://{domain}/.well-known/did.json` with SSRF hardening (RFC-1918 blocked, 5 s timeout, max 1 redirect). The `internal/resolver` package wraps DID resolution with a TTL cache.

### SD-JWT selective disclosure

`pkg/vc/sdjwt.go` implements SD-JWT (draft-ietf-oauth-selective-disclosure-jwt) as a second credential format alongside the W3C DataIntegrityProof VCs:

- `IssueSDJWT(opts)` → `*SDJWTToken` — produces a JWT (`vc+sd-jwt` typ) where each selective claim is replaced by its SHA-256 hash in the `_sd` array. The `SDJWTToken` holds the JWT and all `Disclosure` values.
- `token.Present(keys)` → string — holder picks which claims to reveal; returns `<jwt>~<selected_discs>~`
- `token.PresentWithKeyBinding(keys, holderKey, kid, nonce, aud)` → string — appends a `kb+jwt` that binds the presentation to a verifier nonce (anti-replay)
- `SDJWTVerifier.Verify(token, nonce, aud)` — resolves the issuer DID, verifies the JWT signature, checks each presented disclosure hash against `_sd`, and validates the KB-JWT if present

**Key constraints:**
- `_sd_alg` is always `sha-256`; `cnf` is optional (used for KB-JWT holder key binding)
- `did:key` is blocked as issuer (same `ErrEphemeralIssuer` as W3C VCs)
- `AlwaysVisibleClaims` go directly into the JWT payload; `SelectiveClaims` are hashed
- The `vct` claim carries the versioned schema ID (analogous to `@type` in W3C VCs)
- `api.Server` needs `signingKey`+`signingKeyID` populated (via `Config.SigningKey`) — both credential handlers (`handleIssueCredential` and `handleIssueSDJWT`) use the platform signing key, not caller-provided keys

### Credential schemas

`pkg/schema/registry.go` holds the in-memory registry. All 50+ schemas are registered by the `init()` calls in `pkg/schema/core/*.go` — the serve command blank-imports this package (`_ "github.com/PhillipC05/tpt-identity/pkg/schema/core"`). Tests that need schemas must do the same. Schema IDs are versioned: `healthcare.nhi-credential-v1`; the registry can look up by base ID (`healthcare.nhi-credential`) to find the latest version.

Schemas marked `ExtraSensitive: true` (mental-health, addiction, criminal-record, etc.) require a separate, individually confirmed consent grant even when a category grant is active — enforced in `api/consents.go` and `pkg/consent/policy.go`.

### OIDC provider

`oidc.Provider` is the OIDC server. Every authorize call requires both `state` (CSRF) and `code_challenge` (PKCE S256). Client registration (`POST /oidc/register`, RFC 7591) is required before a `client_id` is accepted — `AuthorizeHandler` validates against the store. Tokens are EdDSA-signed JWTs; the JWKS (`GET /.well-known/jwks.json`) exposes the public key for downstream verification. Refresh tokens are stored by `sha256(raw_token)`, rotated on every use, with a consumed-token grace window to detect theft.

### Identity bridge

`internal/bridge/bridge.go` defines the `Bridge` interface. Providers (OIDC RP, magic link, password, SAML†, LDAP†) authenticate and return an `ExternalIdentity{Provider, ExternalID, Claims}`. `internal/bridge/mapper.go` finds or creates the corresponding platform DID in the store; each external identity maps to exactly one DID. Account linking (`POST /api/v1/me/links`) attaches additional providers to an existing DID. The bridge HTTP handlers in `api/bridge.go` use a HMAC-signed state token to carry OIDC flow parameters across the external provider redirect without a server-side state table.

†Require build tags: `-tags saml` / `-tags ldap`.

### Persistence

`internal/store/store.go` defines the `Store` interface; `internal/store/sqlite.go` is the only implementation. Schema migrations live in `internal/store/migrations/*.sql` and are applied by the embedded runner — `tpt-identity migrate up` applies them; the schema is PostgreSQL-compatible for a future migration. All list/get operations use the context for cancellation. `OIDCSession` stores PKCE challenge, state, user-agent, IP, and refresh token hash alongside the auth code.

### Consent and receipts

Grants are soft-deleted (`RevokedAt` set, never `DELETE`d) for NZ Privacy Act 2020 audit trail compliance. Receipts are append-only and cryptographically signed. The `pkg/consent/policy.go` enforcer checks grant expiry, category vs. schema level, and extra-sensitive overrides before allowing credential access.

### Webhook events

`internal/events/events.go` provides a typed event bus. `events.Bus.Publish` fans out to subscribers from the store, delivers via HTTP POST with `X-TPT-Signature-256: sha256=<hmac>`, and retries up to 3 times with exponential backoff. Published on: `credential.issued`, `credential.revoked`, `consent.granted`, `consent.revoked`, `identity.created`, `session.created`, `session.revoked`.

## Key constraints and non-obvious rules

- **`did:key` cannot issue persistent VCs** — `ErrEphemeralIssuer` enforced in `vc.Issue`.
- **PKCE + state are mandatory** on every `/authorize` call — no opt-out.
- **Client registration required** — `AuthorizeHandler` rejects unknown `client_id` values; downstream TPT modules must call `POST /oidc/register` first.
- **Extra-sensitive schemas need individual grants** — category grants alone are insufficient for mental-health, sexual-health, reproductive-health, addiction, criminal-record schemas.
- **LDAP requires `ldaps://`** — plaintext `ldap://` returns an error at bridge construction, not at runtime.
- **Argon2id is slow by design** — don't call it in tests without a deterministic fixture or it will dominate test time.
- **Schema `init()` must be imported** — tests touching schema validation need `_ "github.com/PhillipC05/tpt-identity/pkg/schema/core"`.
- **SQLite is single-writer** — `db.SetMaxOpenConns(1)` is intentional; don't remove it.

## Configuration

Copy `config.yaml.example` to `config.yaml`. Key fields: `issuer` (canonical HTTPS URL, used as OIDC issuer and `did:web` base), `identity.signing_key` (path to Ed25519 PEM), `identity.passphrase` (Argon2id key derivation), `api_key` (Bearer token for protected admin endpoints). Bridge providers are configured under `bridges.oidc[]`. TOTP uses `totp_passphrase` (defaults to `identity.passphrase`). Environment variable override prefix: `TPT_IDENTITY_`.
