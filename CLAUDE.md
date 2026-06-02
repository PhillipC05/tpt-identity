# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build and development commands

```bash
# Build
go build -mod=vendor ./...

# Vet (run before committing)
go vet ./...

# Tests (none exist yet; run when added)
go test ./...

# Generate keys for local development
go run ./cmd/tpt-identity keygen --out keys/

# Run the server
cp config.yaml.example config.yaml   # set issuer: "http://localhost:8080"
go run ./cmd/tpt-identity serve --config config.yaml

# Health check
curl http://localhost:8080/healthz
curl http://localhost:8080/.well-known/openid-configuration
```

All builds must use `-mod=vendor`. The vendor directory is the canonical source; do not run `go get` without also running `go mod vendor`.

## Architecture overview

tpt-identity is an OIDC identity provider + W3C Verifiable Credential issuer designed to be called over HTTP by downstream TPT services (tpt-healthcare, tpt-email, etc.). It is not a monorepo — each downstream service is a separate repo that imports `client/` and `middleware/` as Go packages.

### Startup wiring (`cmd/tpt-identity/cmd/serve.go`)

```
Load config (internal/config) → Open SQLite (internal/store/sqlite.go)
→ Load Ed25519 signing key (pkg/keystore) → Create DID resolver (internal/resolver)
→ Create OIDC provider (oidc/provider.go) → Create API server (api/server.go)
→ http.ListenAndServe
```

### Request path for a protected downstream route

```
tpt-healthcare HTTP handler
  └─ middleware.RequireCredential(idClient, "healthcare.gp-records")
       ├─ Extract Bearer token from request
       ├─ client.IntrospectToken() → POST /oidc/introspect → subject DID
       ├─ client.ListGrants() → GET /api/v1/consents/grants?subject=...
       ├─ Check grant exists for schema + not revoked + not expired
       └─ Store subjectDID + grants in context → call next handler
```

### Key architectural boundaries

- **`internal/store/store.go`** — The `Store` interface is the only persistence abstraction. All application code targets this interface; `sqlite.go` is the sole implementation. The schema is PostgreSQL-compatible for future migration.
- **`pkg/crypto/` and `pkg/keystore/`** — All cryptographic operations live here. Do not scatter signing, encryption, or key derivation logic into handlers.
- **`pkg/consent/policy.go`** — All consent enforcement logic lives here. Category grants do not cover extra-sensitive schemas; those always require `ExplicitlyConfirmed: true` on an individual grant.
- **`oidc/jwt.go`** — Hand-rolled EdDSA JWT implementation. The `golang-jwt` package is intentionally absent; do not re-add it.
- **`pkg/schema/core/`** — Core schema definitions registered at `init()`. Add new credential schemas here, not in API handlers.

### Auth middleware (`api/server.go` → `auth()`)

Protected routes accept two token forms:
1. Static API key string (config `api_key`) — for ops/admin
2. Valid OIDC access token — issued via `/token` with `grant_type=client_credentials`

`ValidateAccessToken()` on the OIDC provider verifies the JWT signature and checks `token_type == "access"`.

### Token revocation

Revoked tokens are tracked in the `revoked_tokens` SQLite table (hash + expiry). `IsTokenRevoked()` is checked in `IntrospectHandler` before signature verification. `PurgeExpiredRevokedTokens()` cleans up expired entries.

### Consent audit trail

Grants and receipts are **never deleted**. Revocation sets `RevokedAt`; deletion is prohibited. This is a hard requirement under NZ Privacy Act 2020.

### Multibase encoding

`pkg/multibase/multibase.go` is a self-contained implementation (no external dep). It handles `z` (base58btc) and `u` (base64url) prefixes. All call sites that used `github.com/multiformats/go-multibase` now use this package — the API is intentionally narrower: `Encode(raw []byte) string` always produces base58btc; `Decode(s string) ([]byte, error)` accepts either prefix.

### UUID generation

`pkg/uuid/uuid.go` is a self-contained stdlib-only implementation. Replaces `github.com/google/uuid`. Use it instead of that package anywhere in this repo.

### Configuration

`internal/config/config.go` loads YAML and applies `TPT_IDENTITY_*` environment variable overrides. The `Config` struct is the single source of truth for all runtime settings. Do not use `spf13/viper` — it was replaced.

## Dependency rules

Direct dependencies are intentionally minimal (cobra, x/crypto, yaml.v3, modernc/sqlite). Adding a new external dependency requires justification. Check `go.mod` before assuming a package is available. Never add a package that is already implementable with stdlib or an existing dep.

## DID methods

Four methods are registered: `did:web`, `did:key`, `did:peer`, `did:ion`. Registration happens via `did.RegisterMethod()` in `pkg/did/method.go`. `did:key` is ephemeral (no key rotation) and is rejected as a VC issuer DID in `pkg/vc/issue.go`.

## Credential schemas

Schema IDs take the form `category.name` (e.g. `healthcare.gp-records`). Extra-sensitive schemas (mental health, sexual health, reproductive health, addiction, criminal record) are flagged `ExtraSensitive: true` in the registry and always require an individual explicit consent grant — category-level grants are insufficient.
