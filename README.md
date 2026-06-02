# tpt-identity

Identity foundation for the Trusted Public Transport (TPT) ecosystem. Provides OpenID Connect authentication, W3C Verifiable Credential issuance, Decentralised Identifier management, and NZ Privacy Act 2020-compliant consent management for downstream TPT services.

---

## What it does

- **Issues and verifies W3C Verifiable Credentials** — cryptographically signed, portable, user-controlled credentials across healthcare, finance, education, legal, and civic domains
- **Runs an OIDC Provider** — authorization code flow, refresh token rotation, dynamic client registration (RFC 7591), token introspection (RFC 7662), and revocation (RFC 7009)
- **Manages Decentralised Identifiers** — create and resolve `did:web`, `did:key`, and `did:peer` DIDs; serve `/.well-known/did.json` automatically
- **Enforces granular consent** — schema-level and category-level grants with signed audit receipts; extra-sensitive credentials (mental health, sexual health, criminal record) always require individual explicit consent
- **Provides a Go SDK and drop-in middleware** — downstream services integrate in minutes, not hours

---

## Architecture

```
tpt-healthcare ──────────────────────────────────────────────┐
tpt-email     ─── client.NewClient() ─── POST /token         │
tpt-...       ─── middleware.Require* ─── GET /api/v1/...    │
                                                              ▼
                                                    tpt-identity (this repo)
                                                    ├── OIDC Provider
                                                    ├── VC Issuance / Verification
                                                    ├── DID Methods
                                                    ├── Consent Engine
                                                    └── SQLite (→ PostgreSQL ready)
```

Each downstream service registers as an OIDC client, obtains access tokens via the `client_credentials` grant, and calls the REST API or uses the embedded Go SDK. Users control exactly which credentials each service may access via the consent system.

---

## Quick start

**Requirements:** Go 1.22+

```bash
# 1. Generate keys
go run ./cmd/tpt-identity keygen --out keys/

# 2. Copy and edit config
cp config.yaml.example config.yaml
# Set issuer, db_path, identity.signing_key, api_key

# 3. Run
go run ./cmd/tpt-identity serve --config config.yaml
```

Verify it's running:
```bash
curl http://localhost:8080/healthz
curl http://localhost:8080/.well-known/openid-configuration
```

---

## Integrating a downstream service

Register your service and get credentials:

```bash
curl -X POST http://localhost:8080/oidc/register \
  -H "Content-Type: application/json" \
  -d '{"client_name":"tpt-healthcare","redirect_uris":["https://healthcare.example.com/callback"]}'
# → {"client_id":"...","client_secret":"..."}
```

Then in Go:

```go
import "github.com/PhillipC05/tpt-identity/client"
import "github.com/PhillipC05/tpt-identity/middleware"

idClient := client.NewClient(client.Config{
    BaseURL:      "https://identity.tpt.govt.nz",
    ClientID:     os.Getenv("TPT_CLIENT_ID"),
    ClientSecret: os.Getenv("TPT_CLIENT_SECRET"),
})

// Protect a route — requires consent and credential
mux.Handle("/patient/records",
    middleware.RequireCredential(idClient, "healthcare.gp-records")(myHandler))
```

Full integration guide: [docs/developer.md](docs/developer.md)

---

## Documentation

| Audience | Document |
|---|---|
| Service developers | [docs/developer.md](docs/developer.md) |
| End users | [docs/user-guide.md](docs/user-guide.md) |
| Security researchers | [SECURITY.md](SECURITY.md) |
| Contributors | [CONTRIBUTING.md](CONTRIBUTING.md) |
| Deferred risks | [RISKS.md](RISKS.md) |

---

## Configuration

All settings are in `config.yaml`. Every value can be overridden with a `TPT_IDENTITY_*` environment variable:

| YAML key | Env var | Description |
|---|---|---|
| `issuer` | `TPT_IDENTITY_ISSUER` | Canonical URL of this server |
| `db_path` | `TPT_IDENTITY_DB_PATH` | SQLite file path |
| `listen_addr` | `TPT_IDENTITY_LISTEN_ADDR` | HTTP bind address (default `:8080`) |
| `api_key` | `TPT_IDENTITY_API_KEY` | Static admin API key (leave empty to disable) |
| `identity.signing_key` | `TPT_IDENTITY_IDENTITY_SIGNING_KEY` | Path to Ed25519 PEM key file |
| `identity.passphrase` | `TPT_IDENTITY_IDENTITY_PASSPHRASE` | Passphrase for encrypted key file |

See [config.yaml.example](config.yaml.example) for all options.

---

## Technology

| Concern | Choice | Rationale |
|---|---|---|
| Signing | Ed25519 | 256-bit security, compact signatures, fast verification |
| Encryption | X25519 + NaCl secretbox | Standard ECDH key agreement |
| Key derivation | Argon2id | GPU-resistant; 64MB / 3 iterations / 4 threads |
| Credentials | W3C VC Data Model 2.0 | Interoperable, portable, cryptographically verifiable |
| Identifiers | W3C DIDs | Self-sovereign, no central registry dependency |
| Auth protocol | OIDC (RFC 6749 / OIDC Core) | Industry standard, wide tooling support |
| Database | SQLite (pure Go) | Zero deployment dependency; schema is PostgreSQL-compatible |

---

## Licence

[MIT](LICENSE)
