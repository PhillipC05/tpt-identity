# tpt-identity

Sovereign identity backbone for the TPT open-source ecosystem. Every person gets one DID that works across email, healthcare, payments, and civic systems — authenticated however makes sense for them.

## What it does

- **DID management** — create and resolve `did:web`, `did:key`, `did:peer` identifiers (optional: `did:ion` via build tag)
- **Verifiable Credentials** — issue and verify W3C VC Data Model 2.0 credentials with DataIntegrityProof (eddsa-jcs-2022)
- **Consent receipts** — cryptographically signed records of who accessed what, under what legal basis (NZ Privacy Act 2020 compliant)
- **OIDC Provider** — authorization code flow with mandatory PKCE, dynamic client registration (RFC 7591), token revocation (RFC 7009), refresh token rotation
- **Identity bridges** — accept Google, GitHub, Azure AD, SAML 2.0, LDAP/AD, magic link, and password auth; each maps to a platform DID
- **Account linking** — one DID, multiple external auth providers
- **MFA** — TOTP (RFC 6238) with AES-256-GCM encrypted secrets; brute-force lockout
- **Selective disclosure** — SD-JWT (draft-ietf-oauth-selective-disclosure-jwt): holders reveal only the claims each verifier needs; zero-knowledge proof that a credential is valid without disclosing any claims; optional key-binding JWT for anti-replay
- **Credential revocation** — BitstringStatusList (W3C)
- **Webhook events** — push `credential.issued`, `consent.granted`, `session.revoked` etc. to subscribers
- **Presentation Exchange** — DIF PE v2 request/submit flow for structured credential requests
- **Inter-service trust** — short-lived Ed25519-signed permits and federated reputation via DNS TXT

## Quickstart

```bash
# 1. Copy and edit config
cp config.yaml.example config.yaml

# 2. Generate a signing keypair and print the DID
tpt-identity keygen --method web --domain example.com \
  --out-sign keys/ed25519.pem --out-enc keys/x25519.pem

# 3. Run database migrations
tpt-identity migrate up

# 4. Start the server
tpt-identity serve --config config.yaml

# Issue a credential
tpt-identity issue-vc \
  --issuer did:web:example.com \
  --key keys/ed25519.pem \
  --subject did:peer:z6Mk... \
  --schema identity.legal-name \
  --claim givenNames=Alice \
  --claim familyName=Smith \
  --valid-for 8760h

# Verify a credential
tpt-identity verify-vc credential.json

# Resolve any DID
tpt-identity resolve "did:web:example.com"
```

### Optional build tags

```bash
go build -tags "ion"          # include did:ion (Bitcoin/Sidetree)
go build -tags "saml"         # include SAML 2.0 identity bridge
go build -tags "ldap"         # include LDAP/Active Directory bridge
go build -tags "ion,saml,ldap" # all optional features
```

## Configuration

Copy `config.yaml.example` to `config.yaml`. Key settings:

| Key | Description |
|-----|-------------|
| `issuer` | Canonical HTTPS URL — used as OIDC issuer and `did:web` base _(required)_ |
| `listen_addr` | HTTP bind address (default `:8080`) |
| `db_path` | SQLite database file path |
| `api_key` | Bearer token for admin/service endpoints (leave empty to disable) |
| `identity.signing_key` | Path to Ed25519 private key PEM |
| `identity.passphrase` | Argon2id passphrase for key decryption |
| `totp_passphrase` | Passphrase for TOTP secret encryption (defaults to `identity.passphrase`) |
| `rate_limit` | Requests per second per IP (default `50`) |
| `bridges.oidc[]` | OIDC relying-party bridges — `name`, `issuer`, `client_id`, `client_secret`, `scopes` |
| `bridges.password.enabled` | Enable legacy password bridge (default `false`) |

Environment variables override config with the prefix `TPT_IDENTITY_` (e.g. `TPT_IDENTITY_API_KEY`).

## Architecture

```
┌────────────────────────────────────────────────────────────────┐
│                         tpt-identity                           │
│                                                                │
│  ┌──────────────────── Identity Bridge ──────────────────────┐ │
│  │  OIDC RP (Google/GitHub/Azure)  │  Magic Link  │  SAML†  │ │
│  │  LDAP/AD†  │  Password (opt-in) │  WebAuthn (planned)    │ │
│  └───────────────────────┬─────────────────────────────────── ┘ │
│                          │ ExternalIdentity → platform DID      │
│  ┌────────┐  ┌────────┐  ┌───────────┐  ┌──────────────────┐  │
│  │  DID   │  │   VC   │  │  Consent  │  │  OIDC Provider   │  │
│  │ layer  │  │ issue/ │  │ grants +  │  │  PKCE · RFC 7591 │  │
│  │w/k/p/i │  │ verify │  │ receipts  │  │  RFC 7009 · JWKS │  │
│  └────┬───┘  └───┬────┘  └─────┬─────┘  └────────┬─────────┘  │
│       │          │              │                  │            │
│  ┌────┴──────────┴──────────────┴──────────────────┴──────────┐ │
│  │           SQLite store  (PostgreSQL-compatible schema)     │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │   REST API  (audit log · rate limiting · webhook events)   │ │
│  └────────────────────────────────────────────────────────────┘ │
└────────────────────────────────────────────────────────────────┘
 † requires build tag
```

## API endpoints

### Public — no auth required

| Method | Path | Description |
|--------|------|-------------|
| GET | `/.well-known/openid-configuration` | OIDC discovery document |
| GET | `/.well-known/jwks.json` | JSON Web Key Set (Ed25519 public key) |
| GET | `/.well-known/did.json` | Local DID document |
| GET | `/authorize` | OIDC authorization (PKCE + state required) |
| POST | `/token` | Token exchange, refresh token grant |
| GET | `/userinfo` | Subject DID + AMR from bearer token |
| POST | `/oidc/register` | RFC 7591 dynamic client registration |
| POST | `/oidc/revoke` | RFC 7009 token revocation |
| GET | `/healthz` | Liveness probe |
| GET | `/readyz` | Readiness probe (DB check) |
| GET | `/api/v1/status/{listId}` | BitstringStatusList credential |

### Identity bridge — public

| Method | Path | Description |
|--------|------|-------------|
| GET | `/auth/{provider}` | Start redirect-based bridge flow (OIDC RP, SAML†) |
| GET | `/auth/{provider}/callback` | OAuth2/OIDC callback — issues platform auth code |
| POST | `/auth/magiclink/request` | Request a magic link for an email address |
| GET | `/auth/magiclink/verify` | Verify magic link token — issues platform auth code |

### Self-service — bearer token (user's own access token)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/me/sessions` | List active sessions |
| DELETE | `/api/v1/me/sessions/{id}` | Revoke a session |
| GET | `/api/v1/me/links` | List linked external providers |
| DELETE | `/api/v1/me/links/{provider}` | Unlink a provider (refuses if last auth method) |
| POST | `/api/v1/me/totp/enrol` | Enrol TOTP — returns `otpauth://` URI |
| POST | `/api/v1/me/totp/verify` | Verify a TOTP code |
| DELETE | `/api/v1/me/totp` | Remove TOTP enrolment |

### Protected — Bearer `api_key`

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/identities` | Register a DID |
| GET | `/api/v1/identities/{did}` | Resolve identity |
| POST | `/api/v1/credentials` | Issue a W3C VC (DataIntegrityProof) |
| POST | `/api/v1/credentials/verify` | Verify a W3C VC |
| GET | `/api/v1/credentials` | List credentials for a subject |
| DELETE | `/api/v1/credentials/{id}` | Delete a credential |
| POST | `/api/v1/credentials/sd-jwt` | Issue an SD-JWT credential |
| POST | `/api/v1/credentials/sd-jwt/verify` | Verify an SD-JWT presentation |
| GET/POST/DELETE | `/api/v1/consents/grants` | Consent grant management |
| GET | `/api/v1/consents/receipts` | Consent receipt audit trail |
| GET | `/api/v1/schemas` | Full schema taxonomy |
| POST/GET/DELETE | `/api/v1/webhooks` | Webhook subscription management |
| POST | `/api/v1/presentations/request` | Create a DIF PE v2 presentation request |
| POST | `/api/v1/presentations/submit` | Submit a VP against a presentation definition |
| DELETE | `/api/v1/sessions/{id}` | Admin session revocation |

## Security notes

- **PKCE** (S256) is mandatory on all authorization code flows; `state` is also required (CSRF protection)
- **Dynamic client registration** is required — `AuthorizeHandler` rejects unregistered `client_id` values
- **Refresh tokens** are stored by `sha256(raw_token)`, single-use, with replay detection (stolen token detection)
- **did:key** is rejected as a VC issuer DID — key rotation is structurally impossible
- **did:web** resolution blocks RFC-1918 IP ranges with a 5-second timeout (SSRF hardening)
- **Argon2id** (64 MB / 3 iterations / 4 threads) for all key derivation from passphrases
- **LDAP bridge** requires `ldaps://` — plaintext `ldap://` is refused at startup
- Consent grant withdrawal sets `revokedAt` — records are never deleted (NZ Privacy Act 2020 audit trail)
- Extra-sensitive schemas (mental-health, addiction, criminal-record, etc.) require individual explicit grants even when a category grant is active

## Credential schema taxonomy

50+ schemas across 11 categories. See [SCHEMA.md](SCHEMA.md) for the full reference.

Categories: `identity` · `healthcare` · `finance` · `professional` · `education` · `legal` · `property` · `civic` · `social` · `travel` · `insurance`

## License

Apache 2.0 — see [LICENSE](LICENSE).
