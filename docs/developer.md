# Developer Guide

This guide covers everything needed to integrate a Go service with tpt-identity. By the end you will have a service that:

- Authenticates to tpt-identity using OIDC `client_credentials`
- Issues and verifies Verifiable Credentials
- Checks consent before accessing user data
- Protects HTTP routes with drop-in middleware

---

## Prerequisites

- Go 1.22+
- A running tpt-identity instance (see [README.md](../README.md))
- Your service registered as an OIDC client (see below)

---

## 1. Register your service

Every downstream service must register once to receive a `client_id` and `client_secret`. Registration is open (no auth required) and follows RFC 7591.

```bash
curl -X POST https://identity.tpt.govt.nz/oidc/register \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "tpt-healthcare",
    "redirect_uris": ["https://healthcare.tpt.govt.nz/callback"],
    "grant_types": ["authorization_code", "refresh_token", "client_credentials"]
  }'
```

Response:
```json
{
  "client_id": "a3f8b2...",
  "client_secret": "7c91d4...",
  "client_name": "tpt-healthcare",
  "grant_types": ["authorization_code", "refresh_token", "client_credentials"]
}
```

Store `client_id` and `client_secret` as environment variables or secrets. The secret is shown once and cannot be retrieved again.

---

## 2. Install the SDK

```bash
go get github.com/PhillipC05/tpt-identity/client
go get github.com/PhillipC05/tpt-identity/middleware
```

---

## 3. Create a client

```go
import "github.com/PhillipC05/tpt-identity/client"

idClient := client.NewClient(client.Config{
    BaseURL:      "https://identity.tpt.govt.nz",
    ClientID:     os.Getenv("TPT_CLIENT_ID"),
    ClientSecret: os.Getenv("TPT_CLIENT_SECRET"),
})
```

The client is safe for concurrent use. It acquires an access token on the first API call and automatically refreshes it 30 seconds before expiry.

---

## 4. Protect routes with middleware

### Require consent only (verify the user has granted access)

```go
import "github.com/PhillipC05/tpt-identity/middleware"

mux.Handle("/patient/summary",
    middleware.RequireConsent(idClient, "healthcare.gp-records")(handler))
```

### Require consent AND a valid credential

```go
mux.Handle("/patient/records",
    middleware.RequireCredential(idClient, "healthcare.gp-records")(handler))
```

### Multiple credential types

```go
mux.Handle("/patient/full",
    middleware.RequireCredential(idClient,
        "healthcare.gp-records",
        "healthcare.specialist",
    )(handler))
```

### Reading context values in the handler

```go
func myHandler(w http.ResponseWriter, r *http.Request) {
    subjectDID := middleware.SubjectDID(r.Context())
    grants := middleware.Grants(r.Context())
    // subjectDID is the user's DID, e.g. "did:web:alice.example.com"
    // grants is the full list of consent grants for this user
}
```

---

## 5. Issue credentials

```go
cred, err := idClient.IssueCredential(ctx, client.IssueCredentialRequest{
    IssuerDID:            "did:web:identity.tpt.govt.nz",
    VerificationMethodID: "did:web:identity.tpt.govt.nz#signing-key-1",
    SubjectDID:           "did:web:alice.example.com",
    SchemaID:             "healthcare.gp-records",
    Claims: map[string]string{
        "given_name":  "Alice",
        "family_name": "Smith",
        "nhi_number":  "ZZZ0024",
    },
    ValidFor: 365 * 24 * time.Hour,
})
```

---

## 6. Verify a credential

```go
err := idClient.VerifyCredential(ctx, cred)
if err != nil {
    // credential is invalid, expired, or revoked
}
```

---

## 7. Consent management

### Show a user what a service is requesting (consent screen)

```go
challenge, err := idClient.GetConsentChallenge(ctx, clientID, "healthcare.gp-records")
// challenge.ClientName   → "TPT Healthcare"
// challenge.SchemaName   → "GP Records"
// challenge.SchemaDesc   → "Your medical history..."
// challenge.ExtraSensitive → false
// challenge.LegalBasis   → "consent"
// challenge.Revocable    → true
```

### Record consent after user approval

```go
grant, err := idClient.CreateGrant(ctx, &consent.Grant{
    SubjectDID:          "did:web:alice.example.com",
    RelyingDID:          "did:web:healthcare.tpt.govt.nz",
    Level:               consent.GrantSchema,
    ScopeID:             "healthcare.gp-records",
    ExplicitlyConfirmed: true,
})
```

### List a user's grants (audit view)

```go
grants, err := idClient.ListGrants(ctx, "did:web:alice.example.com")
```

### Revoke a grant

```go
err := idClient.RevokeGrant(ctx, grant.ID)
```

---

## 8. Credential schemas

A schema ID has the form `category.name`, e.g. `healthcare.gp-records`.

| Category | Example schemas |
|---|---|
| `healthcare` | `gp-records`, `specialist`, `pharmacy`, `allergies`, `immunisation`, `radiology`, `pathology`, `dental`, `acc-injury`, `disability` |
| `healthcare` (extra-sensitive) | `mental-health`, `sexual-health`, `reproductive-health`, `addiction` |
| `identity` | `legal-name`, `date-of-birth`, `address`, `passport`, `drivers-licence`, `nhi-number`, `ird-number` |
| `finance` | `bank-account`, `income`, `tax-records`, `credit-history`, `benefits`, `insurance`, `investments`, `property` |
| `education` | `enrolments`, `transcripts`, `nzqa-qualifications` |
| `legal` | `court-orders`, `power-of-attorney`, `wills`, `immigration-status` |
| `legal` (extra-sensitive) | `criminal-record` |
| `civic` | `electoral-roll`, `benefits`, `tax-filing`, `business-registration` |

List all available schemas at runtime:
```bash
curl -H "Authorization: Bearer <token>" https://identity.tpt.govt.nz/api/v1/schemas
```

---

## 9. Token operations

### Introspect a token (check if active)

```go
result, err := idClient.IntrospectToken(ctx, token)
if result.Active {
    fmt.Println("subject:", result.Subject)
}
```

### Revoke a token

```go
err := idClient.RevokeToken(ctx, token)
```

---

## 10. API reference

All protected endpoints require `Authorization: Bearer <token>` (OIDC access token or static API key).

### OIDC

| Method | Path | Description |
|---|---|---|
| `GET` | `/.well-known/openid-configuration` | OIDC discovery document |
| `GET` | `/.well-known/jwks.json` | Public signing keys (JWKS) |
| `POST` | `/oidc/register` | Register a new OIDC client (RFC 7591) |
| `GET` | `/authorize` | Start authorization code flow |
| `POST` | `/token` | Exchange code or get token (auth_code, refresh_token, client_credentials) |
| `GET` | `/userinfo` | Get claims for authenticated user |
| `POST` | `/oidc/introspect` | Check if a token is active (RFC 7662) |
| `POST` | `/oidc/revoke` | Revoke a token (RFC 7009) |

### Identities

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/v1/identities` | Create a new DID and keypair |
| `GET` | `/api/v1/identities/{did}` | Resolve a DID to its document |

### Credentials

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/v1/credentials` | Issue a Verifiable Credential |
| `POST` | `/api/v1/credentials/verify` | Verify a credential |
| `GET` | `/api/v1/credentials?subject={did}` | List credentials for a subject |
| `DELETE` | `/api/v1/credentials/{id}` | Delete a credential |

### Consent

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/v1/consents/challenge` | Human-readable description of a consent request |
| `GET` | `/api/v1/consents/grants?subject={did}` | List consent grants |
| `POST` | `/api/v1/consents/grants` | Create a consent grant |
| `DELETE` | `/api/v1/consents/grants/{id}` | Revoke a consent grant |
| `GET` | `/api/v1/consents/receipts?subject={did}` | List signed consent receipts |

### Schemas

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/v1/schemas` | List all credential schemas by category |

---

## 11. Error responses

All errors use the OIDC error format:

```json
{"error": "invalid_client", "error_description": "client_id required"}
```

| Code | HTTP status | Meaning |
|---|---|---|
| `invalid_client` | 400 | Unknown or invalid client credentials |
| `invalid_grant` | 400 | Code or refresh token is invalid or expired |
| `unsupported_grant_type` | 400 | Grant type not supported |
| `invalid_request` | 400 | Missing or malformed parameter |
| `unauthorized_client` | 400 | Client not allowed to use this grant |
| — | 401 | Missing or invalid Bearer token |
| — | 403 | Consent not granted for schema |

---

## 12. Local development

Run tpt-identity locally without TLS or a real domain:

```bash
cp config.yaml.example config.yaml
# Set issuer: "http://localhost:8080"
# Set api_key: "dev-key"

go run ./cmd/tpt-identity keygen --out keys/
go run ./cmd/tpt-identity serve --config config.yaml
```

In your service, set:
```
TPT_CLIENT_ID=<from registration>
TPT_CLIENT_SECRET=<from registration>
TPT_IDENTITY_URL=http://localhost:8080
```
