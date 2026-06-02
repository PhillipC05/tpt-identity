# tpt-identity — Deferred Risks

Items here are real risks that are deliberately deferred because they depend on context that doesn't exist yet (downstream consumers, deployment model, frontend), or because they are pre-release polish. Each has a clear trigger for when to address it.

---

## 1. OIDC back-channel logout

**Risk:** When a user's session at tpt-identity ends, downstream services (tpt-healthcare, tpt-email) retain valid access tokens until expiry. For a multi-service ecosystem this means session termination is not atomic.

**Why deferred:** No downstream consumers exist yet. The back-channel logout spec (OIDC Core / Back-Channel Logout 1.0) requires registered logout URIs per client — that wiring can't be done until there are clients to wire.

**Trigger:** Implement when the first downstream TPT module goes live and registers as an OIDC client. Add `oidc/logout.go` — `POST /oidc/backchannel_logout`; fan out logout tokens to all registered client logout URIs on session end.

---

## 2. DNS reputation is a weak trust anchor

**Risk:** `pkg/trust/reputation.go` (ported from tpt-email) uses DNS TXT records for federated reputation signals. DNS is controlled by registrars, subject to BGP/DNS hijacking, and doesn't align with DID resolution trust models. It should not be used as a security assertion.

**Why deferred:** The module is a direct port and not yet wired into anything critical. Redesigning it requires a clearer trust model for the broader TPT ecosystem.

**Trigger:** Before any production deployment relies on reputation scores for access control decisions. Long-term replacement: reputation expressed as a signed VC from a known issuer, not a DNS lookup.

---

## 3. Keystore backup and recovery

**Risk:** If the keystore file is lost or corrupted, the identity is unrecoverable. For an operator running tpt-identity as the backbone of the TPT ecosystem, this is catastrophic.

**Why deferred:** The right backup mechanism depends on the deployment model (bare metal, Docker, Kubernetes with secrets management, HSM). Providing a generic backup mechanism before knowing the deployment target risks providing a false sense of security.

**Trigger:** Before first production deployment. Add `cmd/tpt-identity/cmd/backup.go` and `restore.go` — encrypted export/import with a separate recovery passphrase. Document that this is an operator responsibility and what the recovery procedure is.

---

## 4. CORS configuration

**Risk:** If any browser-based frontend calls the tpt-identity API directly, CORS headers need to be explicitly configured. Leaving CORS to framework defaults will either block legitimate requests or be too permissive.

**Why deferred:** No browser frontend is planned for MVP. The API is consumed by server-to-server clients.

**Trigger:** When the first browser-facing frontend is built. Add explicit CORS middleware in `api/server.go` with an allowlist of permitted origins; never use wildcard `*` for an authenticated API.

---

## 6. Government identity federation (OIDC RP bridge)

**Risk:** Magic link authentication proves only that a user controls an email inbox — not who they are. For healthcare, legal, and financial credentials this is insufficient. High-assurance use cases require verified identity from a government-backed source. Building country-specific bridges (RealMe, GOV.UK One Login, myID, etc.) in parallel would fragment the codebase and duplicate OIDC RP logic.

**Why deferred:** No downstream consumer yet requires verified identity. The right trigger is the first credential schema that demands it (e.g. `healthcare.gp-records` requiring `assurance_level: verified`). Building before that point risks over-engineering for requirements that don't exist yet.

**Design decision (captured now to avoid re-litigation later):** Implement one generic OIDC RP bridge, not country-specific bridges. Every modern government IdP speaks OIDC — RealMe (NZ), GOV.UK One Login (UK), myID (AU), Singpass (SG), GCKey (CA), Login.gov (US), and eIDAS federation nodes all use the same authorisation code flow. The difference between them is configuration, not code. A NZ deployment configures RealMe; a UK deployment configures GOV.UK One Login; both run the same bridge.

**Trigger:** When the first downstream TPT module requires verified identity for a credential schema, or when tpt-identity is deployed in a jurisdiction where government-verified identity is mandatory for a use case.

**Implementation sketch:**

1. Add `oidc_providers` array to `internal/config/config.go` — each entry has `name`, `display_name`, `issuer` (OIDC discovery URL), `client_id`, `client_secret`:
   ```yaml
   oidc_providers:
     - name: realme
       display_name: "RealMe (New Zealand)"
       issuer: "https://mts.realme.govt.nz/..."
       client_id: "..."
       client_secret: "..."
     - name: google
       display_name: "Sign in with Google"
       issuer: "https://accounts.google.com"
       client_id: "..."
       client_secret: "..."
   ```

2. Implement `internal/bridge/providers/oidcrp.go` — generic OIDC RP bridge (~150 lines). Fetches the discovery document, runs authorisation code flow via stdlib `net/http`, maps the `acr` claim from the IdP token into `ExternalIdentity.Claims["assurance_level"]`.

3. Add `GET /auth/oidc/{provider}/start` and `GET /auth/oidc/{provider}/callback` routes in `internal/auth/login.go`. The login page renders a button per configured provider alongside the existing magic link form.

4. `ExternalIdentity.Claims["assurance_level"]` propagates through `bridge.Mapper.FindOrCreate()` and gets stored on the external link record. Schema issuance checks it when `ExtraSensitive: true` — a category-level consent grant is insufficient; the subject must have `assurance_level: verified`.

**Assurance level mapping:**

| Provider | Claim | Maps to |
|---|---|---|
| RealMe Login | `acr: LowStrength` | `self-asserted` |
| RealMe Verified | `acr: HighStrength` | `verified` |
| GOV.UK One Login | `vot: P1` / `P2` | `self-asserted` / `verified` |
| eIDAS | `acr: low` / `substantial` / `high` | direct |
| Google / Apple / commercial | (no government assurance) | `self-asserted` |

Magic link and commercial social login (Google, Apple) are always `self-asserted` — they prove email control, not legal identity. Only government IdPs at substantial/high assurance produce `verified`.

---

## 5. did:key key rotation (permanent limitation)

**Risk:** did:key encodes the public key into the DID. Key rotation is structurally impossible — a compromised did:key DID is compromised permanently.

**Why deferred:** This is a spec constraint, not a fixable bug. The TODO already enforces the usage constraint (did:key for ephemeral/offline use only; persistent credentials must use did:web). Documenting it here for operator awareness.

**Trigger:** Document explicitly in `PROTOCOL.md` with guidance on what "ephemeral/offline" means in practice and what to do if a did:key private key is suspected compromised (answer: the DID must be considered abandoned; issue new credentials under a did:web DID).
