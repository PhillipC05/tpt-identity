# Contributing

Thank you for considering a contribution to tpt-identity. This is security-critical infrastructure; contributions are reviewed carefully.

---

## Development setup

```bash
git clone https://github.com/PhillipC05/tpt-identity
cd tpt-identity
go mod download

# Generate keys for local testing
go run ./cmd/tpt-identity keygen --out keys/

# Copy and configure
cp config.yaml.example config.yaml
# Set issuer: "http://localhost:8080"

# Run
go run ./cmd/tpt-identity serve --config config.yaml
```

Build and verify:

```bash
go build -mod=vendor ./...
go vet ./...
```

---

## Code standards

- **No new external dependencies without discussion.** The dependency surface is deliberately minimal; additions require justification in the PR.
- **No comments explaining what the code does** — only comments explaining *why* when the reason is non-obvious.
- **No error swallowing.** Every error must be handled or explicitly propagated.
- **No `interface{}` / `any` in public API types** unless unavoidable (e.g. JSON claims).
- **Cryptography stays in `pkg/crypto/` and `pkg/keystore/`.** Do not scatter crypto operations across handlers.
- **Consent rules stay in `pkg/consent/`.** The `ExtraSensitive` flag and explicit confirmation requirements must be enforced consistently.

---

## Testing

There are currently no automated tests (pre-release). New code should be accompanied by tests where possible. Focus areas for test coverage:

- `pkg/vc/` — credential issuance and verification
- `pkg/consent/` — policy enforcement
- `oidc/` — token flows
- `client/` — SDK behaviour

Run tests (when they exist):

```bash
go test ./...
```

---

## Pull requests

1. **Fork** the repository and create a feature branch from `main`
2. Keep changes focused — one logical change per PR
3. Update `RISKS.md` if your change introduces a known limitation that cannot be addressed immediately
4. Describe the *why* in the PR description, not just the what
5. For security-sensitive changes (crypto, auth, consent), request review from the maintainer before investing significant implementation effort

---

## Security-sensitive areas

Extra care is required for changes touching:

| Area | Risk |
|---|---|
| `oidc/provider.go` | Token issuance and validation — vulnerabilities here affect all downstream services |
| `pkg/crypto/`, `pkg/keystore/` | Key material handling — mistakes here can expose private keys |
| `pkg/consent/policy.go` | Consent enforcement — bypasses here violate user privacy and NZ Privacy Act 2020 |
| `internal/store/` | Persistence — SQL injection, data corruption |
| `api/server.go` — auth middleware | Authentication bypass |

If you are unsure whether a change touches these areas, ask before opening a PR.

---

## Licence

By contributing, you agree that your contributions will be licensed under the [MIT Licence](LICENSE).
