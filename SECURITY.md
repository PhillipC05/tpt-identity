# Security Policy

## Supported versions

tpt-identity is pre-release software under active development. Security fixes are applied to the `main` branch only.

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Report security issues by email to: **phillipthen@gmail.com**

Include:
- A description of the vulnerability
- Steps to reproduce, or a proof-of-concept
- The potential impact
- Any suggested mitigations you are aware of

You will receive an acknowledgement within **2 business days** and a full response within **7 business days**.

## Disclosure process

1. You report the vulnerability privately
2. We confirm the issue and assess severity
3. We develop and test a fix
4. We release the fix and notify you
5. You may publish details **14 days** after the fix is released, or earlier by mutual agreement

We ask that you do not disclose the vulnerability publicly until we have had a reasonable opportunity to address it.

## Scope

The following are in scope:

- Authentication and authorisation bypasses
- Token forgery or signature verification flaws
- Privilege escalation
- Credential data exposure
- Consent bypass (accessing data without a valid grant)
- Cryptographic weaknesses in key storage, signing, or encryption
- SQL injection or data corruption

The following are **out of scope**:

- Denial-of-service attacks
- Rate limiting bypass (not yet implemented — see RISKS.md)
- Missing security headers on non-sensitive endpoints
- Issues requiring physical access to the server
- Social engineering

## Cryptographic design

For context when reviewing the codebase:

| Primitive | Usage |
|---|---|
| Ed25519 | JWT signing (OIDC tokens), VC signing, DID key material |
| X25519 + NaCl secretbox | Asymmetric encryption |
| Argon2id | Key derivation for keystore encryption (64MB / 3 iterations / 4 threads) |
| AES-256-GCM | Symmetric encryption of key material at rest |
| SHA-256 | Token hashing, credential proof hashing |
| HMAC-SHA1 | TOTP (RFC 6238 — algorithm is spec-mandated) |

## Known limitations and deferred risks

See [RISKS.md](RISKS.md) for documented deferred risks and their planned resolution triggers.
