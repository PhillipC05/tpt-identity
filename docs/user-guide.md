# Your Identity and Credentials — User Guide

This guide explains how TPT Identity works from your perspective: what data is stored, who can access it, how you control that access, and what your rights are.

---

## What is TPT Identity?

TPT Identity is the secure foundation that lets you share verified information about yourself with TPT services — like healthcare providers, government services, and financial institutions — without those services storing your personal data themselves.

Instead of giving each service a copy of your records, TPT Identity issues you **Verifiable Credentials**: digitally signed statements that prove something about you. You control which services can see which credentials, and you can withdraw that access at any time.

---

## Your credentials

A Verifiable Credential is a tamper-proof digital document that says something specific about you — for example:

- *"This person's legal name is Alice Smith"*
- *"This person has been registered with GP Dr. Jones since 2019"*
- *"This person holds a current NZ driver licence"*

Each credential:
- Is signed with a cryptographic key that proves it came from a trusted issuer
- Can be verified by any service without calling the issuer to check
- Is tied to your unique identity (your DID — see below)
- Can have an expiry date
- Can be revoked if circumstances change

### Credential categories

Your credentials are organised into categories:

| Category | What it covers |
|---|---|
| **Healthcare** | GP records, specialist visits, pharmacy, allergies, immunisation, radiology, pathology, dental, ACC, disability |
| **Identity** | Legal name, date of birth, address, passport, driver licence, NHI number, IRD number |
| **Finance** | Bank accounts, income, tax records, credit history, insurance, investments, property |
| **Education** | School enrolments, transcripts, NZQA qualifications |
| **Legal** | Court orders, power of attorney, wills, immigration status |
| **Civic** | Electoral roll, benefits, tax filing, business registration |
| **Professional** | Qualifications, registrations, practising certificates |
| **Travel** | Passports, visas, vaccination certificates |

### Extra-sensitive credentials

Some credentials are marked **extra-sensitive** because of the particular harm their disclosure could cause. These include:

- Mental health records
- Sexual health records
- Reproductive health records
- Addiction treatment records
- Criminal record

For extra-sensitive credentials, each individual service must receive separate, explicit approval from you — even if you have already approved general healthcare access. You will always be shown a specific prompt before these are shared.

---

## Your digital identity (DID)

Your identity in TPT is a **Decentralised Identifier (DID)** — a unique, cryptographically verifiable identifier that you own. Unlike an email address or username, no company controls your DID; it is mathematically derived from your keys.

Your DID looks something like:
```
did:web:alice.example.com
```
or for a device-based identity:
```
did:key:z6Mk...
```

Your DID is the anchor for all your credentials and consent grants. It is stored in tpt-identity and is not shared with third parties without your consent.

---

## Consent: controlling who sees what

Before any TPT service can access your credentials, it must have your explicit consent. Consent is:

- **Specific** — you approve access to a named credential type (e.g. "GP Records"), not everything at once
- **Time-limited** — consent grants can have an expiry date
- **Revocable** — you can withdraw consent at any time; this takes effect immediately
- **Audited** — every time a service accesses your data, a signed receipt is created

### What you will be shown before approving

When a service requests access, you will see:

| Field | Example |
|---|---|
| Service name | TPT Healthcare |
| What they are requesting | GP Records |
| Why they say they need it | *"To provide you with clinical care and coordinate treatment"* |
| Legal basis | Consent |
| Whether access is extra-sensitive | No |
| Whether you can revoke it later | Yes |

You should not approve access if the purpose is unclear or does not match what the service offers.

### Consent receipts

Every time a service accesses your credentials, tpt-identity creates a **consent receipt** — a cryptographically signed record that includes:

- Which service accessed your data
- Which credential type was accessed
- When the access happened
- The legal basis for the access
- Your consent grant ID

These receipts cannot be altered or deleted. They are your audit trail under the NZ Privacy Act 2020.

---

## Viewing and revoking your access grants

You can see all your active consent grants and receipts through any TPT application that has been granted access to your consent data. Look for **Privacy** or **My Data** settings in any connected TPT service.

To revoke access to a specific service:

1. Find the grant in your Privacy settings
2. Select "Revoke access"
3. Confirm

Revoking a grant does not delete the consent receipt — the record that access was once granted is preserved as required by law. It only prevents future access.

---

## Your rights under the NZ Privacy Act 2020

As a user of TPT services, you have the following rights:

- **Right of access** — you can request a copy of all personal information held about you
- **Right of correction** — you can request correction of information you believe is wrong
- **Right to be informed** — you have the right to know who holds your information and why
- **Right to withdraw consent** — you can revoke access at any time without giving a reason
- **Right to complain** — if you believe your privacy rights have been breached, you can complain to the Privacy Commissioner at [privacy.org.nz](https://www.privacy.org.nz)

---

## Data retention

- **Credentials** — kept until you delete them or they expire
- **Consent grants** — kept permanently (the fact that consent was given is an auditable record), but revoked grants no longer allow access
- **Consent receipts** — kept permanently as required by the NZ Privacy Act 2020 audit obligations
- **OIDC sessions** — automatically purged when they expire

---

## Security

Your private keys never leave the tpt-identity server in unencrypted form. Key files are protected with Argon2id key derivation (GPU-resistant) and AES-256-GCM encryption.

If you believe your identity may have been compromised, contact the operator of the TPT service you use.

---

## Questions?

If you have questions about your data or want to exercise your privacy rights, contact the operator of the TPT service you are using. Their contact details should be available in the service's privacy policy.
