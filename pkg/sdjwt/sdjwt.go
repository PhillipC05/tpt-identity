// Package sdjwt implements Selective Disclosure JWT (SD-JWT) per RFC 9449.
//
// SD-JWT allows a holder to present only a chosen subset of claims from a
// credential without revealing the others. The issuer salts and hashes each
// selectively-disclosable claim; the holder presents the SD-JWT plus the
// disclosures for the claims they choose to reveal.
//
// Wire format:  <header>.<payload>.<sig>~<disclosure1>~<disclosure2>~...
// Disclosure:   BASE64URL(JSON([salt, claim_name, claim_value]))
// Hash in JWT:  BASE64URL(SHA-256(disclosure_bytes))
package sdjwt

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/PhillipC05/tpt-identity/oidc"
)

// Disclosure is the decoded form of a single selectively-disclosed claim.
type Disclosure struct {
	Salt  string
	Name  string
	Value any
}

// IssueOptions controls SD-JWT creation.
type IssueOptions struct {
	Issuer     string
	Subject    string
	KeyID      string
	SigningKey  ed25519.PrivateKey
	TTL        time.Duration
	// PlainClaims are included as ordinary JWT claims visible to all verifiers.
	PlainClaims map[string]any
	// SelectiveClaims are hashed; only disclosed when the holder includes their disclosure.
	SelectiveClaims map[string]any
}

// Issued is the result of SD-JWT issuance.
type Issued struct {
	// Token is the signed JWT (without disclosures appended).
	Token string
	// Disclosures holds one base64url-encoded disclosure per selective claim.
	Disclosures []string
	// Combined is the full presentation string: Token~disc1~disc2~...
	Combined string
}

// Issue creates a signed SD-JWT from the given options.
func Issue(opts IssueOptions) (*Issued, error) {
	if opts.SigningKey == nil {
		return nil, fmt.Errorf("sdjwt: signing key required")
	}
	disclosures := make([]string, 0, len(opts.SelectiveClaims))
	hashes := make([]string, 0, len(opts.SelectiveClaims))

	for name, value := range opts.SelectiveClaims {
		salt, err := randomSalt()
		if err != nil {
			return nil, fmt.Errorf("sdjwt: generate salt: %w", err)
		}
		disc, err := encodeDisclosure(salt, name, value)
		if err != nil {
			return nil, fmt.Errorf("sdjwt: encode disclosure %q: %w", name, err)
		}
		disclosures = append(disclosures, disc)
		hashes = append(hashes, hashDisclosure(disc))
	}

	now := time.Now()
	payload := map[string]any{
		"iss": opts.Issuer,
		"sub": opts.Subject,
		"iat": now.Unix(),
		"exp": now.Add(opts.TTL).Unix(),
		"_sd": hashes,
		"_sd_alg": "sha-256",
	}
	for k, v := range opts.PlainClaims {
		payload[k] = v
	}

	token, err := signPayload(payload, opts.SigningKey, opts.KeyID)
	if err != nil {
		return nil, fmt.Errorf("sdjwt: sign: %w", err)
	}

	parts := []string{token}
	parts = append(parts, disclosures...)
	combined := strings.Join(parts, "~")

	return &Issued{
		Token:       token,
		Disclosures: disclosures,
		Combined:    combined,
	}, nil
}

// Presentation is the set of claims visible after verifying a presentation.
type Presentation struct {
	Issuer    string
	Subject   string
	IssuedAt  time.Time
	ExpiresAt time.Time
	// Claims contains only the claims whose disclosures were included.
	Claims map[string]any
}

// Verify parses and verifies an SD-JWT presentation string (Token~disc1~disc2~...).
// Only claims whose disclosures are present in the presentation are returned.
func Verify(presentation string, pubKey ed25519.PublicKey) (*Presentation, error) {
	parts := strings.Split(presentation, "~")
	if len(parts) == 0 {
		return nil, fmt.Errorf("sdjwt: empty presentation")
	}
	token := parts[0]
	disclosureParts := parts[1:]

	claims, err := oidc.Verify(token, pubKey)
	if err != nil {
		return nil, fmt.Errorf("sdjwt: jwt verification failed: %w", err)
	}

	// Parse the raw payload to get _sd hashes and plain claims.
	rawPayload, err := decodePayload(token)
	if err != nil {
		return nil, fmt.Errorf("sdjwt: decode payload: %w", err)
	}

	// Build a set of accepted _sd hashes from the payload.
	accepted := map[string]bool{}
	if sdAny, ok := rawPayload["_sd"]; ok {
		if sdSlice, ok := sdAny.([]any); ok {
			for _, h := range sdSlice {
				if hs, ok := h.(string); ok {
					accepted[hs] = true
				}
			}
		}
	}

	// Decode each disclosure and accept those whose hash is in the _sd set.
	revealed := map[string]any{}
	for _, disc := range disclosureParts {
		if disc == "" {
			continue
		}
		h := hashDisclosure(disc)
		if !accepted[h] {
			return nil, fmt.Errorf("sdjwt: disclosure hash not found in token")
		}
		d, err := decodeDisclosure(disc)
		if err != nil {
			return nil, fmt.Errorf("sdjwt: decode disclosure: %w", err)
		}
		revealed[d.Name] = d.Value
	}

	return &Presentation{
		Issuer:    claims.Issuer,
		Subject:   claims.Subject,
		IssuedAt:  time.Unix(claims.IssuedAt, 0),
		ExpiresAt: time.Unix(claims.ExpiresAt, 0),
		Claims:    revealed,
	}, nil
}

// SelectivePresent builds a presentation string that discloses only the named claims.
// issued is the Combined string from Issue; revealClaims is the subset to disclose.
func SelectivePresent(issued string, revealClaims []string) (string, error) {
	parts := strings.Split(issued, "~")
	if len(parts) == 0 {
		return "", fmt.Errorf("sdjwt: empty issued string")
	}
	token := parts[0]
	allDisclosures := parts[1:]

	reveal := map[string]bool{}
	for _, c := range revealClaims {
		reveal[c] = true
	}

	selected := []string{token}
	for _, disc := range allDisclosures {
		d, err := decodeDisclosure(disc)
		if err != nil {
			continue
		}
		if reveal[d.Name] {
			selected = append(selected, disc)
		}
	}
	return strings.Join(selected, "~"), nil
}

// --- helpers ---

func randomSalt() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func encodeDisclosure(salt, name string, value any) (string, error) {
	arr := []any{salt, name, value}
	b, err := json.Marshal(arr)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func decodeDisclosure(disc string) (*Disclosure, error) {
	b, err := base64.RawURLEncoding.DecodeString(disc)
	if err != nil {
		return nil, err
	}
	var arr []any
	if err := json.Unmarshal(b, &arr); err != nil {
		return nil, err
	}
	if len(arr) != 3 {
		return nil, fmt.Errorf("disclosure must have 3 elements")
	}
	salt, ok := arr[0].(string)
	if !ok {
		return nil, fmt.Errorf("disclosure salt must be string")
	}
	name, ok := arr[1].(string)
	if !ok {
		return nil, fmt.Errorf("disclosure name must be string")
	}
	return &Disclosure{Salt: salt, Name: name, Value: arr[2]}, nil
}

func hashDisclosure(disc string) string {
	h := sha256.Sum256([]byte(disc))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func decodePayload(token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("not a JWT")
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// signPayload produces a compact JWS (header.payload.sig) using EdDSA / Ed25519.
func signPayload(payload map[string]any, key ed25519.PrivateKey, keyID string) (string, error) {
	header := map[string]any{"alg": "EdDSA", "typ": "sd+jwt"}
	if keyID != "" {
		header["kid"] = keyID
	}
	hb, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	pb, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	h64 := base64.RawURLEncoding.EncodeToString(hb)
	p64 := base64.RawURLEncoding.EncodeToString(pb)
	msg := h64 + "." + p64
	sig := ed25519.Sign(key, []byte(msg))
	return msg + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}
