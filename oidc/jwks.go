package oidc

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
)

// JWK represents a JSON Web Key for an Ed25519 (OKP) public key.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid,omitempty"`
}

// JWKS is a JSON Web Key Set.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWKSHandler serves GET /.well-known/jwks.json.
// The slice allows publishing old+new keys during rotation.
func (p *Provider) JWKSHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	json.NewEncoder(w).Encode(JWKS{Keys: p.publicJWKS()})
}

// publicJWKS returns all trusted public keys as JWKs: current key first, then previous
// keys from the rotation history. Previous keys are included until tokens signed with
// them have expired (typically 1–2 TTLs after the rotation date).
func (p *Provider) publicJWKS() []JWK {
	keys := []JWK{{
		Kty: "OKP",
		Crv: "Ed25519",
		X:   base64.RawURLEncoding.EncodeToString([]byte(p.signingPub)),
		Use: "sig",
		Alg: "EdDSA",
		Kid: p.keyID,
	}}
	for i, prev := range p.prevKeys {
		keys = append(keys, JWK{
			Kty: "OKP",
			Crv: "Ed25519",
			X:   base64.RawURLEncoding.EncodeToString([]byte(prev)),
			Use: "sig",
			Alg: "EdDSA",
			Kid: fmt.Sprintf("%s-prev-%d", p.keyID, i+1),
		})
	}
	return keys
}
