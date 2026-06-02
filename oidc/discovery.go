package oidc

import (
	"encoding/json"
	"net/http"
)

// DiscoveryDocument is the OIDC Provider Configuration per RFC 8414.
type DiscoveryDocument struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	UserinfoEndpoint                  string   `json:"userinfo_endpoint"`
	JwksURI                           string   `json:"jwks_uri"`
	RegistrationEndpoint              string   `json:"registration_endpoint"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	ScopesSupported                   []string `json:"scopes_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	ClaimsSupported                   []string `json:"claims_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
}

// DiscoveryHandler returns an HTTP handler serving the OIDC discovery document.
// It is a method on Provider so the document reflects actual provider configuration.
func (p *Provider) DiscoveryHandler(w http.ResponseWriter, r *http.Request) {
	doc := DiscoveryDocument{
		Issuer:                            p.issuer,
		AuthorizationEndpoint:             p.issuer + "/authorize",
		TokenEndpoint:                     p.issuer + "/token",
		UserinfoEndpoint:                  p.issuer + "/userinfo",
		JwksURI:                           p.issuer + "/.well-known/jwks.json",
		RegistrationEndpoint:              p.issuer + "/oidc/register",
		ResponseTypesSupported:            []string{"code"},
		SubjectTypesSupported:             []string{"public"},
		IDTokenSigningAlgValuesSupported:  []string{"EdDSA"},
		ScopesSupported:                   []string{"openid", "profile", "did"},
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic", "none"},
		ClaimsSupported:                   []string{"sub", "iss", "iat", "exp", "nonce", "did", "amr"},
		GrantTypesSupported:               []string{"authorization_code", "refresh_token"},
	}
	b, _ := json.MarshalIndent(doc, "", "  ")
	w.Header().Set("Content-Type", "application/json")
	w.Write(b)
}
