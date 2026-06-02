package client

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// IntrospectResponse is the RFC 7662 token introspection response.
type IntrospectResponse struct {
	Active   bool   `json:"active"`
	Subject  string `json:"sub"`
	ClientID string `json:"client_id"`
	Issuer   string `json:"iss"`
	IssuedAt int64  `json:"iat"`
	Exp      int64  `json:"exp"`
	DID      string `json:"did"`
}

// IntrospectToken calls POST /oidc/introspect to check whether a token is active and
// retrieve its claims. Returns IntrospectResponse with Active=false for expired or
// revoked tokens (no error is returned in those cases).
func (c *Client) IntrospectToken(ctx context.Context, token string) (*IntrospectResponse, error) {
	body := url.Values{"token": {token}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.cfg.BaseURL+"/oidc/introspect",
		strings.NewReader(body.Encode()))
	if err != nil {
		return nil, fmt.Errorf("IntrospectToken: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("IntrospectToken: %w", err)
	}
	var result IntrospectResponse
	if err := decodeJSON(resp, &result); err != nil {
		return nil, fmt.Errorf("IntrospectToken: %w", err)
	}
	return &result, nil
}

// RevokeToken calls POST /oidc/revoke to revoke an access token.
func (c *Client) RevokeToken(ctx context.Context, token string) error {
	body := url.Values{"token": {token}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.cfg.BaseURL+"/oidc/revoke",
		strings.NewReader(body.Encode()))
	if err != nil {
		return fmt.Errorf("RevokeToken: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(c.cfg.ClientID, c.cfg.ClientSecret)

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("RevokeToken: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("RevokeToken: unexpected status %d", resp.StatusCode)
	}
	return nil
}
