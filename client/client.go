// Package client provides a typed Go SDK for calling the tpt-identity API.
// It handles OIDC client_credentials token acquisition, caching, and refresh
// automatically so callers never need to manage tokens manually.
//
// Usage:
//
//	c := client.NewClient(client.Config{
//	    BaseURL:      "https://identity.tpt.govt.nz",
//	    ClientID:     "my-service",
//	    ClientSecret: "secret",
//	})
//	cred, err := c.IssueCredential(ctx, req)
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// Config holds the connection and auth configuration for the tpt-identity client.
type Config struct {
	// BaseURL is the tpt-identity server root, e.g. "https://identity.tpt.govt.nz".
	BaseURL string
	// ClientID is the OIDC client ID obtained from POST /oidc/register.
	ClientID string
	// ClientSecret is the OIDC client secret obtained from POST /oidc/register.
	ClientSecret string
	// HTTPClient overrides the default HTTP client (optional).
	HTTPClient *http.Client
}

// Client is a thread-safe tpt-identity API client.
type Client struct {
	cfg      Config
	http     *http.Client
	mu       sync.Mutex
	token    string
	tokenExp time.Time
}

// NewClient creates a new Client. No network call is made until the first API request.
func NewClient(cfg Config) *Client {
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	return &Client{cfg: cfg, http: hc}
}

// ensureToken acquires or refreshes the access token, caching it with a 30-second buffer.
func (c *Client) ensureToken(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" && time.Now().Add(30*time.Second).Before(c.tokenExp) {
		return nil
	}
	body := "grant_type=client_credentials"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.BaseURL+"/token",
		bytes.NewBufferString(body))
	if err != nil {
		return fmt.Errorf("client: build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(c.cfg.ClientID, c.cfg.ClientSecret)

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("client: token request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("client: token request failed (%d): %s", resp.StatusCode, b)
	}
	var tok struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		return fmt.Errorf("client: decode token response: %w", err)
	}
	c.token = tok.AccessToken
	c.tokenExp = time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second)
	return nil
}

// do executes an authenticated API request, acquiring a token if needed.
func (c *Client) do(ctx context.Context, method, path string, body any) (*http.Response, error) {
	if err := c.ensureToken(ctx); err != nil {
		return nil, err
	}
	var bodyReader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("client: marshal request: %w", err)
		}
		bodyReader = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.cfg.BaseURL+path, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("client: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return c.http.Do(req)
}

func decodeJSON(resp *http.Response, out any) error {
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("tpt-identity API error (%d): %s", resp.StatusCode, b)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
