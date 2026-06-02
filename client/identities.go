package client

import (
	"context"
	"fmt"
	"net/http"

	"github.com/PhillipC05/tpt-identity/pkg/did"
)

// CreateIdentityRequest specifies the DID method and options for creating a new identity.
type CreateIdentityRequest struct {
	// Method is "web", "key", or "peer".
	Method string `json:"method"`
	// Domain is required for did:web, e.g. "healthcare.tpt.govt.nz".
	Domain string `json:"domain,omitempty"`
	// Passphrase encrypts the generated key at rest. Empty means unencrypted.
	Passphrase string `json:"passphrase,omitempty"`
}

// CreateIdentityResponse holds the new DID and its document.
type CreateIdentityResponse struct {
	DID      string        `json:"did"`
	Document *did.Document `json:"document"`
}

// CreateIdentity creates a new DID and keypair on the tpt-identity server.
func (c *Client) CreateIdentity(ctx context.Context, req CreateIdentityRequest) (*CreateIdentityResponse, error) {
	resp, err := c.do(ctx, http.MethodPost, "/api/v1/identities", req)
	if err != nil {
		return nil, fmt.Errorf("CreateIdentity: %w", err)
	}
	var out CreateIdentityResponse
	if err := decodeJSON(resp, &out); err != nil {
		return nil, fmt.Errorf("CreateIdentity: %w", err)
	}
	return &out, nil
}

// GetIdentity resolves a DID and returns its DID document.
// Works for any DID method supported by the server (did:web, did:key, did:peer).
func (c *Client) GetIdentity(ctx context.Context, id string) (*did.Document, error) {
	resp, err := c.do(ctx, http.MethodGet, "/api/v1/identities/"+id, nil)
	if err != nil {
		return nil, fmt.Errorf("GetIdentity: %w", err)
	}
	var doc did.Document
	if err := decodeJSON(resp, &doc); err != nil {
		return nil, fmt.Errorf("GetIdentity: %w", err)
	}
	return &doc, nil
}
