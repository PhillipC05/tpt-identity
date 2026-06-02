package client

import (
	"context"
	"fmt"
	"net/http"

	"github.com/PhillipC05/tpt-identity/pkg/consent"
)

// ConsentChallenge describes what a client is requesting from a user — shown before consent approval.
type ConsentChallenge struct {
	ClientID       string `json:"client_id"`
	ClientName     string `json:"client_name"`
	SchemaID       string `json:"schema_id"`
	SchemaName     string `json:"schema_name"`
	SchemaDesc     string `json:"schema_description,omitempty"`
	ExtraSensitive bool   `json:"extra_sensitive"`
	LegalBasis     string `json:"legal_basis"`
	Revocable      bool   `json:"revocable"`
}

// GetConsentChallenge fetches a human-readable description of what client_id is requesting
// for schema_id. Use this to populate a consent approval screen.
func (c *Client) GetConsentChallenge(ctx context.Context, clientID, schemaID string) (*ConsentChallenge, error) {
	resp, err := c.do(ctx, http.MethodGet,
		"/api/v1/consents/challenge?client_id="+clientID+"&schema_id="+schemaID, nil)
	if err != nil {
		return nil, fmt.Errorf("GetConsentChallenge: %w", err)
	}
	var ch ConsentChallenge
	if err := decodeJSON(resp, &ch); err != nil {
		return nil, fmt.Errorf("GetConsentChallenge: %w", err)
	}
	return &ch, nil
}

// ListGrants returns all consent grants held by the given subject DID.
func (c *Client) ListGrants(ctx context.Context, subjectDID string) ([]*consent.Grant, error) {
	resp, err := c.do(ctx, http.MethodGet, "/api/v1/consents/grants?subject="+subjectDID, nil)
	if err != nil {
		return nil, fmt.Errorf("ListGrants: %w", err)
	}
	var grants []*consent.Grant
	if err := decodeJSON(resp, &grants); err != nil {
		return nil, fmt.Errorf("ListGrants: %w", err)
	}
	return grants, nil
}

// CreateGrant records a new consent grant (the user has approved sharing).
func (c *Client) CreateGrant(ctx context.Context, g *consent.Grant) (*consent.Grant, error) {
	resp, err := c.do(ctx, http.MethodPost, "/api/v1/consents/grants", g)
	if err != nil {
		return nil, fmt.Errorf("CreateGrant: %w", err)
	}
	var out consent.Grant
	if err := decodeJSON(resp, &out); err != nil {
		return nil, fmt.Errorf("CreateGrant: %w", err)
	}
	return &out, nil
}

// RevokeGrant removes a consent grant by ID.
func (c *Client) RevokeGrant(ctx context.Context, id string) error {
	resp, err := c.do(ctx, http.MethodDelete, "/api/v1/consents/grants/"+id, nil)
	if err != nil {
		return fmt.Errorf("RevokeGrant: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("RevokeGrant: unexpected status %d", resp.StatusCode)
	}
	return nil
}

// ListReceipts returns all consent receipts for a subject DID (audit trail of data access events).
func (c *Client) ListReceipts(ctx context.Context, subjectDID string) ([]*consent.Receipt, error) {
	resp, err := c.do(ctx, http.MethodGet, "/api/v1/consents/receipts?subject="+subjectDID, nil)
	if err != nil {
		return nil, fmt.Errorf("ListReceipts: %w", err)
	}
	var receipts []*consent.Receipt
	if err := decodeJSON(resp, &receipts); err != nil {
		return nil, fmt.Errorf("ListReceipts: %w", err)
	}
	return receipts, nil
}
