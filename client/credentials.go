package client

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/PhillipC05/tpt-identity/pkg/vc"
)

// IssueCredentialRequest is the request body for issuing a new Verifiable Credential.
type IssueCredentialRequest struct {
	// IssuerDID is the DID of the issuing identity (must be did:web or did:peer, not did:key).
	IssuerDID string `json:"issuerDid"`
	// VerificationMethodID is the key ID within the issuer's DID document.
	VerificationMethodID string `json:"verificationMethodId"`
	// SubjectDID is the DID of the credential holder.
	SubjectDID string `json:"subjectDid"`
	// SchemaID identifies the credential type, e.g. "healthcare.gp-records".
	SchemaID string `json:"schemaId"`
	// Claims are the credential payload fields, validated against the schema.
	Claims map[string]string `json:"claims"`
	// ValidFor controls the credential lifetime. Zero means no expiry.
	ValidFor time.Duration `json:"validFor,omitempty"`
}

// IssueCredential requests tpt-identity to issue and sign a new Verifiable Credential.
func (c *Client) IssueCredential(ctx context.Context, req IssueCredentialRequest) (*vc.VerifiableCredential, error) {
	// Map to the API's IssueOptions type. IssuerKey is handled server-side by the keystore.
	body := map[string]any{
		"IssuerDID":            req.IssuerDID,
		"VerificationMethodID": req.VerificationMethodID,
		"SubjectDID":           req.SubjectDID,
		"SchemaID":             req.SchemaID,
		"Claims":               req.Claims,
		"ValidFor":             req.ValidFor,
	}
	resp, err := c.do(ctx, http.MethodPost, "/api/v1/credentials", body)
	if err != nil {
		return nil, fmt.Errorf("IssueCredential: %w", err)
	}
	var cred vc.VerifiableCredential
	if err := decodeJSON(resp, &cred); err != nil {
		return nil, fmt.Errorf("IssueCredential: %w", err)
	}
	return &cred, nil
}

// VerifyCredential asks tpt-identity to verify a credential's signature, expiry, and revocation status.
func (c *Client) VerifyCredential(ctx context.Context, cred *vc.VerifiableCredential) error {
	resp, err := c.do(ctx, http.MethodPost, "/api/v1/credentials/verify", cred)
	if err != nil {
		return fmt.Errorf("VerifyCredential: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnprocessableEntity {
		var result struct {
			Error string `json:"error"`
		}
		_ = decodeJSON(resp, &result)
		return fmt.Errorf("VerifyCredential: credential invalid: %s", result.Error)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("VerifyCredential: unexpected status %d", resp.StatusCode)
	}
	return nil
}

// ListCredentials returns all credentials held by the given subject DID.
func (c *Client) ListCredentials(ctx context.Context, subjectDID string) ([]*vc.VerifiableCredential, error) {
	resp, err := c.do(ctx, http.MethodGet, "/api/v1/credentials?subject="+subjectDID, nil)
	if err != nil {
		return nil, fmt.Errorf("ListCredentials: %w", err)
	}
	var creds []*vc.VerifiableCredential
	if err := decodeJSON(resp, &creds); err != nil {
		return nil, fmt.Errorf("ListCredentials: %w", err)
	}
	return creds, nil
}

// DeleteCredential removes a credential by ID.
func (c *Client) DeleteCredential(ctx context.Context, id string) error {
	resp, err := c.do(ctx, http.MethodDelete, "/api/v1/credentials/"+id, nil)
	if err != nil {
		return fmt.Errorf("DeleteCredential: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("DeleteCredential: unexpected status %d", resp.StatusCode)
	}
	return nil
}
