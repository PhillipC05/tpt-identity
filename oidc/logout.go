package oidc

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const logoutTokenTTL = 2 * time.Minute

// NotifyBackChannelLogout implements OIDC Back-Channel Logout 1.0.
// It issues a signed logout token for subjectDID and fans it out to every
// registered client that has a backchannel_logout_uri. Delivery errors are
// collected and returned but do not prevent other clients from being notified.
func (p *Provider) NotifyBackChannelLogout(ctx context.Context, subjectDID string) error {
	clients, err := p.store.ListClients(ctx)
	if err != nil {
		return fmt.Errorf("backchannel logout: list clients: %w", err)
	}

	var errs []error
	for _, c := range clients {
		if c.BackChannelLogoutURI == "" {
			continue
		}
		token, err := p.issueLogoutToken(subjectDID, c.ClientID)
		if err != nil {
			errs = append(errs, fmt.Errorf("client %s: issue logout token: %w", c.ClientID, err))
			continue
		}
		if err := deliverLogoutToken(ctx, c.BackChannelLogoutURI, token); err != nil {
			errs = append(errs, fmt.Errorf("client %s: deliver: %w", c.ClientID, err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("backchannel logout: %d delivery failure(s): %v", len(errs), errs[0])
	}
	return nil
}

// issueLogoutToken produces a signed logout token per the Back-Channel Logout spec §2.4.
func (p *Provider) issueLogoutToken(subjectDID, clientID string) (string, error) {
	now := time.Now()
	jti, err := randomHex(16)
	if err != nil {
		return "", err
	}
	// Logout tokens look like ID tokens but carry events claim and no nonce.
	payload := map[string]any{
		"iss":    p.issuer,
		"sub":    subjectDID,
		"aud":    clientID,
		"iat":    now.Unix(),
		"exp":    now.Add(logoutTokenTTL).Unix(),
		"jti":    jti,
		"events": map[string]any{"http://schemas.openid.net/event/backchannel-logout": map[string]any{}},
	}
	return signJWT(payload, p.signingKey, p.keyID)
}

// deliverLogoutToken POSTs the logout token to the client's back-channel logout URI.
func deliverLogoutToken(ctx context.Context, uri, token string) error {
	body, _ := json.Marshal(map[string]string{"logout_token": token})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, uri, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("logout URI returned %d", resp.StatusCode)
	}
	return nil
}
