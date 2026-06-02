// Package events provides a typed event bus for platform lifecycle events.
// Subscribers receive HTTP POST deliveries with HMAC-SHA256 signed payloads.
package events

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/PhillipC05/tpt-identity/internal/store"
)

// Event types published by the platform.
const (
	CredentialIssued  = "credential.issued"
	CredentialRevoked = "credential.revoked"
	ConsentGranted    = "consent.granted"
	ConsentRevoked    = "consent.revoked"
	IdentityCreated   = "identity.created"
	SessionCreated    = "session.created"
	SessionRevoked    = "session.revoked"
)

// Event is a platform lifecycle event.
type Event struct {
	ID        string `json:"id"`
	Type      string `json:"type"`
	OccuredAt string `json:"occurred_at"` // RFC 3339
	Payload   any    `json:"payload"`
}

// Bus fans out events to registered webhook subscribers.
type Bus struct {
	st     store.Store
	logger *slog.Logger
	client *http.Client
}

// NewBus creates a new event bus.
func NewBus(st store.Store, logger *slog.Logger) *Bus {
	return &Bus{
		st:     st,
		logger: logger,
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

// Publish delivers the event to all matching webhook subscribers asynchronously.
func (b *Bus) Publish(ctx context.Context, eventType string, payload any) {
	event := Event{
		ID:        randomEventID(),
		Type:      eventType,
		OccuredAt: time.Now().UTC().Format(time.RFC3339),
		Payload:   payload,
	}
	body, err := json.Marshal(event)
	if err != nil {
		b.logger.Error("events: marshal", "err", err)
		return
	}

	subs, err := b.st.ListWebhookSubscriptions(ctx, eventType)
	if err != nil {
		b.logger.Error("events: list subscriptions", "err", err)
		return
	}

	for _, sub := range subs {
		go b.deliver(sub, body)
	}
}

// deliver attempts webhook delivery with up to 3 retries and exponential backoff.
func (b *Bus) deliver(sub *store.WebhookSubscription, body []byte) {
	sig := computeHMAC(body, sub.SecretHash)
	backoff := 2 * time.Second
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			time.Sleep(backoff)
			backoff *= 2
		}
		req, err := http.NewRequest(http.MethodPost, sub.URL, bytes.NewReader(body))
		if err != nil {
			b.logger.Error("events: build request", "url", sub.URL, "err", err)
			return
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-TPT-Signature-256", "sha256="+sig)
		req.Header.Set("X-TPT-Event-ID", extractEventID(body))

		resp, err := b.client.Do(req)
		if err != nil {
			b.logger.Warn("events: delivery failed", "url", sub.URL, "attempt", attempt+1, "err", err)
			continue
		}
		resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return
		}
		b.logger.Warn("events: non-2xx response", "url", sub.URL, "status", resp.StatusCode, "attempt", attempt+1)
	}
	b.logger.Error("events: delivery failed after 3 attempts", "url", sub.URL)
}

func computeHMAC(body []byte, secretHash string) string {
	// secretHash is sha256(raw_secret) — we use it directly as the HMAC key.
	// In production, store the raw secret encrypted; here we use the hash as a proxy.
	h := hmac.New(sha256.New, []byte(secretHash))
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil))
}

func extractEventID(body []byte) string {
	var e struct{ ID string `json:"id"` }
	json.Unmarshal(body, &e)
	return e.ID
}

func randomEventID() string {
	return fmt.Sprintf("evt_%016x", time.Now().UnixNano())
}
