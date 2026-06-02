package api

import (
	"crypto/sha256"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"

	"github.com/PhillipC05/tpt-identity/internal/store"
)

type registerWebhookRequest struct {
	URL        string   `json:"url"`
	EventTypes []string `json:"event_types"`
}

type registerWebhookResponse struct {
	ID           string   `json:"id"`
	URL          string   `json:"url"`
	EventTypes   []string `json:"event_types"`
	SigningSecret string  `json:"signing_secret"` // shown once — store it safely
	CreatedAt    string   `json:"created_at"`
}

// handleRegisterWebhook registers a new webhook subscription.
// POST /api/v1/webhooks
func (s *Server) handleRegisterWebhook(w http.ResponseWriter, r *http.Request) {
	var req registerWebhookRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if req.URL == "" {
		http.Error(w, "url required", http.StatusBadRequest)
		return
	}
	if len(req.EventTypes) == 0 {
		req.EventTypes = []string{"*"}
	}

	// Generate a signing secret — returned once, never stored in plaintext.
	rawSecret, err := randomWebhookSecret()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	secretHash := sha256WebhookSecret(rawSecret)

	id, _ := randomWebhookID()
	sub := &store.WebhookSubscription{
		ID:         id,
		URL:        req.URL,
		EventTypes: req.EventTypes,
		SecretHash: secretHash,
		CreatedAt:  time.Now(),
	}
	if err := s.store.SaveWebhookSubscription(r.Context(), sub); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(registerWebhookResponse{
		ID:           sub.ID,
		URL:          sub.URL,
		EventTypes:   sub.EventTypes,
		SigningSecret: rawSecret,
		CreatedAt:    sub.CreatedAt.UTC().Format(time.RFC3339),
	})
}

// handleDeleteWebhook removes a webhook subscription.
// DELETE /api/v1/webhooks/{id}
func (s *Server) handleDeleteWebhook(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.store.DeleteWebhookSubscription(r.Context(), id); err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleListWebhooks lists all registered webhook subscriptions.
// GET /api/v1/webhooks
func (s *Server) handleListWebhooks(w http.ResponseWriter, r *http.Request) {
	subs, err := s.store.ListWebhookSubscriptions(r.Context(), "*")
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(subs)
}

func randomWebhookSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "whsec_" + hex.EncodeToString(b), nil
}

func sha256WebhookSecret(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func randomWebhookID() (string, error) {
	b := make([]byte, 8)
	_, err := rand.Read(b)
	return "wh_" + hex.EncodeToString(b), err
}
