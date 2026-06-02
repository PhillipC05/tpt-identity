package api

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/PhillipC05/tpt-identity/internal/ratelimit"
	"github.com/PhillipC05/tpt-identity/internal/resolver"
	"github.com/PhillipC05/tpt-identity/internal/store"
	"github.com/PhillipC05/tpt-identity/oidc"
)

type contextKey int

const callerClientIDKey contextKey = iota

// Server is the tpt-identity HTTP server.
type Server struct {
	mux      *http.ServeMux
	store    store.Store
	resolver *resolver.Resolver
	oidc     *oidc.Provider
	apiKey   string
	logger   *slog.Logger
	tokenRL  *ratelimit.Limiter // /token — 20 req/min per IP
	authRL   *ratelimit.Limiter // /authorize — 30 req/min per IP
}

// Config holds Server configuration.
type Config struct {
	APIKey   string
	Issuer   string
	Store    store.Store
	Resolver *resolver.Resolver
	OIDC     *oidc.Provider
	Logger   *slog.Logger
}

// NewServer wires all routes.
func NewServer(cfg Config) *Server {
	s := &Server{
		mux:      http.NewServeMux(),
		store:    cfg.Store,
		resolver: cfg.Resolver,
		oidc:     cfg.OIDC,
		apiKey:   cfg.APIKey,
		logger:   cfg.Logger,
		tokenRL:  ratelimit.New(20, time.Minute),
		authRL:   ratelimit.New(30, time.Minute),
	}
	s.routes()
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *Server) routes() {
	// Public: OIDC discovery + DID document
	s.mux.HandleFunc("GET /.well-known/openid-configuration", s.oidc.DiscoveryHandler)
	s.mux.HandleFunc("GET /.well-known/jwks.json", s.oidc.JWKSHandler)
	s.mux.HandleFunc("GET /.well-known/did.json", s.handleDIDDocument)

	// Public: OIDC token flows + consent challenge (rate-limited)
	s.mux.HandleFunc("GET /authorize", s.authRL.Handler(s.oidc.AuthorizeHandler))
	s.mux.HandleFunc("POST /token", s.tokenRL.Handler(s.oidc.TokenHandler))
	s.mux.HandleFunc("GET /userinfo", s.oidc.UserinfoHandler)
	s.mux.HandleFunc("POST /oidc/register", s.oidc.RegisterClientHandler)
	s.mux.HandleFunc("POST /oidc/introspect", s.oidc.IntrospectHandler)
	s.mux.HandleFunc("POST /oidc/revoke", s.oidc.RevokeHandler)
	s.mux.HandleFunc("POST /oidc/logout", s.auth(s.handleLogout))
	s.mux.HandleFunc("GET /api/v1/consents/challenge", s.handleConsentChallenge)

	// Protected API
	s.mux.HandleFunc("POST /api/v1/identities", s.auth(s.handleCreateIdentity))
	s.mux.HandleFunc("GET /api/v1/identities/{did}", s.auth(s.handleGetIdentity))
	s.mux.HandleFunc("POST /api/v1/credentials", s.auth(s.handleIssueCredential))
	s.mux.HandleFunc("POST /api/v1/credentials/verify", s.auth(s.handleVerifyCredential))
	s.mux.HandleFunc("GET /api/v1/credentials", s.auth(s.handleListCredentials))
	s.mux.HandleFunc("DELETE /api/v1/credentials/{id}", s.auth(s.handleDeleteCredential))
	s.mux.HandleFunc("GET /api/v1/consents/grants", s.auth(s.handleListGrants))
	s.mux.HandleFunc("POST /api/v1/consents/grants", s.auth(s.handleCreateGrant))
	s.mux.HandleFunc("DELETE /api/v1/consents/grants/{id}", s.auth(s.handleRevokeGrant))
	s.mux.HandleFunc("GET /api/v1/consents/receipts", s.auth(s.handleListReceipts))
	s.mux.HandleFunc("DELETE /api/v1/sessions/{id}", s.auth(s.handleDeleteSession))
	s.mux.HandleFunc("GET /api/v1/schemas", s.auth(s.handleListSchemas))
	s.mux.HandleFunc("GET /healthz", s.handleHealthz)
}

// auth middleware accepts either the configured static API key or a valid OIDC access token.
// On success it stores the caller's client ID in the request context for downstream use.
func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		// Static API key — ops/admin use; bypasses OIDC.
		if s.apiKey != "" && bearer == s.apiKey {
			ctx := context.WithValue(r.Context(), callerClientIDKey, "admin")
			next(w, r.WithContext(ctx))
			return
		}
		// OIDC access token — issued via /token to registered clients.
		if bearer != "" {
			if clientID, err := s.oidc.ClientIDFromToken(bearer); err == nil {
				ctx := context.WithValue(r.Context(), callerClientIDKey, clientID)
				next(w, r.WithContext(ctx))
				return
			}
		}
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}
}

// callerClientID retrieves the authenticated caller's client ID from the request context.
func callerClientID(r *http.Request) string {
	v, _ := r.Context().Value(callerClientIDKey).(string)
	return v
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
}

func (s *Server) handleDIDDocument(w http.ResponseWriter, r *http.Request) {
	// Serve the local identity's DID document from the store.
	// The local DID is configured at startup; here we serve the first registered identity.
	// Production: derive from config.
	w.Header().Set("Content-Type", "application/did+json")
	http.Error(w, "not configured — set local DID in config", http.StatusNotFound)
}
