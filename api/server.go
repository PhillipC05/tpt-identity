package api

import (
	"log/slog"
	"net/http"
	"strings"

	"github.com/PhillipC05/tpt-identity/internal/store"
	"github.com/PhillipC05/tpt-identity/internal/resolver"
	"github.com/PhillipC05/tpt-identity/oidc"
)

// Server is the tpt-identity HTTP server.
type Server struct {
	mux      *http.ServeMux
	store    store.Store
	resolver *resolver.Resolver
	oidc     *oidc.Provider
	apiKey   string
	logger   *slog.Logger
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
	}
	s.routes()
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *Server) routes() {
	// Public: OIDC & DID document
	s.mux.HandleFunc("GET /.well-known/openid-configuration", s.oidc.DiscoveryHandler)
	s.mux.HandleFunc("GET /.well-known/did.json", s.handleDIDDocument)
	s.mux.HandleFunc("GET /authorize", s.oidc.AuthorizeHandler)
	s.mux.HandleFunc("POST /token", s.oidc.TokenHandler)
	s.mux.HandleFunc("GET /userinfo", s.oidc.UserinfoHandler)

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

// auth middleware checks the Bearer API key.
func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.apiKey != "" {
			bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if bearer != s.apiKey {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}
		next(w, r)
	}
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
