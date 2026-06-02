package api

import (
	"crypto/ed25519"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	gowebauthn "github.com/go-webauthn/webauthn/webauthn"

	"github.com/PhillipC05/tpt-identity/internal/authn"
	"github.com/PhillipC05/tpt-identity/internal/bridge"
	"github.com/PhillipC05/tpt-identity/internal/events"
	"github.com/PhillipC05/tpt-identity/internal/resolver"
	"github.com/PhillipC05/tpt-identity/internal/store"
	"github.com/PhillipC05/tpt-identity/oidc"
)

// Server is the tpt-identity HTTP server.
type Server struct {
	mux            *http.ServeMux
	store          store.Store
	resolver       *resolver.Resolver
	oidc           *oidc.Provider
	apiKey         string
	issuer         string
	totpPassphrase string
	logger         *slog.Logger
	limiter        *ipRateLimiter
	// Platform signing key — used for issuing VCs and SD-JWT credentials.
	signingKey   ed25519.PrivateKey
	signingKeyID string // verification method ID, e.g. did:web:example.com#signing-key-1
	// Bridge layer
	bridges *bridge.Manager
	mapper  *bridge.Mapper
	// Lifecycle services
	events  *events.Bus
	lockout *authn.LockoutManager
	// WebAuthn / Passkeys — nil when not configured.
	webAuthn      *gowebauthn.WebAuthn
	waRegSessions sync.Map // sessionID → *waSessionEntry (registration flow)
	waAuthSessions sync.Map // sessionID → *waSessionEntry (authentication flow)
}

// Config holds Server configuration.
type Config struct {
	APIKey         string
	Issuer         string
	TotpPassphrase string
	// SigningKey is the platform Ed25519 private key used for VC and SD-JWT issuance.
	SigningKey   ed25519.PrivateKey
	SigningKeyID string // verification method ID
	Store        store.Store
	Resolver     *resolver.Resolver
	OIDC         *oidc.Provider
	Bridges      *bridge.Manager
	Logger       *slog.Logger
	// RateLimit is the number of requests per second per IP (0 = disabled).
	RateLimit float64
	// WebAuthn / Passkeys — all three must be set to enable WebAuthn endpoints.
	WebAuthnRPID          string   // e.g. "example.com"
	WebAuthnRPDisplayName string   // human-readable relying party name
	WebAuthnRPOrigins     []string // e.g. ["https://example.com"]
}

// NewServer wires all routes.
func NewServer(cfg Config) *Server {
	rateLimit := cfg.RateLimit
	if rateLimit == 0 {
		rateLimit = 50 // default: 50 req/s per IP
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	bridges := cfg.Bridges
	if bridges == nil {
		bridges = bridge.NewManager()
	}
	s := &Server{
		mux:            http.NewServeMux(),
		store:          cfg.Store,
		resolver:       cfg.Resolver,
		oidc:           cfg.OIDC,
		apiKey:         cfg.APIKey,
		issuer:         cfg.Issuer,
		totpPassphrase: cfg.TotpPassphrase,
		signingKey:     cfg.SigningKey,
		signingKeyID:   cfg.SigningKeyID,
		logger:         logger,
		limiter:        newIPRateLimiter(rateLimit, int(rateLimit*2)),
		bridges:        bridges,
		mapper:         bridge.NewMapper(cfg.Store),
		events:         events.NewBus(cfg.Store, logger),
		lockout:        authn.NewLockoutManager(cfg.Store),
	}

	// Initialise WebAuthn when all required config fields are present.
	if cfg.WebAuthnRPID != "" {
		origins := cfg.WebAuthnRPOrigins
		if len(origins) == 0 {
			origins = []string{cfg.Issuer}
		}
		rpName := cfg.WebAuthnRPDisplayName
		if rpName == "" {
			rpName = cfg.WebAuthnRPID
		}
		wa, waErr := gowebauthn.New(&gowebauthn.Config{
			RPID:          cfg.WebAuthnRPID,
			RPDisplayName: rpName,
			RPOrigins:     origins,
		})
		if waErr != nil {
			logger.Warn("webauthn init failed — passkey endpoints disabled", "err", waErr)
		} else {
			s.webAuthn = wa
		}
	}

	// Periodically evict expired WebAuthn sessions (both registration and auth).
	go func() {
		for range time.Tick(5 * time.Minute) {
			now := time.Now()
			s.waRegSessions.Range(func(k, v any) bool {
				if v.(*waSessionEntry).expiresAt.Before(now) {
					s.waRegSessions.Delete(k)
				}
				return true
			})
			s.waAuthSessions.Range(func(k, v any) bool {
				if v.(*waSessionEntry).expiresAt.Before(now) {
					s.waAuthSessions.Delete(k)
				}
				return true
			})
		}
	}()

	s.routes()
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *Server) routes() {
	// Public: OIDC, DID, JWKS
	s.mux.HandleFunc("GET /.well-known/openid-configuration", s.audit(s.oidc.DiscoveryHandler))
	s.mux.HandleFunc("GET /.well-known/jwks.json", s.audit(s.oidc.JWKSHandler))
	s.mux.HandleFunc("GET /.well-known/did.json", s.audit(s.handleDIDDocument))
	s.mux.HandleFunc("GET /authorize", s.rateLimit(s.audit(s.oidc.AuthorizeHandler)))
	s.mux.HandleFunc("POST /token", s.rateLimit(s.audit(s.oidc.TokenHandler)))
	s.mux.HandleFunc("GET /userinfo", s.rateLimit(s.audit(s.oidc.UserinfoHandler)))
	s.mux.HandleFunc("POST /oidc/register", s.rateLimit(s.audit(s.oidc.RegisterClientHandler)))
	s.mux.HandleFunc("POST /oidc/revoke", s.rateLimit(s.audit(s.oidc.RevokeHandler)))

	// Health
	s.mux.HandleFunc("GET /healthz", s.handleLiveness)
	s.mux.HandleFunc("GET /readyz", s.handleReadiness)

	// Status list (public — verifiers fetch without auth)
	s.mux.HandleFunc("GET /api/v1/status/{listId}", s.audit(s.handleStatusList))

	// ── Identity bridge (public) ───────────────────────────────────────────
	s.mux.HandleFunc("GET /auth/{provider}", s.rateLimit(s.audit(s.handleBridgeStart)))
	s.mux.HandleFunc("GET /auth/{provider}/callback", s.rateLimit(s.audit(s.handleBridgeCallback)))
	// SAML 2.0 SP endpoints (RealMe and any other SAML IdP).
	s.mux.HandleFunc("GET /auth/{provider}/metadata", s.audit(s.handleSAMLMetadata))
	s.mux.HandleFunc("POST /auth/{provider}/acs", s.rateLimit(s.audit(s.handleSAMLACS)))
	s.mux.HandleFunc("POST /auth/magiclink/request", s.rateLimit(s.audit(s.handleMagicLinkRequest)))
	s.mux.HandleFunc("GET /auth/magiclink/verify", s.rateLimit(s.audit(s.handleMagicLinkVerify)))

	// ── Protected API ──────────────────────────────────────────────────────
	s.mux.HandleFunc("POST /api/v1/identities", s.rateLimit(s.audit(s.auth(s.handleCreateIdentity))))
	s.mux.HandleFunc("GET /api/v1/identities/{did}", s.rateLimit(s.audit(s.auth(s.handleGetIdentity))))
	s.mux.HandleFunc("POST /api/v1/credentials", s.rateLimit(s.audit(s.auth(s.handleIssueCredential))))
	s.mux.HandleFunc("POST /api/v1/credentials/verify", s.rateLimit(s.audit(s.auth(s.handleVerifyCredential))))
	s.mux.HandleFunc("GET /api/v1/credentials", s.rateLimit(s.audit(s.auth(s.handleListCredentials))))
	s.mux.HandleFunc("DELETE /api/v1/credentials/{id}", s.rateLimit(s.audit(s.auth(s.handleDeleteCredential))))
	// SD-JWT selective disclosure
	s.mux.HandleFunc("POST /api/v1/credentials/sd-jwt", s.rateLimit(s.audit(s.auth(s.handleIssueSDJWT))))
	s.mux.HandleFunc("POST /api/v1/credentials/sd-jwt/verify", s.rateLimit(s.audit(s.auth(s.handleVerifySDJWT))))
	s.mux.HandleFunc("GET /api/v1/consents/grants", s.rateLimit(s.audit(s.auth(s.handleListGrants))))
	s.mux.HandleFunc("POST /api/v1/consents/grants", s.rateLimit(s.audit(s.auth(s.handleCreateGrant))))
	s.mux.HandleFunc("DELETE /api/v1/consents/grants/{id}", s.rateLimit(s.audit(s.auth(s.handleRevokeGrant))))
	s.mux.HandleFunc("GET /api/v1/consents/receipts", s.rateLimit(s.audit(s.auth(s.handleListReceipts))))
	s.mux.HandleFunc("DELETE /api/v1/sessions/{id}", s.rateLimit(s.audit(s.auth(s.handleDeleteSession))))
	s.mux.HandleFunc("GET /api/v1/schemas", s.rateLimit(s.audit(s.auth(s.handleListSchemas))))

	// ── Me — user self-service (bearer token, not api-key) ─────────────────
	s.mux.HandleFunc("GET /api/v1/me/sessions", s.rateLimit(s.audit(s.handleListMySessions)))
	s.mux.HandleFunc("DELETE /api/v1/me/sessions/{id}", s.rateLimit(s.audit(s.handleRevokeMySession)))
	s.mux.HandleFunc("GET /api/v1/me/links", s.rateLimit(s.audit(s.handleListLinks)))
	s.mux.HandleFunc("DELETE /api/v1/me/links/{provider}", s.rateLimit(s.audit(s.handleUnlink)))
	s.mux.HandleFunc("POST /api/v1/me/totp/enrol", s.rateLimit(s.audit(s.handleTOTPEnrol)))
	s.mux.HandleFunc("POST /api/v1/me/totp/verify", s.rateLimit(s.audit(s.handleTOTPVerify)))
	s.mux.HandleFunc("DELETE /api/v1/me/totp", s.rateLimit(s.audit(s.handleTOTPUnenrol)))

	// ── Webhooks ───────────────────────────────────────────────────────────
	s.mux.HandleFunc("POST /api/v1/webhooks", s.rateLimit(s.audit(s.auth(s.handleRegisterWebhook))))
	s.mux.HandleFunc("GET /api/v1/webhooks", s.rateLimit(s.audit(s.auth(s.handleListWebhooks))))
	s.mux.HandleFunc("DELETE /api/v1/webhooks/{id}", s.rateLimit(s.audit(s.auth(s.handleDeleteWebhook))))

	// ── Presentation Exchange ──────────────────────────────────────────────
	s.mux.HandleFunc("POST /api/v1/presentations/request", s.rateLimit(s.audit(s.auth(s.handleCreatePresentationRequest))))
	s.mux.HandleFunc("POST /api/v1/presentations/submit", s.rateLimit(s.audit(s.auth(s.handleSubmitPresentation))))

	// ── WebAuthn / Passkeys ────────────────────────────────────────────────
	// Registration uses OIDC bearer auth (user must already have a session).
	s.mux.HandleFunc("POST /api/v1/me/webauthn/register/begin", s.rateLimit(s.audit(s.handleWebAuthnRegisterBegin)))
	s.mux.HandleFunc("POST /api/v1/me/webauthn/register/finish", s.rateLimit(s.audit(s.handleWebAuthnRegisterFinish)))
	// Login is public — credential discovery happens during the ceremony.
	s.mux.HandleFunc("POST /api/v1/webauthn/login/begin", s.rateLimit(s.audit(s.handleWebAuthnLoginBegin)))
	s.mux.HandleFunc("POST /api/v1/webauthn/login/finish", s.rateLimit(s.audit(s.handleWebAuthnLoginFinish)))
	// Credential management requires OIDC bearer auth.
	s.mux.HandleFunc("GET /api/v1/me/webauthn/credentials", s.rateLimit(s.audit(s.handleListWebAuthnCredentials)))
	s.mux.HandleFunc("DELETE /api/v1/me/webauthn/credentials/{id}", s.rateLimit(s.audit(s.handleDeleteWebAuthnCredential)))
}

// --- Middleware ---

// audit logs every request as a structured audit event: method, path, remote IP, status.
func (s *Server) audit(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &responseRecorder{ResponseWriter: w, status: http.StatusOK}
		next(rw, r)
		s.logger.Info("audit",
			"method", r.Method,
			"path", r.URL.Path,
			"ip", clientIP(r),
			"status", rw.status,
			"duration_ms", time.Since(start).Milliseconds(),
			"user_agent", r.UserAgent(),
		)
	}
}

// rateLimit rejects requests from IPs that exceed the configured token-bucket rate.
func (s *Server) rateLimit(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r)
		if !s.limiter.Allow(ip) {
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		next(w, r)
	}
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

// --- Handlers ---

func (s *Server) handleLiveness(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
}

func (s *Server) handleDIDDocument(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/did+json")
	http.Error(w, "not configured — set local DID in config", http.StatusNotFound)
}

// --- responseRecorder captures the status code for audit logging ---

type responseRecorder struct {
	http.ResponseWriter
	status int
}

func (rw *responseRecorder) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}

// --- Rate limiter (token bucket, per IP) ---

type bucket struct {
	tokens   float64
	lastSeen time.Time
}

type ipRateLimiter struct {
	mu       sync.Mutex
	buckets  map[string]*bucket
	rate     float64 // tokens per second
	capacity int     // max burst
}

func newIPRateLimiter(rate float64, capacity int) *ipRateLimiter {
	l := &ipRateLimiter{buckets: make(map[string]*bucket), rate: rate, capacity: capacity}
	// Periodically evict stale entries.
	go func() {
		for range time.Tick(5 * time.Minute) {
			l.evict()
		}
	}()
	return l
}

func (l *ipRateLimiter) Allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[ip]
	if !ok {
		b = &bucket{tokens: float64(l.capacity), lastSeen: time.Now()}
		l.buckets[ip] = b
	}
	now := time.Now()
	elapsed := now.Sub(b.lastSeen).Seconds()
	b.tokens += elapsed * l.rate
	if b.tokens > float64(l.capacity) {
		b.tokens = float64(l.capacity)
	}
	b.lastSeen = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func (l *ipRateLimiter) evict() {
	cutoff := time.Now().Add(-10 * time.Minute)
	l.mu.Lock()
	for ip, b := range l.buckets {
		if b.lastSeen.Before(cutoff) {
			delete(l.buckets, ip)
		}
	}
	l.mu.Unlock()
}

func clientIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		parts := strings.SplitN(fwd, ",", 2)
		if ip := strings.TrimSpace(parts[0]); ip != "" {
			return ip
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

