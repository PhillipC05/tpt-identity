package store

import (
	"context"
	"time"

	"github.com/PhillipC05/tpt-identity/pkg/consent"
	"github.com/PhillipC05/tpt-identity/pkg/did"
	"github.com/PhillipC05/tpt-identity/pkg/vc"
)

// Store is the persistence interface. All upstream code targets this interface only;
// the SQLite implementation is in sqlite.go.
type Store interface {
	// --- Identities ---
	SaveIdentity(ctx context.Context, id *Identity) error
	GetIdentity(ctx context.Context, did string) (*Identity, error)

	// --- DID Documents ---
	SaveDocument(ctx context.Context, doc *did.Document) error
	GetDocument(ctx context.Context, did string) (*did.Document, error)

	// --- Verifiable Credentials ---
	SaveCredential(ctx context.Context, cred *vc.VerifiableCredential) error
	GetCredential(ctx context.Context, id string) (*vc.VerifiableCredential, error)
	ListCredentials(ctx context.Context, subjectDID string) ([]*vc.VerifiableCredential, error)
	DeleteCredential(ctx context.Context, id string) error

	// --- Consent Grants ---
	SaveGrant(ctx context.Context, g *consent.Grant) error
	GetGrant(ctx context.Context, id string) (*consent.Grant, error)
	ListGrants(ctx context.Context, subjectDID string) ([]*consent.Grant, error)
	DeleteGrant(ctx context.Context, id string) error

	// --- Consent Receipts ---
	SaveReceipt(ctx context.Context, r *consent.Receipt) error
	ListReceipts(ctx context.Context, subjectDID string) ([]*consent.Receipt, error)

	// --- OIDC Sessions ---
	SaveSession(ctx context.Context, s *OIDCSession) error
	GetSession(ctx context.Context, id string) (*OIDCSession, error)
	GetSessionByCode(ctx context.Context, code string) (*OIDCSession, error)
	ListSessionsBySubject(ctx context.Context, subjectDID string) ([]*OIDCSession, error)
	DeleteSession(ctx context.Context, id string) error
	PurgeExpiredSessions(ctx context.Context) error

	// --- OIDC Clients (RFC 7591 dynamic registration) ---
	SaveClient(ctx context.Context, c *OIDCClient) error
	GetClient(ctx context.Context, clientID string) (*OIDCClient, error)
	ListClients(ctx context.Context) ([]*OIDCClient, error)
	DeleteClient(ctx context.Context, clientID string) error

	// --- Refresh Tokens ---
	SaveRefreshToken(ctx context.Context, t *RefreshToken) error
	GetRefreshToken(ctx context.Context, hash string) (*RefreshToken, error)
	DeleteRefreshToken(ctx context.Context, hash string) error

	// --- External Provider Links (Identity Bridge) ---
	SaveExternalLink(ctx context.Context, l *ExternalProviderLink) error
	GetExternalLink(ctx context.Context, provider, externalID string) (*ExternalProviderLink, error)
	ListExternalLinks(ctx context.Context, subjectDID string) ([]*ExternalProviderLink, error)
	DeleteExternalLink(ctx context.Context, provider, externalID string) error

	// --- Magic Link Tokens ---
	SaveMagicLinkToken(ctx context.Context, t *MagicLinkToken) error
	GetMagicLinkToken(ctx context.Context, hash string) (*MagicLinkToken, error)
	DeleteMagicLinkToken(ctx context.Context, hash string) error

	// --- WebAuthn Credentials ---
	SaveWebAuthnCredential(ctx context.Context, c *WebAuthnCredential) error
	GetWebAuthnCredential(ctx context.Context, credentialID string) (*WebAuthnCredential, error)
	ListWebAuthnCredentials(ctx context.Context, subjectDID string) ([]*WebAuthnCredential, error)
	UpdateWebAuthnCredential(ctx context.Context, c *WebAuthnCredential) error
	DeleteWebAuthnCredential(ctx context.Context, credentialID string) error

	// --- TOTP Credentials ---
	SaveTOTPCredential(ctx context.Context, c *TOTPCredential) error
	GetTOTPCredential(ctx context.Context, subjectDID string) (*TOTPCredential, error)
	DeleteTOTPCredential(ctx context.Context, subjectDID string) error

	// --- Webhook Subscriptions ---
	SaveWebhookSubscription(ctx context.Context, s *WebhookSubscription) error
	GetWebhookSubscription(ctx context.Context, id string) (*WebhookSubscription, error)
	ListWebhookSubscriptions(ctx context.Context, eventType string) ([]*WebhookSubscription, error)
	DeleteWebhookSubscription(ctx context.Context, id string) error

	// --- Auth Failures (brute-force lockout) ---
	RecordAuthFailure(ctx context.Context, subjectOrEmail string) error
	GetAuthFailures(ctx context.Context, subjectOrEmail string) (count int, lockedUntil *time.Time, err error)
	ClearAuthFailures(ctx context.Context, subjectOrEmail string) error

	// Close releases resources.
	Close() error
}

// Identity records a registered DID and its associated key material.
type Identity struct {
	DID           string    `json:"did"`
	Method        string    `json:"method"` // "web", "key", "peer", "ion"
	SigningKeyPath string    `json:"signingKeyPath,omitempty"`
	EncKeyPath    string    `json:"encKeyPath,omitempty"`
	Role          string    `json:"role"` // "user", "operator", "admin"
	TenantID      string    `json:"tenantId,omitempty"`
	CreatedAt     time.Time `json:"createdAt"`
	UpdatedAt     time.Time `json:"updatedAt"`
}

// OIDCSession tracks an in-progress or completed OIDC authorization code flow.
type OIDCSession struct {
	ID               string     `json:"id"`
	SubjectDID       string     `json:"subjectDid"`
	ClientID         string     `json:"clientId"`
	RedirectURI      string     `json:"redirectUri"`
	Scope            string     `json:"scope"`
	Nonce            string     `json:"nonce,omitempty"`
	Code             string     `json:"code,omitempty"`
	AccessToken      string     `json:"accessToken,omitempty"`
	RefreshTokenHash string     `json:"refreshTokenHash,omitempty"`
	UserAgent        string     `json:"userAgent,omitempty"`
	IPAddress        string     `json:"ipAddress,omitempty"`
	LastUsedAt       *time.Time `json:"lastUsedAt,omitempty"`
	CreatedAt        time.Time  `json:"createdAt"`
	ExpiresAt        time.Time  `json:"expiresAt"`
}

// OIDCClient is a registered OIDC/OAuth2 client (RFC 7591).
type OIDCClient struct {
	ClientID                string    `json:"clientId"`
	ClientSecretHash        string    `json:"-"`
	ClientName              string    `json:"clientName"`
	RedirectURIs            []string  `json:"redirectUris"`
	TokenEndpointAuthMethod string    `json:"tokenEndpointAuthMethod"`
	GrantTypes              []string  `json:"grantTypes"`
	ResponseTypes           []string  `json:"responseTypes"`
	Scope                   string    `json:"scope,omitempty"`
	TenantID                string    `json:"tenantId,omitempty"`
	CreatedAt               time.Time `json:"createdAt"`
}

// RefreshToken stores a hashed refresh token for rotation.
type RefreshToken struct {
	Hash       string     `json:"hash"`      // sha256(raw_token)
	SubjectDID string     `json:"subjectDid"`
	ClientID   string     `json:"clientId"`
	Scope      string     `json:"scope"`
	IssuedAt   time.Time  `json:"issuedAt"`
	ExpiresAt  time.Time  `json:"expiresAt"`
	UsedAt     *time.Time `json:"usedAt,omitempty"` // non-nil = consumed; detect theft during grace window
}

// ExternalProviderLink maps an external identity to a platform DID.
type ExternalProviderLink struct {
	SubjectDID string    `json:"subjectDid"`
	Provider   string    `json:"provider"`   // "google", "github", "magiclink-email", "saml:acme", "ldap", etc.
	ExternalID string    `json:"externalId"` // stable external identifier (sub, NameID, DN, email)
	LinkedAt   time.Time `json:"linkedAt"`
	LastUsedAt time.Time `json:"lastUsedAt"`
}

// MagicLinkToken is a one-time-use token for email-based passwordless auth.
type MagicLinkToken struct {
	Hash      string    `json:"hash"`      // sha256(raw_token)
	Email     string    `json:"email"`     // normalised email address
	ExpiresAt time.Time `json:"expiresAt"`
	CreatedAt time.Time `json:"createdAt"`
}

// WebAuthnCredential stores a registered WebAuthn/FIDO2 authenticator.
type WebAuthnCredential struct {
	CredentialID    string     `json:"credentialId"` // base64url-encoded raw ID
	SubjectDID      string     `json:"subjectDid"`
	PublicKeyCBOR   []byte     `json:"publicKeyCbor"` // COSE public key bytes
	AttestationType string     `json:"attestationType"`
	AAGUID          string     `json:"aaguid"`
	SignCount       uint32     `json:"signCount"`
	Name            string     `json:"name,omitempty"`
	Transports      []string   `json:"transports,omitempty"`
	CreatedAt       time.Time  `json:"createdAt"`
	LastUsedAt      *time.Time `json:"lastUsedAt,omitempty"`
}

// TOTPCredential stores an encrypted TOTP secret for a subject.
type TOTPCredential struct {
	SubjectDID      string    `json:"subjectDid"`
	EncryptedSecret string    `json:"encryptedSecret"` // hex(salt) + ":" + hex(nonce) + ":" + hex(ciphertext)
	AccountName     string    `json:"accountName"`
	CreatedAt       time.Time `json:"createdAt"`
}

// WebhookSubscription registers a URL to receive platform events.
type WebhookSubscription struct {
	ID         string    `json:"id"`
	URL        string    `json:"url"`
	EventTypes []string  `json:"eventTypes"` // e.g. ["credential.issued", "consent.granted"]
	SecretHash string    `json:"-"`          // sha256(signing_secret) — used to HMAC delivery payloads
	TenantID   string    `json:"tenantId,omitempty"`
	CreatedAt  time.Time `json:"createdAt"`
}
