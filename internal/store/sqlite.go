package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/PhillipC05/tpt-identity/pkg/consent"
	"github.com/PhillipC05/tpt-identity/pkg/did"
	"github.com/PhillipC05/tpt-identity/pkg/vc"
	_ "modernc.org/sqlite"
)

// SQLiteStore implements Store using SQLite via modernc (pure-Go, no CGo).
type SQLiteStore struct {
	db *sql.DB
}

// OpenSQLite opens (or creates) a SQLite database at path and runs migrations.
func OpenSQLite(path string) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1) // SQLite is single-writer
	s := &SQLiteStore{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return s, nil
}

func (s *SQLiteStore) Close() error { return s.db.Close() }

// migrate creates or updates tables. Schema is designed to be PostgreSQL-compatible.
func (s *SQLiteStore) migrate() error {
	_, err := s.db.Exec(`
	PRAGMA journal_mode=WAL;

	CREATE TABLE IF NOT EXISTS identities (
		did TEXT PRIMARY KEY,
		method TEXT NOT NULL,
		signing_key_path TEXT,
		enc_key_path TEXT,
		role TEXT NOT NULL DEFAULT 'user',
		tenant_id TEXT,
		created_at DATETIME NOT NULL,
		updated_at DATETIME NOT NULL
	);

	CREATE TABLE IF NOT EXISTS did_documents (
		did TEXT PRIMARY KEY,
		document JSON NOT NULL,
		cached_at DATETIME NOT NULL
	);

	CREATE TABLE IF NOT EXISTS credentials (
		id TEXT PRIMARY KEY,
		subject_did TEXT NOT NULL,
		issuer_did TEXT NOT NULL,
		schema_id TEXT NOT NULL,
		valid_from DATETIME NOT NULL,
		valid_until DATETIME,
		credential JSON NOT NULL,
		created_at DATETIME NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_credentials_subject ON credentials(subject_did);
	CREATE INDEX IF NOT EXISTS idx_credentials_schema ON credentials(schema_id);

	CREATE TABLE IF NOT EXISTS consent_grants (
		id TEXT PRIMARY KEY,
		subject_did TEXT NOT NULL,
		relying_did TEXT NOT NULL,
		level TEXT NOT NULL,
		scope_id TEXT NOT NULL,
		granted_at DATETIME NOT NULL,
		expires_at DATETIME,
		explicitly_confirmed INTEGER NOT NULL DEFAULT 0
	);
	CREATE INDEX IF NOT EXISTS idx_grants_subject ON consent_grants(subject_did);

	CREATE TABLE IF NOT EXISTS consent_receipts (
		id TEXT PRIMARY KEY,
		subject_did TEXT NOT NULL,
		relying_did TEXT NOT NULL,
		schema_id TEXT NOT NULL,
		accessed_at DATETIME NOT NULL,
		legal_basis TEXT NOT NULL,
		purpose TEXT,
		signed_by TEXT,
		signature TEXT
	);
	CREATE INDEX IF NOT EXISTS idx_receipts_subject ON consent_receipts(subject_did);

	CREATE TABLE IF NOT EXISTS oidc_sessions (
		id TEXT PRIMARY KEY,
		subject_did TEXT NOT NULL,
		client_id TEXT NOT NULL,
		redirect_uri TEXT NOT NULL,
		scope TEXT,
		nonce TEXT,
		code TEXT,
		code_challenge TEXT,
		code_challenge_method TEXT,
		access_token TEXT,
		refresh_token_hash TEXT,
		user_agent TEXT,
		ip_address TEXT,
		last_used_at DATETIME,
		created_at DATETIME NOT NULL,
		expires_at DATETIME NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_sessions_subject ON oidc_sessions(subject_did);
	CREATE INDEX IF NOT EXISTS idx_sessions_code ON oidc_sessions(code);

	CREATE TABLE IF NOT EXISTS oidc_clients (
		client_id TEXT PRIMARY KEY,
		client_secret_hash TEXT,
		client_name TEXT NOT NULL,
		redirect_uris JSON NOT NULL,
		token_endpoint_auth_method TEXT NOT NULL,
		grant_types JSON NOT NULL,
		response_types JSON NOT NULL,
		scope TEXT,
		tenant_id TEXT,
		backchannel_logout_uri TEXT,
		created_at DATETIME NOT NULL
	);

	CREATE TABLE IF NOT EXISTS refresh_tokens (
		hash TEXT PRIMARY KEY,
		subject_did TEXT NOT NULL,
		client_id TEXT NOT NULL,
		scope TEXT,
		issued_at DATETIME NOT NULL,
		expires_at DATETIME NOT NULL,
		used_at DATETIME
	);
	CREATE INDEX IF NOT EXISTS idx_refresh_subject ON refresh_tokens(subject_did);

	CREATE TABLE IF NOT EXISTS external_provider_links (
		subject_did TEXT NOT NULL,
		provider TEXT NOT NULL,
		external_id TEXT NOT NULL,
		linked_at DATETIME NOT NULL,
		last_used_at DATETIME NOT NULL,
		PRIMARY KEY (provider, external_id)
	);
	CREATE INDEX IF NOT EXISTS idx_links_subject ON external_provider_links(subject_did);

	CREATE TABLE IF NOT EXISTS magic_link_tokens (
		hash TEXT PRIMARY KEY,
		email TEXT NOT NULL,
		expires_at DATETIME NOT NULL,
		created_at DATETIME NOT NULL
	);

	CREATE TABLE IF NOT EXISTS webauthn_credentials (
		credential_id TEXT PRIMARY KEY,
		subject_did TEXT NOT NULL,
		public_key_cbor BLOB NOT NULL,
		attestation_type TEXT,
		aaguid TEXT,
		sign_count INTEGER NOT NULL DEFAULT 0,
		name TEXT,
		transports JSON,
		created_at DATETIME NOT NULL,
		last_used_at DATETIME
	);
	CREATE INDEX IF NOT EXISTS idx_webauthn_subject ON webauthn_credentials(subject_did);

	CREATE TABLE IF NOT EXISTS totp_credentials (
		subject_did TEXT PRIMARY KEY,
		encrypted_secret TEXT NOT NULL,
		account_name TEXT,
		created_at DATETIME NOT NULL
	);

	CREATE TABLE IF NOT EXISTS webhook_subscriptions (
		id TEXT PRIMARY KEY,
		url TEXT NOT NULL,
		event_types JSON NOT NULL,
		secret_hash TEXT,
		tenant_id TEXT,
		created_at DATETIME NOT NULL
	);

	CREATE TABLE IF NOT EXISTS auth_failures (
		subject_or_email TEXT PRIMARY KEY,
		count INTEGER NOT NULL DEFAULT 0,
		last_failure_at DATETIME NOT NULL,
		locked_until DATETIME
	);

	CREATE TABLE IF NOT EXISTS revoked_tokens (
		hash TEXT PRIMARY KEY,
		revoked_at DATETIME NOT NULL,
		expires_at DATETIME NOT NULL
	);

	CREATE TABLE IF NOT EXISTS oidc_states (
		state TEXT PRIMARY KEY,
		provider TEXT NOT NULL,
		next TEXT NOT NULL,
		expires_at DATETIME NOT NULL,
		created_at DATETIME NOT NULL
	);
	`)
	if err != nil {
		return err
	}
	// Additive column migrations for existing databases. SQLite does not support
	// IF NOT EXISTS on ALTER TABLE, so we ignore "duplicate column" errors.
	addCols := []string{
		`ALTER TABLE oidc_sessions ADD COLUMN code_challenge TEXT`,
		`ALTER TABLE oidc_sessions ADD COLUMN code_challenge_method TEXT`,
		`ALTER TABLE oidc_clients ADD COLUMN backchannel_logout_uri TEXT`,
	}
	for _, stmt := range addCols {
		if _, err := s.db.Exec(stmt); err != nil && !strings.Contains(err.Error(), "duplicate column") {
			return fmt.Errorf("migrate alter: %w", err)
		}
	}
	return nil
}

// --- Identities ---

func (s *SQLiteStore) SaveIdentity(ctx context.Context, id *Identity) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO identities (did, method, signing_key_path, enc_key_path, role, tenant_id, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(did) DO UPDATE SET
			signing_key_path=excluded.signing_key_path,
			enc_key_path=excluded.enc_key_path,
			role=excluded.role,
			tenant_id=excluded.tenant_id,
			updated_at=excluded.updated_at`,
		id.DID, id.Method, id.SigningKeyPath, id.EncKeyPath, id.Role, id.TenantID, id.CreatedAt, id.UpdatedAt)
	return err
}

func (s *SQLiteStore) GetIdentity(ctx context.Context, did string) (*Identity, error) {
	row := s.db.QueryRowContext(ctx, `SELECT did, method, signing_key_path, enc_key_path, role, tenant_id, created_at, updated_at FROM identities WHERE did=?`, did)
	var id Identity
	if err := row.Scan(&id.DID, &id.Method, &id.SigningKeyPath, &id.EncKeyPath, &id.Role, &id.TenantID, &id.CreatedAt, &id.UpdatedAt); err != nil {
		return nil, fmt.Errorf("get identity: %w", err)
	}
	return &id, nil
}

// --- DID Documents ---

func (s *SQLiteStore) SaveDocument(ctx context.Context, doc *did.Document) error {
	b, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO did_documents (did, document, cached_at) VALUES (?,?,?) ON CONFLICT(did) DO UPDATE SET document=excluded.document, cached_at=excluded.cached_at`,
		doc.ID, string(b), time.Now())
	return err
}

func (s *SQLiteStore) GetDocument(ctx context.Context, id string) (*did.Document, error) {
	row := s.db.QueryRowContext(ctx, `SELECT document FROM did_documents WHERE did=?`, id)
	var raw string
	if err := row.Scan(&raw); err != nil {
		return nil, fmt.Errorf("get document: %w", err)
	}
	var doc did.Document
	return &doc, json.Unmarshal([]byte(raw), &doc)
}

// --- Verifiable Credentials ---

func (s *SQLiteStore) SaveCredential(ctx context.Context, cred *vc.VerifiableCredential) error {
	b, err := json.Marshal(cred)
	if err != nil {
		return err
	}
	schemaID := ""
	if cred.CredentialSchema != nil {
		schemaID = cred.CredentialSchema.ID
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO credentials (id, subject_did, issuer_did, schema_id, valid_from, valid_until, credential, created_at) VALUES (?,?,?,?,?,?,?,?)`,
		cred.ID, cred.CredentialSubject.ID, cred.Issuer, schemaID, cred.ValidFrom, cred.ValidUntil, string(b), time.Now())
	return err
}

func (s *SQLiteStore) GetCredential(ctx context.Context, id string) (*vc.VerifiableCredential, error) {
	row := s.db.QueryRowContext(ctx, `SELECT credential FROM credentials WHERE id=?`, id)
	var raw string
	if err := row.Scan(&raw); err != nil {
		return nil, fmt.Errorf("get credential: %w", err)
	}
	var cred vc.VerifiableCredential
	return &cred, json.Unmarshal([]byte(raw), &cred)
}

func (s *SQLiteStore) ListCredentials(ctx context.Context, subjectDID string) ([]*vc.VerifiableCredential, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT credential FROM credentials WHERE subject_did=? ORDER BY valid_from DESC`, subjectDID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanCredentials(rows)
}

func (s *SQLiteStore) DeleteCredential(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM credentials WHERE id=?`, id)
	return err
}

// --- Consent Grants ---

func (s *SQLiteStore) SaveGrant(ctx context.Context, g *consent.Grant) error {
	confirmed := 0
	if g.ExplicitlyConfirmed {
		confirmed = 1
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO consent_grants (id, subject_did, relying_did, level, scope_id, granted_at, expires_at, explicitly_confirmed) VALUES (?,?,?,?,?,?,?,?)`,
		g.ID, g.SubjectDID, g.RelyingDID, string(g.Level), g.ScopeID, g.GrantedAt, g.ExpiresAt, confirmed)
	return err
}

func (s *SQLiteStore) GetGrant(ctx context.Context, id string) (*consent.Grant, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, subject_did, relying_did, level, scope_id, granted_at, expires_at, explicitly_confirmed FROM consent_grants WHERE id=?`, id)
	var g consent.Grant
	var confirmed int
	if err := row.Scan(&g.ID, &g.SubjectDID, &g.RelyingDID, &g.Level, &g.ScopeID, &g.GrantedAt, &g.ExpiresAt, &confirmed); err != nil {
		return nil, fmt.Errorf("get grant: %w", err)
	}
	g.ExplicitlyConfirmed = confirmed == 1
	return &g, nil
}

func (s *SQLiteStore) ListGrants(ctx context.Context, subjectDID string) ([]*consent.Grant, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, subject_did, relying_did, level, scope_id, granted_at, expires_at, explicitly_confirmed FROM consent_grants WHERE subject_did=? ORDER BY granted_at DESC`, subjectDID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*consent.Grant
	for rows.Next() {
		var g consent.Grant
		var confirmed int
		if err := rows.Scan(&g.ID, &g.SubjectDID, &g.RelyingDID, &g.Level, &g.ScopeID, &g.GrantedAt, &g.ExpiresAt, &confirmed); err != nil {
			return nil, err
		}
		g.ExplicitlyConfirmed = confirmed == 1
		out = append(out, &g)
	}
	return out, rows.Err()
}

func (s *SQLiteStore) DeleteGrant(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM consent_grants WHERE id=?`, id)
	return err
}

// --- Consent Receipts ---

func (s *SQLiteStore) SaveReceipt(ctx context.Context, r *consent.Receipt) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO consent_receipts (id, subject_did, relying_did, schema_id, accessed_at, legal_basis, purpose, signed_by, signature) VALUES (?,?,?,?,?,?,?,?,?)`,
		r.ID, r.SubjectDID, r.RelyingDID, r.SchemaID, r.AccessedAt, string(r.LegalBasis), r.Purpose, r.SignedBy, r.Signature)
	return err
}

func (s *SQLiteStore) ListReceipts(ctx context.Context, subjectDID string) ([]*consent.Receipt, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, subject_did, relying_did, schema_id, accessed_at, legal_basis, purpose, signed_by, signature FROM consent_receipts WHERE subject_did=? ORDER BY accessed_at DESC`, subjectDID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*consent.Receipt
	for rows.Next() {
		var r consent.Receipt
		if err := rows.Scan(&r.ID, &r.SubjectDID, &r.RelyingDID, &r.SchemaID, &r.AccessedAt, &r.LegalBasis, &r.Purpose, &r.SignedBy, &r.Signature); err != nil {
			return nil, err
		}
		out = append(out, &r)
	}
	return out, rows.Err()
}

// --- OIDC Sessions ---

func (s *SQLiteStore) SaveSession(ctx context.Context, sess *OIDCSession) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO oidc_sessions (id, subject_did, client_id, redirect_uri, scope, nonce, code, code_challenge, code_challenge_method, access_token, refresh_token_hash, user_agent, ip_address, last_used_at, created_at, expires_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET
			code=excluded.code,
			code_challenge=excluded.code_challenge,
			code_challenge_method=excluded.code_challenge_method,
			access_token=excluded.access_token,
			refresh_token_hash=excluded.refresh_token_hash,
			last_used_at=excluded.last_used_at,
			expires_at=excluded.expires_at`,
		sess.ID, sess.SubjectDID, sess.ClientID, sess.RedirectURI, sess.Scope, sess.Nonce,
		sess.Code, sess.CodeChallenge, sess.CodeChallengeMethod,
		sess.AccessToken, sess.RefreshTokenHash, sess.UserAgent, sess.IPAddress,
		sess.LastUsedAt, sess.CreatedAt, sess.ExpiresAt)
	return err
}

func (s *SQLiteStore) GetSession(ctx context.Context, id string) (*OIDCSession, error) {
	return s.scanSession(s.db.QueryRowContext(ctx, `SELECT id, subject_did, client_id, redirect_uri, scope, nonce, code, code_challenge, code_challenge_method, access_token, refresh_token_hash, user_agent, ip_address, last_used_at, created_at, expires_at FROM oidc_sessions WHERE id=?`, id))
}

func (s *SQLiteStore) GetSessionByCode(ctx context.Context, code string) (*OIDCSession, error) {
	return s.scanSession(s.db.QueryRowContext(ctx, `SELECT id, subject_did, client_id, redirect_uri, scope, nonce, code, code_challenge, code_challenge_method, access_token, refresh_token_hash, user_agent, ip_address, last_used_at, created_at, expires_at FROM oidc_sessions WHERE code=?`, code))
}

func (s *SQLiteStore) ListSessionsBySubject(ctx context.Context, subjectDID string) ([]*OIDCSession, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, subject_did, client_id, redirect_uri, scope, nonce, code, code_challenge, code_challenge_method, access_token, refresh_token_hash, user_agent, ip_address, last_used_at, created_at, expires_at FROM oidc_sessions WHERE subject_did=? AND expires_at > ? ORDER BY created_at DESC`, subjectDID, time.Now())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*OIDCSession
	for rows.Next() {
		sess, err := s.scanSessionRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sess)
	}
	return out, rows.Err()
}

func (s *SQLiteStore) DeleteSession(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM oidc_sessions WHERE id=?`, id)
	return err
}

func (s *SQLiteStore) PurgeExpiredSessions(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM oidc_sessions WHERE expires_at < ?`, time.Now())
	return err
}

func (s *SQLiteStore) scanSession(row *sql.Row) (*OIDCSession, error) {
	var sess OIDCSession
	var lastUsedAt sql.NullTime
	if err := row.Scan(&sess.ID, &sess.SubjectDID, &sess.ClientID, &sess.RedirectURI, &sess.Scope, &sess.Nonce,
		&sess.Code, &sess.CodeChallenge, &sess.CodeChallengeMethod,
		&sess.AccessToken, &sess.RefreshTokenHash, &sess.UserAgent, &sess.IPAddress,
		&lastUsedAt, &sess.CreatedAt, &sess.ExpiresAt); err != nil {
		return nil, fmt.Errorf("scan session: %w", err)
	}
	if lastUsedAt.Valid {
		sess.LastUsedAt = &lastUsedAt.Time
	}
	return &sess, nil
}

func (s *SQLiteStore) scanSessionRow(rows *sql.Rows) (*OIDCSession, error) {
	var sess OIDCSession
	var lastUsedAt sql.NullTime
	if err := rows.Scan(&sess.ID, &sess.SubjectDID, &sess.ClientID, &sess.RedirectURI, &sess.Scope, &sess.Nonce,
		&sess.Code, &sess.CodeChallenge, &sess.CodeChallengeMethod,
		&sess.AccessToken, &sess.RefreshTokenHash, &sess.UserAgent, &sess.IPAddress,
		&lastUsedAt, &sess.CreatedAt, &sess.ExpiresAt); err != nil {
		return nil, err
	}
	if lastUsedAt.Valid {
		sess.LastUsedAt = &lastUsedAt.Time
	}
	return &sess, nil
}

// --- OIDC Clients ---

func (s *SQLiteStore) SaveClient(ctx context.Context, c *OIDCClient) error {
	redirectURIs, _ := json.Marshal(c.RedirectURIs)
	grantTypes, _ := json.Marshal(c.GrantTypes)
	responseTypes, _ := json.Marshal(c.ResponseTypes)
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO oidc_clients (client_id, client_secret_hash, client_name, redirect_uris, token_endpoint_auth_method, grant_types, response_types, scope, tenant_id, backchannel_logout_uri, created_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(client_id) DO UPDATE SET
			client_secret_hash=excluded.client_secret_hash,
			client_name=excluded.client_name,
			redirect_uris=excluded.redirect_uris,
			token_endpoint_auth_method=excluded.token_endpoint_auth_method,
			grant_types=excluded.grant_types,
			response_types=excluded.response_types,
			scope=excluded.scope,
			backchannel_logout_uri=excluded.backchannel_logout_uri`,
		c.ClientID, c.ClientSecretHash, c.ClientName, string(redirectURIs),
		c.TokenEndpointAuthMethod, string(grantTypes), string(responseTypes),
		c.Scope, c.TenantID, c.BackChannelLogoutURI, c.CreatedAt)
	return err
}

func (s *SQLiteStore) GetClient(ctx context.Context, clientID string) (*OIDCClient, error) {
	row := s.db.QueryRowContext(ctx, `SELECT client_id, client_secret_hash, client_name, redirect_uris, token_endpoint_auth_method, grant_types, response_types, scope, tenant_id, backchannel_logout_uri, created_at FROM oidc_clients WHERE client_id=?`, clientID)
	return s.scanClient(row)
}

func (s *SQLiteStore) ListClients(ctx context.Context) ([]*OIDCClient, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT client_id, client_secret_hash, client_name, redirect_uris, token_endpoint_auth_method, grant_types, response_types, scope, tenant_id, backchannel_logout_uri, created_at FROM oidc_clients ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*OIDCClient
	for rows.Next() {
		c, err := s.scanClientRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *SQLiteStore) DeleteClient(ctx context.Context, clientID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM oidc_clients WHERE client_id=?`, clientID)
	return err
}

func (s *SQLiteStore) scanClient(row *sql.Row) (*OIDCClient, error) {
	var c OIDCClient
	var redirectURIs, grantTypes, responseTypes string
	if err := row.Scan(&c.ClientID, &c.ClientSecretHash, &c.ClientName, &redirectURIs,
		&c.TokenEndpointAuthMethod, &grantTypes, &responseTypes, &c.Scope, &c.TenantID, &c.BackChannelLogoutURI, &c.CreatedAt); err != nil {
		return nil, fmt.Errorf("scan client: %w", err)
	}
	json.Unmarshal([]byte(redirectURIs), &c.RedirectURIs)
	json.Unmarshal([]byte(grantTypes), &c.GrantTypes)
	json.Unmarshal([]byte(responseTypes), &c.ResponseTypes)
	return &c, nil
}

func (s *SQLiteStore) scanClientRow(rows *sql.Rows) (*OIDCClient, error) {
	var c OIDCClient
	var redirectURIs, grantTypes, responseTypes string
	if err := rows.Scan(&c.ClientID, &c.ClientSecretHash, &c.ClientName, &redirectURIs,
		&c.TokenEndpointAuthMethod, &grantTypes, &responseTypes, &c.Scope, &c.TenantID, &c.BackChannelLogoutURI, &c.CreatedAt); err != nil {
		return nil, err
	}
	json.Unmarshal([]byte(redirectURIs), &c.RedirectURIs)
	json.Unmarshal([]byte(grantTypes), &c.GrantTypes)
	json.Unmarshal([]byte(responseTypes), &c.ResponseTypes)
	return &c, nil
}

// --- Refresh Tokens ---

func (s *SQLiteStore) SaveRefreshToken(ctx context.Context, t *RefreshToken) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO refresh_tokens (hash, subject_did, client_id, scope, issued_at, expires_at, used_at)
		VALUES (?,?,?,?,?,?,?)
		ON CONFLICT(hash) DO UPDATE SET used_at=excluded.used_at`,
		t.Hash, t.SubjectDID, t.ClientID, t.Scope, t.IssuedAt, t.ExpiresAt, t.UsedAt)
	return err
}

func (s *SQLiteStore) GetRefreshToken(ctx context.Context, hash string) (*RefreshToken, error) {
	row := s.db.QueryRowContext(ctx, `SELECT hash, subject_did, client_id, scope, issued_at, expires_at, used_at FROM refresh_tokens WHERE hash=?`, hash)
	var t RefreshToken
	var usedAt sql.NullTime
	if err := row.Scan(&t.Hash, &t.SubjectDID, &t.ClientID, &t.Scope, &t.IssuedAt, &t.ExpiresAt, &usedAt); err != nil {
		return nil, fmt.Errorf("get refresh token: %w", err)
	}
	if usedAt.Valid {
		t.UsedAt = &usedAt.Time
	}
	return &t, nil
}

func (s *SQLiteStore) DeleteRefreshToken(ctx context.Context, hash string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM refresh_tokens WHERE hash=?`, hash)
	return err
}

// --- External Provider Links ---

func (s *SQLiteStore) SaveExternalLink(ctx context.Context, l *ExternalProviderLink) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO external_provider_links (subject_did, provider, external_id, linked_at, last_used_at)
		VALUES (?,?,?,?,?)
		ON CONFLICT(provider, external_id) DO UPDATE SET
			subject_did=excluded.subject_did,
			last_used_at=excluded.last_used_at`,
		l.SubjectDID, l.Provider, l.ExternalID, l.LinkedAt, l.LastUsedAt)
	return err
}

func (s *SQLiteStore) GetExternalLink(ctx context.Context, provider, externalID string) (*ExternalProviderLink, error) {
	row := s.db.QueryRowContext(ctx, `SELECT subject_did, provider, external_id, linked_at, last_used_at FROM external_provider_links WHERE provider=? AND external_id=?`, provider, externalID)
	var l ExternalProviderLink
	if err := row.Scan(&l.SubjectDID, &l.Provider, &l.ExternalID, &l.LinkedAt, &l.LastUsedAt); err != nil {
		return nil, fmt.Errorf("get external link: %w", err)
	}
	return &l, nil
}

func (s *SQLiteStore) ListExternalLinks(ctx context.Context, subjectDID string) ([]*ExternalProviderLink, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT subject_did, provider, external_id, linked_at, last_used_at FROM external_provider_links WHERE subject_did=? ORDER BY linked_at DESC`, subjectDID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*ExternalProviderLink
	for rows.Next() {
		var l ExternalProviderLink
		if err := rows.Scan(&l.SubjectDID, &l.Provider, &l.ExternalID, &l.LinkedAt, &l.LastUsedAt); err != nil {
			return nil, err
		}
		out = append(out, &l)
	}
	return out, rows.Err()
}

func (s *SQLiteStore) DeleteExternalLink(ctx context.Context, provider, externalID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM external_provider_links WHERE provider=? AND external_id=?`, provider, externalID)
	return err
}

// --- Magic Link Tokens ---

func (s *SQLiteStore) SaveMagicLinkToken(ctx context.Context, t *MagicLinkToken) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO magic_link_tokens (hash, email, expires_at, created_at) VALUES (?,?,?,?)`,
		t.Hash, t.Email, t.ExpiresAt, t.CreatedAt)
	return err
}

func (s *SQLiteStore) GetMagicLinkToken(ctx context.Context, hash string) (*MagicLinkToken, error) {
	row := s.db.QueryRowContext(ctx, `SELECT hash, email, expires_at, created_at FROM magic_link_tokens WHERE hash=?`, hash)
	var t MagicLinkToken
	if err := row.Scan(&t.Hash, &t.Email, &t.ExpiresAt, &t.CreatedAt); err != nil {
		return nil, fmt.Errorf("get magic link token: %w", err)
	}
	return &t, nil
}

func (s *SQLiteStore) DeleteMagicLinkToken(ctx context.Context, hash string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM magic_link_tokens WHERE hash=?`, hash)
	return err
}

// --- WebAuthn Credentials ---

func (s *SQLiteStore) SaveWebAuthnCredential(ctx context.Context, c *WebAuthnCredential) error {
	transports, _ := json.Marshal(c.Transports)
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO webauthn_credentials (credential_id, subject_did, public_key_cbor, attestation_type, aaguid, sign_count, name, transports, created_at, last_used_at)
		VALUES (?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(credential_id) DO UPDATE SET sign_count=excluded.sign_count, name=excluded.name, last_used_at=excluded.last_used_at`,
		c.CredentialID, c.SubjectDID, c.PublicKeyCBOR, c.AttestationType, c.AAGUID,
		c.SignCount, c.Name, string(transports), c.CreatedAt, c.LastUsedAt)
	return err
}

func (s *SQLiteStore) GetWebAuthnCredential(ctx context.Context, credentialID string) (*WebAuthnCredential, error) {
	row := s.db.QueryRowContext(ctx, `SELECT credential_id, subject_did, public_key_cbor, attestation_type, aaguid, sign_count, name, transports, created_at, last_used_at FROM webauthn_credentials WHERE credential_id=?`, credentialID)
	return s.scanWebAuthnCredential(row)
}

func (s *SQLiteStore) ListWebAuthnCredentials(ctx context.Context, subjectDID string) ([]*WebAuthnCredential, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT credential_id, subject_did, public_key_cbor, attestation_type, aaguid, sign_count, name, transports, created_at, last_used_at FROM webauthn_credentials WHERE subject_did=? ORDER BY created_at DESC`, subjectDID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*WebAuthnCredential
	for rows.Next() {
		c, err := s.scanWebAuthnRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *SQLiteStore) UpdateWebAuthnCredential(ctx context.Context, c *WebAuthnCredential) error {
	_, err := s.db.ExecContext(ctx, `UPDATE webauthn_credentials SET sign_count=?, last_used_at=?, name=? WHERE credential_id=?`,
		c.SignCount, c.LastUsedAt, c.Name, c.CredentialID)
	return err
}

func (s *SQLiteStore) DeleteWebAuthnCredential(ctx context.Context, credentialID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM webauthn_credentials WHERE credential_id=?`, credentialID)
	return err
}

func (s *SQLiteStore) scanWebAuthnCredential(row *sql.Row) (*WebAuthnCredential, error) {
	var c WebAuthnCredential
	var transports string
	var lastUsedAt sql.NullTime
	if err := row.Scan(&c.CredentialID, &c.SubjectDID, &c.PublicKeyCBOR, &c.AttestationType, &c.AAGUID,
		&c.SignCount, &c.Name, &transports, &c.CreatedAt, &lastUsedAt); err != nil {
		return nil, fmt.Errorf("scan webauthn credential: %w", err)
	}
	json.Unmarshal([]byte(transports), &c.Transports)
	if lastUsedAt.Valid {
		c.LastUsedAt = &lastUsedAt.Time
	}
	return &c, nil
}

func (s *SQLiteStore) scanWebAuthnRow(rows *sql.Rows) (*WebAuthnCredential, error) {
	var c WebAuthnCredential
	var transports string
	var lastUsedAt sql.NullTime
	if err := rows.Scan(&c.CredentialID, &c.SubjectDID, &c.PublicKeyCBOR, &c.AttestationType, &c.AAGUID,
		&c.SignCount, &c.Name, &transports, &c.CreatedAt, &lastUsedAt); err != nil {
		return nil, err
	}
	json.Unmarshal([]byte(transports), &c.Transports)
	if lastUsedAt.Valid {
		c.LastUsedAt = &lastUsedAt.Time
	}
	return &c, nil
}

// --- TOTP Credentials ---

func (s *SQLiteStore) SaveTOTPCredential(ctx context.Context, c *TOTPCredential) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO totp_credentials (subject_did, encrypted_secret, account_name, created_at)
		VALUES (?,?,?,?)
		ON CONFLICT(subject_did) DO UPDATE SET encrypted_secret=excluded.encrypted_secret, account_name=excluded.account_name`,
		c.SubjectDID, c.EncryptedSecret, c.AccountName, c.CreatedAt)
	return err
}

func (s *SQLiteStore) GetTOTPCredential(ctx context.Context, subjectDID string) (*TOTPCredential, error) {
	row := s.db.QueryRowContext(ctx, `SELECT subject_did, encrypted_secret, account_name, created_at FROM totp_credentials WHERE subject_did=?`, subjectDID)
	var c TOTPCredential
	if err := row.Scan(&c.SubjectDID, &c.EncryptedSecret, &c.AccountName, &c.CreatedAt); err != nil {
		return nil, fmt.Errorf("get totp credential: %w", err)
	}
	return &c, nil
}

func (s *SQLiteStore) DeleteTOTPCredential(ctx context.Context, subjectDID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM totp_credentials WHERE subject_did=?`, subjectDID)
	return err
}

// --- Webhook Subscriptions ---

func (s *SQLiteStore) SaveWebhookSubscription(ctx context.Context, sub *WebhookSubscription) error {
	eventTypes, _ := json.Marshal(sub.EventTypes)
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO webhook_subscriptions (id, url, event_types, secret_hash, tenant_id, created_at)
		VALUES (?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET url=excluded.url, event_types=excluded.event_types`,
		sub.ID, sub.URL, string(eventTypes), sub.SecretHash, sub.TenantID, sub.CreatedAt)
	return err
}

func (s *SQLiteStore) GetWebhookSubscription(ctx context.Context, id string) (*WebhookSubscription, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, url, event_types, secret_hash, tenant_id, created_at FROM webhook_subscriptions WHERE id=?`, id)
	return s.scanWebhookSub(row)
}

func (s *SQLiteStore) ListWebhookSubscriptions(ctx context.Context, eventType string) ([]*WebhookSubscription, error) {
	// Filter: subscriptions that include the given event type, or "all" wildcard
	rows, err := s.db.QueryContext(ctx, `SELECT id, url, event_types, secret_hash, tenant_id, created_at FROM webhook_subscriptions`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*WebhookSubscription
	for rows.Next() {
		sub, err := s.scanWebhookSubRow(rows)
		if err != nil {
			return nil, err
		}
		for _, et := range sub.EventTypes {
			if et == "*" || et == eventType {
				out = append(out, sub)
				break
			}
		}
	}
	return out, rows.Err()
}

func (s *SQLiteStore) DeleteWebhookSubscription(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM webhook_subscriptions WHERE id=?`, id)
	return err
}

func (s *SQLiteStore) scanWebhookSub(row *sql.Row) (*WebhookSubscription, error) {
	var sub WebhookSubscription
	var eventTypes string
	if err := row.Scan(&sub.ID, &sub.URL, &eventTypes, &sub.SecretHash, &sub.TenantID, &sub.CreatedAt); err != nil {
		return nil, fmt.Errorf("scan webhook subscription: %w", err)
	}
	json.Unmarshal([]byte(eventTypes), &sub.EventTypes)
	return &sub, nil
}

func (s *SQLiteStore) scanWebhookSubRow(rows *sql.Rows) (*WebhookSubscription, error) {
	var sub WebhookSubscription
	var eventTypes string
	if err := rows.Scan(&sub.ID, &sub.URL, &eventTypes, &sub.SecretHash, &sub.TenantID, &sub.CreatedAt); err != nil {
		return nil, err
	}
	json.Unmarshal([]byte(eventTypes), &sub.EventTypes)
	return &sub, nil
}

// --- Auth Failures ---

const (
	lockThreshold1 = 5
	lockDuration1  = 5 * time.Minute
	lockThreshold2 = 10
	lockDuration2  = 30 * time.Minute
	lockThreshold3 = 20 // permanent (admin reset required)
)

func (s *SQLiteStore) RecordAuthFailure(ctx context.Context, subjectOrEmail string) error {
	now := time.Now()
	var lockedUntil *time.Time
	var count int
	row := s.db.QueryRowContext(ctx, `SELECT count FROM auth_failures WHERE subject_or_email=?`, subjectOrEmail)
	_ = row.Scan(&count)
	count++
	switch {
	case count >= lockThreshold3:
		// permanent lock — set far future
		t := now.Add(100 * 365 * 24 * time.Hour)
		lockedUntil = &t
	case count >= lockThreshold2:
		t := now.Add(lockDuration2)
		lockedUntil = &t
	case count >= lockThreshold1:
		t := now.Add(lockDuration1)
		lockedUntil = &t
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO auth_failures (subject_or_email, count, last_failure_at, locked_until) VALUES (?,?,?,?)
		ON CONFLICT(subject_or_email) DO UPDATE SET count=excluded.count, last_failure_at=excluded.last_failure_at, locked_until=excluded.locked_until`,
		subjectOrEmail, count, now, lockedUntil)
	return err
}

func (s *SQLiteStore) GetAuthFailures(ctx context.Context, subjectOrEmail string) (int, *time.Time, error) {
	row := s.db.QueryRowContext(ctx, `SELECT count, locked_until FROM auth_failures WHERE subject_or_email=?`, subjectOrEmail)
	var count int
	var lockedUntil sql.NullTime
	if err := row.Scan(&count, &lockedUntil); err != nil {
		if strings.Contains(err.Error(), "no rows") {
			return 0, nil, nil
		}
		return 0, nil, err
	}
	var lu *time.Time
	if lockedUntil.Valid {
		lu = &lockedUntil.Time
	}
	return count, lu, nil
}

func (s *SQLiteStore) ClearAuthFailures(ctx context.Context, subjectOrEmail string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM auth_failures WHERE subject_or_email=?`, subjectOrEmail)
	return err
}

// --- Revoked Tokens ---

func (s *SQLiteStore) SaveRevokedToken(ctx context.Context, hash string, expiresAt time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT OR REPLACE INTO revoked_tokens(hash, revoked_at, expires_at) VALUES(?,?,?)`,
		hash, time.Now(), expiresAt,
	)
	return err
}

func (s *SQLiteStore) IsTokenRevoked(ctx context.Context, hash string) (bool, error) {
	var count int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM revoked_tokens WHERE hash=? AND expires_at > ?`,
		hash, time.Now(),
	).Scan(&count)
	return count > 0, err
}

func (s *SQLiteStore) PurgeExpiredRevokedTokens(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM revoked_tokens WHERE expires_at <= ?`, time.Now())
	return err
}

// --- OIDC RP State ---

func (s *SQLiteStore) SaveOIDCState(ctx context.Context, st *OIDCState) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO oidc_states (state, provider, next, expires_at, created_at)
		 VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT(state) DO UPDATE SET expires_at=excluded.expires_at`,
		st.State, st.Provider, st.Next, st.ExpiresAt, st.CreatedAt,
	)
	return err
}

func (s *SQLiteStore) GetOIDCState(ctx context.Context, state string) (*OIDCState, error) {
	var st OIDCState
	err := s.db.QueryRowContext(ctx,
		`SELECT state, provider, next, expires_at, created_at FROM oidc_states WHERE state=?`,
		state,
	).Scan(&st.State, &st.Provider, &st.Next, &st.ExpiresAt, &st.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &st, nil
}

func (s *SQLiteStore) DeleteOIDCState(ctx context.Context, state string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM oidc_states WHERE state=?`, state)
	return err
}

// --- helpers ---

func scanCredentials(rows *sql.Rows) ([]*vc.VerifiableCredential, error) {
	var out []*vc.VerifiableCredential
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var cred vc.VerifiableCredential
		if err := json.Unmarshal([]byte(raw), &cred); err != nil {
			return nil, err
		}
		out = append(out, &cred)
	}
	return out, rows.Err()
}
