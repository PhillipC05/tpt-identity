package oidc

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/PhillipC05/tpt-identity/internal/store"
)

const (
	codeTTL          = 5 * time.Minute
	idTokenTTL       = time.Hour
	accessTokenTTL   = time.Hour
	refreshTokenTTL  = 30 * 24 * time.Hour // 30 days
)

// Provider handles OIDC authorization code flow endpoints.
type Provider struct {
	issuer     string
	signingKey ed25519.PrivateKey  // current key — used for new token issuance
	signingPub ed25519.PublicKey   // current public key
	keyID      string
	prevKeys   []ed25519.PublicKey // previous public keys — trusted for verification but not issuance
	store      store.Store
}

// NewProvider creates an OIDC Provider.
func NewProvider(issuer string, key ed25519.PrivateKey, keyID string, st store.Store) *Provider {
	return &Provider{
		issuer:     issuer,
		signingKey: key,
		signingPub: key.Public().(ed25519.PublicKey),
		keyID:      keyID,
		store:      st,
	}
}

// AddPreviousKey registers a retired public key that is still trusted for verifying
// existing tokens during a key rotation transition period.
func (p *Provider) AddPreviousKey(pub ed25519.PublicKey) {
	p.prevKeys = append(p.prevKeys, pub)
}

// TrustedPublicKeys returns all public keys trusted for verification: current + previous.
func (p *Provider) TrustedPublicKeys() []ed25519.PublicKey {
	keys := []ed25519.PublicKey{p.signingPub}
	keys = append(keys, p.prevKeys...)
	return keys
}

// AuthorizeHandler handles GET /authorize.
// Validates the registered client and redirect_uri before issuing an authorization code.
// Supports PKCE (RFC 7636) via code_challenge / code_challenge_method parameters.
func (p *Provider) AuthorizeHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	scope := q.Get("scope")
	nonce := q.Get("nonce")
	state := q.Get("state")
	codeChallenge := q.Get("code_challenge")
	codeChallengeMethod := q.Get("code_challenge_method")
	subjectDID := r.Header.Get("X-Subject-DID") // set by bridge or trusted gateway

	if clientID == "" || redirectURI == "" || subjectDID == "" {
		http.Error(w, "missing required parameters", http.StatusBadRequest)
		return
	}

	// Validate client and redirect_uri against registration.
	client, err := p.store.GetClient(r.Context(), clientID)
	if err != nil {
		writeError(w, "unauthorized_client", "unknown client_id")
		return
	}
	if !containsURI(client.RedirectURIs, redirectURI) {
		writeError(w, "invalid_request", "redirect_uri not registered for this client")
		return
	}

	// PKCE: only S256 is accepted; plain is a security downgrade we don't support.
	if codeChallenge != "" && codeChallengeMethod != "S256" {
		writeError(w, "invalid_request", "only code_challenge_method=S256 is supported")
		return
	}

	code, err := randomHex(32)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	sess := &store.OIDCSession{
		ID:                  randomID(),
		SubjectDID:          subjectDID,
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		Scope:               scope,
		Nonce:               nonce,
		Code:                code,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		UserAgent:           r.UserAgent(),
		IPAddress:           remoteIP(r),
		CreatedAt:           time.Now(),
		ExpiresAt:           time.Now().Add(codeTTL),
	}
	if err := p.store.SaveSession(r.Context(), sess); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	redirect := redirectURI + "?code=" + code
	if state != "" {
		redirect += "&state=" + state
	}
	http.Redirect(w, r, redirect, http.StatusFound)
}

// TokenHandler handles POST /token — authorization code exchange and refresh token rotation.
func (p *Provider) TokenHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	grantType := r.FormValue("grant_type")
	if grantType == "" {
		grantType = "authorization_code"
	}

	switch grantType {
	case "authorization_code":
		p.handleAuthCodeExchange(w, r)
	case "refresh_token":
		p.handleRefreshTokenGrant(w, r)
	case "client_credentials":
		p.handleClientCredentials(w, r)
	default:
		writeError(w, "unsupported_grant_type", "supported: authorization_code, refresh_token, client_credentials")
	}
}

func (p *Provider) handleAuthCodeExchange(w http.ResponseWriter, r *http.Request) {
	code := r.FormValue("code")
	clientID := r.FormValue("client_id")
	if code == "" {
		writeError(w, "invalid_request", "missing code")
		return
	}

	sess, err := p.store.GetSessionByCode(r.Context(), code)
	if err != nil || time.Now().After(sess.ExpiresAt) {
		writeError(w, "invalid_grant", "code not found or expired")
		return
	}

	// Validate client matches.
	if clientID != "" && clientID != sess.ClientID {
		writeError(w, "invalid_grant", "client_id mismatch")
		return
	}

	// Validate client secret for confidential clients.
	if err := p.validateClientAuth(r, sess.ClientID); err != nil {
		writeError(w, "invalid_client", err.Error())
		return
	}

	// PKCE verification (RFC 7636 §4.6). If the session carried a challenge the
	// token request must supply a matching verifier.
	if sess.CodeChallenge != "" {
		verifier := r.FormValue("code_verifier")
		if verifier == "" {
			writeError(w, "invalid_grant", "code_verifier required")
			return
		}
		if !pkceVerify(verifier, sess.CodeChallenge) {
			writeError(w, "invalid_grant", "code_verifier mismatch")
			return
		}
	}

	idToken, err := IssueIDToken(p.issuer, sess.SubjectDID, sess.ClientID, sess.Nonce, idTokenTTL, p.signingKey, nil, p.keyID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	accessToken, err := IssueAccessToken(p.issuer, sess.SubjectDID, sess.ClientID, accessTokenTTL, p.signingKey, p.keyID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	rawRefresh, refreshHash, err := generateRefreshToken()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Persist refresh token.
	rt := &store.RefreshToken{
		Hash:       refreshHash,
		SubjectDID: sess.SubjectDID,
		ClientID:   sess.ClientID,
		Scope:      sess.Scope,
		IssuedAt:   time.Now(),
		ExpiresAt:  time.Now().Add(refreshTokenTTL),
	}
	if err := p.store.SaveRefreshToken(r.Context(), rt); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Invalidate the used code.
	_ = p.store.DeleteSession(r.Context(), sess.ID)

	writeTokenResponse(w, accessToken, idToken, rawRefresh, sess.Scope, accessTokenTTL)
}

func (p *Provider) handleRefreshTokenGrant(w http.ResponseWriter, r *http.Request) {
	rawToken := r.FormValue("refresh_token")
	if rawToken == "" {
		writeError(w, "invalid_request", "missing refresh_token")
		return
	}

	hash := hashToken(rawToken)
	rt, err := p.store.GetRefreshToken(r.Context(), hash)
	if err != nil {
		writeError(w, "invalid_grant", "refresh token not found")
		return
	}
	if time.Now().After(rt.ExpiresAt) {
		_ = p.store.DeleteRefreshToken(r.Context(), hash)
		writeError(w, "invalid_grant", "refresh token expired")
		return
	}
	// Detect replay of an already-consumed token (theft indicator).
	if rt.UsedAt != nil {
		_ = p.store.DeleteRefreshToken(r.Context(), hash)
		writeError(w, "invalid_grant", "refresh token already used")
		return
	}

	// Validate client auth.
	if err := p.validateClientAuth(r, rt.ClientID); err != nil {
		writeError(w, "invalid_client", err.Error())
		return
	}

	// Mark old token as used (keep briefly for theft detection, then GC).
	now := time.Now()
	rt.UsedAt = &now
	_ = p.store.SaveRefreshToken(r.Context(), rt)

	// Issue new tokens.
	accessToken, err := IssueAccessToken(p.issuer, rt.SubjectDID, rt.ClientID, accessTokenTTL, p.signingKey, p.keyID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	rawRefresh, refreshHash, err := generateRefreshToken()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	newRT := &store.RefreshToken{
		Hash:       refreshHash,
		SubjectDID: rt.SubjectDID,
		ClientID:   rt.ClientID,
		Scope:      rt.Scope,
		IssuedAt:   time.Now(),
		ExpiresAt:  time.Now().Add(refreshTokenTTL),
	}
	if err := p.store.SaveRefreshToken(r.Context(), newRT); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	writeTokenResponse(w, accessToken, "", rawRefresh, rt.Scope, accessTokenTTL)
}

// UserinfoHandler handles GET /userinfo.
func (p *Provider) UserinfoHandler(w http.ResponseWriter, r *http.Request) {
	bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if bearer == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	claims, err := p.verifyAny(bearer)
	if err != nil {
		http.Error(w, "invalid token: "+err.Error(), http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"sub": claims.Subject,
		"did": claims.DID,
		"amr": claims.AMR,
	})
}

// IssueSessionForDID is called by the bridge layer to directly issue an OIDC session
// after external authentication, bypassing the authorize endpoint.
func (p *Provider) IssueSessionForDID(subjectDID, clientID, redirectURI, scope, nonce string, amr []string) (code string, err error) {
	code, err = randomHex(32)
	if err != nil {
		return "", err
	}
	sess := &store.OIDCSession{
		ID:          randomID(),
		SubjectDID:  subjectDID,
		ClientID:    clientID,
		RedirectURI: redirectURI,
		Scope:       scope,
		Nonce:       nonce,
		Code:        code,
		CreatedAt:   time.Now(),
		ExpiresAt:   time.Now().Add(codeTTL),
	}
	return code, p.store.SaveSession(nil, sess) //nolint:staticcheck // ctx provided by caller
}

// IssueSessionForDIDCtx is the context-aware version used by bridge handlers.
func (p *Provider) IssueSessionForDIDCtx(r *http.Request, subjectDID, clientID, redirectURI, scope, nonce string, amr []string) (string, error) {
	code, err := randomHex(32)
	if err != nil {
		return "", err
	}
	sess := &store.OIDCSession{
		ID:          randomID(),
		SubjectDID:  subjectDID,
		ClientID:    clientID,
		RedirectURI: redirectURI,
		Scope:       scope,
		Nonce:       nonce,
		Code:        code,
		UserAgent:   r.UserAgent(),
		IPAddress:   remoteIP(r),
		CreatedAt:   time.Now(),
		ExpiresAt:   time.Now().Add(codeTTL),
	}
	return code, p.store.SaveSession(r.Context(), sess)
}

// SubjectFromBearer extracts and verifies the subject DID from a Bearer token.
func (p *Provider) SubjectFromBearer(authHeader string) (string, error) {
	bearer := strings.TrimPrefix(authHeader, "Bearer ")
	if bearer == "" {
		return "", fmt.Errorf("no bearer token")
	}
	claims, err := Verify(bearer, p.signingPub)
	if err != nil {
		return "", err
	}
	return claims.Subject, nil
}

// handleClientCredentials handles grant_type=client_credentials for service-to-service auth.
func (p *Provider) handleClientCredentials(w http.ResponseWriter, r *http.Request) {
	// Client ID from Basic auth or form param.
	clientID := ""
	if user, _, ok := r.BasicAuth(); ok {
		clientID = user
	} else {
		clientID = r.FormValue("client_id")
	}
	if clientID == "" {
		writeError(w, "invalid_client", "client_id required")
		return
	}
	if err := p.validateClientAuth(r, clientID); err != nil {
		writeError(w, "invalid_client", err.Error())
		return
	}
	scope := r.FormValue("scope")
	// sub == clientID for service accounts; no refresh token issued.
	accessToken, err := IssueAccessToken(p.issuer, clientID, clientID, accessTokenTTL, p.signingKey, p.keyID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(map[string]any{
		"token_type":   "Bearer",
		"expires_in":   int(accessTokenTTL.Seconds()),
		"access_token": accessToken,
		"scope":        scope,
	})
}

// ValidateAccessToken verifies an access token JWT and checks it is the access type.
func (p *Provider) ValidateAccessToken(token string) error {
	_, err := p.ClientIDFromToken(token)
	return err
}

// ClientIDFromToken verifies the token and returns the client ID (audience) it was issued to.
func (p *Provider) ClientIDFromToken(token string) (string, error) {
	claims, err := p.verifyAny(token)
	if err != nil {
		return "", err
	}
	if claims.TokenType != "access" {
		return "", fmt.Errorf("not an access token")
	}
	return claims.Audience, nil
}

// verifyAny tries the current public key then any previous keys. This allows tokens
// issued under a retired key to remain valid during a rotation transition window.
func (p *Provider) verifyAny(token string) (*Claims, error) {
	if claims, err := Verify(token, p.signingPub); err == nil {
		return claims, nil
	}
	for _, prev := range p.prevKeys {
		if claims, err := Verify(token, prev); err == nil {
			return claims, nil
		}
	}
	return nil, fmt.Errorf("jwt: no trusted key accepted the token")
}

// IntrospectHandler handles POST /oidc/introspect (RFC 7662).
func (p *Provider) IntrospectHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	token := r.FormValue("token")
	w.Header().Set("Content-Type", "application/json")
	if token == "" {
		json.NewEncoder(w).Encode(map[string]any{"active": false})
		return
	}
	// Check revocation before signature verification.
	if revoked, _ := p.store.IsTokenRevoked(r.Context(), hashToken(token)); revoked {
		json.NewEncoder(w).Encode(map[string]any{"active": false})
		return
	}
	claims, err := p.verifyAny(token)
	if err != nil || claims.TokenType != "access" {
		json.NewEncoder(w).Encode(map[string]any{"active": false})
		return
	}
	json.NewEncoder(w).Encode(map[string]any{
		"active":    true,
		"sub":       claims.Subject,
		"client_id": claims.Audience,
		"iss":       claims.Issuer,
		"iat":       claims.IssuedAt,
		"exp":       claims.ExpiresAt,
		"did":       claims.DID,
	})
}

// RevokeHandler handles POST /oidc/revoke (RFC 7009).
func (p *Provider) RevokeHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	token := r.FormValue("token")
	if token == "" {
		w.WriteHeader(http.StatusOK) // RFC 7009: always 200
		return
	}
	expiresAt := time.Now().Add(accessTokenTTL)
	if claims, err := ParseUnverified(token); err == nil {
		expiresAt = time.Unix(claims.ExpiresAt, 0)
	}
	_ = p.store.SaveRevokedToken(r.Context(), hashToken(token), expiresAt)
	w.WriteHeader(http.StatusOK)
}

// validateClientAuth checks the client secret for confidential clients.
func (p *Provider) validateClientAuth(r *http.Request, clientID string) error {
	client, err := p.store.GetClient(r.Context(), clientID)
	if err != nil {
		return fmt.Errorf("unknown client")
	}
	if client.TokenEndpointAuthMethod == "none" {
		return nil // public client, no secret required
	}
	// Check Authorization: Basic or client_secret form param.
	var providedSecret string
	if user, pass, ok := r.BasicAuth(); ok && user == clientID {
		providedSecret = pass
	} else {
		providedSecret = r.FormValue("client_secret")
	}
	if providedSecret == "" {
		return fmt.Errorf("client authentication required")
	}
	if subtle.ConstantTimeCompare([]byte(hashSecret(providedSecret)), []byte(client.ClientSecretHash)) != 1 {
		return fmt.Errorf("invalid client credentials")
	}
	return nil
}

func writeTokenResponse(w http.ResponseWriter, accessToken, idToken, refreshToken, scope string, ttl time.Duration) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	resp := map[string]any{
		"token_type":    "Bearer",
		"expires_in":    int(ttl.Seconds()),
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"scope":         scope,
	}
	if idToken != "" {
		resp["id_token"] = idToken
	}
	json.NewEncoder(w).Encode(resp)
}

func generateRefreshToken() (raw, hash string, err error) {
	raw, err = randomHex(32)
	if err != nil {
		return "", "", err
	}
	return raw, hashToken(raw), nil
}

func hashToken(raw string) string {
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}

func containsURI(list []string, uri string) bool {
	for _, u := range list {
		if u == uri {
			return true
		}
	}
	return false
}

func remoteIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		return strings.SplitN(fwd, ",", 2)[0]
	}
	ip := r.RemoteAddr
	if idx := strings.LastIndex(ip, ":"); idx > 0 {
		return ip[:idx]
	}
	return ip
}

func writeError(w http.ResponseWriter, code, desc string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	json.NewEncoder(w).Encode(map[string]string{"error": code, "error_description": desc})
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func randomID() string {
	s, _ := randomHex(16)
	return fmt.Sprintf("sess_%s", s)
}

// pkceVerify checks that SHA-256(verifier) == challenge (base64url, no padding).
func pkceVerify(verifier, challenge string) bool {
	h := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(h[:])
	return subtle.ConstantTimeCompare([]byte(computed), []byte(challenge)) == 1
}
