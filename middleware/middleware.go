// Package middleware provides drop-in HTTP middleware for services that consume tpt-identity.
//
// Typical usage in tpt-healthcare:
//
//	idClient := client.NewClient(client.Config{
//	    BaseURL:      "https://identity.tpt.govt.nz",
//	    ClientID:     os.Getenv("TPT_CLIENT_ID"),
//	    ClientSecret: os.Getenv("TPT_CLIENT_SECRET"),
//	})
//
//	mux.Handle("/patient/records",
//	    middleware.RequireConsent(idClient, "healthcare.gp-records")(myHandler))
//
// The middleware verifies the OIDC access token, resolves the subject DID, checks that
// a consent grant exists for the relying party and schema, then passes the request to
// the next handler with the subject DID available via middleware.SubjectDID(ctx).
package middleware

import (
	"net/http"
	"strings"
	"time"

	tptclient "github.com/PhillipC05/tpt-identity/client"
	"github.com/PhillipC05/tpt-identity/pkg/consent"
)

// RequireConsent returns middleware that:
//  1. Extracts and introspects the Bearer access token
//  2. Resolves the subject DID from the token's sub claim
//  3. Checks that a non-expired, non-revoked consent grant exists for this subject + schemaID
//  4. Stores the subject DID and all grants in the request context
//
// Use middleware.SubjectDID(ctx) and middleware.Grants(ctx) in the handler.
func RequireConsent(c *tptclient.Client, schemaID string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			subjectDID, grants, ok := resolveSubjectAndGrants(w, r, c, schemaID)
			if !ok {
				return
			}
			ctx := withSubjectDID(r.Context(), subjectDID)
			ctx = withGrants(ctx, grants)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireCredential returns middleware that does everything RequireConsent does, and also
// verifies that the subject holds a valid credential of each required schema type.
func RequireCredential(c *tptclient.Client, schemaIDs ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if len(schemaIDs) == 0 {
				next.ServeHTTP(w, r)
				return
			}
			subjectDID, grants, ok := resolveSubjectAndGrants(w, r, c, schemaIDs[0])
			if !ok {
				return
			}

			creds, err := c.ListCredentials(r.Context(), subjectDID)
			if err != nil {
				http.Error(w, "failed to retrieve credentials", http.StatusInternalServerError)
				return
			}
			for _, required := range schemaIDs {
				found := false
				for _, cred := range creds {
					for _, t := range cred.Type {
						if t == required {
							found = true
							break
						}
					}
					if found {
						break
					}
				}
				if !found {
					http.Error(w, "credential required: "+required, http.StatusForbidden)
					return
				}
			}

			ctx := withSubjectDID(r.Context(), subjectDID)
			ctx = withGrants(ctx, grants)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// resolveSubjectAndGrants introspects the Bearer token, extracts subject DID,
// and checks consent grants for the given schema.
func resolveSubjectAndGrants(w http.ResponseWriter, r *http.Request, c *tptclient.Client, schemaID string) (string, []*consent.Grant, bool) {
	bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if bearer == "" {
		http.Error(w, "authorization required", http.StatusUnauthorized)
		return "", nil, false
	}

	introspect, err := c.IntrospectToken(r.Context(), bearer)
	if err != nil || !introspect.Active {
		http.Error(w, "invalid or expired token", http.StatusUnauthorized)
		return "", nil, false
	}
	subjectDID := introspect.Subject

	allGrants, err := c.ListGrants(r.Context(), subjectDID)
	if err != nil {
		http.Error(w, "failed to check consent", http.StatusInternalServerError)
		return "", nil, false
	}

	now := time.Now()
	for _, g := range allGrants {
		if g.ScopeID != schemaID {
			continue
		}
		if g.RevokedAt != nil {
			continue
		}
		if g.ExpiresAt != nil && now.After(*g.ExpiresAt) {
			continue
		}
		return subjectDID, allGrants, true
	}
	http.Error(w, "consent not granted for "+schemaID, http.StatusForbidden)
	return "", nil, false
}
