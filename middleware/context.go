package middleware

import (
	"context"

	"github.com/PhillipC05/tpt-identity/pkg/consent"
)

type contextKey int

const (
	ctxSubjectDID contextKey = iota
	ctxGrants
)

// SubjectDID returns the verified OIDC subject DID stored in the context by RequireConsent
// or RequireCredential middleware.
func SubjectDID(ctx context.Context) string {
	v, _ := ctx.Value(ctxSubjectDID).(string)
	return v
}

// Grants returns the consent grants stored in the context by RequireConsent middleware.
func Grants(ctx context.Context) []*consent.Grant {
	v, _ := ctx.Value(ctxGrants).([]*consent.Grant)
	return v
}

func withSubjectDID(ctx context.Context, did string) context.Context {
	return context.WithValue(ctx, ctxSubjectDID, did)
}

func withGrants(ctx context.Context, grants []*consent.Grant) context.Context {
	return context.WithValue(ctx, ctxGrants, grants)
}
