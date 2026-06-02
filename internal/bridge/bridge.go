// Package bridge provides the identity bridge layer — a registry of authentication
// providers that map external identities to platform DIDs.
package bridge

import (
	"context"
	"fmt"
	"net/http"
	"sync"
)

// ExternalIdentity is the normalized result of authenticating via an external provider.
type ExternalIdentity struct {
	Provider   string            // "google", "github", "saml:acme", "ldap", "magiclink-email", "password"
	ExternalID string            // stable identifier from the provider (sub, NameID, DN, normalised email)
	Claims     map[string]string // additional claims: email, given_name, family_name, groups, etc.
}

// Bridge authenticates a request via an external provider and returns the external identity.
type Bridge interface {
	Name() string
	Authenticate(ctx context.Context, r *http.Request) (*ExternalIdentity, error)
}

// Manager holds the registered bridge providers.
type Manager struct {
	mu       sync.RWMutex
	bridges  map[string]Bridge
}

// NewManager creates an empty bridge manager.
func NewManager() *Manager {
	return &Manager{bridges: make(map[string]Bridge)}
}

// Register adds a bridge provider. Panics on duplicate name.
func (m *Manager) Register(b Bridge) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.bridges[b.Name()]; exists {
		panic(fmt.Sprintf("bridge: duplicate provider %q", b.Name()))
	}
	m.bridges[b.Name()] = b
}

// Get returns a bridge by name.
func (m *Manager) Get(name string) (Bridge, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	b, ok := m.bridges[name]
	return b, ok
}

// Names returns all registered provider names.
func (m *Manager) Names() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	names := make([]string, 0, len(m.bridges))
	for n := range m.bridges {
		names = append(names, n)
	}
	return names
}
