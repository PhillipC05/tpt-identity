package schema

import (
	"fmt"
	"sync"
)

// Source classifies where a schema came from.
type Source string

const (
	SourceCore      Source = "core"
	SourceCommunity Source = "community"
	SourceThirdParty Source = "third-party"
)

// ClaimDefinition describes a single claim field within a schema.
type ClaimDefinition struct {
	Name        string `json:"name"`
	Type        string `json:"type"` // "string", "date", "number", "boolean"
	Required    bool   `json:"required"`
	Description string `json:"description,omitempty"`
}

// Category is a top-level grouping of credential schemas (e.g. "healthcare").
type Category struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Icon        string `json:"icon,omitempty"`
}

// Schema describes a specific credential type within a category (e.g. "healthcare.gp-records").
type Schema struct {
	// ID is the dotted category.name identifier, e.g. "healthcare.gp-records".
	ID string `json:"id"`
	// CategoryID is the parent category, e.g. "healthcare".
	CategoryID string `json:"categoryId"`
	// Name is the human-readable label.
	Name string `json:"name"`
	// Description explains what credentials matching this schema contain.
	Description string `json:"description,omitempty"`
	// ExtraSensitive marks schemas that require individual explicit consent even when a
	// category-wide grant has been given. Examples: mental health, sexual health, criminal record.
	ExtraSensitive bool `json:"extraSensitive,omitempty"`
	// AuthorisedIssuers, if non-empty, restricts which OIDC client IDs are permitted to issue
	// credentials of this type. An empty slice means any authenticated client may issue.
	// Example: only the "tpt-health-moh" client can issue "healthcare.gp-records".
	AuthorisedIssuers []string `json:"authorisedIssuers,omitempty"`
	// Claims defines the fields carried by credentials of this type.
	Claims []ClaimDefinition `json:"claims,omitempty"`
	// Source indicates whether this is a core, community, or third-party schema.
	Source Source `json:"source"`
}

var (
	mu         sync.RWMutex
	categories = map[string]Category{}
	schemas    = map[string]Schema{}
)

// RegisterCategory adds a category to the global registry.
func RegisterCategory(c Category) {
	mu.Lock()
	defer mu.Unlock()
	categories[c.ID] = c
}

// RegisterSchema adds a schema to the global registry.
// Panics if a schema with the same ID is already registered.
func RegisterSchema(s Schema) {
	mu.Lock()
	defer mu.Unlock()
	if _, ok := schemas[s.ID]; ok {
		panic(fmt.Sprintf("schema: %q already registered", s.ID))
	}
	schemas[s.ID] = s
}

// GetSchema returns the schema for id, or an error if not found.
func GetSchema(id string) (Schema, error) {
	mu.RLock()
	defer mu.RUnlock()
	s, ok := schemas[id]
	if !ok {
		return Schema{}, fmt.Errorf("schema: %q not found", id)
	}
	return s, nil
}

// GetCategory returns the category for id.
func GetCategory(id string) (Category, error) {
	mu.RLock()
	defer mu.RUnlock()
	c, ok := categories[id]
	if !ok {
		return Category{}, fmt.Errorf("schema: category %q not found", id)
	}
	return c, nil
}

// SchemasForCategory returns all schemas belonging to the given category ID.
func SchemasForCategory(categoryID string) []Schema {
	mu.RLock()
	defer mu.RUnlock()
	var out []Schema
	for _, s := range schemas {
		if s.CategoryID == categoryID {
			out = append(out, s)
		}
	}
	return out
}

// AllCategories returns all registered categories.
func AllCategories() []Category {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]Category, 0, len(categories))
	for _, c := range categories {
		out = append(out, c)
	}
	return out
}

// IsExtraSensitive reports whether the schema at id has ExtraSensitive set.
func IsExtraSensitive(id string) bool {
	mu.RLock()
	defer mu.RUnlock()
	s, ok := schemas[id]
	return ok && s.ExtraSensitive
}

// CanIssue reports whether clientID is authorised to issue credentials for schemaID.
// Returns true when the schema has no authorised-issuer restriction, or when clientID
// appears in the schema's AuthorisedIssuers list.
func CanIssue(schemaID, clientID string) bool {
	mu.RLock()
	defer mu.RUnlock()
	s, ok := schemas[schemaID]
	if !ok || len(s.AuthorisedIssuers) == 0 {
		return true
	}
	for _, id := range s.AuthorisedIssuers {
		if id == clientID {
			return true
		}
	}
	return false
}

// SetAuthorisedIssuers replaces the authorised issuers list for schemaID at runtime.
// This is intended for operator tooling; schema definitions in core/init.go are the
// canonical source of truth for static deployments.
func SetAuthorisedIssuers(schemaID string, issuers []string) error {
	mu.Lock()
	defer mu.Unlock()
	s, ok := schemas[schemaID]
	if !ok {
		return fmt.Errorf("schema: %q not found", schemaID)
	}
	s.AuthorisedIssuers = issuers
	schemas[schemaID] = s
	return nil
}
