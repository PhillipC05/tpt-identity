package api

import (
	"encoding/json"
	"net/http"

	"github.com/PhillipC05/tpt-identity/pkg/consent"
	"github.com/PhillipC05/tpt-identity/pkg/schema"
)

func (s *Server) handleListGrants(w http.ResponseWriter, r *http.Request) {
	subjectDID := r.URL.Query().Get("subject")
	if subjectDID == "" {
		http.Error(w, "subject query parameter required", http.StatusBadRequest)
		return
	}
	grants, err := s.store.ListGrants(r.Context(), subjectDID)
	if err != nil {
		http.Error(w, "list grants: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(grants)
}

func (s *Server) handleCreateGrant(w http.ResponseWriter, r *http.Request) {
	var g consent.Grant
	if err := json.NewDecoder(r.Body).Decode(&g); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	// Enforce: category grants and extra-sensitive schemas always require explicit confirmation.
	if g.Level == consent.GrantCategory && !g.ExplicitlyConfirmed {
		http.Error(w, "category grants require explicitlyConfirmed=true — the user must explicitly approve sharing all schemas in this category", http.StatusBadRequest)
		return
	}
	if g.Level == consent.GrantSchema {
		s, _ := schema.GetSchema(g.ScopeID)
		if s.ExtraSensitive && !g.ExplicitlyConfirmed {
			http.Error(w, "this schema is extra-sensitive and requires explicitlyConfirmed=true", http.StatusBadRequest)
			return
		}
	}
	if err := s.store.SaveGrant(r.Context(), &g); err != nil {
		http.Error(w, "save grant: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(g)
}

func (s *Server) handleRevokeGrant(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.store.DeleteGrant(r.Context(), id); err != nil {
		http.Error(w, "revoke grant: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleListReceipts(w http.ResponseWriter, r *http.Request) {
	subjectDID := r.URL.Query().Get("subject")
	if subjectDID == "" {
		http.Error(w, "subject query parameter required", http.StatusBadRequest)
		return
	}
	receipts, err := s.store.ListReceipts(r.Context(), subjectDID)
	if err != nil {
		http.Error(w, "list receipts: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(receipts)
}

func (s *Server) handleDeleteSession(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.store.DeleteSession(r.Context(), id); err != nil {
		http.Error(w, "delete session: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleListSchemas(w http.ResponseWriter, r *http.Request) {
	cats := schema.AllCategories()
	type categoryWithSchemas struct {
		schema.Category
		Schemas []schema.Schema `json:"schemas"`
	}
	result := make([]categoryWithSchemas, 0, len(cats))
	for _, cat := range cats {
		result = append(result, categoryWithSchemas{
			Category: cat,
			Schemas:  schema.SchemasForCategory(cat.ID),
		})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}
