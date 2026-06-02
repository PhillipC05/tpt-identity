package api

import (
	"encoding/json"
	"net/http"

	"github.com/PhillipC05/tpt-identity/pkg/schema"
	"github.com/PhillipC05/tpt-identity/pkg/vc"
)

func (s *Server) handleIssueCredential(w http.ResponseWriter, r *http.Request) {
	var opts vc.IssueOptions
	if err := json.NewDecoder(r.Body).Decode(&opts); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	// IssuerKey must be loaded from keystore in a full implementation.
	// Here we return a clear error so the caller knows what's needed.
	if opts.IssuerKey == nil {
		http.Error(w, "issuer key must be provided (load from keystore)", http.StatusBadRequest)
		return
	}

	// Trust registry: enforce authorised issuers per schema.
	clientID := callerClientID(r)
	if !schema.CanIssue(opts.SchemaID, clientID) {
		http.Error(w, "forbidden: client not authorised to issue credentials for schema "+opts.SchemaID, http.StatusForbidden)
		return
	}

	cred, err := vc.Issue(opts)
	if err != nil {
		http.Error(w, "issue: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.store.SaveCredential(r.Context(), cred); err != nil {
		http.Error(w, "save credential: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(cred)
}

func (s *Server) handleVerifyCredential(w http.ResponseWriter, r *http.Request) {
	var cred vc.VerifiableCredential
	if err := json.NewDecoder(r.Body).Decode(&cred); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	verifier := vc.NewVerifier(s.resolver)
	if err := verifier.Verify(&cred); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnprocessableEntity)
		json.NewEncoder(w).Encode(map[string]string{"valid": "false", "error": err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"valid": "true"})
}

func (s *Server) handleListCredentials(w http.ResponseWriter, r *http.Request) {
	subjectDID := r.URL.Query().Get("subject")
	if subjectDID == "" {
		http.Error(w, "subject query parameter required", http.StatusBadRequest)
		return
	}
	creds, err := s.store.ListCredentials(r.Context(), subjectDID)
	if err != nil {
		http.Error(w, "list: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(creds)
}

func (s *Server) handleDeleteCredential(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.store.DeleteCredential(r.Context(), id); err != nil {
		http.Error(w, "delete: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
