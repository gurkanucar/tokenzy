package ui

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"tokenzy/internal/auth"
	"tokenzy/internal/db"
	"tokenzy/internal/model"
)

// KeyRow is one row of the API key table.
type KeyRow struct {
	Project string
	Env     string
	Key     model.APIKey
	Created string
	Revoked string
}

// KeysView backs keys.html and the "keys_panel" fragment. NewKey is set exactly
// once, on the response to a creation, and never stored.
type KeysView struct {
	Layout
	Rows   []KeyRow
	Scopes []string
	NewKey string
	Error  string
}

func (s *Server) keysView(r *http.Request, scope envScope, newKey, errMsg string) (KeysView, error) {
	keys, err := s.db.ListAPIKeys(r.Context(), scope.Env.ID)
	if err != nil {
		return KeysView{}, err
	}

	rows := make([]KeyRow, 0, len(keys))
	for _, k := range keys {
		row := KeyRow{
			Project: scope.Project.Slug,
			Env:     scope.Env.Slug,
			Key:     k,
			Created: formatTime(k.CreatedAt),
		}
		if k.RevokedAt != nil {
			row.Revoked = formatTime(*k.RevokedAt)
		}
		rows = append(rows, row)
	}

	project, env := scope.Project, scope.Env
	return KeysView{
		Layout: s.layoutFor(r, "API keys · "+project.Name, &project, &env, scope.Envs, "keys"),
		Rows:   rows,
		Scopes: model.Scopes,
		NewKey: newKey,
		Error:  errMsg,
	}, nil
}

func (s *Server) keysPage(w http.ResponseWriter, r *http.Request) {
	scope, ok := s.resolveEnv(w, r)
	if !ok {
		return
	}
	view, err := s.keysView(r, scope, "", "")
	if err != nil {
		internalError(w, "list api keys", err)
		return
	}
	s.renderPage(w, http.StatusOK, "keys.html", view)
}

func (s *Server) createKey(w http.ResponseWriter, r *http.Request) {
	scope, ok := s.resolveEnv(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}

	scopeName := strings.TrimSpace(r.FormValue("scope"))
	label := strings.TrimSpace(r.FormValue("label"))

	if !model.ValidScope(scopeName) {
		s.renderKeysPanel(w, r, scope, "", "Invalid scope.", http.StatusUnprocessableEntity)
		return
	}

	plaintext, err := auth.GenerateKey(scopeName, scope.Env.Slug)
	if err != nil {
		internalError(w, "generate api key", err)
		return
	}

	_, err = s.db.CreateAPIKey(r.Context(), scope.Env.ID,
		auth.HashKey(plaintext), auth.KeyPrefix(plaintext), scopeName, label)
	if err != nil {
		internalError(w, "create api key", err)
		return
	}

	s.renderKeysPanel(w, r, scope, plaintext, "", http.StatusOK)
}

func (s *Server) revokeKey(w http.ResponseWriter, r *http.Request) {
	scope, ok := s.resolveEnv(w, r)
	if !ok {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "invalid key id", http.StatusBadRequest)
		return
	}

	if err := s.db.RevokeAPIKey(r.Context(), id, scope.Env.ID); err != nil && !errors.Is(err, db.ErrNotFound) {
		internalError(w, "revoke api key", err)
		return
	}
	s.renderKeysPanel(w, r, scope, "", "", http.StatusOK)
}

func (s *Server) deleteKey(w http.ResponseWriter, r *http.Request) {
	scope, ok := s.resolveEnv(w, r)
	if !ok {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "invalid key id", http.StatusBadRequest)
		return
	}

	if err := s.db.DeleteAPIKey(r.Context(), id, scope.Env.ID); err != nil && !errors.Is(err, db.ErrNotFound) {
		internalError(w, "delete api key", err)
		return
	}
	s.renderKeysPanel(w, r, scope, "", "", http.StatusOK)
}

func (s *Server) renderKeysPanel(w http.ResponseWriter, r *http.Request, scope envScope,
	newKey, errMsg string, status int) {

	view, err := s.keysView(r, scope, newKey, errMsg)
	if err != nil {
		internalError(w, "list api keys", err)
		return
	}
	s.renderFragment(w, status, "keys_panel", view)
}
