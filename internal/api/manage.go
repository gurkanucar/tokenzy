package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"tokenzy/internal/db"
	"tokenzy/internal/httpx"
	"tokenzy/internal/model"
	"tokenzy/internal/token"
)

// defaultPageSize is the listing page size when the caller does not ask.
const defaultPageSize = 50

// Manage serves the administrative endpoints under /v1/manage.
//
// Redemption works from the token; management works from the id. That split is
// what makes "the phone with the pass on it was lost" a solvable problem:
// whoever runs the service can cancel a token they can no longer produce.
type Manage struct {
	DB *db.DB
}

// Register mounts management behind the admin-scope middleware.
func (m *Manage) Register(mux *http.ServeMux, requireAdmin func(http.Handler) http.Handler) {
	handle := func(pattern string, h http.HandlerFunc) {
		mux.Handle(pattern, requireAdmin(h))
	}
	handle("GET /v1/manage/tokens", m.list)
	handle("GET /v1/manage/tokens/{id}", m.get)
	handle("POST /v1/manage/tokens/{id}/revoke", m.revoke)
	handle("DELETE /v1/manage/tokens/{id}", m.delete)
}

// tokenSummary is what a listing returns: metadata only.
//
// There is no token field and no payload field, and that is structural rather
// than a matter of remembering. One endpoint below returns the full thing, and
// it is one endpoint precisely so that it can be the one thing to audit.
type tokenSummary struct {
	ID         string  `json:"id"`
	Prefix     string  `json:"prefix"`
	Status     string  `json:"status"`
	UsedCount  int64   `json:"usedCount"`
	MaxUses    *int64  `json:"maxUses"`
	ExpiresAt  string  `json:"expiresAt"`
	CreatedAt  string  `json:"createdAt"`
	LastUsedAt *string `json:"lastUsedAt"`
	RevokedAt  *string `json:"revokedAt"`
}

// tokenDetail adds the payload and the token itself.
//
// Returning the plaintext is what the storage decision was made for: a pass
// can be shown again, a QR reprinted, a link resent. It is also, exactly,
// the ability to mint a working token — so this shape is only ever produced by
// the single-token endpoint, and that endpoint is why the admin scope exists.
type tokenDetail struct {
	tokenSummary
	Token   string          `json:"token"`
	Payload json.RawMessage `json:"payload"`
}

type listResponse struct {
	Tokens []tokenSummary `json:"tokens"`
	// NextCursor is empty when the listing is exhausted.
	NextCursor string `json:"nextCursor"`
}

func summarise(t model.Token, now int64) tokenSummary {
	return tokenSummary{
		ID:         t.ID,
		Prefix:     t.Prefix,
		Status:     token.StatusOf(t, now),
		UsedCount:  t.UsedCount,
		MaxUses:    t.MaxUses,
		ExpiresAt:  rfc3339(t.ExpiresAt),
		CreatedAt:  rfc3339(t.CreatedAt),
		LastUsedAt: rfc3339Ptr(t.LastUsedAt),
		RevokedAt:  rfc3339Ptr(t.RevokedAt),
	}
}

func (m *Manage) list(w http.ResponseWriter, r *http.Request) {
	ac, ok := requireAuth(w, r)
	if !ok {
		return
	}

	query := r.URL.Query()
	filter := db.TokenFilter{
		Status: query.Get("status"),
		Limit:  defaultPageSize,
		Cursor: db.ParseCursor(query.Get("cursor")),
	}
	if filter.Status != "" && !token.ValidStatus(filter.Status) {
		httpx.WriteError(w, http.StatusBadRequest, httpx.CodeInvalidRequest,
			"'status' must be one of active, expired, exhausted, revoked")
		return
	}
	if raw := query.Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 {
			httpx.WriteError(w, http.StatusBadRequest, httpx.CodeInvalidRequest,
				"'limit' must be a positive integer")
			return
		}
		filter.Limit = n
	}

	tokens, next, err := m.DB.ListTokens(r.Context(), ac.Environment.ID, filter)
	if err != nil {
		internalError(w, "list tokens", err)
		return
	}

	now := time.Now().Unix()
	summaries := make([]tokenSummary, 0, len(tokens))
	for _, t := range tokens {
		summaries = append(summaries, summarise(t, now))
	}

	httpx.WriteJSON(w, http.StatusOK, listResponse{
		Tokens:     summaries,
		NextCursor: next.String(),
	})
}

// get returns one token in full, including its plaintext.
//
// Reading is not spending. This endpoint does not touch used_count, and a
// single-use token inspected here is still a single-use token afterwards. The
// only thing that consumes a token is /v1/consume.
func (m *Manage) get(w http.ResponseWriter, r *http.Request) {
	ac, ok := requireAuth(w, r)
	if !ok {
		return
	}

	id := r.PathValue("id")
	found, err := m.DB.GetToken(r.Context(), ac.Environment.ID, id)
	if errors.Is(err, db.ErrNotFound) {
		httpx.WriteError(w, http.StatusNotFound, httpx.CodeNotFound, "token not found")
		return
	}
	if err != nil {
		internalError(w, "get token", err)
		return
	}

	value, err := m.DB.GetTokenValue(r.Context(), ac.Environment.ID, id)
	if err != nil {
		internalError(w, "get token value", err)
		return
	}

	httpx.WriteJSON(w, http.StatusOK, tokenDetail{
		tokenSummary: summarise(found, time.Now().Unix()),
		Token:        value,
		Payload:      json.RawMessage(found.PayloadJSON),
	})
}

// revoke cancels a token. It is idempotent in effect: revoking an
// already-revoked token reports the token as it stands rather than failing,
// because the caller's intent — "this must not work any more" — is satisfied
// either way.
func (m *Manage) revoke(w http.ResponseWriter, r *http.Request) {
	ac, ok := requireAuth(w, r)
	if !ok {
		return
	}

	id := r.PathValue("id")
	revoked, err := m.DB.RevokeToken(r.Context(), ac.Environment.ID, id)

	if errors.Is(err, db.ErrNotFound) {
		// Either it does not exist here, or it was already revoked. Reading it
		// back tells the two apart.
		existing, getErr := m.DB.GetToken(r.Context(), ac.Environment.ID, id)
		if errors.Is(getErr, db.ErrNotFound) {
			httpx.WriteError(w, http.StatusNotFound, httpx.CodeNotFound, "token not found")
			return
		}
		if getErr != nil {
			internalError(w, "get token", getErr)
			return
		}
		httpx.WriteJSON(w, http.StatusOK, summarise(existing, time.Now().Unix()))
		return
	}
	if err != nil {
		internalError(w, "revoke token", err)
		return
	}

	httpx.WriteJSON(w, http.StatusOK, summarise(revoked, time.Now().Unix()))
}

// delete removes the record entirely.
//
// Revoking is almost always the better move: it stops the token and keeps the
// history of what it was and whether it was ever used. Deleting is for when
// the record itself is what has to go.
func (m *Manage) delete(w http.ResponseWriter, r *http.Request) {
	ac, ok := requireAuth(w, r)
	if !ok {
		return
	}

	err := m.DB.DeleteToken(r.Context(), ac.Environment.ID, r.PathValue("id"))
	switch {
	case errors.Is(err, db.ErrNotFound):
		httpx.WriteError(w, http.StatusNotFound, httpx.CodeNotFound, "token not found")
	case err != nil:
		internalError(w, "delete token", err)
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}
