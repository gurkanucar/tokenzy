package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"tokenzy/internal/db"
	"tokenzy/internal/httpx"
	"tokenzy/internal/token"
)

// Tokens serves token issuance.
type Tokens struct {
	DB     *db.DB
	Limits token.Limits
}

// Register mounts issuance behind the write-scope middleware.
func (t *Tokens) Register(mux *http.ServeMux, requireWrite func(http.Handler) http.Handler) {
	mux.Handle("POST /v1/tokens", requireWrite(http.HandlerFunc(t.create)))
}

type createRequest struct {
	Payload json.RawMessage `json:"payload"`
	// MaxUses is a pointer so that an absent field (unlimited) is
	// distinguishable from an explicit 0, which is not a legal count.
	MaxUses    *int64 `json:"maxUses"`
	TTLSeconds int64  `json:"ttlSeconds"`
}

// createResponse is the only response in the service that carries a token, and
// the only moment the caller is guaranteed to see it without asking an admin.
type createResponse struct {
	ID        string `json:"id"`
	Token     string `json:"token"`
	ExpiresAt string `json:"expiresAt"`
	MaxUses   *int64 `json:"maxUses"`
}

func (t *Tokens) create(w http.ResponseWriter, r *http.Request) {
	ac, ok := requireAuth(w, r)
	if !ok {
		return
	}

	var req createRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	payload, err := token.ValidatePayload(req.Payload)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, httpx.CodeInvalidRequest, err.Error())
		return
	}
	if err := token.ValidateMaxUses(req.MaxUses); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, httpx.CodeInvalidRequest, err.Error())
		return
	}
	ttl, err := t.Limits.ValidateTTL(req.TTLSeconds)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, httpx.CodeInvalidRequest, err.Error())
		return
	}

	id, err := token.NewID()
	if err != nil {
		internalError(w, "generate token id", err)
		return
	}
	value, err := token.Generate()
	if err != nil {
		internalError(w, "generate token", err)
		return
	}

	created, err := t.DB.CreateToken(r.Context(), ac.Environment.ID, id, value, payload,
		req.MaxUses, time.Now().Add(ttl).Unix())
	if err != nil {
		// A UNIQUE collision on 244 bits of randomness is not something to
		// paper over with a retry loop; if it ever happens, the RNG is broken
		// and quietly minting a second token would hide that.
		if errors.Is(err, db.ErrDuplicate) {
			internalError(w, "token collision", err)
			return
		}
		internalError(w, "create token", err)
		return
	}

	httpx.WriteJSON(w, http.StatusCreated, createResponse{
		ID:        created.ID,
		Token:     created.Value,
		ExpiresAt: rfc3339(created.ExpiresAt),
		MaxUses:   created.MaxUses,
	})
}
