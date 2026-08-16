package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"tokenzy/internal/db"
	"tokenzy/internal/httpx"
)

// Consume serves token redemption — the endpoint the whole service exists for.
type Consume struct {
	DB *db.DB
}

// Register mounts redemption behind the consume-scope middleware.
func (c *Consume) Register(mux *http.ServeMux, requireConsume func(http.Handler) http.Handler) {
	mux.Handle("POST /v1/consume", requireConsume(http.HandlerFunc(c.consume)))
}

// consumeRequest carries the token in the body, never in the path or query.
//
// A URL is written down everywhere a request goes: the browser's history, the
// reverse proxy's access log, the referrer header of the next page. A body is
// written down nowhere. That is the whole reason this is a POST with a body
// rather than the GET that would otherwise be natural.
type consumeRequest struct {
	Token string `json:"token"`
}

type usageBody struct {
	Used int64 `json:"used"`
	// Maximum and Remaining are null for a token with no usage limit, rather
	// than 0 or -1, so a client that renders them does not have to know which
	// sentinel this service picked.
	Maximum   *int64 `json:"maximum"`
	Remaining *int64 `json:"remaining"`
}

type consumeResponse struct {
	Valid   bool            `json:"valid"`
	Payload json.RawMessage `json:"payload"`
	Usage   usageBody       `json:"usage"`
}

type invalidResponse struct {
	Valid bool   `json:"valid"`
	Error string `json:"error"`
}

func (c *Consume) consume(w http.ResponseWriter, r *http.Request) {
	ac, ok := requireAuth(w, r)
	if !ok {
		return
	}

	var req consumeRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	value := strings.TrimSpace(req.Token)
	if value == "" {
		// A missing field is a mistake in the caller's code, not a failed
		// redemption, so it says so plainly. Nothing is revealed: this answer
		// does not depend on any token that exists.
		httpx.WriteError(w, http.StatusBadRequest, httpx.CodeInvalidRequest, "'token' is required")
		return
	}

	consumed, err := c.DB.ConsumeToken(r.Context(), ac.Environment.ID, value)

	if errors.Is(err, db.ErrNotFound) {
		// One answer for every kind of miss: never issued, mistyped, expired,
		// already spent, revoked, or belonging to a different environment.
		//
		// Telling them apart would be more helpful to the one caller in a
		// thousand that is debugging, and more helpful still to anyone probing:
		// "expired" confirms the token was real, "exhausted" confirms somebody
		// already used it, and the difference between "unknown" and anything
		// else turns a guess into a signal. The panel has the real answer for
		// whoever is entitled to it.
		//
		// 200, not 404: the request was understood and answered. The token was
		// the thing that was not found, and that is a fact in the body.
		httpx.WriteJSON(w, http.StatusOK, invalidResponse{
			Valid: false,
			Error: httpx.CodeInvalidToken,
		})
		return
	}
	if err != nil {
		internalError(w, "consume token", err)
		return
	}

	usage := usageBody{Used: consumed.UsedCount}
	if consumed.MaxUses != nil {
		remaining, _ := consumed.Remaining()
		usage.Maximum = consumed.MaxUses
		usage.Remaining = &remaining
	}

	// The payload comes back exactly as it went in. The service never parsed
	// it, so there is nothing here it could have got wrong.
	httpx.WriteJSON(w, http.StatusOK, consumeResponse{
		Valid:   true,
		Payload: json.RawMessage(consumed.PayloadJSON),
		Usage:   usage,
	})
}
