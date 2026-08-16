// Package api implements the JSON HTTP surface. Every endpoint authenticates
// with an X-App-Key header and operates on the single environment that key is
// bound to — a caller never names a project or environment itself, so a key
// issued for staging cannot reach production by changing a path.
package api

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"tokenzy/internal/auth"
	"tokenzy/internal/httpx"
)

// maxBodyBytes caps request bodies. It is comfortably above the 16 KiB payload
// limit so that an oversized payload is rejected with a message that explains
// the actual rule, rather than being cut off by the transport.
const maxBodyBytes = 1 << 20 // 1 MiB

// requireAuth pulls the authenticated key and environment off the request.
func requireAuth(w http.ResponseWriter, r *http.Request) (*auth.APIContext, bool) {
	ac, ok := auth.APIFromContext(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusUnauthorized, httpx.CodeUnauthorized, "not authenticated")
		return nil, false
	}
	return ac, true
}

// decodeJSON reads a bounded JSON body into dst.
func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, httpx.CodeInvalidRequest,
			"invalid JSON body: "+err.Error())
		return false
	}
	return true
}

// internalError logs the detail and tells the caller nothing beyond the fact.
//
// The rule matters more here than in most services: an error from the token
// tables can have a token bound into it, and an error message is the one place
// a secret can escape without anyone noticing. The log gets the error; the
// response gets a sentence.
func internalError(w http.ResponseWriter, what string, err error) {
	log.Printf("api: %s: %v", what, err)
	httpx.WriteError(w, http.StatusInternalServerError, httpx.CodeInternal, "internal error")
}

// rfc3339 renders a stored timestamp for a JSON response. Timestamps are
// stored as unix seconds and served as RFC 3339 in UTC: unambiguous to read,
// and every client library already parses it.
func rfc3339(ts int64) string {
	return time.Unix(ts, 0).UTC().Format(time.RFC3339)
}

// rfc3339Ptr renders an optional timestamp, keeping null as null.
func rfc3339Ptr(ts *int64) *string {
	if ts == nil {
		return nil
	}
	s := rfc3339(*ts)
	return &s
}
