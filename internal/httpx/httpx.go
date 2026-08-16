// Package httpx holds the JSON response helpers shared by the auth middleware
// and the API handlers, so the error envelope is defined exactly once.
package httpx

import (
	"encoding/json"
	"log"
	"net/http"
)

// Error codes used across every JSON endpoint.
const (
	CodeUnauthorized   = "unauthorized"
	CodeForbidden      = "forbidden"
	CodeNotFound       = "not_found"
	CodeInvalidRequest = "invalid_request"
	CodeInternal       = "internal_error"

	// CodeInvalidToken is the single answer /v1/consume gives to every kind of
	// failed resolution. See the consume handler for why it is not broken down.
	CodeInvalidToken = "invalid_token"
)

// ErrorBody is the inner object of every error response.
type ErrorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// ErrorEnvelope is the uniform error shape.
type ErrorEnvelope struct {
	Error ErrorBody `json:"error"`
}

// WriteJSON serialises v as the response body with the given status.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		log.Printf("httpx: marshal response: %v", err)
		WriteError(w, http.StatusInternalServerError, CodeInternal, "failed to encode response")
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	w.Write(body)
}

// WriteError emits the uniform {"error":{"code","message"}} envelope.
func WriteError(w http.ResponseWriter, status int, code, message string) {
	body, err := json.Marshal(ErrorEnvelope{Error: ErrorBody{Code: code, Message: message}})
	if err != nil {
		http.Error(w, `{"error":{"code":"internal_error","message":"failed to encode error"}}`,
			http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	w.Write(body)
}
