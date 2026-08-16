package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"strings"

	"tokenzy/internal/db"
	"tokenzy/internal/httpx"
	"tokenzy/internal/model"
)

// HeaderName carries the API key on every /v1 request.
const HeaderName = "X-App-Key"

// KeyPrefixLen is how much of a key is stored in clear for display purposes.
const KeyPrefixLen = 12

const (
	keyRandomLen = 24
	keyAlphabet  = "abcdefghijklmnopqrstuvwxyz0123456789"
)

// GenerateKey builds a plaintext key of the form tk_{scope}_{env}_{random}.
// The caller must show it to the user once and then discard it: only the hash
// is stored.
func GenerateKey(scope, envSlug string) (string, error) {
	suffix, err := randomString(keyRandomLen)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("tk_%s_%s_%s", scope, envSlug, suffix), nil
}

// HashKey returns the hex SHA-256 of a plaintext key; this is what is stored.
//
// API keys are hashed even though tokens are not. The plaintext decision in
// this service is specific to tokens, which have to be re-displayable so a
// pass can be reprinted; an API key never needs showing twice, so there is
// nothing to trade against keeping it one-way.
func HashKey(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

// KeyPrefix returns the leading characters shown in the admin UI.
func KeyPrefix(key string) string {
	if len(key) <= KeyPrefixLen {
		return key
	}
	return key[:KeyPrefixLen]
}

// randomString draws n characters uniformly from keyAlphabet using crypto/rand.
func randomString(n int) (string, error) {
	var sb strings.Builder
	sb.Grow(n)
	max := big.NewInt(int64(len(keyAlphabet)))
	for i := 0; i < n; i++ {
		idx, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", fmt.Errorf("generate random key: %w", err)
		}
		sb.WriteByte(keyAlphabet[idx.Int64()])
	}
	return sb.String(), nil
}

// APIContext is what a successfully authenticated /v1 request carries.
type APIContext struct {
	Key         model.APIKey
	Environment model.Environment
}

type apiCtxKey struct{}

// APIFromContext returns the authenticated key and environment for a request.
func APIFromContext(ctx context.Context) (*APIContext, bool) {
	v, ok := ctx.Value(apiCtxKey{}).(*APIContext)
	return v, ok
}

// APIAuthenticator validates X-App-Key headers against the database.
type APIAuthenticator struct {
	DB *db.DB
}

// Require builds middleware that rejects requests whose key is missing,
// unknown, revoked, or of insufficient scope.
func (a *APIAuthenticator) Require(requiredScope string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw := strings.TrimSpace(r.Header.Get(HeaderName))
			if raw == "" {
				httpx.WriteError(w, http.StatusUnauthorized, httpx.CodeUnauthorized,
					"missing "+HeaderName+" header")
				return
			}

			key, err := a.DB.LookupActiveAPIKey(r.Context(), HashKey(raw))
			if errors.Is(err, db.ErrNotFound) {
				httpx.WriteError(w, http.StatusUnauthorized, httpx.CodeUnauthorized,
					"invalid or revoked API key")
				return
			}
			if err != nil {
				log.Printf("auth: lookup api key: %v", err)
				httpx.WriteError(w, http.StatusInternalServerError, httpx.CodeInternal,
					"failed to verify API key")
				return
			}

			if !model.ScopeAllows(key.Scope, requiredScope) {
				httpx.WriteError(w, http.StatusForbidden, httpx.CodeForbidden,
					"this key has scope '"+key.Scope+"', '"+requiredScope+"' is required")
				return
			}

			env, err := a.DB.GetEnvironmentByID(r.Context(), key.EnvironmentID)
			if err != nil {
				// The environment is gone but the key survived: treat as invalid.
				if errors.Is(err, db.ErrNotFound) {
					httpx.WriteError(w, http.StatusUnauthorized, httpx.CodeUnauthorized,
						"invalid or revoked API key")
					return
				}
				log.Printf("auth: load environment: %v", err)
				httpx.WriteError(w, http.StatusInternalServerError, httpx.CodeInternal,
					"failed to verify API key")
				return
			}

			ctx := context.WithValue(r.Context(), apiCtxKey{}, &APIContext{Key: key, Environment: env})
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
