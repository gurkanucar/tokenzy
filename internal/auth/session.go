package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"time"

	"tokenzy/internal/db"
	"tokenzy/internal/model"
)

// SessionCookie is the admin UI cookie name.
const SessionCookie = "tokenzy_session"

// SessionTTL is how long a login lasts.
const SessionTTL = 7 * 24 * time.Hour

// Sessions issues and validates admin UI browser sessions.
type Sessions struct {
	DB *db.DB
}

// NewSessionID returns 32 random bytes, hex encoded.
func NewSessionID() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate session id: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

// Start creates a session for userID and sets the cookie on w.
func (s *Sessions) Start(ctx context.Context, w http.ResponseWriter, r *http.Request, userID int64) error {
	id, err := NewSessionID()
	if err != nil {
		return err
	}
	expires := time.Now().Add(SessionTTL)
	if err := s.DB.CreateSession(ctx, id, userID, expires.Unix()); err != nil {
		return err
	}

	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookie,
		Value:    id,
		Path:     "/",
		Expires:  expires,
		MaxAge:   int(SessionTTL / time.Second),
		HttpOnly: true,
		// SameSite=Lax keeps the cookie off cross-site POSTs, which is what
		// stands in for CSRF tokens in this version.
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil,
	})
	return nil
}

// End deletes the current session and clears the cookie.
func (s *Sessions) End(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	if c, err := r.Cookie(SessionCookie); err == nil && c.Value != "" {
		if err := s.DB.DeleteSession(ctx, c.Value); err != nil {
			return err
		}
	}
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookie,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil,
	})
	return nil
}

// Current resolves the logged-in user, if any. Expired sessions are deleted as
// they are encountered.
func (s *Sessions) Current(ctx context.Context, r *http.Request) (model.User, bool) {
	c, err := r.Cookie(SessionCookie)
	if err != nil || c.Value == "" {
		return model.User{}, false
	}

	sess, err := s.DB.GetSession(ctx, c.Value)
	if err != nil {
		return model.User{}, false
	}
	if sess.ExpiresAt < time.Now().Unix() {
		if err := s.DB.DeleteSession(ctx, sess.ID); err != nil && !errors.Is(err, db.ErrNotFound) {
			// Best effort: an expired session is already unusable.
			_ = err
		}
		return model.User{}, false
	}

	user, err := s.DB.GetUserByID(ctx, sess.UserID)
	if err != nil {
		return model.User{}, false
	}
	return user, true
}

type userCtxKey struct{}

// UserFromContext returns the admin user attached by RequireLogin.
func UserFromContext(ctx context.Context) (model.User, bool) {
	u, ok := ctx.Value(userCtxKey{}).(model.User)
	return u, ok
}

// WithUser attaches a user to a context.
func WithUser(ctx context.Context, u model.User) context.Context {
	return context.WithValue(ctx, userCtxKey{}, u)
}

// RequireLogin redirects anonymous browsers to the login page. HTMX requests
// get an HX-Redirect header instead so the browser navigates rather than
// swapping a login page into a fragment.
func (s *Sessions) RequireLogin(loginPath string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, ok := s.Current(r.Context(), r)
		if !ok {
			if r.Header.Get("HX-Request") == "true" {
				w.Header().Set("HX-Redirect", loginPath)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			http.Redirect(w, r, loginPath, http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r.WithContext(WithUser(r.Context(), user)))
	})
}
