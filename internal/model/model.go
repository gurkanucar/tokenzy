// Package model holds the domain structs and the shared validation rules that
// both the JSON API and the admin UI enforce.
package model

import (
	"errors"
	"regexp"
)

// Scope values for API keys, ordered from least to most privileged.
//
// The split exists because the three audiences are genuinely different: a
// consume key ends up on a phone or in a kiosk and can only spend a token it
// already holds; a write key mints tokens and belongs on a backend; an admin
// key can read a token back out in full, which is the same power as minting
// one.
const (
	ScopeConsume = "consume"
	ScopeWrite   = "write"
	ScopeAdmin   = "admin"
)

var scopeRank = map[string]int{
	ScopeConsume: 1,
	ScopeWrite:   2,
	ScopeAdmin:   3,
}

// Scopes lists the scopes in privilege order, for the admin panel's dropdown.
var Scopes = []string{ScopeConsume, ScopeWrite, ScopeAdmin}

// ValidScope reports whether s is one of the three known scopes.
func ValidScope(s string) bool {
	_, ok := scopeRank[s]
	return ok
}

// ScopeAllows reports whether a key carrying have is permitted to perform an
// action that requires want.
func ScopeAllows(have, want string) bool {
	h, ok := scopeRank[have]
	if !ok {
		return false
	}
	w, ok := scopeRank[want]
	if !ok {
		return false
	}
	return h >= w
}

var slugRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)

// ErrInvalidSlug and friends are returned by the validators below so callers
// can map them onto a 400 response.
var (
	ErrInvalidSlug     = errors.New("slug must match ^[a-z0-9][a-z0-9_-]{0,62}$")
	ErrInvalidUsername = errors.New("username must be 3-64 characters")
	ErrInvalidPassword = errors.New("password must be at least 8 characters")
)

// ValidSlug reports whether s is a legal project or environment slug.
func ValidSlug(s string) bool { return slugRe.MatchString(s) }

// MinPasswordLen is the shortest admin password accepted.
const MinPasswordLen = 8

// ValidUsername reports whether s is an acceptable admin username.
func ValidUsername(s string) bool { return len(s) >= 3 && len(s) <= 64 }

// ValidPassword reports whether s is long enough to be accepted.
func ValidPassword(s string) bool { return len(s) >= MinPasswordLen }

// User is an admin panel account.
type User struct {
	ID           int64
	Username     string
	PasswordHash string
	CreatedAt    int64
}

// Session is a logged-in admin browser session.
type Session struct {
	ID        string
	UserID    int64
	ExpiresAt int64
}

// Project groups a set of environments.
type Project struct {
	ID        int64
	Slug      string
	Name      string
	CreatedAt int64
}

// Environment owns tokens, API keys and webhooks. Every API key is bound to
// exactly one, so a client never names a project or environment itself.
type Environment struct {
	ID        int64
	ProjectID int64
	Slug      string
	CreatedAt int64
}

// APIKey is the stored half of an issued key. The plaintext key is shown once
// at creation time and never persisted — unlike tokens, an API key has no
// reason to be shown again.
type APIKey struct {
	ID            int64
	EnvironmentID int64
	KeyHash       string
	KeyPrefix     string
	Scope         string
	Label         string
	CreatedAt     int64
	RevokedAt     *int64
}

// Active reports whether the key has not been revoked.
func (k APIKey) Active() bool { return k.RevokedAt == nil }

// Token is an opaque bearer of a JSON payload.
//
// Value holds the plaintext token. It is stored in the clear so the panel can
// show a token again after issue, but it is populated on a loaded Token only
// where that is the point of the call: creation, and the single admin-scope
// inspection endpoint. Listings leave it empty and carry Prefix instead.
type Token struct {
	ID            string
	EnvironmentID int64
	Value         string
	Prefix        string
	PayloadJSON   string
	// MaxUses is nil for a token with no usage limit.
	MaxUses    *int64
	UsedCount  int64
	ExpiresAt  int64
	RevokedAt  *int64
	CreatedAt  int64
	LastUsedAt *int64
}

// Remaining reports how many uses are left, and false when the token has no
// limit at all.
func (t Token) Remaining() (int64, bool) {
	if t.MaxUses == nil {
		return 0, false
	}
	left := *t.MaxUses - t.UsedCount
	if left < 0 {
		left = 0
	}
	return left, true
}

// Webhook event types. There is deliberately no token.expired: expiry is a
// condition on the clock, not a moment something happens to the row, so there
// is nothing to fire from.
const (
	EventTokenCreated   = "token.created"
	EventTokenConsumed  = "token.consumed"
	EventTokenExhausted = "token.exhausted"
	EventTokenRevoked   = "token.revoked"
)

// WebhookEvents lists every event a webhook can subscribe to.
var WebhookEvents = []string{
	EventTokenCreated,
	EventTokenConsumed,
	EventTokenExhausted,
	EventTokenRevoked,
}

// ValidWebhookEvent reports whether e is a known event type.
func ValidWebhookEvent(e string) bool {
	for _, known := range WebhookEvents {
		if e == known {
			return true
		}
	}
	return false
}

// Webhook is an HTTP receiver for the events of one environment.
type Webhook struct {
	ID            int64
	EnvironmentID int64
	URL           string
	// Secret signs the body; it is shown in the panel because the receiver
	// needs it to verify, and it grants nothing on its own.
	Secret string
	// Events is the subscription list. Empty means every event.
	Events []string
	// Headers are extra request headers, for receivers that sit behind a
	// gateway wanting an Authorization or a routing key of its own. They are
	// applied before tokenzy's own headers, so none of them can overwrite the
	// signature.
	Headers map[string]string
	Label   string
	// IncludePayload adds the token's own JSON payload to the delivery. Off by
	// default: the payload is the caller's data, and it does not have to travel
	// to a third host just because a token changed.
	IncludePayload bool
	CreatedAt      int64
	DisabledAt     *int64
}

// Enabled reports whether deliveries should be attempted.
func (w Webhook) Enabled() bool { return w.DisabledAt == nil }

// Subscribes reports whether this webhook wants the given event type.
func (w Webhook) Subscribes(event string) bool {
	if len(w.Events) == 0 {
		return true
	}
	for _, e := range w.Events {
		if e == event {
			return true
		}
	}
	return false
}

// WebhookDelivery is one attempt log for one event on one webhook. It is kept
// after success too, so "did the receiver ever get this" has an answer.
type WebhookDelivery struct {
	ID         int64
	WebhookID  int64
	EventID    string
	EventType  string
	Payload    string
	Attempt    int64
	StatusCode *int64
	Error      string
	// NextRetryAt is set while another attempt is due, and cleared once the
	// delivery has either succeeded or run out of attempts.
	NextRetryAt *int64
	DeliveredAt *int64
	CreatedAt   int64
}

// Delivered reports whether the receiver accepted this delivery.
func (d WebhookDelivery) Delivered() bool { return d.DeliveredAt != nil }

// Pending reports whether another attempt is still scheduled.
func (d WebhookDelivery) Pending() bool { return d.DeliveredAt == nil && d.NextRetryAt != nil }

// GaveUp reports whether the delivery failed and will not be retried.
func (d WebhookDelivery) GaveUp() bool { return d.DeliveredAt == nil && d.NextRetryAt == nil }
