package token

import (
	"tokenzy/internal/model"
)

// Status values. A token's status is never stored: it is derived from the row
// every time it is asked for, so a token cannot be "active" in a column while
// being expired in fact.
const (
	StatusActive    = "active"
	StatusExpired   = "expired"
	StatusExhausted = "exhausted"
	StatusRevoked   = "revoked"
)

// Statuses lists every status, in the order the panel's filter chips use.
var Statuses = []string{StatusActive, StatusExpired, StatusExhausted, StatusRevoked}

// ValidStatus reports whether s names a status, for validating a filter.
func ValidStatus(s string) bool {
	for _, known := range Statuses {
		if s == known {
			return true
		}
	}
	return false
}

// StatusOf derives a token's status at the instant now (a unix timestamp).
//
// The order of the tests is the whole definition. A revoked token that has
// also expired reads as "revoked", because the interesting fact is that
// somebody stepped in. Likewise expiry outranks exhaustion. The distinction
// that matters most is the last one: `exhausted` means the token was spent
// down to its limit — a natural death, and for a single-use token the direct
// result of the consume that used it — whereas `revoked` means an
// administrator cancelled it. Both make the token unusable, and collapsing
// them would throw away the answer to "was this pass used, or did somebody
// cancel it?".
func StatusOf(t model.Token, now int64) string {
	switch {
	case t.RevokedAt != nil:
		return StatusRevoked
	case t.ExpiresAt <= now:
		return StatusExpired
	case t.MaxUses != nil && t.UsedCount >= *t.MaxUses:
		return StatusExhausted
	default:
		return StatusActive
	}
}

// Usable reports whether a consume would be accepted right now. It exists for
// display; the consume path never asks it, because asking and then acting is
// exactly the race the atomic UPDATE is there to avoid.
func Usable(t model.Token, now int64) bool {
	return StatusOf(t, now) == StatusActive
}
