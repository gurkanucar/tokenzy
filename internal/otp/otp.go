// Package otp owns one-time codes: how one is generated, how its status is
// derived, and what inputs are accepted when one is issued. The SQL that
// stores and spends them lives in package db.
//
// The difference from package token is not cosmetic. A token carries ~244 bits
// and cannot be guessed, so it needs no attempt counter. A six-digit code is
// one million possibilities, which is minutes of work for a script — so here
// the attempt ceiling is not a nicety, it is the entire defence, and nothing
// in this package should be changed in a way that weakens it.
package otp

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"tokenzy/internal/model"
	"tokenzy/internal/ttl"
)

// IDPrefix marks the identifier used by the management API. An OTP id is not a
// secret; the code is.
const IDPrefix = "otp_"

// Code length bounds. Four digits is ten thousand possibilities, which is only
// defensible because of the attempt ceiling — it is offered because some flows
// (a card reader, a phone keypad) genuinely cannot ask for more, not because
// it is a good default.
const (
	MinLength     = 4
	MaxLength     = 10
	DefaultLength = 6
)

// Attempt bounds. One means the code dies on a single mistake; twenty is
// already generous against a million-wide space.
const (
	MinAttempts     = 1
	MaxAttempts     = 20
	DefaultAttempts = 5
)

// DefaultMaxTTL is the ceiling on a code's lifetime when the deployment does
// not set one. Codes are meant to be used within minutes of being sent; an hour
// is a generous outer bound, not a target.
const DefaultMaxTTL = time.Hour

// AbsoluteMaxTTL is a hard ceiling no configuration can raise. A one-time code
// that lives for days is not a one-time code, it is a password.
const AbsoluteMaxTTL = 24 * time.Hour

// Errors returned by the validators, so handlers can map them onto a 400.
var (
	ErrTTLRequired = errors.New("'ttlSeconds' is required and must be greater than 0")
	ErrLength      = fmt.Errorf("'length' must be between %d and %d", MinLength, MaxLength)
	ErrAttempts    = fmt.Errorf("'maxAttempts' must be between %d and %d", MinAttempts, MaxAttempts)
)

// Status values. Derived from the row on every read, never stored, so a code
// cannot be "active" in a column while being locked in fact.
const (
	StatusActive   = "active"
	StatusConsumed = "consumed"
	StatusExpired  = "expired"
	StatusLocked   = "locked"
	StatusRevoked  = "revoked"
)

// Statuses lists every status, in the order the panel's filter chips use.
var Statuses = []string{StatusActive, StatusConsumed, StatusExpired, StatusLocked, StatusRevoked}

// ValidStatus reports whether s names a status, for validating a filter.
func ValidStatus(s string) bool {
	for _, known := range Statuses {
		if s == known {
			return true
		}
	}
	return false
}

// StatusOf derives a code's status at the instant now (a unix timestamp).
//
// The order of the tests is the definition. `revoked` outranks everything
// because somebody stepping in is the most interesting fact about a code;
// `consumed` outranks `expired` because a code that was used and then ran out
// of time was, first and foremost, used. `locked` sits last of the dead states:
// a code that expired while locked reads as expired, since the clock would have
// killed it regardless of the attempts.
func StatusOf(o model.OTP, now int64) string {
	switch {
	case o.RevokedAt != nil:
		return StatusRevoked
	case o.ConsumedAt != nil:
		return StatusConsumed
	case o.ExpiresAt <= now:
		return StatusExpired
	case o.AttemptCount >= o.MaxAttempts:
		return StatusLocked
	default:
		return StatusActive
	}
}

// NewID returns an identifier for an OTP row.
func NewID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate otp id: %w", err)
	}
	return IDPrefix + hex.EncodeToString(buf), nil
}

// GenerateCode returns a numeric code of the given length.
//
// It is a string, not a number, and that is load-bearing: "048291" is a
// perfectly good six-digit code, and the moment it passes through an integer
// it becomes 48291 and stops matching what the user was sent.
//
// Each digit is drawn with crypto/rand.Int, which rejects internally to stay
// uniform. Taking a random byte modulo ten would be cheaper and would make the
// digits 0-5 slightly likelier than 6-9 — a small bias, but this is a space
// small enough to be searched, and there is no reason to hand any of it back.
func GenerateCode(length int) (string, error) {
	if length < MinLength || length > MaxLength {
		return "", ErrLength
	}

	var sb strings.Builder
	sb.Grow(length)
	ten := big.NewInt(10)

	for i := 0; i < length; i++ {
		digit, err := rand.Int(rand.Reader, ten)
		if err != nil {
			return "", fmt.Errorf("generate otp code: %w", err)
		}
		sb.WriteByte(byte('0' + digit.Int64()))
	}
	return sb.String(), nil
}

// Mask renders a code safe to write down. Nothing in this service logs a code
// today; this exists so that when something is tempted to, there is an obvious
// right way to do it.
func Mask(code string) string {
	if code == "" {
		return ""
	}
	return strings.Repeat("•", len(code))
}

// MaskIdentifier renders an identifier safe for a log line.
//
// Identifiers are usually email addresses or phone numbers, which makes them
// personal data. Keeping the first and last character leaves just enough to
// correlate two entries about the same person without writing down who they
// are.
func MaskIdentifier(identifier string) string {
	runes := []rune(identifier)
	switch {
	case len(runes) == 0:
		return ""
	case len(runes) <= 2:
		return strings.Repeat("•", len(runes))
	default:
		return string(runes[0]) + strings.Repeat("•", len(runes)-2) + string(runes[len(runes)-1])
	}
}

// Limits are the deployment-configurable input bounds.
type Limits struct {
	// MaxTTL is the longest lifetime a caller may ask for.
	MaxTTL time.Duration
}

// NewLimits clamps a configured ceiling into something usable.
func NewLimits(maxTTL time.Duration) Limits {
	if maxTTL <= 0 {
		maxTTL = DefaultMaxTTL
	}
	if maxTTL > AbsoluteMaxTTL {
		maxTTL = AbsoluteMaxTTL
	}
	return Limits{MaxTTL: maxTTL}
}

// Ceiling is the effective longest lifetime.
func (l Limits) Ceiling() time.Duration {
	if l.MaxTTL > AbsoluteMaxTTL || l.MaxTTL <= 0 {
		return AbsoluteMaxTTL
	}
	return l.MaxTTL
}

// ValidateTTL checks a requested lifetime against the ceiling.
func (l Limits) ValidateTTL(seconds int64) (time.Duration, error) {
	if seconds <= 0 {
		return 0, ErrTTLRequired
	}
	// Compared in seconds rather than by building a Duration first: an absurd
	// input would overflow the multiplication into a negative duration and slip
	// past the ceiling it is meant to hit.
	max := l.Ceiling()
	if seconds > int64(max/time.Second) {
		return 0, fmt.Errorf("'ttlSeconds' must be at most %d seconds (%s)",
			int64(max/time.Second), ttl.Human(max))
	}
	return time.Duration(seconds) * time.Second, nil
}

// ParseTTL turns the admin panel's "value + unit" pair into a lifetime.
func (l Limits) ParseTTL(value, unit string) (time.Duration, error) {
	return ttl.Parse(value, unit, l.Ceiling())
}

// ResolveLength applies the default to an absent length and checks the bounds.
func ResolveLength(length *int64) (int, error) {
	if length == nil {
		return DefaultLength, nil
	}
	if *length < MinLength || *length > MaxLength {
		return 0, ErrLength
	}
	return int(*length), nil
}

// ResolveAttempts applies the default to an absent ceiling and checks the
// bounds. Zero is rejected rather than treated as "unlimited": an OTP with no
// attempt ceiling is a six-digit password waiting to be enumerated, and it must
// not be reachable by leaving a field out.
func ResolveAttempts(attempts *int64) (int64, error) {
	if attempts == nil {
		return DefaultAttempts, nil
	}
	if *attempts < MinAttempts || *attempts > MaxAttempts {
		return 0, ErrAttempts
	}
	return *attempts, nil
}
