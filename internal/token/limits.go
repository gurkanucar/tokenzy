package token

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// MaxPayloadBytes caps the stored payload.
//
// The limit is what keeps the service honest about what a token is: a
// reference to something, not the something. A payload that wants to be larger
// than this is data that belongs in the caller's own store, with an id in the
// token pointing at it.
const MaxPayloadBytes = 16 << 10 // 16 KiB

// DefaultMaxTTL is the operational ceiling on a token's lifetime when the
// deployment does not set one.
const DefaultMaxTTL = 90 * 24 * time.Hour

// AbsoluteMaxTTL is a hard ceiling no configuration can raise.
//
// The operational ceiling above is a policy knob and someone will eventually
// set it to something enormous. This one is arithmetic: it keeps
// `now + ttl` far away from the range where a unix timestamp overflows or
// wraps into the past, which would produce a token that is born expired — or
// worse, one whose expiry check quietly passes forever.
const AbsoluteMaxTTL = 10 * 365 * 24 * time.Hour

// Errors returned by the validators, so handlers can map them onto a 400.
var (
	ErrPayloadRequired = errors.New("'payload' is required")
	ErrPayloadInvalid  = errors.New("'payload' is not valid JSON")
	ErrPayloadTooLarge = fmt.Errorf("'payload' must be at most %d bytes once serialised", MaxPayloadBytes)
	ErrTTLRequired     = errors.New("'ttlSeconds' is required and must be greater than 0")
	ErrMaxUses         = errors.New("'maxUses' must be null (unlimited) or at least 1")
)

// Limits are the deployment-configurable input bounds.
type Limits struct {
	// MaxTTL is the longest lifetime a caller may ask for.
	MaxTTL time.Duration
}

// NewLimits clamps a configured ceiling into something usable. A zero or
// negative value falls back to the default; anything above the absolute
// ceiling is capped at it.
func NewLimits(maxTTL time.Duration) Limits {
	if maxTTL <= 0 {
		maxTTL = DefaultMaxTTL
	}
	if maxTTL > AbsoluteMaxTTL {
		maxTTL = AbsoluteMaxTTL
	}
	return Limits{MaxTTL: maxTTL}
}

// ValidateTTL checks a requested lifetime against both ceilings and returns it
// as a duration.
func (l Limits) ValidateTTL(seconds int64) (time.Duration, error) {
	if seconds <= 0 {
		return 0, ErrTTLRequired
	}
	// Compared in seconds rather than by building a Duration first: an absurd
	// input would overflow the multiplication into a negative duration and slip
	// past the ceiling it is meant to hit.
	max := l.MaxTTL
	if max > AbsoluteMaxTTL {
		max = AbsoluteMaxTTL
	}
	if seconds > int64(max/time.Second) {
		return 0, fmt.Errorf("'ttlSeconds' must be at most %d (%s)",
			int64(max/time.Second), max)
	}
	return time.Duration(seconds) * time.Second, nil
}

// ValidatePayload checks that raw is JSON of an acceptable size and returns the
// compacted form that gets stored.
//
// The content is never interpreted. Whatever goes in comes back out of
// /v1/consume unchanged — the service has no opinion about what the fields
// mean, and no way to be wrong about them.
func ValidatePayload(raw json.RawMessage) (string, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return "", ErrPayloadRequired
	}
	if !json.Valid(raw) {
		return "", ErrPayloadInvalid
	}

	var buf bytes.Buffer
	if err := json.Compact(&buf, raw); err != nil {
		return "", ErrPayloadInvalid
	}
	// Measured after compaction, so a caller is not punished for pretty-printing.
	if buf.Len() > MaxPayloadBytes {
		return "", ErrPayloadTooLarge
	}
	return buf.String(), nil
}

// ValidateMaxUses accepts nil (unlimited) or a positive count.
func ValidateMaxUses(v *int64) error {
	if v != nil && *v < 1 {
		return ErrMaxUses
	}
	return nil
}
