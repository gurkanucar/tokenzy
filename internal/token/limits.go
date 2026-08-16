package token

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
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

	// Lifetime errors are worded for the admin panel, where the field is
	// labelled "Lifetime" and the caller has never heard of ttlSeconds.
	ErrLifetimeRequired = errors.New("lifetime must be a whole number greater than 0")
	ErrLifetimeUnit     = errors.New("unknown lifetime unit")
)

// TTLUnit is a unit the admin panel offers for a token's lifetime.
//
// The JSON API stays in seconds — one unambiguous number is the right shape
// for a machine. A human filling in a form is a different audience: "15
// minutes" is a lifetime somebody can check at a glance, and "900" is a number
// they have to decode before they can spot that they meant 15 minutes and
// typed 15 days.
type TTLUnit struct {
	// Name is the value submitted by the form.
	Name string
	// Singular and Plural are what the operator reads.
	Singular string
	Plural   string
	// Seconds is how many seconds one of this unit is.
	Seconds int64
}

// TTLUnits are the units the lifetime field offers, smallest first. Nothing
// above days: the ceiling is measured in months at most, so weeks and years
// would only invite values the service is going to reject.
var TTLUnits = []TTLUnit{
	{Name: "second", Singular: "second", Plural: "seconds", Seconds: 1},
	{Name: "minute", Singular: "minute", Plural: "minutes", Seconds: 60},
	{Name: "hour", Singular: "hour", Plural: "hours", Seconds: 3600},
	{Name: "day", Singular: "day", Plural: "days", Seconds: 86400},
}

// DefaultTTLUnit is what the issue form starts on.
const DefaultTTLUnit = "minute"

// LookupTTLUnit resolves a submitted unit name.
func LookupTTLUnit(name string) (TTLUnit, bool) {
	for _, u := range TTLUnits {
		if u.Name == name {
			return u, true
		}
	}
	return TTLUnit{}, false
}

// HumanDuration renders a duration in the largest unit that divides it
// exactly, so a ceiling reads "90 days" rather than "2160h0m0s".
func HumanDuration(d time.Duration) string {
	seconds := int64(d / time.Second)
	if seconds <= 0 {
		return "0 seconds"
	}

	for i := len(TTLUnits) - 1; i >= 0; i-- {
		u := TTLUnits[i]
		if seconds%u.Seconds != 0 {
			continue
		}
		n := seconds / u.Seconds
		if n == 1 {
			return "1 " + u.Singular
		}
		return fmt.Sprintf("%d %s", n, u.Plural)
	}
	return fmt.Sprintf("%d seconds", seconds)
}

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

// Ceiling is the effective longest lifetime: the configured limit, never above
// the absolute one.
func (l Limits) Ceiling() time.Duration {
	if l.MaxTTL > AbsoluteMaxTTL || l.MaxTTL <= 0 {
		return AbsoluteMaxTTL
	}
	return l.MaxTTL
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
	max := l.Ceiling()
	if seconds > int64(max/time.Second) {
		return 0, fmt.Errorf("'ttlSeconds' must be at most %d (%s)",
			int64(max/time.Second), HumanDuration(max))
	}
	return time.Duration(seconds) * time.Second, nil
}

// ParseTTL turns the admin panel's "value + unit" pair into a lifetime.
//
// The multiplication is guarded before it happens rather than checked
// afterwards. "9999999999 days" would otherwise overflow int64 into a negative
// duration and sail straight past the ceiling it was meant to hit — arriving
// as a token that expired before it was issued, or worse, one whose expiry
// check quietly never fires.
func (l Limits) ParseTTL(value, unit string) (time.Duration, error) {
	n, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	if err != nil || n < 1 {
		return 0, ErrLifetimeRequired
	}

	u, ok := LookupTTLUnit(unit)
	if !ok {
		return 0, ErrLifetimeUnit
	}

	max := l.Ceiling()
	// Integer division, so this is conservative: it can only reject a value
	// that the multiplication would have put over the ceiling anyway.
	if n > int64(max/time.Second)/u.Seconds {
		return 0, fmt.Errorf("lifetime must be at most %s", HumanDuration(max))
	}
	return time.Duration(n*u.Seconds) * time.Second, nil
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
