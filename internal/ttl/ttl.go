// Package ttl holds the lifetime input helpers shared by tokens and one-time
// codes: the units the admin panel offers, and the conversion from "a number
// and a unit" into a duration.
//
// It exists so there is one unit table rather than two. Both modules ask a
// human how long something should live, and if each kept its own list they
// would drift — one gaining weeks, the other still stopping at days, for no
// reason anybody could name.
package ttl

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Unit is a lifetime unit offered by the admin panel.
//
// The JSON API stays in seconds — one unambiguous number is the right shape for
// a machine. A human filling in a form is a different audience: "15 minutes" is
// a lifetime somebody can check at a glance, and "900" is a number they have to
// decode before they can spot that they meant minutes and left the box on days.
type Unit struct {
	// Name is the value submitted by the form.
	Name string
	// Singular and Plural are what the operator reads.
	Singular string
	Plural   string
	// Seconds is how many seconds one of this unit is.
	Seconds int64
}

// Units are the units a lifetime field offers, smallest first. Nothing above
// days: the ceilings here are months at most, so weeks and years would only
// invite values the service is going to reject.
var Units = []Unit{
	{Name: "second", Singular: "second", Plural: "seconds", Seconds: 1},
	{Name: "minute", Singular: "minute", Plural: "minutes", Seconds: 60},
	{Name: "hour", Singular: "hour", Plural: "hours", Seconds: 3600},
	{Name: "day", Singular: "day", Plural: "days", Seconds: 86400},
}

// DefaultUnit is what a fresh form starts on.
const DefaultUnit = "minute"

// Errors returned by Parse, worded for a form rather than for a JSON field.
var (
	ErrRequired = errors.New("lifetime must be a whole number greater than 0")
	ErrUnit     = errors.New("unknown lifetime unit")
)

// LookupUnit resolves a submitted unit name.
func LookupUnit(name string) (Unit, bool) {
	for _, u := range Units {
		if u.Name == name {
			return u, true
		}
	}
	return Unit{}, false
}

// Human renders a duration in the largest unit that divides it exactly, so a
// ceiling reads "90 days" rather than "2160h0m0s".
func Human(d time.Duration) string {
	seconds := int64(d / time.Second)
	if seconds <= 0 {
		return "0 seconds"
	}

	for i := len(Units) - 1; i >= 0; i-- {
		u := Units[i]
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

// Parse turns a "value + unit" pair into a lifetime, rejecting anything above
// the ceiling.
//
// The multiplication is guarded before it happens rather than checked
// afterwards. "9999999999999999 days" would otherwise overflow int64 into a
// negative duration and sail straight past the ceiling it was meant to hit —
// arriving as something that expired before it was created, or worse, whose
// expiry check quietly never fires.
func Parse(value, unit string, ceiling time.Duration) (time.Duration, error) {
	n, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	if err != nil || n < 1 {
		return 0, ErrRequired
	}

	u, ok := LookupUnit(unit)
	if !ok {
		return 0, ErrUnit
	}

	// Integer division, so this is conservative: it can only reject a value
	// that the multiplication would have put over the ceiling anyway.
	if n > int64(ceiling/time.Second)/u.Seconds {
		return 0, fmt.Errorf("lifetime must be at most %s", Human(ceiling))
	}
	return time.Duration(n*u.Seconds) * time.Second, nil
}
