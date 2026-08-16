package token

import (
	"testing"
	"time"
)

// TestParseTTL covers the conversion the admin panel's lifetime field relies
// on, including the overflow that a units dropdown makes reachable.
func TestParseTTL(t *testing.T) {
	limits := NewLimits(90 * 24 * time.Hour)

	ok := []struct {
		value string
		unit  string
		want  time.Duration
	}{
		{"15", "minute", 15 * time.Minute},
		{"900", "second", 900 * time.Second},
		{"1", "hour", time.Hour},
		{"7", "day", 7 * 24 * time.Hour},
		{" 30 ", "minute", 30 * time.Minute},
		// Exactly on the ceiling, expressed in each unit that lands there.
		{"90", "day", 90 * 24 * time.Hour},
		{"2160", "hour", 90 * 24 * time.Hour},
	}
	for _, tc := range ok {
		got, err := limits.ParseTTL(tc.value, tc.unit)
		if err != nil {
			t.Errorf("ParseTTL(%q, %q): %v", tc.value, tc.unit, err)
			continue
		}
		if got != tc.want {
			t.Errorf("ParseTTL(%q, %q) = %s, want %s", tc.value, tc.unit, got, tc.want)
		}
	}

	bad := []struct {
		name  string
		value string
		unit  string
	}{
		{"empty", "", "minute"},
		{"zero", "0", "minute"},
		{"negative", "-5", "minute"},
		{"not a number", "abc", "minute"},
		{"fractional", "1.5", "minute"},
		{"unknown unit", "5", "fortnight"},
		{"missing unit", "5", ""},
		{"one over the ceiling", "91", "day"},
		// The reason the multiplication is guarded rather than checked after:
		// this would overflow int64 into a negative duration and sail past
		// every ceiling, arriving as a token that never expires.
		{"overflows int64", "9999999999999999", "day"},
		{"overflows int64 in hours", "999999999999999999", "hour"},
	}
	for _, tc := range bad {
		if got, err := limits.ParseTTL(tc.value, tc.unit); err == nil {
			t.Errorf("%s: ParseTTL(%q, %q) = %s, want an error", tc.name, tc.value, tc.unit, got)
		}
	}
}

// TestParseTTLRespectsTheConfiguredCeiling: lowering MaxTTL lowers what the
// form accepts, in every unit.
func TestParseTTLRespectsTheConfiguredCeiling(t *testing.T) {
	limits := NewLimits(time.Hour)

	if _, err := limits.ParseTTL("60", "minute"); err != nil {
		t.Fatalf("exactly the ceiling was rejected: %v", err)
	}
	if _, err := limits.ParseTTL("61", "minute"); err == nil {
		t.Fatal("a minute over the ceiling was accepted")
	}
	if _, err := limits.ParseTTL("1", "day"); err == nil {
		t.Fatal("a day was accepted under a one-hour ceiling")
	}
}

// TestCeilingNeverExceedsTheAbsoluteOne: no configuration can raise the hard
// limit, and a zero value falls back rather than meaning "no limit".
func TestCeilingNeverExceedsTheAbsoluteOne(t *testing.T) {
	if got := NewLimits(100 * 365 * 24 * time.Hour).Ceiling(); got != AbsoluteMaxTTL {
		t.Fatalf("ceiling = %s, want the absolute maximum %s", got, AbsoluteMaxTTL)
	}
	if got := NewLimits(0).Ceiling(); got != DefaultMaxTTL {
		t.Fatalf("ceiling = %s, want the default %s", got, DefaultMaxTTL)
	}
	if _, err := NewLimits(0).ParseTTL("100", "day"); err == nil {
		t.Fatal("100 days was accepted under the 90-day default ceiling")
	}
}

// TestValidateTTLStillGuardsTheAPI: the JSON API takes seconds directly and
// must enforce the same ceilings the form does.
func TestValidateTTLStillGuardsTheAPI(t *testing.T) {
	limits := NewLimits(90 * 24 * time.Hour)

	if _, err := limits.ValidateTTL(900); err != nil {
		t.Fatalf("900 seconds rejected: %v", err)
	}
	for _, seconds := range []int64{0, -1, 90*24*3600 + 1} {
		if _, err := limits.ValidateTTL(seconds); err == nil {
			t.Errorf("ValidateTTL(%d) = nil error, want a rejection", seconds)
		}
	}
}
