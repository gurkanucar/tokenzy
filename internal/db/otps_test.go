package db

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"tokenzy/internal/model"
	"tokenzy/internal/otp"
)

// issueOTP creates a code and returns it.
func issueOTP(t *testing.T, database *DB, envID int64, otpType, identifier string,
	maxAttempts int64, ttl time.Duration) (model.OTP, bool) {
	t.Helper()

	id, err := otp.NewID()
	if err != nil {
		t.Fatalf("new id: %v", err)
	}
	code, err := otp.GenerateCode(otp.DefaultLength)
	if err != nil {
		t.Fatalf("generate code: %v", err)
	}

	issued, reused, err := database.GenerateOTP(context.Background(), envID, id, OTPRequest{
		Type:        otpType,
		Identifier:  identifier,
		Code:        code,
		MaxAttempts: maxAttempts,
		ExpiresAt:   time.Now().Add(ttl).Unix(),
	})
	if err != nil {
		t.Fatalf("generate otp: %v", err)
	}
	return issued, reused
}

// TestResendReturnsTheSameCodeWithoutExtendingIt is the resend contract.
//
// Both halves matter. Returning the same code is what stops a user who pressed
// "send again" from holding two codes and guessing which one the site wants.
// Not extending the expiry is what stops that button from being a way to keep
// one code alive forever.
func TestResendReturnsTheSameCodeWithoutExtendingIt(t *testing.T) {
	database := newTestDB(t)
	envID := newTestEnv(t, database)

	first, reused := issueOTP(t, database, envID, "password_reset", "user@example.com", 5, 5*time.Minute)
	if reused {
		t.Fatal("the first issuance reported itself as a resend")
	}

	second, reused := issueOTP(t, database, envID, "password_reset", "user@example.com", 5, time.Hour)
	if !reused {
		t.Fatal("a second issuance while a code was live made a new one")
	}
	if second.Code != first.Code {
		t.Fatalf("resend returned a different code (%s then %s)",
			otp.Mask(first.Code), otp.Mask(second.Code))
	}
	if second.ID != first.ID {
		t.Fatal("resend created a new row")
	}
	// The second call asked for an hour; it must not have got one.
	if second.ExpiresAt != first.ExpiresAt {
		t.Fatalf("resend moved the expiry from %d to %d — a resend must not extend a code",
			first.ExpiresAt, second.ExpiresAt)
	}
}

// TestDifferentContextsGetDifferentCodes: the uniqueness rule is per (type,
// identifier), not per identifier.
func TestDifferentContextsGetDifferentCodes(t *testing.T) {
	database := newTestDB(t)
	envID := newTestEnv(t, database)

	reset, _ := issueOTP(t, database, envID, "password_reset", "user@example.com", 5, 5*time.Minute)
	verify, _ := issueOTP(t, database, envID, "email_verify", "user@example.com", 5, 5*time.Minute)
	other, _ := issueOTP(t, database, envID, "password_reset", "someone@example.com", 5, 5*time.Minute)

	if reset.ID == verify.ID {
		t.Fatal("two different types shared one code")
	}
	if reset.ID == other.ID {
		t.Fatal("two different identifiers shared one code")
	}
}

// TestValidateSpendsTheCode: a correct code works exactly once, and the second
// attempt with the very same code is refused.
func TestValidateSpendsTheCode(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t)
	envID := newTestEnv(t, database)

	issued, _ := issueOTP(t, database, envID, "password_reset", "user@example.com", 5, 5*time.Minute)

	consumed, err := database.ValidateOTP(ctx, envID, "password_reset", "user@example.com", issued.Code)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if consumed.ConsumedAt == nil {
		t.Fatal("a successful validation did not mark the code consumed")
	}
	if got := otp.StatusOf(consumed, time.Now().Unix()); got != otp.StatusConsumed {
		t.Fatalf("status after validation = %q, want %q", got, otp.StatusConsumed)
	}

	// The same code, immediately: spending it is what killed it.
	if _, err := database.ValidateOTP(ctx, envID, "password_reset", "user@example.com", issued.Code); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second validation: got %v, want ErrNotFound", err)
	}
}

// TestTypeMustMatch: a code issued for one purpose cannot be spent on another,
// even by whoever legitimately holds it.
func TestTypeMustMatch(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t)
	envID := newTestEnv(t, database)

	issued, _ := issueOTP(t, database, envID, "password_reset", "user@example.com", 5, 5*time.Minute)

	if _, err := database.ValidateOTP(ctx, envID, "email_verify", "user@example.com", issued.Code); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a password_reset code passed as email_verify: %v", err)
	}
	if _, err := database.ValidateOTP(ctx, envID, "password_reset", "someone@example.com", issued.Code); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a code passed for the wrong identifier: %v", err)
	}
	// And it is still usable for what it was actually issued for.
	if _, err := database.ValidateOTP(ctx, envID, "password_reset", "user@example.com", issued.Code); err != nil {
		t.Fatalf("the code stopped working after mismatched attempts: %v", err)
	}
}

// TestAttemptCeilingLocksTheCode is the test the module exists for.
//
// Six digits is a million possibilities. The only thing between that and a
// script is this counter, so the assertion that matters is the last one: once
// the ceiling is reached, even the *correct* code is refused.
func TestAttemptCeilingLocksTheCode(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t)
	envID := newTestEnv(t, database)

	const maxAttempts = 3
	issued, _ := issueOTP(t, database, envID, "password_reset", "user@example.com",
		maxAttempts, 5*time.Minute)

	wrong := "000000"
	if wrong == issued.Code {
		wrong = "111111"
	}

	for i := 1; i <= maxAttempts; i++ {
		if _, err := database.ValidateOTP(ctx, envID, "password_reset", "user@example.com", wrong); !errors.Is(err, ErrNotFound) {
			t.Fatalf("wrong guess %d: got %v, want ErrNotFound", i, err)
		}

		after, err := database.GetOTP(ctx, envID, issued.ID)
		if err != nil {
			t.Fatalf("get otp: %v", err)
		}
		if after.AttemptCount != int64(i) {
			t.Fatalf("after %d wrong guesses the counter reads %d", i, after.AttemptCount)
		}
	}

	locked, err := database.GetOTP(ctx, envID, issued.ID)
	if err != nil {
		t.Fatalf("get otp: %v", err)
	}
	if got := otp.StatusOf(locked, time.Now().Unix()); got != otp.StatusLocked {
		t.Fatalf("status after exhausting attempts = %q, want %q", got, otp.StatusLocked)
	}

	// The whole point: the right code no longer works.
	if _, err := database.ValidateOTP(ctx, envID, "password_reset", "user@example.com", issued.Code); !errors.Is(err, ErrNotFound) {
		t.Fatal("the correct code was accepted after the attempt ceiling was reached")
	}
}

// TestAttemptCounterStopsAtTheCeiling: further guesses against a locked code do
// not push the counter past its maximum, so the panel never shows "9 of 5".
func TestAttemptCounterStopsAtTheCeiling(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t)
	envID := newTestEnv(t, database)

	issued, _ := issueOTP(t, database, envID, "password_reset", "user@example.com", 2, 5*time.Minute)

	for i := 0; i < 6; i++ {
		database.ValidateOTP(ctx, envID, "password_reset", "user@example.com", "999999")
	}

	after, err := database.GetOTP(ctx, envID, issued.ID)
	if err != nil {
		t.Fatalf("get otp: %v", err)
	}
	if after.AttemptCount > after.MaxAttempts {
		t.Fatalf("counter reads %d of %d", after.AttemptCount, after.MaxAttempts)
	}
}

// TestLockedCodeIsNotHandedBackByResend: once a code has burned its attempts,
// asking again gives a fresh one rather than the dead one.
func TestLockedCodeIsNotHandedBackByResend(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t)
	envID := newTestEnv(t, database)

	first, _ := issueOTP(t, database, envID, "password_reset", "user@example.com", 1, 5*time.Minute)
	database.ValidateOTP(ctx, envID, "password_reset", "user@example.com", "000000")

	second, reused := issueOTP(t, database, envID, "password_reset", "user@example.com", 1, 5*time.Minute)
	if reused {
		t.Fatal("a locked code was handed back as a resend")
	}
	if second.ID == first.ID {
		t.Fatal("the locked row was reused")
	}
	if _, err := database.ValidateOTP(ctx, envID, "password_reset", "user@example.com", second.Code); err != nil {
		t.Fatalf("the replacement code did not work: %v", err)
	}
}

// TestExpiredCodeIsRefusedAndReplaced.
func TestExpiredCodeIsRefusedAndReplaced(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t)
	envID := newTestEnv(t, database)

	stale, _ := issueOTP(t, database, envID, "password_reset", "user@example.com", 5, -time.Second)

	if _, err := database.ValidateOTP(ctx, envID, "password_reset", "user@example.com", stale.Code); !errors.Is(err, ErrNotFound) {
		t.Fatalf("an expired code was accepted: %v", err)
	}

	fresh, reused := issueOTP(t, database, envID, "password_reset", "user@example.com", 5, 5*time.Minute)
	if reused {
		t.Fatal("an expired code was handed back as a resend")
	}
	if _, err := database.ValidateOTP(ctx, envID, "password_reset", "user@example.com", fresh.Code); err != nil {
		t.Fatalf("the replacement code did not work: %v", err)
	}
}

// TestRevokedCodeIsRefused.
func TestRevokedCodeIsRefused(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t)
	envID := newTestEnv(t, database)

	issued, _ := issueOTP(t, database, envID, "password_reset", "user@example.com", 5, 5*time.Minute)
	if _, err := database.RevokeOTP(ctx, envID, issued.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	if _, err := database.ValidateOTP(ctx, envID, "password_reset", "user@example.com", issued.Code); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a revoked code was accepted: %v", err)
	}
}

// TestValidateIsAtomicUnderConcurrency: many requests carrying the *correct*
// code, and exactly one of them may spend it.
func TestValidateIsAtomicUnderConcurrency(t *testing.T) {
	database := newTestDB(t)
	envID := newTestEnv(t, database)

	issued, _ := issueOTP(t, database, envID, "password_reset", "user@example.com", 50, time.Hour)

	const racers = 50
	var (
		start     sync.WaitGroup
		done      sync.WaitGroup
		mu        sync.Mutex
		successes int
	)
	start.Add(1)
	done.Add(racers)

	for i := 0; i < racers; i++ {
		go func() {
			defer done.Done()
			start.Wait()

			_, err := database.ValidateOTP(context.Background(), envID,
				"password_reset", "user@example.com", issued.Code)

			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				successes++
			} else if !errors.Is(err, ErrNotFound) {
				t.Errorf("unexpected error: %v", err)
			}
		}()
	}

	start.Done()
	done.Wait()

	if successes != 1 {
		t.Fatalf("expected exactly 1 successful validation, got %d", successes)
	}
}

// TestConcurrentGenerateYieldsOneCode: two requests for the same identifier
// arriving together must not each create a code, or the user receives two SMS
// messages and neither one is authoritative.
func TestConcurrentGenerateYieldsOneCode(t *testing.T) {
	database := newTestDB(t)
	envID := newTestEnv(t, database)

	const racers = 20
	var (
		start sync.WaitGroup
		done  sync.WaitGroup
		mu    sync.Mutex
		codes = map[string]bool{}
	)
	start.Add(1)
	done.Add(racers)

	for i := 0; i < racers; i++ {
		go func() {
			defer done.Done()
			start.Wait()

			id, _ := otp.NewID()
			code, _ := otp.GenerateCode(otp.DefaultLength)
			issued, _, err := database.GenerateOTP(context.Background(), envID, id, OTPRequest{
				Type:        "password_reset",
				Identifier:  "user@example.com",
				Code:        code,
				MaxAttempts: 5,
				ExpiresAt:   time.Now().Add(5 * time.Minute).Unix(),
			})
			if err != nil {
				t.Errorf("generate: %v", err)
				return
			}

			mu.Lock()
			defer mu.Unlock()
			codes[issued.ID] = true
		}()
	}

	start.Done()
	done.Wait()

	if len(codes) != 1 {
		t.Fatalf("%d concurrent requests produced %d different codes, want 1", racers, len(codes))
	}
}

// TestListingsNeverCarryTheCode.
func TestListingsNeverCarryTheCode(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t)
	envID := newTestEnv(t, database)

	issued, _ := issueOTP(t, database, envID, "password_reset", "user@example.com", 5, 5*time.Minute)

	listed, _, err := database.ListOTPs(ctx, envID, OTPFilter{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(listed) != 1 {
		t.Fatalf("listed %d codes, want 1", len(listed))
	}
	if listed[0].Code != "" {
		t.Fatal("a listing returned a plaintext code")
	}

	single, err := database.GetOTP(ctx, envID, issued.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if single.Code != "" {
		t.Fatal("GetOTP returned a plaintext code")
	}

	// Only the one method that says so hands it over — and reading it does not
	// spend the code.
	code, err := database.GetOTPCode(ctx, envID, issued.ID)
	if err != nil {
		t.Fatalf("get code: %v", err)
	}
	if code != issued.Code {
		t.Fatal("the code returned for inspection differs from the one issued")
	}
	if _, err := database.ValidateOTP(ctx, envID, "password_reset", "user@example.com", code); err != nil {
		t.Fatalf("the code stopped working after being inspected: %v", err)
	}
}

// TestOTPStatusFiltersPartitionTheSet: the five filters are disjoint and cover
// everything, which is what makes the panel's chip counts add up.
func TestOTPStatusFiltersPartitionTheSet(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t)
	envID := newTestEnv(t, database)

	// One of each, each on its own identifier so they do not reuse one another.
	issueOTP(t, database, envID, "t", "active@example.com", 5, 5*time.Minute)
	issueOTP(t, database, envID, "t", "expired@example.com", 5, -time.Minute)

	spent, _ := issueOTP(t, database, envID, "t", "consumed@example.com", 5, 5*time.Minute)
	if _, err := database.ValidateOTP(ctx, envID, "t", "consumed@example.com", spent.Code); err != nil {
		t.Fatalf("validate: %v", err)
	}

	issueOTP(t, database, envID, "t", "locked@example.com", 1, 5*time.Minute)
	database.ValidateOTP(ctx, envID, "t", "locked@example.com", "000000")

	cancelled, _ := issueOTP(t, database, envID, "t", "revoked@example.com", 5, 5*time.Minute)
	if _, err := database.RevokeOTP(ctx, envID, cancelled.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	counts, err := database.CountOTPsByStatus(ctx, envID)
	if err != nil {
		t.Fatalf("count: %v", err)
	}

	var total int64
	for _, status := range otp.Statuses {
		if counts[status] != 1 {
			t.Errorf("%s: counted %d, want 1", status, counts[status])
		}
		total += counts[status]
	}
	if total != 5 {
		t.Fatalf("counts sum to %d, want 5 — the filters overlap or leave a gap", total)
	}

	for _, status := range otp.Statuses {
		got, _, err := database.ListOTPs(ctx, envID, OTPFilter{Status: status})
		if err != nil {
			t.Fatalf("list %s: %v", status, err)
		}
		if len(got) != 1 {
			t.Fatalf("list %s returned %d rows, want 1", status, len(got))
		}
		if s := otp.StatusOf(got[0], time.Now().Unix()); s != status {
			t.Fatalf("filter %s returned a code whose status is %s", status, s)
		}
	}
}

// TestOTPCleanupRespectsRetention.
func TestOTPCleanupRespectsRetention(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t)
	envID := newTestEnv(t, database)

	live, _ := issueOTP(t, database, envID, "t", "live@example.com", 5, 5*time.Minute)
	stale, _ := issueOTP(t, database, envID, "t", "stale@example.com", 5, -48*time.Hour)

	n, err := database.DeleteDeadOTPs(ctx, time.Now().Add(-24*time.Hour).Unix(), 100)
	if err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if n != 1 {
		t.Fatalf("deleted %d codes, want 1", n)
	}
	if _, err := database.GetOTP(ctx, envID, stale.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("the stale code survived: %v", err)
	}
	if _, err := database.GetOTP(ctx, envID, live.ID); err != nil {
		t.Fatalf("the live code was collateral damage: %v", err)
	}
}

// TestCodesAreNumericAndKeepLeadingZeros: a code is a string all the way
// through, so "048291" survives as six characters rather than becoming 48291.
func TestCodesAreNumericAndKeepLeadingZeros(t *testing.T) {
	sawLeadingZero := false

	for i := 0; i < 2000; i++ {
		code, err := otp.GenerateCode(6)
		if err != nil {
			t.Fatalf("generate: %v", err)
		}
		if len(code) != 6 {
			t.Fatalf("code %q is %d characters, want 6", code, len(code))
		}
		for _, c := range code {
			if c < '0' || c > '9' {
				t.Fatalf("code %q contains a non-digit", code)
			}
		}
		if code[0] == '0' {
			sawLeadingZero = true
		}
	}

	// Roughly one in ten codes starts with a zero, so 2000 draws without one
	// means they are being dropped somewhere.
	if !sawLeadingZero {
		t.Fatal("no generated code began with 0 — leading zeros are being lost")
	}
}
