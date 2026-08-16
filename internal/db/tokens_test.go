package db

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"tokenzy/internal/model"
	"tokenzy/internal/token"
)

// newTestDB opens a migrated database in a temporary directory.
func newTestDB(t *testing.T) *DB {
	t.Helper()

	database, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { database.Close() })

	if err := database.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return database
}

// newTestEnv creates a project and returns the id of its default environment.
func newTestEnv(t *testing.T, database *DB) int64 {
	t.Helper()

	ctx := context.Background()
	project, err := database.CreateProject(ctx, "test", "Test")
	if err != nil {
		t.Fatalf("create project: %v", err)
	}
	env, err := database.GetEnvironment(ctx, project.ID, DefaultEnvironment)
	if err != nil {
		t.Fatalf("get environment: %v", err)
	}
	return env.ID
}

// mint issues a token and returns its plaintext and id.
func mint(t *testing.T, database *DB, envID int64, maxUses *int64, ttl time.Duration) (string, string) {
	t.Helper()

	id, err := token.NewID()
	if err != nil {
		t.Fatalf("new id: %v", err)
	}
	value, err := token.Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	created, err := database.CreateToken(context.Background(), envID, id, value,
		`{"userId":"usr_123"}`, maxUses, time.Now().Add(ttl).Unix())
	if err != nil {
		t.Fatalf("create token: %v", err)
	}
	return created.Value, created.ID
}

func ptr(v int64) *int64 { return &v }

// TestConsumeIsAtomicUnderConcurrency is the test the whole design exists for.
//
// Fifty goroutines race for one single-use token. Exactly one must win. If
// consume were ever rewritten as "read the row, check it, then update it", this
// is what would catch it: two readers would both see used_count = 0 and both
// proceed, and the count of successes would come back greater than one.
func TestConsumeIsAtomicUnderConcurrency(t *testing.T) {
	database := newTestDB(t)
	envID := newTestEnv(t, database)
	value, id := mint(t, database, envID, ptr(1), time.Hour)

	const racers = 50

	var (
		start     sync.WaitGroup
		done      sync.WaitGroup
		mu        sync.Mutex
		successes int
		failures  int
	)
	start.Add(1)
	done.Add(racers)

	for i := 0; i < racers; i++ {
		go func() {
			defer done.Done()
			// Line every goroutine up behind one gate, so they contend for the
			// row rather than arriving one after another.
			start.Wait()

			_, err := database.ConsumeToken(context.Background(), envID, value)

			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				successes++
			case errors.Is(err, ErrNotFound):
				failures++
			default:
				t.Errorf("unexpected error: %v", err)
			}
		}()
	}

	start.Done()
	done.Wait()

	if successes != 1 {
		t.Fatalf("expected exactly 1 successful consume, got %d (with %d rejections)",
			successes, failures)
	}
	if failures != racers-1 {
		t.Fatalf("expected %d rejections, got %d", racers-1, failures)
	}

	// And the row agrees: one use recorded, not fifty. A count above 1 would
	// mean the UPDATE ran more than once — the same bug seen from the data
	// rather than from the return values.
	after, err := database.GetToken(context.Background(), envID, id)
	if err != nil {
		t.Fatalf("get token: %v", err)
	}
	if after.UsedCount != 1 {
		t.Fatalf("used count = %d after %d concurrent attempts, want 1", after.UsedCount, racers)
	}
}

// TestSingleUseTokenDiesOnConsume proves the claim that a maxUses=1 token needs
// no separate revocation: spending it is what invalidates it.
func TestSingleUseTokenDiesOnConsume(t *testing.T) {
	database := newTestDB(t)
	envID := newTestEnv(t, database)
	value, id := mint(t, database, envID, ptr(1), time.Hour)

	ctx := context.Background()

	consumed, err := database.ConsumeToken(ctx, envID, value)
	if err != nil {
		t.Fatalf("first consume: %v", err)
	}
	if consumed.UsedCount != 1 {
		t.Fatalf("used count after first consume = %d, want 1", consumed.UsedCount)
	}
	if got := token.StatusOf(consumed, time.Now().Unix()); got != token.StatusExhausted {
		t.Fatalf("status after first consume = %q, want %q", got, token.StatusExhausted)
	}

	if _, err := database.ConsumeToken(ctx, envID, value); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second consume: got %v, want ErrNotFound", err)
	}

	// Exhausted, not revoked: nobody stepped in, the token simply ran out. The
	// panel shows those differently and the distinction must survive.
	after, err := database.GetToken(ctx, envID, id)
	if err != nil {
		t.Fatalf("get token: %v", err)
	}
	if after.RevokedAt != nil {
		t.Fatal("a spent token must not be marked revoked")
	}
	if after.UsedCount != 1 {
		t.Fatalf("used count = %d after a rejected second attempt, want 1", after.UsedCount)
	}
}

// TestConsumeRejectsExpiredExhaustedRevoked walks the three ways a token stops
// working, and checks each one is refused.
func TestConsumeRejectsExpiredExhaustedRevoked(t *testing.T) {
	ctx := context.Background()

	t.Run("expired", func(t *testing.T) {
		database := newTestDB(t)
		envID := newTestEnv(t, database)
		value, _ := mint(t, database, envID, nil, -time.Second)

		if _, err := database.ConsumeToken(ctx, envID, value); !errors.Is(err, ErrNotFound) {
			t.Fatalf("got %v, want ErrNotFound", err)
		}
	})

	t.Run("exhausted", func(t *testing.T) {
		database := newTestDB(t)
		envID := newTestEnv(t, database)
		value, _ := mint(t, database, envID, ptr(2), time.Hour)

		for i := 0; i < 2; i++ {
			if _, err := database.ConsumeToken(ctx, envID, value); err != nil {
				t.Fatalf("consume %d: %v", i+1, err)
			}
		}
		if _, err := database.ConsumeToken(ctx, envID, value); !errors.Is(err, ErrNotFound) {
			t.Fatalf("third consume: got %v, want ErrNotFound", err)
		}
	})

	t.Run("revoked", func(t *testing.T) {
		database := newTestDB(t)
		envID := newTestEnv(t, database)
		value, id := mint(t, database, envID, nil, time.Hour)

		if _, err := database.RevokeToken(ctx, envID, id); err != nil {
			t.Fatalf("revoke: %v", err)
		}
		if _, err := database.ConsumeToken(ctx, envID, value); !errors.Is(err, ErrNotFound) {
			t.Fatalf("got %v, want ErrNotFound", err)
		}
	})
}

// TestConsumeIsScopedToEnvironment: a token is only redeemable through a key
// bound to the environment that issued it.
func TestConsumeIsScopedToEnvironment(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t)

	project, err := database.CreateProject(ctx, "test", "Test")
	if err != nil {
		t.Fatalf("create project: %v", err)
	}
	prod, err := database.GetEnvironment(ctx, project.ID, DefaultEnvironment)
	if err != nil {
		t.Fatalf("get environment: %v", err)
	}
	staging, err := database.CreateEnvironment(ctx, project.ID, "staging")
	if err != nil {
		t.Fatalf("create environment: %v", err)
	}

	value, _ := mint(t, database, prod.ID, nil, time.Hour)

	if _, err := database.ConsumeToken(ctx, staging.ID, value); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-environment consume: got %v, want ErrNotFound", err)
	}
	if _, err := database.ConsumeToken(ctx, prod.ID, value); err != nil {
		t.Fatalf("same-environment consume: %v", err)
	}
}

// TestUnlimitedTokenKeepsWorking covers the maxUses = nil case, which has no
// ceiling to hit.
func TestUnlimitedTokenKeepsWorking(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t)
	envID := newTestEnv(t, database)
	value, _ := mint(t, database, envID, nil, time.Hour)

	for i := 1; i <= 5; i++ {
		consumed, err := database.ConsumeToken(ctx, envID, value)
		if err != nil {
			t.Fatalf("consume %d: %v", i, err)
		}
		if consumed.UsedCount != int64(i) {
			t.Fatalf("used count = %d, want %d", consumed.UsedCount, i)
		}
		if got := token.StatusOf(consumed, time.Now().Unix()); got != token.StatusActive {
			t.Fatalf("status = %q after use %d, want %q", got, i, token.StatusActive)
		}
	}
}

// TestInspectionDoesNotConsume: reading a token from the management side must
// never spend it.
func TestInspectionDoesNotConsume(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t)
	envID := newTestEnv(t, database)
	value, id := mint(t, database, envID, ptr(1), time.Hour)

	for i := 0; i < 3; i++ {
		if _, err := database.GetToken(ctx, envID, id); err != nil {
			t.Fatalf("get token: %v", err)
		}
		got, err := database.GetTokenValue(ctx, envID, id)
		if err != nil {
			t.Fatalf("get token value: %v", err)
		}
		if got != value {
			t.Fatal("the value returned for inspection differs from the one issued")
		}
	}

	// After three inspections it is still redeemable exactly once.
	if _, err := database.ConsumeToken(ctx, envID, value); err != nil {
		t.Fatalf("consume after inspection: %v", err)
	}
}

// TestListingsNeverCarryPlaintext guards the rule that a listing shows a prefix
// and nothing more, whatever a future change does to the columns.
func TestListingsNeverCarryPlaintext(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t)
	envID := newTestEnv(t, database)

	for i := 0; i < 3; i++ {
		mint(t, database, envID, nil, time.Hour)
	}

	tokens, _, err := database.ListTokens(ctx, envID, TokenFilter{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(tokens) != 3 {
		t.Fatalf("listed %d tokens, want 3", len(tokens))
	}
	for _, tok := range tokens {
		if tok.Value != "" {
			t.Fatal("a listing returned a plaintext token")
		}
		if tok.Prefix == "" {
			t.Fatal("a listing returned no prefix")
		}
	}

	// The same holds for a single lookup: only GetTokenValue hands one out.
	single, err := database.GetToken(ctx, envID, tokens[0].ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if single.Value != "" {
		t.Fatal("GetToken returned a plaintext token")
	}
}

// TestStatusFiltersPartitionTheSet checks that the four filters are disjoint
// and together cover everything — the property that makes the panel's chip
// counts add up to the total.
func TestStatusFiltersPartitionTheSet(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t)
	envID := newTestEnv(t, database)

	// One of each: active, expired, exhausted, revoked.
	mint(t, database, envID, nil, time.Hour)
	mint(t, database, envID, nil, -time.Minute)

	spent, _ := mint(t, database, envID, ptr(1), time.Hour)
	if _, err := database.ConsumeToken(ctx, envID, spent); err != nil {
		t.Fatalf("consume: %v", err)
	}

	_, cancelledID := mint(t, database, envID, nil, time.Hour)
	if _, err := database.RevokeToken(ctx, envID, cancelledID); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	counts, err := database.CountTokensByStatus(ctx, envID)
	if err != nil {
		t.Fatalf("count: %v", err)
	}

	var total int64
	for _, status := range token.Statuses {
		if counts[status] != 1 {
			t.Errorf("%s: counted %d, want 1", status, counts[status])
		}
		total += counts[status]
	}
	if total != 4 {
		t.Fatalf("counts sum to %d, want 4 — the filters overlap or leave a gap", total)
	}

	// And each filter returns what it counted.
	for _, status := range token.Statuses {
		listed, _, err := database.ListTokens(ctx, envID, TokenFilter{Status: status})
		if err != nil {
			t.Fatalf("list %s: %v", status, err)
		}
		if len(listed) != 1 {
			t.Fatalf("list %s returned %d rows, want 1", status, len(listed))
		}
		if got := token.StatusOf(listed[0], time.Now().Unix()); got != status {
			t.Fatalf("filter %s returned a token whose status is %s", status, got)
		}
	}
}

// TestPaginationVisitsEveryTokenOnce is the paging property that matters: with
// second-resolution timestamps, a whole page of tokens can share a created_at,
// and a cursor that ignored the id would skip or repeat rows at the boundary.
func TestPaginationVisitsEveryTokenOnce(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t)
	envID := newTestEnv(t, database)

	const count = 25
	for i := 0; i < count; i++ {
		mint(t, database, envID, nil, time.Hour)
	}

	seen := map[string]int{}
	cursor := Cursor{}
	for pages := 0; ; pages++ {
		if pages > count {
			t.Fatal("paging did not terminate")
		}

		page, next, err := database.ListTokens(ctx, envID, TokenFilter{Limit: 4, Cursor: cursor})
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		for _, tok := range page {
			seen[tok.ID]++
		}
		if !next.Set() {
			break
		}
		cursor = next
	}

	if len(seen) != count {
		t.Fatalf("paged over %d distinct tokens, want %d", len(seen), count)
	}
	for id, times := range seen {
		if times != 1 {
			t.Fatalf("token %s appeared %d times across pages", id, times)
		}
	}
}

// TestCleanupRespectsRetention checks the two windows delete what they should
// and leave alone what they should.
func TestCleanupRespectsRetention(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t)
	envID := newTestEnv(t, database)

	fresh, _ := mint(t, database, envID, nil, time.Hour)
	_, staleID := mint(t, database, envID, nil, -48*time.Hour)

	// A day of retention: the two-day-old expired token goes, the live one stays.
	cutoff := time.Now().Add(-24 * time.Hour).Unix()
	n, err := database.DeleteExpiredTokens(ctx, cutoff, 100)
	if err != nil {
		t.Fatalf("delete expired: %v", err)
	}
	if n != 1 {
		t.Fatalf("deleted %d expired tokens, want 1", n)
	}
	if _, err := database.GetToken(ctx, envID, staleID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("stale token survived: %v", err)
	}
	if _, err := database.ConsumeToken(ctx, envID, fresh); err != nil {
		t.Fatalf("live token was collateral damage: %v", err)
	}
}

// TestEventsFireAfterTheWriteLands checks the event stream, including the
// separate exhaustion event a single-use redemption produces.
func TestEventsFireAfterTheWriteLands(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t)
	envID := newTestEnv(t, database)

	var (
		mu     sync.Mutex
		events []string
	)
	database.OnTokenEvent = func(_ int64, eventType string, tok model.Token) {
		mu.Lock()
		defer mu.Unlock()
		if tok.Value != "" {
			t.Error("an event carried a plaintext token")
		}
		events = append(events, eventType)
	}

	value, id := mint(t, database, envID, ptr(1), time.Hour)
	if _, err := database.ConsumeToken(ctx, envID, value); err != nil {
		t.Fatalf("consume: %v", err)
	}
	// Revoking an already-spent token is still a revocation.
	if _, err := database.RevokeToken(ctx, envID, id); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	want := []string{
		model.EventTokenCreated,
		model.EventTokenConsumed,
		model.EventTokenExhausted,
		model.EventTokenRevoked,
	}

	mu.Lock()
	defer mu.Unlock()
	if len(events) != len(want) {
		t.Fatalf("events = %v, want %v", events, want)
	}
	for i := range want {
		if events[i] != want[i] {
			t.Fatalf("events = %v, want %v", events, want)
		}
	}
}

// TestFailedConsumeEmitsNothing: a rejected redemption is not an event. A
// receiver that acted on one would be acting on something that did not happen.
func TestFailedConsumeEmitsNothing(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t)
	envID := newTestEnv(t, database)

	value, _ := mint(t, database, envID, ptr(1), time.Hour)
	if _, err := database.ConsumeToken(ctx, envID, value); err != nil {
		t.Fatalf("consume: %v", err)
	}

	var fired int
	database.OnTokenEvent = func(int64, string, model.Token) { fired++ }

	if _, err := database.ConsumeToken(ctx, envID, value); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second consume: got %v, want ErrNotFound", err)
	}
	if fired != 0 {
		t.Fatalf("a rejected consume emitted %d events, want 0", fired)
	}
}
