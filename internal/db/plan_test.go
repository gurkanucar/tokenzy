package db

import (
	"context"
	"strings"
	"testing"
)

// queryPlan returns SQLite's plan for a statement, one line per step.
func queryPlan(t *testing.T, database *DB, sql string, args ...any) []string {
	t.Helper()

	rows, err := database.Read.QueryContext(context.Background(), "EXPLAIN QUERY PLAN "+sql, args...)
	if err != nil {
		t.Fatalf("explain: %v\nquery: %s", err, sql)
	}
	defer rows.Close()

	var plan []string
	for rows.Next() {
		var id, parent, notUsed int
		var detail string
		if err := rows.Scan(&id, &parent, &notUsed, &detail); err != nil {
			t.Fatalf("scan plan: %v", err)
		}
		plan = append(plan, detail)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("explain: %v", err)
	}
	return plan
}

// TestHotQueriesUseIndexes pins the plans of the queries whose cost grows with
// the size of the table and where an index was measured to help.
//
// The failures this catches are the quiet kind. Nothing breaks when an index
// stops being used — the answers stay correct, the tests stay green, and the
// service just gets slower in proportion to how much data somebody put in it.
//
// Note what this test does NOT assert, because getting that wrong is how the
// indexes in this package were nearly made worse. A SCAN in a query plan is not
// a bug by itself, and neither is a temp b-tree. Both were treated as bugs
// here at one point, indexes were added to remove them, and measurement against
// a 200k-row table showed the result was slower across the board. The list
// below is the set of queries where an index was measured to pay; the ones that
// still scan are documented in TestKnownTableScans.
func TestHotQueriesUseIndexes(t *testing.T) {
	database := newTestDB(t)
	const now = 1786880000

	cases := []struct {
		name string
		sql  string
		args []any
		// want is a fragment the plan must contain, naming the access this
		// query depends on.
		want string
	}{
		{
			// The one that has to be fastest: every redemption starts here, and
			// it must resolve to a single row by the unique index on the token.
			// Anything else means the hot path became a range scan.
			name: "consume",
			sql: `UPDATE tokens SET used_count = used_count + 1, last_used_at = ?
			       WHERE token = ? AND environment_id = ? AND revoked_at IS NULL
			         AND expires_at > ? AND (max_uses IS NULL OR used_count < max_uses)`,
			args: []any{now, "tkn_x", 1, now},
			want: "token=?",
		},
		{
			// Runs on every authenticated request in the service.
			name: "api key lookup",
			sql:  `SELECT id FROM api_keys WHERE key_hash = ? AND revoked_at IS NULL`,
			args: []any{"hash"},
			want: "key_hash=?",
		},
		{
			// Must seek straight to the environment. A scan here would read
			// every token in the database to render one page.
			name: "token listing",
			sql: `SELECT id FROM tokens WHERE environment_id = ?
			       ORDER BY created_at DESC, id DESC LIMIT ?`,
			args: []any{1, 26},
			want: "idx_tokens_env_created",
		},
		{
			name: "status counts",
			sql: `SELECT COUNT(*) FILTER (WHERE revoked_at IS NOT NULL),
			             COUNT(*) FILTER (WHERE revoked_at IS NULL AND expires_at <= ?)
			        FROM tokens WHERE environment_id = ?`,
			args: []any{now, 1},
			want: "idx_tokens_env_created",
		},
		{
			name: "cleanup: expired tokens",
			sql:  `SELECT id FROM tokens WHERE expires_at < ? LIMIT ?`,
			args: []any{now, 1000},
			want: "idx_tokens_expires",
		},
		{
			// The retry queue. Its partial index is what keeps this the size of
			// the backlog rather than the size of the delivery history.
			name: "webhook: due deliveries",
			sql: `SELECT id FROM webhook_deliveries
			       WHERE delivered_at IS NULL AND next_retry_at IS NOT NULL AND next_retry_at <= ?
			       ORDER BY next_retry_at ASC, id ASC LIMIT ?`,
			args: []any{now, 50},
			want: "idx_webhook_deliveries_due",
		},
		{
			name: "webhook: delivery history",
			sql: `SELECT id FROM webhook_deliveries WHERE webhook_id = ?
			       ORDER BY created_at DESC, id DESC LIMIT ?`,
			args: []any{1, 20},
			want: "idx_webhook_deliveries_hook",
		},
		{
			// Measured at 16ms of the single write connection per sweep without
			// this index, and 0.0ms with it. See migration 004.
			name: "cleanup: old deliveries",
			sql: `SELECT id FROM webhook_deliveries
			       WHERE created_at < ? AND (delivered_at IS NOT NULL OR next_retry_at IS NULL) LIMIT ?`,
			args: []any{now, 1000},
			want: "idx_webhook_deliveries_created",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			plan := queryPlan(t, database, tc.sql, tc.args...)
			joined := strings.Join(plan, "\n  ")

			if !strings.Contains(joined, tc.want) {
				t.Errorf("plan does not use %q:\n  %s", tc.want, joined)
			}
			for _, step := range plan {
				if strings.HasPrefix(strings.TrimSpace(step), "SCAN") {
					t.Errorf("reads the whole table:\n  %s", joined)
					break
				}
			}
		})
	}
}

// TestKnownTableScans records the queries that do scan a table, so that the
// list is a decision somebody made rather than something nobody noticed.
//
// Both were measured with indexes that removed the scan, and both were slower
// that way. The test asserts they still scan — not because scanning is good,
// but so that anyone who changes it has to come here, read why, and measure
// again rather than trusting the query plan the way it was trusted the first
// time.
func TestKnownTableScans(t *testing.T) {
	database := newTestDB(t)
	const now = 1786880000

	cases := []struct {
		name   string
		sql    string
		args   []any
		reason string
	}{
		{
			name: "cleanup: settled tokens",
			sql: `SELECT id FROM tokens
			       WHERE (revoked_at IS NOT NULL AND revoked_at < ?)
			          OR (max_uses IS NOT NULL AND used_count >= max_uses
			              AND COALESCE(last_used_at, created_at) < ?) LIMIT ?`,
			args: []any{now, now, 1000},
			// Partial indexes on revoked_at and on the spent expression turn
			// this into a MULTI-INDEX OR, which measured slower on 200k rows
			// (19ms against 14ms): the union of two index scans costs more than
			// one linear pass, and the LIMIT means a pass usually stops early.
			reason: "a MULTI-INDEX OR over two partial indexes measured slower than the scan",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			plan := queryPlan(t, database, tc.sql, tc.args...)
			joined := strings.Join(plan, "\n  ")

			scans := false
			for _, step := range plan {
				if strings.HasPrefix(strings.TrimSpace(step), "SCAN") {
					scans = true
				}
			}
			if !scans {
				t.Errorf("this query no longer scans, which may well be an "+
					"improvement — but it was left scanning on purpose (%s). "+
					"Re-measure before updating this test.\n  %s", tc.reason, joined)
			}
		})
	}
}
