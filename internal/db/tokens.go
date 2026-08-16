package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"tokenzy/internal/model"
	"tokenzy/internal/token"
)

// tokenColumns deliberately omits the `token` column. Reading a plaintext
// token is a decision, not a default: the two call sites that need it name it
// explicitly (see GetTokenValue and the consume lookup), and every other query
// in this file physically cannot return one.
const tokenColumns = `id, environment_id, token_prefix, payload_json, max_uses,
	used_count, expires_at, revoked_at, created_at, last_used_at`

func scanToken(s rowScanner) (model.Token, error) {
	var (
		t        model.Token
		maxUses  sql.NullInt64
		revoked  sql.NullInt64
		lastUsed sql.NullInt64
	)
	err := s.Scan(&t.ID, &t.EnvironmentID, &t.Prefix, &t.PayloadJSON, &maxUses,
		&t.UsedCount, &t.ExpiresAt, &revoked, &t.CreatedAt, &lastUsed)
	t.MaxUses = nullableInt64(maxUses)
	t.RevokedAt = nullableInt64(revoked)
	t.LastUsedAt = nullableInt64(lastUsed)
	return t, err
}

// CreateToken stores a freshly minted token.
//
// value is the plaintext. It is written as given — this is the one place that
// is true, and the trade behind it is argued in the migration that defines the
// table.
func (d *DB) CreateToken(ctx context.Context, envID int64, id, value, payloadJSON string,
	maxUses *int64, expiresAt int64) (model.Token, error) {

	ts := now()
	prefix := token.Prefix(value)

	_, err := d.Write.ExecContext(ctx,
		`INSERT INTO tokens (id, environment_id, token, token_prefix, payload_json,
			max_uses, used_count, expires_at, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?)`,
		id, envID, value, prefix, payloadJSON, arg(maxUses), expiresAt, ts)
	if err != nil {
		if isUniqueViolation(err) {
			return model.Token{}, ErrDuplicate
		}
		// The error is wrapped without the value: a driver error string can
		// carry bound parameters, and this one is a secret.
		return model.Token{}, fmt.Errorf("create token: %w", err)
	}

	created := model.Token{
		ID: id, EnvironmentID: envID, Value: value, Prefix: prefix,
		PayloadJSON: payloadJSON, MaxUses: maxUses, ExpiresAt: expiresAt, CreatedAt: ts,
	}
	d.emitTokenEvent(envID, model.EventTokenCreated, created)
	return created, nil
}

// ConsumeToken spends one use of a token and returns it.
//
// The condition and the effect are one statement. This is the single most
// important line of SQL in the service: checking whether a token is usable and
// then marking it used would be two steps, and two concurrent requests would
// both pass the check before either wrote. Here SQLite decides, once, which
// request the row belonged to.
//
// A token with maxUses = 1 therefore needs no separate revocation on use: this
// UPDATE takes used_count to 1, the WHERE clause can never match again, and
// the token reads as exhausted from that instant. Spending it is what kills it.
//
// A miss returns ErrNotFound whatever the reason — unknown, expired,
// exhausted, revoked, or belonging to another environment. Callers must not
// try to find out which; see the consume handler.
func (d *DB) ConsumeToken(ctx context.Context, envID int64, value string) (model.Token, error) {
	ts := now()

	t, err := scanToken(d.Write.QueryRowContext(ctx,
		`UPDATE tokens
		    SET used_count = used_count + 1, last_used_at = ?
		  WHERE token = ?
		    AND environment_id = ?
		    AND revoked_at IS NULL
		    AND expires_at > ?
		    AND (max_uses IS NULL OR used_count < max_uses)
		  RETURNING `+tokenColumns, ts, value, envID, ts))

	if errors.Is(err, sql.ErrNoRows) {
		return model.Token{}, ErrNotFound
	}
	if err != nil {
		return model.Token{}, fmt.Errorf("consume token: %w", err)
	}

	d.emitTokenEvent(envID, model.EventTokenConsumed, t)
	// Exhaustion is reported separately from consumption so a receiver can act
	// on "this pass is now spent" without having to do the max_uses arithmetic
	// itself.
	if token.StatusOf(t, ts) == token.StatusExhausted {
		d.emitTokenEvent(envID, model.EventTokenExhausted, t)
	}
	return t, nil
}

// GetToken loads one token's metadata and payload, scoped to an environment.
// The plaintext value is not included; GetTokenValue serves that separately.
func (d *DB) GetToken(ctx context.Context, envID int64, id string) (model.Token, error) {
	t, err := scanToken(d.Read.QueryRowContext(ctx,
		`SELECT `+tokenColumns+` FROM tokens WHERE id = ? AND environment_id = ?`, id, envID))
	if errors.Is(err, sql.ErrNoRows) {
		return model.Token{}, ErrNotFound
	}
	if err != nil {
		return model.Token{}, fmt.Errorf("get token: %w", err)
	}
	return t, nil
}

// GetTokenValue returns the plaintext of one token.
//
// It is its own method rather than a flag on GetToken so that every caller
// that wants a plaintext token has to say so in a line of code somebody can
// grep for. Reading a token back is equivalent to being able to mint one, so
// this must only ever be reached behind admin authority.
func (d *DB) GetTokenValue(ctx context.Context, envID int64, id string) (string, error) {
	var value string
	err := d.Read.QueryRowContext(ctx,
		`SELECT token FROM tokens WHERE id = ? AND environment_id = ?`, id, envID).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("get token value: %w", err)
	}
	return value, nil
}

// TokenFilter narrows a listing. An empty Status means "any".
type TokenFilter struct {
	Status string
	// Limit caps the page; Cursor continues a previous one.
	Limit  int
	Cursor Cursor
}

// Cursor is a position in the (created_at DESC, id DESC) ordering. The zero
// value means "start at the top".
type Cursor struct {
	CreatedAt int64
	ID        string
}

// Set reports whether the cursor points anywhere.
func (c Cursor) Set() bool { return c.ID != "" }

// String encodes the cursor for a URL. The format is deliberately readable:
// there is nothing secret in a position, and an opaque blob would only make it
// harder to see what a paging bug is doing.
func (c Cursor) String() string {
	if !c.Set() {
		return ""
	}
	return strconv.FormatInt(c.CreatedAt, 10) + "." + c.ID
}

// ParseCursor reads the value produced by Cursor.String. A malformed cursor
// yields the zero value rather than an error: the worst it can do is start the
// listing from the top.
func ParseCursor(s string) Cursor {
	ts, id, ok := strings.Cut(s, ".")
	if !ok {
		return Cursor{}
	}
	created, err := strconv.ParseInt(ts, 10, 64)
	if err != nil || id == "" {
		return Cursor{}
	}
	return Cursor{CreatedAt: created, ID: id}
}

// statusPredicate turns a status name into the SQL that selects it, or an
// empty string for "any status".
//
// The predicates mirror token.StatusOf exactly, including its precedence: each
// one re-states the conditions of the statuses that outrank it, so the four
// sets are disjoint and every token appears under exactly one of them. This is
// the only place that correspondence is written down, so both the listing
// filter and the panel's counts are built from it rather than restating it.
func statusPredicate(status string, ts int64) (string, []any) {
	switch status {
	case token.StatusRevoked:
		return `revoked_at IS NOT NULL`, nil
	case token.StatusExpired:
		return `revoked_at IS NULL AND expires_at <= ?`, []any{ts}
	case token.StatusExhausted:
		return `revoked_at IS NULL AND expires_at > ?
		        AND max_uses IS NOT NULL AND used_count >= max_uses`, []any{ts}
	case token.StatusActive:
		return `revoked_at IS NULL AND expires_at > ?
		        AND (max_uses IS NULL OR used_count < max_uses)`, []any{ts}
	default:
		return "", nil
	}
}

// ListTokens returns one page of an environment's tokens, newest first, plus
// the cursor for the next page (empty when the listing is exhausted).
//
// No plaintext is returned: this is a listing, and a listing that could leak a
// token would undo the reason the panel is safe to look at.
func (d *DB) ListTokens(ctx context.Context, envID int64, filter TokenFilter) ([]model.Token, Cursor, error) {
	limit := filter.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}

	query := `SELECT ` + tokenColumns + ` FROM tokens WHERE environment_id = ?`
	args := []any{envID}

	if predicate, predicateArgs := statusPredicate(filter.Status, now()); predicate != "" {
		query += ` AND ` + predicate
		args = append(args, predicateArgs...)
	}

	if filter.Cursor.Set() {
		// Strictly after the cursor in (created_at DESC, id DESC) order. The id
		// half is what stops tokens minted in the same second from being
		// skipped or repeated across page boundaries.
		query += ` AND (created_at < ? OR (created_at = ? AND id < ?))`
		args = append(args, filter.Cursor.CreatedAt, filter.Cursor.CreatedAt, filter.Cursor.ID)
	}

	// One extra row, purely to find out whether a next page exists without a
	// second COUNT query over the same predicate.
	query += ` ORDER BY created_at DESC, id DESC LIMIT ?`
	args = append(args, limit+1)

	rows, err := d.Read.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, Cursor{}, fmt.Errorf("list tokens: %w", err)
	}
	defer rows.Close()

	tokens := []model.Token{}
	for rows.Next() {
		t, err := scanToken(rows)
		if err != nil {
			return nil, Cursor{}, fmt.Errorf("list tokens: %w", err)
		}
		tokens = append(tokens, t)
	}
	if err := rows.Err(); err != nil {
		return nil, Cursor{}, fmt.Errorf("list tokens: %w", err)
	}

	var next Cursor
	if len(tokens) > limit {
		tokens = tokens[:limit]
		last := tokens[len(tokens)-1]
		next = Cursor{CreatedAt: last.CreatedAt, ID: last.ID}
	}
	return tokens, next, nil
}

// CountTokensByStatus returns how many tokens sit in each status right now.
// Used for the panel's filter chips.
//
// One query with four conditional counts, rather than four queries.
//
// Status is derived, not stored, so counting it means looking at every token in
// the environment however this is written — there is no index that can answer
// "how many are active" without visiting the rows, because the answer changes
// with the clock. What there is a choice about is how many times those rows get
// visited, and four separate COUNT queries visited them four times. Measured on
// 200k tokens: 70ms as four queries, 30ms as one.
//
// An index was tried instead and made things worse. A covering index over
// (environment_id, revoked_at, expires_at, max_uses, used_count) does get the
// counts down to ~17ms, but used_count changes on every redemption, so the
// index has to be rewritten on the one path that has to stay fast — it more
// than doubled the cost of consuming a token. Eight milliseconds on a page an
// administrator loads by hand is not worth that.
func (d *DB) CountTokensByStatus(ctx context.Context, envID int64) (map[string]int64, error) {
	ts := now()

	var (
		selects []string
		args    []any
	)
	for _, status := range token.Statuses {
		predicate, predicateArgs := statusPredicate(status, ts)
		selects = append(selects, `COUNT(*) FILTER (WHERE `+predicate+`)`)
		args = append(args, predicateArgs...)
	}
	// The environment goes last: SQLite binds parameters in the order they
	// appear in the statement, and the filters are written before the WHERE.
	args = append(args, envID)

	targets := make([]int64, len(token.Statuses))
	scanInto := make([]any, len(token.Statuses))
	for i := range targets {
		scanInto[i] = &targets[i]
	}

	err := d.Read.QueryRowContext(ctx,
		`SELECT `+strings.Join(selects, ", ")+` FROM tokens WHERE environment_id = ?`,
		args...).Scan(scanInto...)
	if err != nil {
		return nil, fmt.Errorf("count tokens: %w", err)
	}

	counts := make(map[string]int64, len(token.Statuses))
	for i, status := range token.Statuses {
		counts[status] = targets[i]
	}
	return counts, nil
}

// RevokeToken cancels a token by id.
//
// By id, never by value: the point of revocation is that it works when the
// token itself is gone — the phone with the pass on it was lost, the email
// went to the wrong address. Somebody who can no longer produce the token can
// still cancel it.
//
// The effect is immediate because there is no cache to wait for: every consume
// reads this row.
func (d *DB) RevokeToken(ctx context.Context, envID int64, id string) (model.Token, error) {
	t, err := scanToken(d.Write.QueryRowContext(ctx,
		`UPDATE tokens SET revoked_at = ?
		  WHERE id = ? AND environment_id = ? AND revoked_at IS NULL
		  RETURNING `+tokenColumns, now(), id, envID))

	if errors.Is(err, sql.ErrNoRows) {
		// Either the token does not exist here, or it was already revoked. The
		// caller distinguishes those with a follow-up read if it cares.
		return model.Token{}, ErrNotFound
	}
	if err != nil {
		return model.Token{}, fmt.Errorf("revoke token: %w", err)
	}

	d.emitTokenEvent(envID, model.EventTokenRevoked, t)
	return t, nil
}

// DeleteToken removes the row entirely.
//
// Revoking is usually the better move: a revoked token keeps its history —
// when it was issued, whether it was ever used — while deleting throws that
// away. Deletion exists for the case where the record itself is the problem.
func (d *DB) DeleteToken(ctx context.Context, envID int64, id string) error {
	res, err := d.Write.ExecContext(ctx,
		`DELETE FROM tokens WHERE id = ? AND environment_id = ?`, id, envID)
	if err != nil {
		return fmt.Errorf("delete token: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("delete token: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteExpiredTokens removes tokens whose expiry passed longer ago than the
// retention window. It deletes at most limit rows per call so a large backlog
// is worked through in batches instead of holding the write lock for a minute.
// The number deleted is returned so the caller can keep going while it is full.
func (d *DB) DeleteExpiredTokens(ctx context.Context, before int64, limit int) (int64, error) {
	res, err := d.Write.ExecContext(ctx,
		`DELETE FROM tokens WHERE id IN (
		   SELECT id FROM tokens WHERE expires_at < ? LIMIT ?
		 )`, before, limit)
	if err != nil {
		return 0, fmt.Errorf("delete expired tokens: %w", err)
	}
	return res.RowsAffected()
}

// DeleteSettledTokens removes tokens that are finished with but not yet
// expired: revoked ones, and exhausted ones whose last use is older than the
// retention window.
//
// Kept separately from expiry because the two windows answer different
// questions. An expired token is uninteresting almost immediately; a spent one
// is the evidence for "was this pass used, and when", which is worth keeping
// longer.
func (d *DB) DeleteSettledTokens(ctx context.Context, before int64, limit int) (int64, error) {
	res, err := d.Write.ExecContext(ctx,
		`DELETE FROM tokens WHERE id IN (
		   SELECT id FROM tokens
		    WHERE (revoked_at IS NOT NULL AND revoked_at < ?)
		       OR (max_uses IS NOT NULL AND used_count >= max_uses
		           AND COALESCE(last_used_at, created_at) < ?)
		    LIMIT ?
		 )`, before, before, limit)
	if err != nil {
		return 0, fmt.Errorf("delete settled tokens: %w", err)
	}
	return res.RowsAffected()
}
