package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"tokenzy/internal/model"
	"tokenzy/internal/otp"
)

// otpColumns deliberately omits the `code` column, for the same reason the
// token columns omit the token: reading a secret is a decision, not a default.
// The two call sites that need it name it explicitly.
const otpColumns = `id, environment_id, type, identifier, attempt_count, max_attempts,
	expires_at, consumed_at, revoked_at, created_at`

func scanOTP(s rowScanner) (model.OTP, error) {
	var (
		o        model.OTP
		consumed sql.NullInt64
		revoked  sql.NullInt64
	)
	err := s.Scan(&o.ID, &o.EnvironmentID, &o.Type, &o.Identifier, &o.AttemptCount,
		&o.MaxAttempts, &o.ExpiresAt, &consumed, &revoked, &o.CreatedAt)
	o.ConsumedAt = nullableInt64(consumed)
	o.RevokedAt = nullableInt64(revoked)
	return o, err
}

// OTPRequest is one issuance.
type OTPRequest struct {
	Type        string
	Identifier  string
	Code        string
	MaxAttempts int64
	ExpiresAt   int64
}

// GenerateOTP issues a code, or hands back the one already outstanding.
//
// The rule it keeps is "at most one live code per (environment, type,
// identifier)", and the reason is the resend button. When somebody presses
// "send it again", they must receive the code they were already given — two
// different live codes for one password reset is a user staring at two SMS
// messages wondering which one the site wants. So a second call while a code is
// still alive returns that code and reports reused.
//
// Deliberately, a resend does not extend the lifetime. If it did, pressing the
// button often enough would keep a code alive indefinitely, which is the one
// property a short-lived secret must not have.
//
// The read and the write are one transaction on the single write connection,
// so two simultaneous requests for the same identifier cannot both decide the
// field is empty and both insert. The second waits, sees the first one's row,
// and reuses it.
func (d *DB) GenerateOTP(ctx context.Context, envID int64, id string, req OTPRequest) (model.OTP, bool, error) {
	ts := now()

	tx, err := d.Write.BeginTx(ctx, nil)
	if err != nil {
		return model.OTP{}, false, fmt.Errorf("generate otp: %w", err)
	}
	defer tx.Rollback()

	// An existing code counts as reusable only while it is genuinely usable:
	// not spent, not cancelled, not expired, and not already locked out. A
	// locked code is not handed back — that would let anyone reset nothing and
	// receive a code with no attempts left on it.
	existing, err := scanOTP(tx.QueryRowContext(ctx,
		`SELECT `+otpColumns+` FROM otps
		  WHERE environment_id = ? AND type = ? AND identifier = ?
		    AND consumed_at IS NULL AND revoked_at IS NULL
		    AND expires_at > ? AND attempt_count < max_attempts
		  ORDER BY created_at DESC, id DESC LIMIT 1`,
		envID, req.Type, req.Identifier, ts))

	switch {
	case err == nil:
		code, err := d.otpCodeTx(ctx, tx, existing.ID)
		if err != nil {
			return model.OTP{}, false, err
		}
		if err := tx.Commit(); err != nil {
			return model.OTP{}, false, fmt.Errorf("generate otp: %w", err)
		}
		existing.Code = code
		return existing, true, nil

	case !errors.Is(err, sql.ErrNoRows):
		return model.OTP{}, false, fmt.Errorf("generate otp: %w", err)
	}

	_, err = tx.ExecContext(ctx,
		`INSERT INTO otps (id, environment_id, type, identifier, code,
			attempt_count, max_attempts, expires_at, created_at)
		 VALUES (?, ?, ?, ?, ?, 0, ?, ?, ?)`,
		id, envID, req.Type, req.Identifier, req.Code, req.MaxAttempts, req.ExpiresAt, ts)
	if err != nil {
		// Wrapped without the row's values: a driver error can carry bound
		// parameters, and two of these are a secret and an email address.
		return model.OTP{}, false, fmt.Errorf("generate otp: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return model.OTP{}, false, fmt.Errorf("generate otp: %w", err)
	}

	return model.OTP{
		ID: id, EnvironmentID: envID, Type: req.Type, Identifier: req.Identifier,
		Code: req.Code, MaxAttempts: req.MaxAttempts, ExpiresAt: req.ExpiresAt,
		CreatedAt: ts,
	}, false, nil
}

func (d *DB) otpCodeTx(ctx context.Context, tx *sql.Tx, id string) (string, error) {
	var code string
	if err := tx.QueryRowContext(ctx, `SELECT code FROM otps WHERE id = ?`, id).Scan(&code); err != nil {
		return "", fmt.Errorf("read otp code: %w", err)
	}
	return code, nil
}

// ValidateOTP checks a code and, if it is right, spends it.
//
// Two statements, one transaction.
//
// The first is the same shape as the token consume: the condition and the
// effect together, so that two simultaneous requests carrying the right code
// cannot both succeed. Setting consumed_at is what kills the code — there is no
// separate "expire it now" step, because the successful validation *is* the
// expiry.
//
// The second is what the whole module exists for. If the first matched nothing,
// somebody guessed wrong, and the attempt is counted against the live code for
// that identifier. When the count reaches the ceiling the code stops being
// usable even by whoever has it right — a six-digit space is small enough that
// this is the only thing making it safe.
//
// Note which statement counts the attempt: the *second*. A correct code costs
// nothing, so a legitimate user who fumbles once and then succeeds is not
// penalised for the successful try.
func (d *DB) ValidateOTP(ctx context.Context, envID int64, otpType, identifier, code string) (model.OTP, error) {
	ts := now()

	tx, err := d.Write.BeginTx(ctx, nil)
	if err != nil {
		return model.OTP{}, fmt.Errorf("validate otp: %w", err)
	}
	defer tx.Rollback()

	consumed, err := scanOTP(tx.QueryRowContext(ctx,
		`UPDATE otps SET consumed_at = ?
		  WHERE environment_id = ? AND type = ? AND identifier = ? AND code = ?
		    AND consumed_at IS NULL
		    AND revoked_at IS NULL
		    AND expires_at > ?
		    AND attempt_count < max_attempts
		  RETURNING `+otpColumns,
		ts, envID, otpType, identifier, code, ts))

	if err == nil {
		if err := tx.Commit(); err != nil {
			return model.OTP{}, fmt.Errorf("validate otp: %w", err)
		}
		return consumed, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return model.OTP{}, fmt.Errorf("validate otp: %w", err)
	}

	// Wrong code, or there was nothing live to match. Count it against whatever
	// is live for this identifier; if nothing is, this updates no rows and
	// there was nothing to protect anyway.
	//
	// The ceiling is repeated in the WHERE so the counter stops at it rather
	// than running past — a code showing "9 of 5 attempts" would be reporting
	// something that cannot happen.
	_, err = tx.ExecContext(ctx,
		`UPDATE otps SET attempt_count = attempt_count + 1
		  WHERE environment_id = ? AND type = ? AND identifier = ?
		    AND consumed_at IS NULL AND revoked_at IS NULL
		    AND expires_at > ? AND attempt_count < max_attempts`,
		envID, otpType, identifier, ts)
	if err != nil {
		return model.OTP{}, fmt.Errorf("validate otp: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return model.OTP{}, fmt.Errorf("validate otp: %w", err)
	}

	return model.OTP{}, ErrNotFound
}

// GetOTP loads one code's metadata, scoped to an environment. The code itself
// is not included; GetOTPCode serves that separately.
func (d *DB) GetOTP(ctx context.Context, envID int64, id string) (model.OTP, error) {
	o, err := scanOTP(d.Read.QueryRowContext(ctx,
		`SELECT `+otpColumns+` FROM otps WHERE id = ? AND environment_id = ?`, id, envID))
	if errors.Is(err, sql.ErrNoRows) {
		return model.OTP{}, ErrNotFound
	}
	if err != nil {
		return model.OTP{}, fmt.Errorf("get otp: %w", err)
	}
	return o, nil
}

// GetOTPCode returns the plaintext code.
//
// Its own method, so that every caller wanting a code has to say so in a line
// somebody can grep for.
func (d *DB) GetOTPCode(ctx context.Context, envID int64, id string) (string, error) {
	var code string
	err := d.Read.QueryRowContext(ctx,
		`SELECT code FROM otps WHERE id = ? AND environment_id = ?`, id, envID).Scan(&code)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("get otp code: %w", err)
	}
	return code, nil
}

// OTPFilter narrows a listing.
type OTPFilter struct {
	Status string
	Type   string
	// Identifier matches as a substring, which is what makes the panel's
	// search box useful for "everything sent to this person".
	Identifier string
	Limit      int
	Cursor     Cursor
}

// otpStatusPredicate turns a status name into the SQL that selects it.
//
// Mirrors otp.StatusOf exactly, including its precedence: each predicate
// restates the conditions of the statuses that outrank it, so the five sets are
// disjoint and every code appears under exactly one of them.
func otpStatusPredicate(status string, ts int64) (string, []any) {
	switch status {
	case otp.StatusRevoked:
		return `revoked_at IS NOT NULL`, nil
	case otp.StatusConsumed:
		return `revoked_at IS NULL AND consumed_at IS NOT NULL`, nil
	case otp.StatusExpired:
		return `revoked_at IS NULL AND consumed_at IS NULL AND expires_at <= ?`, []any{ts}
	case otp.StatusLocked:
		return `revoked_at IS NULL AND consumed_at IS NULL AND expires_at > ?
		        AND attempt_count >= max_attempts`, []any{ts}
	case otp.StatusActive:
		return `revoked_at IS NULL AND consumed_at IS NULL AND expires_at > ?
		        AND attempt_count < max_attempts`, []any{ts}
	default:
		return "", nil
	}
}

// ListOTPs returns one page of an environment's codes, newest first, plus the
// cursor for the next page. No plaintext code is returned.
func (d *DB) ListOTPs(ctx context.Context, envID int64, filter OTPFilter) ([]model.OTP, Cursor, error) {
	limit := filter.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}

	query := `SELECT ` + otpColumns + ` FROM otps WHERE environment_id = ?`
	args := []any{envID}

	if predicate, predicateArgs := otpStatusPredicate(filter.Status, now()); predicate != "" {
		query += ` AND ` + predicate
		args = append(args, predicateArgs...)
	}
	if filter.Type != "" {
		query += ` AND type = ?`
		args = append(args, filter.Type)
	}
	if filter.Identifier != "" {
		query += ` AND identifier LIKE ? ESCAPE '\'`
		args = append(args, "%"+escapeLike(filter.Identifier)+"%")
	}

	if filter.Cursor.Set() {
		query += ` AND (created_at < ? OR (created_at = ? AND id < ?))`
		args = append(args, filter.Cursor.CreatedAt, filter.Cursor.CreatedAt, filter.Cursor.ID)
	}

	query += ` ORDER BY created_at DESC, id DESC LIMIT ?`
	args = append(args, limit+1)

	rows, err := d.Read.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, Cursor{}, fmt.Errorf("list otps: %w", err)
	}
	defer rows.Close()

	otps := []model.OTP{}
	for rows.Next() {
		o, err := scanOTP(rows)
		if err != nil {
			return nil, Cursor{}, fmt.Errorf("list otps: %w", err)
		}
		otps = append(otps, o)
	}
	if err := rows.Err(); err != nil {
		return nil, Cursor{}, fmt.Errorf("list otps: %w", err)
	}

	var next Cursor
	if len(otps) > limit {
		otps = otps[:limit]
		last := otps[len(otps)-1]
		next = Cursor{CreatedAt: last.CreatedAt, ID: last.ID}
	}
	return otps, next, nil
}

// escapeLike neutralises the wildcards in a user-typed search term, so that a
// search for "%" means the character rather than "everything".
func escapeLike(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(s)
}

// CountOTPsByStatus returns how many codes sit in each status right now, in one
// pass rather than one query per status. See CountTokensByStatus for why.
func (d *DB) CountOTPsByStatus(ctx context.Context, envID int64) (map[string]int64, error) {
	ts := now()

	var (
		selects []string
		args    []any
	)
	for _, status := range otp.Statuses {
		predicate, predicateArgs := otpStatusPredicate(status, ts)
		selects = append(selects, `COUNT(*) FILTER (WHERE `+predicate+`)`)
		args = append(args, predicateArgs...)
	}
	args = append(args, envID)

	targets := make([]int64, len(otp.Statuses))
	scanInto := make([]any, len(otp.Statuses))
	for i := range targets {
		scanInto[i] = &targets[i]
	}

	err := d.Read.QueryRowContext(ctx,
		`SELECT `+strings.Join(selects, ", ")+` FROM otps WHERE environment_id = ?`,
		args...).Scan(scanInto...)
	if err != nil {
		return nil, fmt.Errorf("count otps: %w", err)
	}

	counts := make(map[string]int64, len(otp.Statuses))
	for i, status := range otp.Statuses {
		counts[status] = targets[i]
	}
	return counts, nil
}

// ListOTPTypes returns the distinct type labels in use, for the panel's filter.
func (d *DB) ListOTPTypes(ctx context.Context, envID int64) ([]string, error) {
	rows, err := d.Read.QueryContext(ctx,
		`SELECT DISTINCT type FROM otps WHERE environment_id = ? ORDER BY type ASC`, envID)
	if err != nil {
		return nil, fmt.Errorf("list otp types: %w", err)
	}
	defer rows.Close()

	types := []string{}
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			return nil, fmt.Errorf("list otp types: %w", err)
		}
		types = append(types, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list otp types: %w", err)
	}
	return types, nil
}

// RevokeOTP cancels a code by id — by id, not by code, so that a support agent
// can kill a code they were never shown.
func (d *DB) RevokeOTP(ctx context.Context, envID int64, id string) (model.OTP, error) {
	o, err := scanOTP(d.Write.QueryRowContext(ctx,
		`UPDATE otps SET revoked_at = ?
		  WHERE id = ? AND environment_id = ? AND revoked_at IS NULL
		  RETURNING `+otpColumns, now(), id, envID))

	if errors.Is(err, sql.ErrNoRows) {
		return model.OTP{}, ErrNotFound
	}
	if err != nil {
		return model.OTP{}, fmt.Errorf("revoke otp: %w", err)
	}
	return o, nil
}

// DeleteOTP removes the row entirely.
func (d *DB) DeleteOTP(ctx context.Context, envID int64, id string) error {
	res, err := d.Write.ExecContext(ctx,
		`DELETE FROM otps WHERE id = ? AND environment_id = ?`, id, envID)
	if err != nil {
		return fmt.Errorf("delete otp: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("delete otp: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteDeadOTPs removes codes that can no longer be used and are older than
// the retention window.
//
// This matters more than the token sweep. A row here holds a plaintext secret
// *and* an identifier that is usually an email address or a phone number — so
// keeping a spent code around is keeping personal data for no reason. Which is
// why the retention window on this table is measured in hours.
func (d *DB) DeleteDeadOTPs(ctx context.Context, before int64, limit int) (int64, error) {
	res, err := d.Write.ExecContext(ctx,
		`DELETE FROM otps WHERE id IN (
		   SELECT id FROM otps
		    WHERE expires_at < ?
		       OR (consumed_at IS NOT NULL AND consumed_at < ?)
		       OR (revoked_at IS NOT NULL AND revoked_at < ?)
		    LIMIT ?
		 )`, before, before, before, limit)
	if err != nil {
		return 0, fmt.Errorf("delete dead otps: %w", err)
	}
	return res.RowsAffected()
}
