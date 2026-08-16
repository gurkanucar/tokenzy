package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"tokenzy/internal/model"
)

// CountUsers returns how many admin accounts exist.
func (d *DB) CountUsers(ctx context.Context) (int, error) {
	var n int
	err := d.Read.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count users: %w", err)
	}
	return n, nil
}

// CreateUser inserts an admin account. Returns ErrDuplicate if the username is
// taken.
func (d *DB) CreateUser(ctx context.Context, username, passwordHash string) (model.User, error) {
	ts := now()
	res, err := d.Write.ExecContext(ctx,
		`INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)`,
		username, passwordHash, ts)
	if err != nil {
		if isUniqueViolation(err) {
			return model.User{}, ErrDuplicate
		}
		return model.User{}, fmt.Errorf("create user: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return model.User{}, fmt.Errorf("create user: %w", err)
	}
	return model.User{ID: id, Username: username, PasswordHash: passwordHash, CreatedAt: ts}, nil
}

// SetUserPassword replaces the stored hash for an existing account.
func (d *DB) SetUserPassword(ctx context.Context, username, passwordHash string) error {
	res, err := d.Write.ExecContext(ctx,
		`UPDATE users SET password_hash = ? WHERE username = ?`, passwordHash, username)
	if err != nil {
		return fmt.Errorf("set password: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("set password: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// GetUserByUsername looks an account up for login.
func (d *DB) GetUserByUsername(ctx context.Context, username string) (model.User, error) {
	var u model.User
	err := d.Read.QueryRowContext(ctx,
		`SELECT id, username, password_hash, created_at FROM users WHERE username = ?`, username).
		Scan(&u.ID, &u.Username, &u.PasswordHash, &u.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return model.User{}, ErrNotFound
	}
	if err != nil {
		return model.User{}, fmt.Errorf("get user: %w", err)
	}
	return u, nil
}

// GetUserByID resolves the user behind a session.
func (d *DB) GetUserByID(ctx context.Context, id int64) (model.User, error) {
	var u model.User
	err := d.Read.QueryRowContext(ctx,
		`SELECT id, username, password_hash, created_at FROM users WHERE id = ?`, id).
		Scan(&u.ID, &u.Username, &u.PasswordHash, &u.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return model.User{}, ErrNotFound
	}
	if err != nil {
		return model.User{}, fmt.Errorf("get user: %w", err)
	}
	return u, nil
}

// CreateSession stores a browser session.
func (d *DB) CreateSession(ctx context.Context, id string, userID, expiresAt int64) error {
	_, err := d.Write.ExecContext(ctx,
		`INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)`, id, userID, expiresAt)
	if err != nil {
		return fmt.Errorf("create session: %w", err)
	}
	return nil
}

// GetSession returns a session by id without checking expiry; callers compare
// ExpiresAt themselves.
func (d *DB) GetSession(ctx context.Context, id string) (model.Session, error) {
	var s model.Session
	err := d.Read.QueryRowContext(ctx,
		`SELECT id, user_id, expires_at FROM sessions WHERE id = ?`, id).
		Scan(&s.ID, &s.UserID, &s.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Session{}, ErrNotFound
	}
	if err != nil {
		return model.Session{}, fmt.Errorf("get session: %w", err)
	}
	return s, nil
}

// DeleteSession logs a session out.
func (d *DB) DeleteSession(ctx context.Context, id string) error {
	_, err := d.Write.ExecContext(ctx, `DELETE FROM sessions WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete session: %w", err)
	}
	return nil
}

// DeleteExpiredSessions clears sessions that are past their expiry.
func (d *DB) DeleteExpiredSessions(ctx context.Context) error {
	_, err := d.Write.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at < ?`, now())
	if err != nil {
		return fmt.Errorf("prune sessions: %w", err)
	}
	return nil
}
