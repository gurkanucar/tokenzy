package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"tokenzy/internal/model"
)

const apiKeyColumns = `id, environment_id, key_hash, key_prefix, scope, label, created_at, revoked_at`

func scanAPIKey(s rowScanner) (model.APIKey, error) {
	var (
		k       model.APIKey
		revoked sql.NullInt64
	)
	err := s.Scan(&k.ID, &k.EnvironmentID, &k.KeyHash, &k.KeyPrefix, &k.Scope, &k.Label,
		&k.CreatedAt, &revoked)
	k.RevokedAt = nullableInt64(revoked)
	return k, err
}

// CreateAPIKey stores the hash of a freshly generated key. The plaintext never
// reaches this layer.
func (d *DB) CreateAPIKey(ctx context.Context, envID int64, keyHash, keyPrefix, scope, label string) (model.APIKey, error) {
	ts := now()
	res, err := d.Write.ExecContext(ctx,
		`INSERT INTO api_keys (environment_id, key_hash, key_prefix, scope, label, created_at)
		 VALUES (?, ?, ?, ?, ?, ?)`, envID, keyHash, keyPrefix, scope, label, ts)
	if err != nil {
		if isUniqueViolation(err) {
			return model.APIKey{}, ErrDuplicate
		}
		return model.APIKey{}, fmt.Errorf("create api key: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return model.APIKey{}, fmt.Errorf("create api key: %w", err)
	}
	return model.APIKey{
		ID: id, EnvironmentID: envID, KeyHash: keyHash, KeyPrefix: keyPrefix,
		Scope: scope, Label: label, CreatedAt: ts,
	}, nil
}

// ListAPIKeys returns every key for an environment, active ones first.
func (d *DB) ListAPIKeys(ctx context.Context, envID int64) ([]model.APIKey, error) {
	rows, err := d.Read.QueryContext(ctx,
		`SELECT `+apiKeyColumns+` FROM api_keys WHERE environment_id = ?
		 ORDER BY revoked_at IS NOT NULL ASC, created_at DESC, id DESC`, envID)
	if err != nil {
		return nil, fmt.Errorf("list api keys: %w", err)
	}
	defer rows.Close()

	keys := []model.APIKey{}
	for rows.Next() {
		k, err := scanAPIKey(rows)
		if err != nil {
			return nil, fmt.Errorf("list api keys: %w", err)
		}
		keys = append(keys, k)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list api keys: %w", err)
	}
	return keys, nil
}

// LookupActiveAPIKey resolves an incoming X-App-Key by its hash. Revoked keys
// are treated as missing.
func (d *DB) LookupActiveAPIKey(ctx context.Context, keyHash string) (model.APIKey, error) {
	k, err := scanAPIKey(d.Read.QueryRowContext(ctx,
		`SELECT `+apiKeyColumns+` FROM api_keys WHERE key_hash = ? AND revoked_at IS NULL`, keyHash))
	if errors.Is(err, sql.ErrNoRows) {
		return model.APIKey{}, ErrNotFound
	}
	if err != nil {
		return model.APIKey{}, fmt.Errorf("lookup api key: %w", err)
	}
	return k, nil
}

// RevokeAPIKey marks a key inactive. It is scoped to envID so a UI request
// cannot revoke a key belonging to another environment.
func (d *DB) RevokeAPIKey(ctx context.Context, id, envID int64) error {
	res, err := d.Write.ExecContext(ctx,
		`UPDATE api_keys SET revoked_at = ? WHERE id = ? AND environment_id = ? AND revoked_at IS NULL`,
		now(), id, envID)
	if err != nil {
		return fmt.Errorf("revoke api key: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("revoke api key: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteAPIKey removes a key row outright.
func (d *DB) DeleteAPIKey(ctx context.Context, id, envID int64) error {
	res, err := d.Write.ExecContext(ctx,
		`DELETE FROM api_keys WHERE id = ? AND environment_id = ?`, id, envID)
	if err != nil {
		return fmt.Errorf("delete api key: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("delete api key: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}
