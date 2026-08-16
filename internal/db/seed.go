package db

import (
	"context"
	_ "embed"
	"fmt"
)

//go:embed seed.sql
var seedSQL string

// Seed inserts the demo dataset, but only into a database that holds no
// projects yet. It reports whether it actually wrote anything, so a restart
// against an existing database is a no-op rather than a duplicate-key error.
//
// Everything runs in one transaction: a half-applied demo dataset would be
// worse than none.
func (d *DB) Seed(ctx context.Context) (bool, error) {
	var projects int
	err := d.Read.QueryRowContext(ctx, `SELECT COUNT(*) FROM projects`).Scan(&projects)
	if err != nil {
		return false, fmt.Errorf("count projects: %w", err)
	}
	if projects > 0 {
		return false, nil
	}

	tx, err := d.Write.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("seed: %w", err)
	}
	defer tx.Rollback()

	for _, stmt := range splitStatements(seedSQL) {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return false, fmt.Errorf("seed: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("seed: %w", err)
	}
	return true, nil
}
