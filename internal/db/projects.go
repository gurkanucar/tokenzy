package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"tokenzy/internal/model"
)

// DefaultEnvironment is created automatically with every new project.
const DefaultEnvironment = "prod"

// CreateProject inserts a project together with its default environment.
func (d *DB) CreateProject(ctx context.Context, slug, name string) (model.Project, error) {
	ts := now()

	tx, err := d.Write.BeginTx(ctx, nil)
	if err != nil {
		return model.Project{}, fmt.Errorf("create project: %w", err)
	}
	defer tx.Rollback()

	res, err := tx.ExecContext(ctx,
		`INSERT INTO projects (slug, name, created_at) VALUES (?, ?, ?)`, slug, name, ts)
	if err != nil {
		if isUniqueViolation(err) {
			return model.Project{}, ErrDuplicate
		}
		return model.Project{}, fmt.Errorf("create project: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return model.Project{}, fmt.Errorf("create project: %w", err)
	}

	_, err = tx.ExecContext(ctx,
		`INSERT INTO environments (project_id, slug, created_at) VALUES (?, ?, ?)`,
		id, DefaultEnvironment, ts)
	if err != nil {
		return model.Project{}, fmt.Errorf("create default environment: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return model.Project{}, fmt.Errorf("create project: %w", err)
	}
	return model.Project{ID: id, Slug: slug, Name: name, CreatedAt: ts}, nil
}

// ListProjects returns every project, newest first.
func (d *DB) ListProjects(ctx context.Context) ([]model.Project, error) {
	rows, err := d.Read.QueryContext(ctx,
		`SELECT id, slug, name, created_at FROM projects ORDER BY created_at DESC, id DESC`)
	if err != nil {
		return nil, fmt.Errorf("list projects: %w", err)
	}
	defer rows.Close()

	projects := []model.Project{}
	for rows.Next() {
		var p model.Project
		if err := rows.Scan(&p.ID, &p.Slug, &p.Name, &p.CreatedAt); err != nil {
			return nil, fmt.Errorf("list projects: %w", err)
		}
		projects = append(projects, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list projects: %w", err)
	}
	return projects, nil
}

// GetProjectBySlug resolves the {slug} path segment used across the UI.
func (d *DB) GetProjectBySlug(ctx context.Context, slug string) (model.Project, error) {
	var p model.Project
	err := d.Read.QueryRowContext(ctx,
		`SELECT id, slug, name, created_at FROM projects WHERE slug = ?`, slug).
		Scan(&p.ID, &p.Slug, &p.Name, &p.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Project{}, ErrNotFound
	}
	if err != nil {
		return model.Project{}, fmt.Errorf("get project: %w", err)
	}
	return p, nil
}

// DeleteProject removes a project and, by cascade, everything below it —
// environments, their keys, and every token they hold.
func (d *DB) DeleteProject(ctx context.Context, id int64) error {
	res, err := d.Write.ExecContext(ctx, `DELETE FROM projects WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete project: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("delete project: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// CreateEnvironment adds an environment to a project.
func (d *DB) CreateEnvironment(ctx context.Context, projectID int64, slug string) (model.Environment, error) {
	ts := now()
	res, err := d.Write.ExecContext(ctx,
		`INSERT INTO environments (project_id, slug, created_at) VALUES (?, ?, ?)`,
		projectID, slug, ts)
	if err != nil {
		if isUniqueViolation(err) {
			return model.Environment{}, ErrDuplicate
		}
		return model.Environment{}, fmt.Errorf("create environment: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return model.Environment{}, fmt.Errorf("create environment: %w", err)
	}
	return model.Environment{ID: id, ProjectID: projectID, Slug: slug, CreatedAt: ts}, nil
}

// ListEnvironments returns a project's environments in creation order.
func (d *DB) ListEnvironments(ctx context.Context, projectID int64) ([]model.Environment, error) {
	rows, err := d.Read.QueryContext(ctx,
		`SELECT id, project_id, slug, created_at
		   FROM environments WHERE project_id = ? ORDER BY created_at ASC, id ASC`, projectID)
	if err != nil {
		return nil, fmt.Errorf("list environments: %w", err)
	}
	defer rows.Close()

	envs := []model.Environment{}
	for rows.Next() {
		var e model.Environment
		if err := rows.Scan(&e.ID, &e.ProjectID, &e.Slug, &e.CreatedAt); err != nil {
			return nil, fmt.Errorf("list environments: %w", err)
		}
		envs = append(envs, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list environments: %w", err)
	}
	return envs, nil
}

// GetEnvironment resolves a (project, env) slug pair.
func (d *DB) GetEnvironment(ctx context.Context, projectID int64, slug string) (model.Environment, error) {
	var e model.Environment
	err := d.Read.QueryRowContext(ctx,
		`SELECT id, project_id, slug, created_at
		   FROM environments WHERE project_id = ? AND slug = ?`, projectID, slug).
		Scan(&e.ID, &e.ProjectID, &e.Slug, &e.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Environment{}, ErrNotFound
	}
	if err != nil {
		return model.Environment{}, fmt.Errorf("get environment: %w", err)
	}
	return e, nil
}

// GetEnvironmentByID resolves the environment an API key is bound to.
func (d *DB) GetEnvironmentByID(ctx context.Context, id int64) (model.Environment, error) {
	var e model.Environment
	err := d.Read.QueryRowContext(ctx,
		`SELECT id, project_id, slug, created_at FROM environments WHERE id = ?`, id).
		Scan(&e.ID, &e.ProjectID, &e.Slug, &e.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Environment{}, ErrNotFound
	}
	if err != nil {
		return model.Environment{}, fmt.Errorf("get environment: %w", err)
	}
	return e, nil
}

// DeleteEnvironment removes an environment and everything below it.
func (d *DB) DeleteEnvironment(ctx context.Context, id int64) error {
	res, err := d.Write.ExecContext(ctx, `DELETE FROM environments WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete environment: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("delete environment: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}
