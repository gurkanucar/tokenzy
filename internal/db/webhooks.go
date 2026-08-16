package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"tokenzy/internal/model"
)

const webhookColumns = `id, environment_id, url, secret, events, headers, label,
	include_payload, created_at, disabled_at`

func scanWebhook(s rowScanner) (model.Webhook, error) {
	var (
		w        model.Webhook
		events   string
		headers  string
		disabled sql.NullInt64
	)
	err := s.Scan(&w.ID, &w.EnvironmentID, &w.URL, &w.Secret, &events, &headers, &w.Label,
		&w.IncludePayload, &w.CreatedAt, &disabled)
	if err != nil {
		return model.Webhook{}, err
	}

	w.Events = splitEvents(events)
	w.Headers = map[string]string{}
	if headers != "" {
		// A malformed header blob must not take a whole listing down; the
		// webhook is still worth showing, just without its headers.
		_ = json.Unmarshal([]byte(headers), &w.Headers)
	}
	w.DisabledAt = nullableInt64(disabled)
	return w, nil
}

// splitEvents decodes the stored subscription list. An empty column means "all
// events", which is why the empty string maps to a nil slice rather than to a
// slice holding one empty name.
func splitEvents(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// CreateWebhook adds a webhook to an environment.
func (d *DB) CreateWebhook(ctx context.Context, envID int64, url, secret string,
	events []string, headers map[string]string, label string, includePayload bool) (model.Webhook, error) {

	if headers == nil {
		headers = map[string]string{}
	}
	encoded, err := json.Marshal(headers)
	if err != nil {
		return model.Webhook{}, fmt.Errorf("create webhook: %w", err)
	}

	ts := now()
	res, err := d.Write.ExecContext(ctx,
		`INSERT INTO webhooks (environment_id, url, secret, events, headers, label,
			include_payload, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		envID, url, secret, strings.Join(events, ","), string(encoded), label, includePayload, ts)
	if err != nil {
		return model.Webhook{}, fmt.Errorf("create webhook: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return model.Webhook{}, fmt.Errorf("create webhook: %w", err)
	}
	return model.Webhook{
		ID: id, EnvironmentID: envID, URL: url, Secret: secret, Events: events,
		Headers: headers, Label: label, IncludePayload: includePayload, CreatedAt: ts,
	}, nil
}

// ListWebhooks returns every webhook on an environment, newest first.
func (d *DB) ListWebhooks(ctx context.Context, envID int64) ([]model.Webhook, error) {
	rows, err := d.Read.QueryContext(ctx,
		`SELECT `+webhookColumns+` FROM webhooks WHERE environment_id = ?
		 ORDER BY created_at DESC, id DESC`, envID)
	if err != nil {
		return nil, fmt.Errorf("list webhooks: %w", err)
	}
	defer rows.Close()

	hooks := []model.Webhook{}
	for rows.Next() {
		w, err := scanWebhook(rows)
		if err != nil {
			return nil, fmt.Errorf("list webhooks: %w", err)
		}
		hooks = append(hooks, w)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list webhooks: %w", err)
	}
	return hooks, nil
}

// ListEnabledWebhooks returns the webhooks that should actually be delivered
// to. Whether each one subscribes to a given event is decided in Go, since the
// subscription list is a text column and matching it in SQL would be worse
// than the loop.
func (d *DB) ListEnabledWebhooks(ctx context.Context, envID int64) ([]model.Webhook, error) {
	rows, err := d.Read.QueryContext(ctx,
		`SELECT `+webhookColumns+` FROM webhooks
		  WHERE environment_id = ? AND disabled_at IS NULL ORDER BY id ASC`, envID)
	if err != nil {
		return nil, fmt.Errorf("list webhooks: %w", err)
	}
	defer rows.Close()

	hooks := []model.Webhook{}
	for rows.Next() {
		w, err := scanWebhook(rows)
		if err != nil {
			return nil, fmt.Errorf("list webhooks: %w", err)
		}
		hooks = append(hooks, w)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list webhooks: %w", err)
	}
	return hooks, nil
}

// GetWebhook loads one webhook, scoped to its environment so a request cannot
// reach a webhook belonging elsewhere.
func (d *DB) GetWebhook(ctx context.Context, id, envID int64) (model.Webhook, error) {
	w, err := scanWebhook(d.Read.QueryRowContext(ctx,
		`SELECT `+webhookColumns+` FROM webhooks WHERE id = ? AND environment_id = ?`, id, envID))
	if errors.Is(err, sql.ErrNoRows) {
		return model.Webhook{}, ErrNotFound
	}
	if err != nil {
		return model.Webhook{}, fmt.Errorf("get webhook: %w", err)
	}
	return w, nil
}

// GetWebhookByID loads a webhook without an environment to scope it.
//
// Only the delivery worker uses this: it starts from a delivery row, which
// already establishes which webhook the work belongs to. Request handlers use
// GetWebhook so that a webhook id from a URL can never reach across
// environments.
func (d *DB) GetWebhookByID(ctx context.Context, id int64) (model.Webhook, error) {
	w, err := scanWebhook(d.Read.QueryRowContext(ctx,
		`SELECT `+webhookColumns+` FROM webhooks WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return model.Webhook{}, ErrNotFound
	}
	if err != nil {
		return model.Webhook{}, fmt.Errorf("get webhook: %w", err)
	}
	return w, nil
}

// SetWebhookEnabled turns delivery on or off without losing the configuration.
func (d *DB) SetWebhookEnabled(ctx context.Context, id, envID int64, enabled bool) error {
	var disabledAt any
	if !enabled {
		disabledAt = now()
	}
	res, err := d.Write.ExecContext(ctx,
		`UPDATE webhooks SET disabled_at = ? WHERE id = ? AND environment_id = ?`,
		disabledAt, id, envID)
	if err != nil {
		return fmt.Errorf("update webhook: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("update webhook: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteWebhook removes a webhook and, by cascade, its delivery history.
func (d *DB) DeleteWebhook(ctx context.Context, id, envID int64) error {
	res, err := d.Write.ExecContext(ctx,
		`DELETE FROM webhooks WHERE id = ? AND environment_id = ?`, id, envID)
	if err != nil {
		return fmt.Errorf("delete webhook: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("delete webhook: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// Deliveries.

const deliveryColumns = `id, webhook_id, event_id, event_type, payload, attempt,
	status_code, error, next_retry_at, delivered_at, created_at`

func scanDelivery(s rowScanner) (model.WebhookDelivery, error) {
	var (
		d         model.WebhookDelivery
		status    sql.NullInt64
		nextRetry sql.NullInt64
		delivered sql.NullInt64
	)
	err := s.Scan(&d.ID, &d.WebhookID, &d.EventID, &d.EventType, &d.Payload, &d.Attempt,
		&status, &d.Error, &nextRetry, &delivered, &d.CreatedAt)
	d.StatusCode = nullableInt64(status)
	d.NextRetryAt = nullableInt64(nextRetry)
	d.DeliveredAt = nullableInt64(delivered)
	return d, err
}

// EnqueueDelivery records an event for one webhook, due immediately.
//
// The queue lives in the database rather than in memory so a process that
// stops between the third and fourth attempt resumes where it left off instead
// of silently dropping the delivery.
func (d *DB) EnqueueDelivery(ctx context.Context, webhookID int64, eventID, eventType, payload string) (model.WebhookDelivery, error) {
	ts := now()
	res, err := d.Write.ExecContext(ctx,
		`INSERT INTO webhook_deliveries (webhook_id, event_id, event_type, payload,
			attempt, next_retry_at, created_at)
		 VALUES (?, ?, ?, ?, 0, ?, ?)`, webhookID, eventID, eventType, payload, ts, ts)
	if err != nil {
		return model.WebhookDelivery{}, fmt.Errorf("enqueue delivery: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return model.WebhookDelivery{}, fmt.Errorf("enqueue delivery: %w", err)
	}
	return model.WebhookDelivery{
		ID: id, WebhookID: webhookID, EventID: eventID, EventType: eventType,
		Payload: payload, NextRetryAt: &ts, CreatedAt: ts,
	}, nil
}

// DueDeliveries returns deliveries whose next attempt is owed.
func (d *DB) DueDeliveries(ctx context.Context, at int64, limit int) ([]model.WebhookDelivery, error) {
	rows, err := d.Read.QueryContext(ctx,
		`SELECT `+deliveryColumns+` FROM webhook_deliveries
		  WHERE delivered_at IS NULL AND next_retry_at IS NOT NULL AND next_retry_at <= ?
		  ORDER BY next_retry_at ASC, id ASC LIMIT ?`, at, limit)
	if err != nil {
		return nil, fmt.Errorf("list due deliveries: %w", err)
	}
	defer rows.Close()

	out := []model.WebhookDelivery{}
	for rows.Next() {
		item, err := scanDelivery(rows)
		if err != nil {
			return nil, fmt.Errorf("list due deliveries: %w", err)
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list due deliveries: %w", err)
	}
	return out, nil
}

// RecordDeliveryResult writes the outcome of one attempt. nextRetryAt is nil
// when nothing further is scheduled, which — combined with delivered_at — is
// what separates "waiting to retry" from "gave up".
func (d *DB) RecordDeliveryResult(ctx context.Context, id int64, attempt int64,
	statusCode int, deliveryErr string, nextRetryAt *int64, delivered bool) error {

	var statusArg any
	if statusCode > 0 {
		statusArg = statusCode
	}
	var deliveredArg any
	if delivered {
		deliveredArg = now()
	}

	_, err := d.Write.ExecContext(ctx,
		`UPDATE webhook_deliveries
		    SET attempt = ?, status_code = ?, error = ?, next_retry_at = ?, delivered_at = ?
		  WHERE id = ?`, attempt, statusArg, deliveryErr, arg(nextRetryAt), deliveredArg, id)
	if err != nil {
		return fmt.Errorf("record delivery result: %w", err)
	}
	return nil
}

// ListDeliveries returns the recent delivery history for one webhook.
func (d *DB) ListDeliveries(ctx context.Context, webhookID int64, limit int) ([]model.WebhookDelivery, error) {
	rows, err := d.Read.QueryContext(ctx,
		`SELECT `+deliveryColumns+` FROM webhook_deliveries
		  WHERE webhook_id = ? ORDER BY created_at DESC, id DESC LIMIT ?`, webhookID, limit)
	if err != nil {
		return nil, fmt.Errorf("list deliveries: %w", err)
	}
	defer rows.Close()

	out := []model.WebhookDelivery{}
	for rows.Next() {
		item, err := scanDelivery(rows)
		if err != nil {
			return nil, fmt.Errorf("list deliveries: %w", err)
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list deliveries: %w", err)
	}
	return out, nil
}

// DeleteOldDeliveries prunes settled delivery rows. Pending ones are left
// alone however old they are: a delivery still waiting on a retry is work, not
// history.
func (d *DB) DeleteOldDeliveries(ctx context.Context, before int64, limit int) (int64, error) {
	res, err := d.Write.ExecContext(ctx,
		`DELETE FROM webhook_deliveries WHERE id IN (
		   SELECT id FROM webhook_deliveries
		    WHERE created_at < ? AND (delivered_at IS NOT NULL OR next_retry_at IS NULL)
		    LIMIT ?
		 )`, before, limit)
	if err != nil {
		return 0, fmt.Errorf("delete old deliveries: %w", err)
	}
	return res.RowsAffected()
}
