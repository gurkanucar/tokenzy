// Package webhook delivers token lifecycle events to HTTP receivers.
//
// One rule governs everything here: a delivery never carries the token itself.
// The plaintext is in the database because the panel has to be able to show a
// pass again, and that is the only reason it is there. What goes out is the
// id, the prefix and the metadata — enough for a receiver to match the event
// against its own records, useless to anyone who intercepts it.
package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"tokenzy/internal/db"
	"tokenzy/internal/model"
	"tokenzy/internal/token"
)

const (
	// deliveryTimeout caps a single attempt. A slow receiver must not pin a
	// worker forever.
	deliveryTimeout = 10 * time.Second

	// queueSize bounds the buffer between the request path and the worker that
	// writes deliveries down. Overflow is dropped and logged rather than
	// allowed to block a request handler.
	queueSize = 512

	// sweepInterval is the backstop for the retry queue. Normal deliveries do
	// not wait for it — writing one wakes the sender immediately — but a retry
	// scheduled ten minutes out has nothing to wake it, so the sweep runs
	// anyway.
	sweepInterval = 15 * time.Second

	// sweepBatch is how many due deliveries are claimed per round.
	sweepBatch = 50

	// maxConcurrent caps in-flight HTTP requests, so one environment with fifty
	// webhooks cannot open fifty sockets at once.
	maxConcurrent = 4

	// deliveryHistory is how many past deliveries the panel shows per webhook.
	deliveryHistory = 20
)

// retrySchedule is the delay before each attempt after the first. An attempt
// happens immediately, then after 30s, 2m and 10m — four tries spanning about
// twelve minutes, which covers a receiver restart without hammering one that
// is genuinely broken.
var retrySchedule = []time.Duration{
	30 * time.Second,
	2 * time.Minute,
	10 * time.Minute,
}

// EventTypeTest is the event type used by the panel's Test button. It is not
// in model.WebhookEvents on purpose: nothing in the service produces it, so a
// webhook cannot subscribe to it, and a receiver seeing one knows a human
// pressed a button.
const EventTypeTest = "webhook.test"

// ErrInvalidURL is returned when a webhook target is not a usable http(s) URL.
var ErrInvalidURL = errors.New("webhook URL must be an absolute http:// or https:// URL")

// ValidateURL checks a target before it is stored. Only http and https are
// accepted: other schemes (file:, gopher:) are not something this should reach.
func ValidateURL(raw string) error {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return ErrInvalidURL
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return ErrInvalidURL
	}
	if parsed.Host == "" {
		return ErrInvalidURL
	}
	return nil
}

// NewSecret returns a signing secret for a new webhook.
func NewSecret() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate webhook secret: %w", err)
	}
	return "whsec_" + hex.EncodeToString(buf), nil
}

// event is one thing that happened, on its way to becoming deliveries.
type event struct {
	envID     int64
	eventType string
	tok       model.Token
}

// Dispatcher turns token events into signed HTTP deliveries.
type Dispatcher struct {
	db     *db.DB
	client *http.Client
	queue  chan event
	// wake nudges the sender after new work is written, so a delivery does not
	// wait for the next sweep. Buffered to one: a pending nudge already means
	// "look again", and a second would say nothing new.
	wake chan struct{}
}

// New builds a dispatcher. Call Run to start delivering.
func New(database *db.DB) *Dispatcher {
	return &Dispatcher{
		db: database,
		client: &http.Client{
			Timeout: deliveryTimeout,
			// Deliveries are signed for a specific URL; following a redirect
			// would hand a signed body to a host the operator never named.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		queue: make(chan event, queueSize),
		wake:  make(chan struct{}, 1),
	}
}

// Notify records that something happened to a token. It is called from the db
// layer after the change has committed — never before, because an event for a
// write that then rolled back is a lie the receiver cannot detect.
//
// Safe to call from a request handler: it never blocks, and drops rather than
// waits if the queue is full.
func (d *Dispatcher) Notify(envID int64, eventType string, tok model.Token) {
	select {
	case d.queue <- event{envID: envID, eventType: eventType, tok: tok}:
	default:
		log.Printf("webhook: queue full, dropped %s for environment %d", eventType, envID)
	}
}

// Run delivers until ctx is cancelled.
//
// Two loops rather than one. The first turns events into rows and nothing
// else, so it stays fast and the queue behind it stays empty. The second does
// the HTTP work, which is slow and can fail. Keeping them apart means a
// receiver that takes ten seconds to answer cannot cause an event to be
// dropped at the front door.
func (d *Dispatcher) Run(ctx context.Context) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		d.recordLoop(ctx)
	}()
	go func() {
		defer wg.Done()
		d.sendLoop(ctx)
	}()

	wg.Wait()
}

// recordLoop writes each event out as one delivery row per interested webhook.
func (d *Dispatcher) recordLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-d.queue:
			if err := d.record(ctx, ev); err != nil && ctx.Err() == nil {
				log.Printf("webhook: record %s: %v", ev.eventType, err)
			}
		}
	}
}

func (d *Dispatcher) record(ctx context.Context, ev event) error {
	hooks, err := d.db.ListEnabledWebhooks(ctx, ev.envID)
	if err != nil {
		return err
	}
	if len(hooks) == 0 {
		return nil
	}

	env, err := d.db.GetEnvironmentByID(ctx, ev.envID)
	if err != nil {
		return err
	}

	eventID, err := newEventID()
	if err != nil {
		return err
	}

	queued := 0
	for _, hook := range hooks {
		if !hook.Subscribes(ev.eventType) {
			continue
		}
		body, err := buildPayload(eventID, ev.eventType, env.Slug, ev.tok, hook.IncludePayload)
		if err != nil {
			return err
		}
		if _, err := d.db.EnqueueDelivery(ctx, hook.ID, eventID, ev.eventType, body); err != nil {
			return err
		}
		queued++
	}

	if queued > 0 {
		d.nudge()
	}
	return nil
}

// nudge asks the sender to look for work now.
func (d *Dispatcher) nudge() {
	select {
	case d.wake <- struct{}{}:
	default:
	}
}

// sendLoop drains the due queue whenever it is woken and on a timer.
func (d *Dispatcher) sendLoop(ctx context.Context) {
	ticker := time.NewTicker(sweepInterval)
	defer ticker.Stop()

	for {
		d.sweep(ctx)

		select {
		case <-ctx.Done():
			return
		case <-d.wake:
		case <-ticker.C:
		}
	}
}

// sweep attempts every delivery that is currently due, in batches. It runs to
// completion before returning, so two sweeps can never overlap and no delivery
// is attempted twice at once.
//
// Within a batch, attempts run concurrently, so deliveries are not ordered:
// a redemption's token.consumed and token.exhausted can arrive in either
// order, and a retried delivery arrives minutes after events that came later.
// Ordering could not be promised anyway once retries exist, so instead every
// delivery carries the state it describes — status, usedCount, maxUses — and a
// receiver reasons from that rather than from arrival order.
func (d *Dispatcher) sweep(ctx context.Context) {
	for {
		if ctx.Err() != nil {
			return
		}

		due, err := d.db.DueDeliveries(ctx, time.Now().Unix(), sweepBatch)
		if err != nil {
			if ctx.Err() == nil {
				log.Printf("webhook: list due deliveries: %v", err)
			}
			return
		}
		if len(due) == 0 {
			return
		}

		// One hook is usually behind many of a batch's deliveries; loading it
		// once per batch keeps the read pool out of it.
		hooks := map[int64]model.Webhook{}
		var (
			wg  sync.WaitGroup
			sem = make(chan struct{}, maxConcurrent)
		)

		for _, delivery := range due {
			hook, ok := hooks[delivery.WebhookID]
			if !ok {
				hook, err = d.db.GetWebhookByID(ctx, delivery.WebhookID)
				if err != nil {
					// The webhook is gone but the delivery survived (or the read
					// failed). Either way there is nothing to send it to.
					log.Printf("webhook: load %d for delivery %d: %v",
						delivery.WebhookID, delivery.ID, err)
					continue
				}
				hooks[delivery.WebhookID] = hook
			}

			wg.Add(1)
			sem <- struct{}{}
			go func(delivery model.WebhookDelivery, hook model.Webhook) {
				defer wg.Done()
				defer func() { <-sem }()
				d.attempt(ctx, delivery, hook)
			}(delivery, hook)
		}
		wg.Wait()

		if len(due) < sweepBatch {
			return
		}
	}
}

// attempt makes one delivery and records what happened, including scheduling
// the next try.
func (d *Dispatcher) attempt(ctx context.Context, delivery model.WebhookDelivery, hook model.Webhook) {
	n := delivery.Attempt + 1
	status, err := d.post(ctx, hook, delivery, n)

	if err == nil {
		d.recordResult(delivery.ID, n, status, "", nil, true)
		return
	}

	var next *int64
	if int(n) <= len(retrySchedule) {
		at := time.Now().Add(retrySchedule[n-1]).Unix()
		next = &at
	} else {
		log.Printf("webhook %d (%s): giving up on %s after %d attempts: %v",
			hook.ID, hook.URL, delivery.EventType, n, err)
	}
	d.recordResult(delivery.ID, n, status, err.Error(), next, false)
}

// post sends the body and reports the receiver's answer.
func (d *Dispatcher) post(ctx context.Context, hook model.Webhook,
	delivery model.WebhookDelivery, attempt int64) (int, error) {

	reqCtx, cancel := context.WithTimeout(ctx, deliveryTimeout)
	defer cancel()

	body := []byte(delivery.Payload)
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, hook.URL, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}

	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("User-Agent", "tokenzy-webhook/1")
	req.Header.Set("X-Webhook-Id", delivery.EventID)
	req.Header.Set("X-Webhook-Event", delivery.EventType)
	req.Header.Set("X-Webhook-Attempt", strconv.FormatInt(attempt, 10))
	req.Header.Set("X-Webhook-Signature", Sign(hook.Secret, body))

	resp, err := d.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return resp.StatusCode, fmt.Errorf("receiver answered %s", resp.Status)
	}
	return resp.StatusCode, nil
}

// recordResult writes the outcome on its own context: the delivery context may
// already be cancelled by a shutdown, and the result is still worth keeping.
func (d *Dispatcher) recordResult(id, attempt int64, status int, deliveryErr string,
	nextRetryAt *int64, delivered bool) {

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := d.db.RecordDeliveryResult(ctx, id, attempt, status, deliveryErr, nextRetryAt, delivered); err != nil {
		log.Printf("webhook: record result for delivery %d: %v", id, err)
	}
}

// Sign returns the value of the X-Webhook-Signature header for a body.
//
// A receiver verifies by computing the same HMAC over the raw bytes it read —
// before any JSON parsing, since re-serialising would change them — and
// comparing in constant time.
func Sign(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// Test sends one synthetic delivery so an operator can check a receiver
// without waiting for a real token event. It goes through the same queue as
// everything else, so what it proves is what will actually happen.
func (d *Dispatcher) Test(ctx context.Context, hook model.Webhook) error {
	eventID, err := newEventID()
	if err != nil {
		return err
	}

	env, err := d.db.GetEnvironmentByID(ctx, hook.EnvironmentID)
	if err != nil {
		return err
	}

	body, err := json.Marshal(eventBody{
		ID:          eventID,
		Type:        EventTypeTest,
		CreatedAt:   rfc3339(time.Now().Unix()),
		Environment: env.Slug,
	})
	if err != nil {
		return fmt.Errorf("build test payload: %w", err)
	}

	if _, err := d.db.EnqueueDelivery(ctx, hook.ID, eventID, EventTypeTest, string(body)); err != nil {
		return err
	}
	d.nudge()
	return nil
}

// DeliveryHistory returns the recent deliveries shown in the panel.
func (d *Dispatcher) DeliveryHistory(ctx context.Context, webhookID int64) ([]model.WebhookDelivery, error) {
	return d.db.ListDeliveries(ctx, webhookID, deliveryHistory)
}

// Payload shapes.

type eventBody struct {
	ID          string     `json:"id"`
	Type        string     `json:"type"`
	CreatedAt   string     `json:"createdAt"`
	Environment string     `json:"environment"`
	Data        *tokenData `json:"data,omitempty"`
}

// tokenData is the token as a receiver sees it. There is no field for the
// token value, which is the point: the shape itself makes leaking one
// impossible rather than merely forbidden.
type tokenData struct {
	ID          string          `json:"id"`
	TokenPrefix string          `json:"tokenPrefix"`
	Status      string          `json:"status"`
	UsedCount   int64           `json:"usedCount"`
	MaxUses     *int64          `json:"maxUses"`
	ExpiresAt   string          `json:"expiresAt"`
	CreatedAt   string          `json:"createdAt"`
	LastUsedAt  *string         `json:"lastUsedAt"`
	Payload     json.RawMessage `json:"payload,omitempty"`
}

func buildPayload(eventID, eventType, envSlug string, tok model.Token, includePayload bool) (string, error) {
	ts := time.Now().Unix()

	data := &tokenData{
		ID:          tok.ID,
		TokenPrefix: tok.Prefix,
		Status:      token.StatusOf(tok, ts),
		UsedCount:   tok.UsedCount,
		MaxUses:     tok.MaxUses,
		ExpiresAt:   rfc3339(tok.ExpiresAt),
		CreatedAt:   rfc3339(tok.CreatedAt),
	}
	if tok.LastUsedAt != nil {
		at := rfc3339(*tok.LastUsedAt)
		data.LastUsedAt = &at
	}
	if includePayload && tok.PayloadJSON != "" {
		data.Payload = json.RawMessage(tok.PayloadJSON)
	}

	body, err := json.Marshal(eventBody{
		ID:          eventID,
		Type:        eventType,
		CreatedAt:   rfc3339(ts),
		Environment: envSlug,
		Data:        data,
	})
	if err != nil {
		return "", fmt.Errorf("build webhook payload: %w", err)
	}
	return string(body), nil
}

func newEventID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate event id: %w", err)
	}
	return "evt_" + hex.EncodeToString(buf), nil
}

func rfc3339(ts int64) string {
	return time.Unix(ts, 0).UTC().Format(time.RFC3339)
}
