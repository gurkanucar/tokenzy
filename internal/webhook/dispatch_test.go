package webhook

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"tokenzy/internal/db"
	"tokenzy/internal/model"
	"tokenzy/internal/token"
)

// received is one request as the receiver saw it.
type received struct {
	body      []byte
	signature string
	eventID   string
	eventType string
	attempt   string
}

// receiver is a stand-in webhook endpoint whose answer the test controls.
type receiver struct {
	mu     sync.Mutex
	got    []received
	status int
	server *httptest.Server
}

func newReceiver(t *testing.T) *receiver {
	t.Helper()

	r := &receiver{status: http.StatusOK}
	r.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)

		r.mu.Lock()
		r.got = append(r.got, received{
			body:      body,
			signature: req.Header.Get("X-Webhook-Signature"),
			eventID:   req.Header.Get("X-Webhook-Id"),
			eventType: req.Header.Get("X-Webhook-Event"),
			attempt:   req.Header.Get("X-Webhook-Attempt"),
		})
		status := r.status
		r.mu.Unlock()

		w.WriteHeader(status)
	}))
	t.Cleanup(r.server.Close)
	return r
}

func (r *receiver) setStatus(code int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.status = code
}

func (r *receiver) requests() []received {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]received(nil), r.got...)
}

// waitFor polls until cond holds or the deadline passes. Delivery is
// asynchronous by design, so the alternative is a sleep long enough to be slow
// and short enough to be flaky.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// fixture is a running dispatcher over a temporary database.
type fixture struct {
	db    *db.DB
	envID int64
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	ctx := context.Background()

	database, err := db.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { database.Close() })

	if err := database.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	project, err := database.CreateProject(ctx, "test", "Test")
	if err != nil {
		t.Fatalf("create project: %v", err)
	}
	env, err := database.GetEnvironment(ctx, project.ID, db.DefaultEnvironment)
	if err != nil {
		t.Fatalf("get environment: %v", err)
	}

	f := &fixture{db: database, envID: env.ID}

	dispatcher := New(database)
	runCtx, stop := context.WithCancel(context.Background())
	t.Cleanup(stop)
	go dispatcher.Run(runCtx)
	database.OnTokenEvent = dispatcher.Notify

	return f
}

// mint issues a token, which is what produces events.
func (f *fixture) mint(t *testing.T, maxUses *int64) model.Token {
	t.Helper()

	id, err := token.NewID()
	if err != nil {
		t.Fatalf("new id: %v", err)
	}
	value, err := token.Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	created, err := f.db.CreateToken(context.Background(), f.envID, id, value,
		`{"userId":"usr_123","secret":"sentinel-payload-value"}`, maxUses,
		time.Now().Add(time.Hour).Unix())
	if err != nil {
		t.Fatalf("create token: %v", err)
	}
	return created
}

func ptr(v int64) *int64 { return &v }

// TestDeliveryNeverCarriesTheToken is the rule the package exists to enforce.
// The token is in the database in plaintext; it must not be on the wire.
func TestDeliveryNeverCarriesTheToken(t *testing.T) {
	f := newFixture(t)
	rec := newReceiver(t)

	// include_payload on, so this is the most generous shape a delivery can
	// have — and even here the token itself must be absent.
	hook, err := f.db.CreateWebhook(context.Background(), f.envID, rec.server.URL,
		"whsec_test", nil, nil, "test", true)
	if err != nil {
		t.Fatalf("create webhook: %v", err)
	}

	tok := f.mint(t, ptr(1))
	waitFor(t, "the created event", func() bool { return len(rec.requests()) >= 1 })

	got := rec.requests()[0]
	body := string(got.body)

	if strings.Contains(body, tok.Value) {
		t.Fatal("a webhook delivery contained the plaintext token")
	}
	if !strings.Contains(body, tok.Prefix) {
		t.Fatalf("delivery does not carry the prefix: %s", body)
	}
	if !strings.Contains(body, tok.ID) {
		t.Fatalf("delivery does not carry the id: %s", body)
	}
	// include_payload was on, so this one is expected.
	if !strings.Contains(body, "sentinel-payload-value") {
		t.Fatalf("include_payload was set but the payload is missing: %s", body)
	}

	var event struct {
		ID          string `json:"id"`
		Type        string `json:"type"`
		Environment string `json:"environment"`
		Data        struct {
			ID          string `json:"id"`
			TokenPrefix string `json:"tokenPrefix"`
			Status      string `json:"status"`
			MaxUses     *int64 `json:"maxUses"`
		} `json:"data"`
	}
	if err := json.Unmarshal(got.body, &event); err != nil {
		t.Fatalf("decode delivery: %v", err)
	}
	if event.Type != model.EventTokenCreated {
		t.Fatalf("event type = %q, want %q", event.Type, model.EventTokenCreated)
	}
	if event.Environment != "prod" {
		t.Fatalf("environment = %q, want prod", event.Environment)
	}
	if event.Data.Status != token.StatusActive {
		t.Fatalf("status = %q, want active", event.Data.Status)
	}
	if got.eventID != event.ID || got.eventType != event.Type {
		t.Fatalf("headers (%s, %s) disagree with the body (%s, %s)",
			got.eventID, got.eventType, event.ID, event.Type)
	}
	if got.attempt != "1" {
		t.Fatalf("attempt header = %q, want 1", got.attempt)
	}
	_ = hook
}

// TestPayloadIsWithheldByDefault: include_payload off means the caller's data
// stays out of the delivery.
func TestPayloadIsWithheldByDefault(t *testing.T) {
	f := newFixture(t)
	rec := newReceiver(t)

	if _, err := f.db.CreateWebhook(context.Background(), f.envID, rec.server.URL,
		"whsec_test", nil, nil, "", false); err != nil {
		t.Fatalf("create webhook: %v", err)
	}

	f.mint(t, nil)
	waitFor(t, "the created event", func() bool { return len(rec.requests()) >= 1 })

	if body := string(rec.requests()[0].body); strings.Contains(body, "sentinel-payload-value") {
		t.Fatalf("the payload was sent despite include_payload being off: %s", body)
	}
}

// TestSignatureVerifies checks a receiver can actually authenticate a delivery,
// computed the way a receiver would compute it: over the raw bytes.
func TestSignatureVerifies(t *testing.T) {
	f := newFixture(t)
	rec := newReceiver(t)

	const secret = "whsec_0123456789abcdef"
	if _, err := f.db.CreateWebhook(context.Background(), f.envID, rec.server.URL,
		secret, nil, nil, "", false); err != nil {
		t.Fatalf("create webhook: %v", err)
	}

	f.mint(t, nil)
	waitFor(t, "the created event", func() bool { return len(rec.requests()) >= 1 })

	got := rec.requests()[0]

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(got.body)
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	if got.signature != want {
		t.Fatalf("signature = %q, want %q", got.signature, want)
	}
	if Sign(secret, got.body) != want {
		t.Fatal("Sign disagrees with a hand-computed HMAC")
	}
	// A different secret must not verify.
	if Sign("whsec_wrong", got.body) == want {
		t.Fatal("the signature does not depend on the secret")
	}
}

// TestSubscriptionFiltering: a webhook that asked for one event type gets that
// one and nothing else.
func TestSubscriptionFiltering(t *testing.T) {
	f := newFixture(t)
	rec := newReceiver(t)

	if _, err := f.db.CreateWebhook(context.Background(), f.envID, rec.server.URL,
		"whsec_test", []string{model.EventTokenExhausted}, nil, "", false); err != nil {
		t.Fatalf("create webhook: %v", err)
	}

	tok := f.mint(t, ptr(1))
	if _, err := f.db.ConsumeToken(context.Background(), f.envID, tok.Value); err != nil {
		t.Fatalf("consume: %v", err)
	}

	// The redemption produces consumed and exhausted; only the latter is wanted.
	waitFor(t, "the exhausted event", func() bool { return len(rec.requests()) >= 1 })
	time.Sleep(150 * time.Millisecond) // let any unwanted delivery arrive if it is coming

	for _, got := range rec.requests() {
		if got.eventType != model.EventTokenExhausted {
			t.Fatalf("received %q, but only %q was subscribed to",
				got.eventType, model.EventTokenExhausted)
		}
	}
}

// TestDisabledWebhookReceivesNothing.
func TestDisabledWebhookReceivesNothing(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	rec := newReceiver(t)

	hook, err := f.db.CreateWebhook(ctx, f.envID, rec.server.URL, "whsec_test", nil, nil, "", false)
	if err != nil {
		t.Fatalf("create webhook: %v", err)
	}
	if err := f.db.SetWebhookEnabled(ctx, hook.ID, f.envID, false); err != nil {
		t.Fatalf("disable: %v", err)
	}

	f.mint(t, nil)
	time.Sleep(250 * time.Millisecond)

	if n := len(rec.requests()); n != 0 {
		t.Fatalf("a disabled webhook received %d deliveries", n)
	}
}

// TestFailedDeliveryIsRetried checks that a rejected delivery is recorded as
// pending with a future retry rather than dropped or marked delivered.
func TestFailedDeliveryIsRetried(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	rec := newReceiver(t)
	rec.setStatus(http.StatusInternalServerError)

	hook, err := f.db.CreateWebhook(ctx, f.envID, rec.server.URL, "whsec_test", nil, nil, "", false)
	if err != nil {
		t.Fatalf("create webhook: %v", err)
	}

	f.mint(t, nil)
	waitFor(t, "the first attempt", func() bool { return len(rec.requests()) >= 1 })

	var delivery model.WebhookDelivery
	waitFor(t, "the failure to be recorded", func() bool {
		list, err := f.db.ListDeliveries(ctx, hook.ID, 10)
		if err != nil || len(list) == 0 {
			return false
		}
		delivery = list[0]
		return delivery.Attempt >= 1
	})

	if delivery.Delivered() {
		t.Fatal("a 500 was recorded as delivered")
	}
	if !delivery.Pending() {
		t.Fatal("a failed delivery was not scheduled for a retry")
	}
	if delivery.StatusCode == nil || *delivery.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status code = %v, want 500", delivery.StatusCode)
	}
	if delivery.Error == "" {
		t.Fatal("the failure was recorded without a reason")
	}

	// The first retry is 30s out, which is what makes this a backoff rather
	// than a hot loop.
	gap := *delivery.NextRetryAt - time.Now().Unix()
	if gap < 20 || gap > 40 {
		t.Fatalf("next retry is %ds away, want roughly 30s", gap)
	}
}

// TestSuccessfulDeliveryIsRecordedOnce.
func TestSuccessfulDeliveryIsRecordedOnce(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	rec := newReceiver(t)

	hook, err := f.db.CreateWebhook(ctx, f.envID, rec.server.URL, "whsec_test", nil, nil, "", false)
	if err != nil {
		t.Fatalf("create webhook: %v", err)
	}

	f.mint(t, nil)
	waitFor(t, "the delivery", func() bool { return len(rec.requests()) >= 1 })

	var delivery model.WebhookDelivery
	waitFor(t, "the success to be recorded", func() bool {
		list, err := f.db.ListDeliveries(ctx, hook.ID, 10)
		if err != nil || len(list) == 0 {
			return false
		}
		delivery = list[0]
		return delivery.Delivered()
	})

	if delivery.NextRetryAt != nil {
		t.Fatal("a delivered event is still scheduled for a retry")
	}

	// A delivered event must not be sent again by the next sweep.
	before := len(rec.requests())
	time.Sleep(250 * time.Millisecond)
	if after := len(rec.requests()); after != before {
		t.Fatalf("a delivered event was re-sent (%d then %d)", before, after)
	}
}

// TestValidateURL rejects what should never be reachable.
func TestValidateURL(t *testing.T) {
	valid := []string{
		"http://example.com/hook",
		"https://example.com/hook?x=1",
		"http://127.0.0.1:9000/hook",
	}
	for _, u := range valid {
		if err := ValidateURL(u); err != nil {
			t.Errorf("ValidateURL(%q) = %v, want nil", u, err)
		}
	}

	invalid := []string{
		"",
		"example.com/hook", // no scheme
		"/hook",            // relative
		"file:///etc/passwd",
		"gopher://example.com",
		"https://", // no host
	}
	for _, u := range invalid {
		if err := ValidateURL(u); err == nil {
			t.Errorf("ValidateURL(%q) = nil, want an error", u)
		}
	}
}

// TestParseHeaders covers the shapes an operator can type into the form.
func TestParseHeaders(t *testing.T) {
	got, err := ParseHeaders("Authorization: Bearer abc123\n\n  X-Tenant:  acme  \n")
	if err != nil {
		t.Fatalf("ParseHeaders: %v", err)
	}
	want := map[string]string{"Authorization": "Bearer abc123", "X-Tenant": "acme"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for name, value := range want {
		if got[name] != value {
			t.Fatalf("header %q = %q, want %q", name, got[name], value)
		}
	}

	// A value may legitimately contain colons; only the first one splits.
	got, err = ParseHeaders("X-Trace: a:b:c")
	if err != nil {
		t.Fatalf("ParseHeaders: %v", err)
	}
	if got["X-Trace"] != "a:b:c" {
		t.Fatalf("X-Trace = %q, want a:b:c", got["X-Trace"])
	}

	rejected := map[string]string{
		"no colon":           "Authorization Bearer abc",
		"empty name":         ": value",
		"space in name":      "X Tenant: acme",
		"newline in name":    "X-A\rB: c",
		"carriage return":    "X-A: b\rX-Injected: c",
		"reserved signature": "X-Webhook-Signature: sha256=deadbeef",
		"reserved id":        "x-webhook-id: mine",
		"reserved conteent":  "Content-Type: text/plain",
	}
	for name, input := range rejected {
		if _, err := ParseHeaders(input); err == nil {
			t.Errorf("%s: ParseHeaders(%q) = nil error, want a rejection", name, input)
		}
	}
}

// TestCustomHeadersAreSentButCannotOverrideOurs is the security property behind
// applying them first: a webhook's own headers reach the receiver, and none of
// them can displace the signature.
func TestCustomHeadersAreSentButCannotOverrideOurs(t *testing.T) {
	f := newFixture(t)

	var (
		mu   sync.Mutex
		seen http.Header
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		mu.Lock()
		seen = req.Header.Clone()
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	// The reserved header is planted directly in the database, bypassing the
	// form validation, so this tests the delivery path's own guarantee rather
	// than the form's.
	headers := map[string]string{
		"Authorization":       "Bearer gateway-token",
		"X-Tenant":            "acme",
		"X-Webhook-Signature": "sha256=forged",
	}
	if _, err := f.db.CreateWebhook(context.Background(), f.envID, server.URL,
		"whsec_test", nil, headers, "", false); err != nil {
		t.Fatalf("create webhook: %v", err)
	}

	f.mint(t, nil)
	waitFor(t, "the delivery", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return seen != nil
	})

	mu.Lock()
	defer mu.Unlock()

	if got := seen.Get("Authorization"); got != "Bearer gateway-token" {
		t.Fatalf("Authorization = %q, want the configured value", got)
	}
	if got := seen.Get("X-Tenant"); got != "acme" {
		t.Fatalf("X-Tenant = %q, want acme", got)
	}
	if got := seen.Get("X-Webhook-Signature"); got == "sha256=forged" {
		t.Fatal("a configured header overwrote the delivery signature")
	}
	if !strings.HasPrefix(seen.Get("X-Webhook-Signature"), "sha256=") {
		t.Fatalf("signature header is missing or malformed: %q", seen.Get("X-Webhook-Signature"))
	}
}
