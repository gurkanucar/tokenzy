package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tokenzy/internal/auth"
	"tokenzy/internal/db"
	"tokenzy/internal/model"
	"tokenzy/internal/token"
)

// harness is the whole service wired the way serve wires it, in front of a
// throwaway database. Testing through buildHandler rather than around it means
// the scope middleware and the routing are under test too — which is where a
// mistake would actually be dangerous.
type harness struct {
	t       *testing.T
	handler http.Handler
	db      *db.DB
	keys    map[string]string // scope -> plaintext key
}

func newHarness(t *testing.T) *harness {
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

	keys := map[string]string{}
	for _, scope := range model.Scopes {
		plaintext, err := auth.GenerateKey(scope, env.Slug)
		if err != nil {
			t.Fatalf("generate key: %v", err)
		}
		_, err = database.CreateAPIKey(ctx, env.ID, auth.HashKey(plaintext),
			auth.KeyPrefix(plaintext), scope, "test")
		if err != nil {
			t.Fatalf("create key: %v", err)
		}
		keys[scope] = plaintext
	}

	// No dispatcher: webhook delivery is exercised in its own test, and a live
	// one here would try to reach the network.
	handler, err := buildHandler(database, nil, token.NewLimits(token.DefaultMaxTTL))
	if err != nil {
		t.Fatalf("build handler: %v", err)
	}

	return &harness{t: t, handler: handler, db: database, keys: keys}
}

// do sends a request with the key for scope ("" for no key at all).
func (h *harness) do(method, path, scope string, body any) *httptest.ResponseRecorder {
	h.t.Helper()

	var reader *bytes.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			h.t.Fatalf("marshal body: %v", err)
		}
		reader = bytes.NewReader(encoded)
	} else {
		reader = bytes.NewReader(nil)
	}

	req := httptest.NewRequest(method, path, reader)
	if scope != "" {
		req.Header.Set(auth.HeaderName, h.keys[scope])
	}
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, req)
	return rec
}

// decode reads a JSON response, failing the test on an unexpected status.
func (h *harness) decode(rec *httptest.ResponseRecorder, wantStatus int, dst any) {
	h.t.Helper()
	if rec.Code != wantStatus {
		h.t.Fatalf("status = %d, want %d; body: %s", rec.Code, wantStatus, rec.Body.String())
	}
	if dst == nil {
		return
	}
	if err := json.Unmarshal(rec.Body.Bytes(), dst); err != nil {
		h.t.Fatalf("decode response: %v; body: %s", err, rec.Body.String())
	}
}

type issued struct {
	ID        string `json:"id"`
	Token     string `json:"token"`
	ExpiresAt string `json:"expiresAt"`
	MaxUses   *int64 `json:"maxUses"`
}

// issue mints a token through the API and returns it.
func (h *harness) issue(payload any, maxUses *int64, ttl int64) issued {
	h.t.Helper()

	rec := h.do("POST", "/v1/tokens", model.ScopeWrite, map[string]any{
		"payload":    payload,
		"maxUses":    maxUses,
		"ttlSeconds": ttl,
	})
	var out issued
	h.decode(rec, http.StatusCreated, &out)
	return out
}

func ptr(v int64) *int64 { return &v }

// TestIssueAndConsumeRoundTrip: the payload that comes back is the payload that
// went in, byte for byte in meaning, and the usage counters read correctly.
func TestIssueAndConsumeRoundTrip(t *testing.T) {
	h := newHarness(t)

	payload := map[string]any{
		"userId": "usr_123",
		"action": "accept_invitation",
		"nested": map[string]any{"seats": float64(3)},
	}
	tok := h.issue(payload, ptr(1), 900)

	if !strings.HasPrefix(tok.Token, token.ValuePrefix) {
		t.Fatalf("token %q does not start with %q", tok.Token, token.ValuePrefix)
	}
	if len(tok.Token) != len(token.ValuePrefix)+64 {
		t.Fatalf("token length = %d, want %d", len(tok.Token), len(token.ValuePrefix)+64)
	}
	if !strings.HasPrefix(tok.ID, token.IDPrefix) {
		t.Fatalf("id %q does not start with %q", tok.ID, token.IDPrefix)
	}

	var out struct {
		Valid   bool           `json:"valid"`
		Payload map[string]any `json:"payload"`
		Usage   struct {
			Used      int64  `json:"used"`
			Maximum   *int64 `json:"maximum"`
			Remaining *int64 `json:"remaining"`
		} `json:"usage"`
	}
	h.decode(h.do("POST", "/v1/consume", model.ScopeConsume,
		map[string]any{"token": tok.Token}), http.StatusOK, &out)

	if !out.Valid {
		t.Fatal("valid = false on a fresh token")
	}
	if out.Payload["userId"] != "usr_123" {
		t.Fatalf("payload came back as %v", out.Payload)
	}
	nested, ok := out.Payload["nested"].(map[string]any)
	if !ok || nested["seats"] != float64(3) {
		t.Fatalf("nested payload came back as %v", out.Payload["nested"])
	}
	if out.Usage.Used != 1 || out.Usage.Maximum == nil || *out.Usage.Maximum != 1 {
		t.Fatalf("usage = %+v, want used 1 of 1", out.Usage)
	}
	if out.Usage.Remaining == nil || *out.Usage.Remaining != 0 {
		t.Fatalf("remaining = %v, want 0", out.Usage.Remaining)
	}
}

// TestConsumeGivesOneAnswerToEveryFailure is the anti-oracle test: whatever is
// wrong with a token, the caller learns the same thing. If a future change
// starts distinguishing "expired" from "unknown", this fails.
func TestConsumeGivesOneAnswerToEveryFailure(t *testing.T) {
	h := newHarness(t)

	spent := h.issue(map[string]any{"a": 1}, ptr(1), 900)
	h.decode(h.do("POST", "/v1/consume", model.ScopeConsume,
		map[string]any{"token": spent.Token}), http.StatusOK, nil)

	revoked := h.issue(map[string]any{"a": 1}, nil, 900)
	h.decode(h.do("POST", "/v1/manage/tokens/"+revoked.ID+"/revoke", model.ScopeAdmin, nil),
		http.StatusOK, nil)

	// An expired token has to be planted directly: the API refuses to mint one
	// that is already dead, which is itself the right behaviour.
	expired := h.issue(map[string]any{"a": 1}, nil, 900)
	if _, err := h.db.Write.Exec(`UPDATE tokens SET expires_at = ? WHERE id = ?`,
		time.Now().Add(-time.Hour).Unix(), expired.ID); err != nil {
		t.Fatalf("age the token: %v", err)
	}

	cases := map[string]string{
		"never issued":  token.ValuePrefix + strings.Repeat("a", 64),
		"malformed":     "not-a-token",
		"already spent": spent.Token,
		"revoked":       revoked.Token,
		"expired":       expired.Token,
	}

	var first string
	for name, value := range cases {
		rec := h.do("POST", "/v1/consume", model.ScopeConsume, map[string]any{"token": value})
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status = %d, want 200", name, rec.Code)
		}

		body := rec.Body.String()
		if first == "" {
			first = body
		} else if body != first {
			t.Fatalf("%s answered %q but another failure answered %q — "+
				"the response distinguishes failure modes", name, body, first)
		}

		var out struct {
			Valid bool   `json:"valid"`
			Error string `json:"error"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("%s: decode: %v", name, err)
		}
		if out.Valid || out.Error != "invalid_token" {
			t.Fatalf("%s: got %+v, want valid=false error=invalid_token", name, out)
		}
	}
}

// TestScopeMatrix walks the whole grid: every endpoint against every scope.
// The line that matters most is the last one — a consume key must not be able
// to read a token back out, because that would make a token on a phone as
// powerful as the key that issued it.
func TestScopeMatrix(t *testing.T) {
	h := newHarness(t)
	tok := h.issue(map[string]any{"a": 1}, nil, 900)

	type call struct {
		method string
		path   string
		body   any
	}

	consumeCall := call{"POST", "/v1/consume", map[string]any{"token": tok.Token}}
	issueCall := call{"POST", "/v1/tokens", map[string]any{"payload": map[string]any{"a": 1}, "ttlSeconds": 60}}
	listCall := call{"GET", "/v1/manage/tokens", nil}
	readCall := call{"GET", "/v1/manage/tokens/" + tok.ID, nil}

	cases := []struct {
		name    string
		scope   string
		call    call
		allowed bool
	}{
		{"consume key redeems", model.ScopeConsume, consumeCall, true},
		{"consume key cannot issue", model.ScopeConsume, issueCall, false},
		{"consume key cannot list", model.ScopeConsume, listCall, false},
		{"consume key cannot read a token back", model.ScopeConsume, readCall, false},

		{"write key redeems", model.ScopeWrite, consumeCall, true},
		{"write key issues", model.ScopeWrite, issueCall, true},
		{"write key cannot list", model.ScopeWrite, listCall, false},
		{"write key cannot read a token back", model.ScopeWrite, readCall, false},

		{"admin key redeems", model.ScopeAdmin, consumeCall, true},
		{"admin key issues", model.ScopeAdmin, issueCall, true},
		{"admin key lists", model.ScopeAdmin, listCall, true},
		{"admin key reads a token back", model.ScopeAdmin, readCall, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := h.do(tc.call.method, tc.call.path, tc.scope, tc.call.body)
			forbidden := rec.Code == http.StatusForbidden

			if tc.allowed && forbidden {
				t.Fatalf("refused with 403: %s", rec.Body.String())
			}
			if !tc.allowed && !forbidden {
				t.Fatalf("allowed with status %d, want 403: %s", rec.Code, rec.Body.String())
			}
		})
	}
}

// TestNoKeyIsRejected covers the missing and bogus header cases.
func TestNoKeyIsRejected(t *testing.T) {
	h := newHarness(t)

	endpoints := []struct{ method, path string }{
		{"POST", "/v1/consume"},
		{"POST", "/v1/tokens"},
		{"GET", "/v1/manage/tokens"},
		{"GET", "/v1/manage/tokens/tok_whatever"},
		{"POST", "/v1/manage/tokens/tok_whatever/revoke"},
		{"DELETE", "/v1/manage/tokens/tok_whatever"},
	}
	for _, e := range endpoints {
		// 401 before 404: an unauthenticated caller must not learn whether an id
		// exists.
		if rec := h.do(e.method, e.path, "", map[string]any{}); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s with no key: status = %d, want 401", e.method, e.path, rec.Code)
		}
	}

	req := httptest.NewRequest("POST", "/v1/consume", strings.NewReader(`{"token":"x"}`))
	req.Header.Set(auth.HeaderName, "tk_admin_prod_totallymadeup")
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("bogus key: status = %d, want 401", rec.Code)
	}
}

// TestRevokedKeyStopsWorking: revocation takes effect on the next request,
// with no cache to wait for.
func TestRevokedKeyStopsWorking(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	keys, err := h.db.ListAPIKeys(ctx, 1)
	if err != nil {
		t.Fatalf("list keys: %v", err)
	}
	for _, k := range keys {
		if k.Scope == model.ScopeWrite {
			if err := h.db.RevokeAPIKey(ctx, k.ID, k.EnvironmentID); err != nil {
				t.Fatalf("revoke key: %v", err)
			}
		}
	}

	rec := h.do("POST", "/v1/tokens", model.ScopeWrite, map[string]any{
		"payload": map[string]any{"a": 1}, "ttlSeconds": 60,
	})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 after the key was revoked", rec.Code)
	}
}

// TestIssueValidation checks every input rule, including the two TTL ceilings.
func TestIssueValidation(t *testing.T) {
	h := newHarness(t)

	oversized := strings.Repeat("x", token.MaxPayloadBytes)

	cases := []struct {
		name string
		body map[string]any
	}{
		{"no payload", map[string]any{"ttlSeconds": 60}},
		{"no ttl", map[string]any{"payload": map[string]any{"a": 1}}},
		{"zero ttl", map[string]any{"payload": map[string]any{"a": 1}, "ttlSeconds": 0}},
		{"negative ttl", map[string]any{"payload": map[string]any{"a": 1}, "ttlSeconds": -5}},
		{"ttl above the ceiling", map[string]any{
			"payload": map[string]any{"a": 1}, "ttlSeconds": int64(365 * 24 * 3600 * 50),
		}},
		{"zero maxUses", map[string]any{
			"payload": map[string]any{"a": 1}, "ttlSeconds": 60, "maxUses": 0,
		}},
		{"negative maxUses", map[string]any{
			"payload": map[string]any{"a": 1}, "ttlSeconds": 60, "maxUses": -1,
		}},
		{"payload above 16 KiB", map[string]any{
			"payload": map[string]any{"blob": oversized}, "ttlSeconds": 60,
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := h.do("POST", "/v1/tokens", model.ScopeWrite, tc.body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400: %s", rec.Code, rec.Body.String())
			}
		})
	}
}

// TestManageListsMetadataOnly: the listing must not contain a token or a
// payload anywhere in its bytes, however the shape changes.
func TestManageListsMetadataOnly(t *testing.T) {
	h := newHarness(t)

	const secretMarker = "sentinel-payload-value"
	tok := h.issue(map[string]any{"secret": secretMarker}, nil, 900)

	rec := h.do("GET", "/v1/manage/tokens", model.ScopeAdmin, nil)
	body := rec.Body.String()
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, body)
	}
	if strings.Contains(body, tok.Token) {
		t.Fatal("the listing contains a plaintext token")
	}
	if strings.Contains(body, secretMarker) {
		t.Fatal("the listing contains a token payload")
	}

	var out struct {
		Tokens []struct {
			ID     string `json:"id"`
			Prefix string `json:"prefix"`
			Status string `json:"status"`
		} `json:"tokens"`
		NextCursor string `json:"nextCursor"`
	}
	h.decode(rec, http.StatusOK, &out)
	if len(out.Tokens) != 1 {
		t.Fatalf("listed %d tokens, want 1", len(out.Tokens))
	}
	if out.Tokens[0].Prefix != tok.Token[:token.PrefixLen] {
		t.Fatalf("prefix = %q, want %q", out.Tokens[0].Prefix, tok.Token[:token.PrefixLen])
	}
	if out.Tokens[0].Status != token.StatusActive {
		t.Fatalf("status = %q, want active", out.Tokens[0].Status)
	}
}

// TestManageDetailReturnsTheTokenWithoutSpendingIt is the plaintext decision
// being cashed in — and the guarantee that comes with it.
func TestManageDetailReturnsTheTokenWithoutSpendingIt(t *testing.T) {
	h := newHarness(t)
	tok := h.issue(map[string]any{"userId": "usr_1"}, ptr(1), 900)

	var detail struct {
		ID      string         `json:"id"`
		Token   string         `json:"token"`
		Status  string         `json:"status"`
		Payload map[string]any `json:"payload"`
	}
	// Read it three times: inspection is not redemption, however often it
	// happens.
	for i := 0; i < 3; i++ {
		h.decode(h.do("GET", "/v1/manage/tokens/"+tok.ID, model.ScopeAdmin, nil),
			http.StatusOK, &detail)

		if detail.Token != tok.Token {
			t.Fatal("the token returned differs from the one issued")
		}
		if detail.Status != token.StatusActive {
			t.Fatalf("status = %q after inspection %d, want active", detail.Status, i+1)
		}
		if detail.Payload["userId"] != "usr_1" {
			t.Fatalf("payload = %v", detail.Payload)
		}
	}

	// Still redeemable exactly once.
	h.decode(h.do("POST", "/v1/consume", model.ScopeConsume,
		map[string]any{"token": tok.Token}), http.StatusOK, nil)
}

// TestRevokeWorksWithoutTheToken: cancelling needs the id, not the secret —
// the "the phone is gone" case.
func TestRevokeWorksWithoutTheToken(t *testing.T) {
	h := newHarness(t)
	tok := h.issue(map[string]any{"a": 1}, nil, 900)

	var out struct {
		Status    string  `json:"status"`
		RevokedAt *string `json:"revokedAt"`
	}
	h.decode(h.do("POST", "/v1/manage/tokens/"+tok.ID+"/revoke", model.ScopeAdmin, nil),
		http.StatusOK, &out)

	if out.Status != token.StatusRevoked {
		t.Fatalf("status = %q, want revoked", out.Status)
	}
	if out.RevokedAt == nil {
		t.Fatal("revokedAt is null on a revoked token")
	}

	// Revoking again is not an error: the caller wanted it dead, and it is.
	h.decode(h.do("POST", "/v1/manage/tokens/"+tok.ID+"/revoke", model.ScopeAdmin, nil),
		http.StatusOK, nil)

	rec := h.do("POST", "/v1/consume", model.ScopeConsume, map[string]any{"token": tok.Token})
	var consumed struct {
		Valid bool `json:"valid"`
	}
	h.decode(rec, http.StatusOK, &consumed)
	if consumed.Valid {
		t.Fatal("a revoked token was redeemed")
	}
}

// TestManageStatusFilterAndDelete covers the listing filter and the hard delete.
func TestManageStatusFilterAndDelete(t *testing.T) {
	h := newHarness(t)

	live := h.issue(map[string]any{"a": 1}, nil, 900)
	gone := h.issue(map[string]any{"a": 2}, nil, 900)
	h.decode(h.do("POST", "/v1/manage/tokens/"+gone.ID+"/revoke", model.ScopeAdmin, nil),
		http.StatusOK, nil)

	var out struct {
		Tokens []struct {
			ID string `json:"id"`
		} `json:"tokens"`
	}
	h.decode(h.do("GET", "/v1/manage/tokens?status=active", model.ScopeAdmin, nil),
		http.StatusOK, &out)
	if len(out.Tokens) != 1 || out.Tokens[0].ID != live.ID {
		t.Fatalf("active filter returned %+v, want just %s", out.Tokens, live.ID)
	}

	if rec := h.do("GET", "/v1/manage/tokens?status=nonsense", model.ScopeAdmin, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown status: status = %d, want 400", rec.Code)
	}

	if rec := h.do("DELETE", "/v1/manage/tokens/"+gone.ID, model.ScopeAdmin, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("delete: status = %d, want 204", rec.Code)
	}
	if rec := h.do("GET", "/v1/manage/tokens/"+gone.ID, model.ScopeAdmin, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("get after delete: status = %d, want 404", rec.Code)
	}
	if rec := h.do("GET", "/v1/manage/tokens/tok_doesnotexist", model.ScopeAdmin, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown id: status = %d, want 404", rec.Code)
	}
}

// TestTokensAreUnique is a cheap sanity check on the generator: a repeat in a
// small sample would mean the randomness is not what the design assumes.
func TestTokensAreUnique(t *testing.T) {
	h := newHarness(t)

	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		tok := h.issue(map[string]any{"i": i}, nil, 900)
		if seen[tok.Token] {
			t.Fatal("the generator produced a duplicate token")
		}
		seen[tok.Token] = true
	}
}

// TestUIRequiresASession: the panel is the one place a token can be read back
// from, so an anonymous browser must not get anywhere near it.
func TestUIRequiresASession(t *testing.T) {
	h := newHarness(t)

	for _, path := range []string{"/ui/projects", "/ui/p/test/prod/tokens", "/ui/p/test/prod/keys"} {
		req := httptest.NewRequest("GET", path, nil)
		rec := httptest.NewRecorder()
		h.handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusSeeOther {
			t.Errorf("%s: status = %d, want 303", path, rec.Code)
			continue
		}
		if got := rec.Header().Get("Location"); got != "/ui/login" {
			t.Errorf("%s: redirected to %q, want /ui/login", path, got)
		}
	}
}
