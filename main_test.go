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
	"tokenzy/internal/otp"
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
	handler, err := buildHandler(database, nil,
		token.NewLimits(token.DefaultMaxTTL), otp.NewLimits(otp.DefaultMaxTTL))
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

// One-time codes.

type issuedCode struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	Identifier  string `json:"identifier"`
	Code        string `json:"code"`
	ExpiresAt   string `json:"expiresAt"`
	MaxAttempts int64  `json:"maxAttempts"`
	Reused      bool   `json:"reused"`
}

// issueCode asks for a code through the API.
func (h *harness) issueCode(body map[string]any, wantStatus int) issuedCode {
	h.t.Helper()
	rec := h.do("POST", "/v1/otp", model.ScopeWrite, body)
	var out issuedCode
	h.decode(rec, wantStatus, &out)
	return out
}

// checkCode validates one and reports whether it was accepted.
func (h *harness) checkCode(otpType, identifier, code string) bool {
	h.t.Helper()
	rec := h.do("POST", "/v1/otp/validate", model.ScopeConsume, map[string]any{
		"type": otpType, "identifier": identifier, "code": code,
	})
	var out struct {
		Valid bool   `json:"valid"`
		Error string `json:"error"`
	}
	h.decode(rec, http.StatusOK, &out)
	if !out.Valid && out.Error != "invalid_code" {
		h.t.Fatalf("a rejection came back with error %q, want invalid_code", out.Error)
	}
	return out.Valid
}

// TestOTPRoundTrip: issue, validate, and the code dies on the way through.
func TestOTPRoundTrip(t *testing.T) {
	h := newHarness(t)

	issued := h.issueCode(map[string]any{
		"type": "password_reset", "identifier": "user@example.com", "ttlSeconds": 300,
	}, http.StatusCreated)

	if len(issued.Code) != otp.DefaultLength {
		t.Fatalf("code is %d digits, want %d", len(issued.Code), otp.DefaultLength)
	}
	if !strings.HasPrefix(issued.ID, otp.IDPrefix) {
		t.Fatalf("id %q does not start with %q", issued.ID, otp.IDPrefix)
	}
	if issued.Reused {
		t.Fatal("a first issuance reported itself as a resend")
	}
	if issued.MaxAttempts != otp.DefaultAttempts {
		t.Fatalf("maxAttempts = %d, want the default %d", issued.MaxAttempts, otp.DefaultAttempts)
	}

	if !h.checkCode("password_reset", "user@example.com", issued.Code) {
		t.Fatal("a fresh code was refused")
	}
	// Spending it is what killed it.
	if h.checkCode("password_reset", "user@example.com", issued.Code) {
		t.Fatal("the same code was accepted twice")
	}
}

// TestOTPResendOverTheAPI: the second call returns 200 and the same code,
// where a first issuance returns 201.
func TestOTPResendOverTheAPI(t *testing.T) {
	h := newHarness(t)

	first := h.issueCode(map[string]any{
		"type": "password_reset", "identifier": "user@example.com", "ttlSeconds": 300,
	}, http.StatusCreated)

	second := h.issueCode(map[string]any{
		"type": "password_reset", "identifier": "user@example.com", "ttlSeconds": 3600,
	}, http.StatusOK)

	if !second.Reused {
		t.Fatal("the second issuance did not report itself as a resend")
	}
	if second.Code != first.Code || second.ID != first.ID {
		t.Fatal("the resend produced a different code")
	}
	if second.ExpiresAt != first.ExpiresAt {
		t.Fatalf("the resend extended the expiry from %s to %s", first.ExpiresAt, second.ExpiresAt)
	}
}

// TestOTPValidateGivesOneAnswerToEveryFailure is the anti-oracle test. Probing
// an address must not reveal whether a reset is in flight for it.
func TestOTPValidateGivesOneAnswerToEveryFailure(t *testing.T) {
	h := newHarness(t)

	live := h.issueCode(map[string]any{
		"type": "password_reset", "identifier": "live@example.com", "ttlSeconds": 300,
	}, http.StatusCreated)

	spent := h.issueCode(map[string]any{
		"type": "password_reset", "identifier": "spent@example.com", "ttlSeconds": 300,
	}, http.StatusCreated)
	h.checkCode("password_reset", "spent@example.com", spent.Code)

	revoked := h.issueCode(map[string]any{
		"type": "password_reset", "identifier": "revoked@example.com", "ttlSeconds": 300,
	}, http.StatusCreated)
	h.decode(h.do("POST", "/v1/manage/otps/"+revoked.ID+"/revoke", model.ScopeAdmin, nil),
		http.StatusOK, nil)

	wrong := "000000"
	if wrong == live.Code {
		wrong = "111111"
	}

	cases := map[string][3]string{
		"wrong code":          {"password_reset", "live@example.com", wrong},
		"no code ever issued": {"password_reset", "nobody@example.com", "123456"},
		"wrong type":          {"email_verify", "live@example.com", live.Code},
		"already spent":       {"password_reset", "spent@example.com", spent.Code},
		"revoked":             {"password_reset", "revoked@example.com", revoked.Code},
	}

	var first string
	for name, c := range cases {
		rec := h.do("POST", "/v1/otp/validate", model.ScopeConsume, map[string]any{
			"type": c[0], "identifier": c[1], "code": c[2],
		})
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
	}
}

// TestOTPAttemptCeilingOverTheAPI: the defence works end to end.
func TestOTPAttemptCeilingOverTheAPI(t *testing.T) {
	h := newHarness(t)

	issued := h.issueCode(map[string]any{
		"type": "password_reset", "identifier": "user@example.com",
		"ttlSeconds": 300, "maxAttempts": 3,
	}, http.StatusCreated)

	wrong := "000000"
	if wrong == issued.Code {
		wrong = "111111"
	}
	for i := 0; i < 3; i++ {
		if h.checkCode("password_reset", "user@example.com", wrong) {
			t.Fatalf("guess %d was accepted", i+1)
		}
	}

	if h.checkCode("password_reset", "user@example.com", issued.Code) {
		t.Fatal("the correct code was accepted after the attempt ceiling was reached")
	}

	var detail struct {
		Status       string `json:"status"`
		AttemptCount int64  `json:"attemptCount"`
		MaxAttempts  int64  `json:"maxAttempts"`
	}
	h.decode(h.do("GET", "/v1/manage/otps/"+issued.ID, model.ScopeAdmin, nil), http.StatusOK, &detail)
	if detail.Status != otp.StatusLocked {
		t.Fatalf("status = %q, want locked", detail.Status)
	}
	if detail.AttemptCount != 3 {
		t.Fatalf("attemptCount = %d, want 3", detail.AttemptCount)
	}
}

// TestOTPValidation covers the input rules.
func TestOTPValidation(t *testing.T) {
	h := newHarness(t)

	cases := []struct {
		name string
		body map[string]any
	}{
		{"no type", map[string]any{"identifier": "a@b.c", "ttlSeconds": 300}},
		{"bad type", map[string]any{"type": "Password Reset", "identifier": "a@b.c", "ttlSeconds": 300}},
		{"no identifier", map[string]any{"type": "t", "ttlSeconds": 300}},
		{"identifier too long", map[string]any{
			"type": "t", "identifier": strings.Repeat("x", 257), "ttlSeconds": 300,
		}},
		{"no ttl", map[string]any{"type": "t", "identifier": "a@b.c"}},
		{"ttl over the ceiling", map[string]any{"type": "t", "identifier": "a@b.c", "ttlSeconds": 90000}},
		{"length too short", map[string]any{"type": "t", "identifier": "a@b.c", "ttlSeconds": 300, "length": 3}},
		{"length too long", map[string]any{"type": "t", "identifier": "a@b.c", "ttlSeconds": 300, "length": 11}},
		// Zero attempts must be rejected rather than read as "unlimited": a
		// code with no ceiling is a six-digit password.
		{"zero attempts", map[string]any{"type": "t", "identifier": "a@b.c", "ttlSeconds": 300, "maxAttempts": 0}},
		{"too many attempts", map[string]any{"type": "t", "identifier": "a@b.c", "ttlSeconds": 300, "maxAttempts": 21}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if rec := h.do("POST", "/v1/otp", model.ScopeWrite, tc.body); rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400: %s", rec.Code, rec.Body.String())
			}
		})
	}

	// Validation needs all three fields; a missing one is the caller's mistake,
	// not a failed check, so it says so rather than answering invalid_code.
	for _, body := range []map[string]any{
		{"identifier": "a@b.c", "code": "123456"},
		{"type": "t", "code": "123456"},
		{"type": "t", "identifier": "a@b.c"},
	} {
		if rec := h.do("POST", "/v1/otp/validate", model.ScopeConsume, body); rec.Code != http.StatusBadRequest {
			t.Errorf("incomplete validate: status = %d, want 400", rec.Code)
		}
	}
}

// TestOTPScopeMatrix: a client key may spend a code but must not be able to
// mint one or read one back.
func TestOTPScopeMatrix(t *testing.T) {
	h := newHarness(t)
	issued := h.issueCode(map[string]any{
		"type": "password_reset", "identifier": "user@example.com", "ttlSeconds": 300,
	}, http.StatusCreated)

	issueBody := map[string]any{"type": "t", "identifier": "a@b.c", "ttlSeconds": 300}
	validateBody := map[string]any{"type": "password_reset", "identifier": "user@example.com", "code": "000000"}

	cases := []struct {
		name    string
		scope   string
		method  string
		path    string
		body    any
		allowed bool
	}{
		{"consume validates", model.ScopeConsume, "POST", "/v1/otp/validate", validateBody, true},
		{"consume cannot issue", model.ScopeConsume, "POST", "/v1/otp", issueBody, false},
		{"consume cannot list", model.ScopeConsume, "GET", "/v1/manage/otps", nil, false},
		{"consume cannot read a code back", model.ScopeConsume, "GET", "/v1/manage/otps/" + issued.ID, nil, false},

		{"write issues", model.ScopeWrite, "POST", "/v1/otp", issueBody, true},
		{"write cannot read a code back", model.ScopeWrite, "GET", "/v1/manage/otps/" + issued.ID, nil, false},

		{"admin lists", model.ScopeAdmin, "GET", "/v1/manage/otps", nil, true},
		{"admin reads a code back", model.ScopeAdmin, "GET", "/v1/manage/otps/" + issued.ID, nil, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := h.do(tc.method, tc.path, tc.scope, tc.body)
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

// TestOTPListingCarriesNoCode.
func TestOTPListingCarriesNoCode(t *testing.T) {
	h := newHarness(t)

	issued := h.issueCode(map[string]any{
		"type": "password_reset", "identifier": "user@example.com", "ttlSeconds": 300,
	}, http.StatusCreated)

	rec := h.do("GET", "/v1/manage/otps", model.ScopeAdmin, nil)
	body := rec.Body.String()
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, body)
	}
	if strings.Contains(body, issued.Code) {
		t.Fatal("the listing contains a plaintext code")
	}

	var out struct {
		OTPs []struct {
			ID         string `json:"id"`
			Type       string `json:"type"`
			Identifier string `json:"identifier"`
			Status     string `json:"status"`
		} `json:"otps"`
	}
	h.decode(rec, http.StatusOK, &out)
	if len(out.OTPs) != 1 {
		t.Fatalf("listed %d codes, want 1", len(out.OTPs))
	}
	if out.OTPs[0].Identifier != "user@example.com" || out.OTPs[0].Status != otp.StatusActive {
		t.Fatalf("listing row = %+v", out.OTPs[0])
	}

	// Reading the single record does return it, and does not spend it.
	var detail struct {
		Code string `json:"code"`
	}
	h.decode(h.do("GET", "/v1/manage/otps/"+issued.ID, model.ScopeAdmin, nil), http.StatusOK, &detail)
	if detail.Code != issued.Code {
		t.Fatal("the code returned for inspection differs from the one issued")
	}
	if !h.checkCode("password_reset", "user@example.com", issued.Code) {
		t.Fatal("inspecting the code spent it")
	}
}
