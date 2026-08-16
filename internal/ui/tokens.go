package ui

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"tokenzy/internal/db"
	"tokenzy/internal/model"
	"tokenzy/internal/token"
	"tokenzy/internal/ttl"
)

// pageSize is how many tokens one "Load more" brings in.
const pageSize = 25

// StatusChip is one filter button, with the count it currently matches.
type StatusChip struct {
	Status string
	Label  string
	Count  int64
	Active bool
	// URL is the listing address for this filter. The chips are links to real
	// URLs rather than pure htmx swaps, so a filtered view can be bookmarked,
	// reloaded and shared.
	URL string
}

// TokenRow is one token in the table.
type TokenRow struct {
	Project string
	Env     string
	Token   model.Token
	Status  string
	// Filter is the status filter the listing is under, carried so that an
	// action taken from a row returns to the same view rather than resetting
	// to "all".
	Filter string
	// Uses reads "1 / 1" or "3 / ∞" — the two facts a glance needs.
	Uses     string
	Expires  string
	Created  string
	LastUsed string
	// Detail is set only on an expanded row.
	Detail *TokenDetail
}

// TokenDetail is the expanded view under a row.
type TokenDetail struct {
	// Payload is pretty-printed for reading.
	Payload string
	// Value is the plaintext token, and is filled in only after the operator
	// has explicitly asked to see it. Until then the token is not in the page
	// at all — not hidden with CSS, not present in the DOM.
	Value string
}

// TokenForm is the state of the issue form.
//
// It exists so that a rejected submission comes back with what was typed still
// in it. Losing a carefully written payload because the lifetime was a digit
// too long is the kind of small cruelty that makes people stop using a panel.
type TokenForm struct {
	Payload  string
	TTLValue string
	TTLUnit  string
	MaxUses  string
}

// defaultTokenForm is what a fresh form starts with: a payload shaped like a
// reference rather than a record, and a lifetime short enough to be a sensible
// default for the links most people are issuing.
func defaultTokenForm() TokenForm {
	return TokenForm{
		Payload:  "{\n  \"userId\": \"usr_123\",\n  \"action\": \"accept_invitation\"\n}",
		TTLValue: "15",
		TTLUnit:  ttl.DefaultUnit,
		MaxUses:  "1",
	}
}

// TokensView backs tokens.html and its fragments.
type TokensView struct {
	Layout
	Rows  []TokenRow
	Chips []StatusChip
	// NewToken is set exactly once, on the response to an issuance.
	NewToken   string
	NewTokenID string
	Error      string
	// MoreURL loads the next page; empty when the listing is exhausted.
	MoreURL string
	// Status is the active filter, carried into the fragments' own URLs.
	Status string
	Form   TokenForm
	// TTLUnits populates the lifetime unit dropdown.
	TTLUnits []ttl.Unit
	// MaxTTLSeconds bounds the field in the browser; MaxTTLLabel says the same
	// thing in words, so the ceiling is visible before a request is rejected
	// for exceeding it.
	MaxTTLSeconds int64
	MaxTTLLabel   string
	Total         int64
}

// tokensQuery is everything that shapes a rendering of the tokens page. It is
// a struct rather than eight positional arguments because most callers care
// about one field and would otherwise have to count commas to reach it.
type tokensQuery struct {
	scope      envScope
	status     string
	cursor     string
	newToken   string
	newTokenID string
	errMsg     string
	form       *TokenForm
}

func (s *Server) tokensBase(scope envScope) string {
	return fmt.Sprintf("/ui/p/%s/%s/tokens", scope.Project.Slug, scope.Env.Slug)
}

// tokensView assembles the whole page: the filter chips with live counts, and
// one page of rows.
func (s *Server) tokensView(r *http.Request, q tokensQuery) (TokensView, error) {
	scope := q.scope
	status := q.status
	if status != "" && !token.ValidStatus(status) {
		status = ""
	}

	form := defaultTokenForm()
	if q.form != nil {
		form = *q.form
	}

	tokens, next, err := s.db.ListTokens(r.Context(), scope.Env.ID, db.TokenFilter{
		Status: status,
		Limit:  pageSize,
		Cursor: db.ParseCursor(q.cursor),
	})
	if err != nil {
		return TokensView{}, err
	}

	counts, err := s.db.CountTokensByStatus(r.Context(), scope.Env.ID)
	if err != nil {
		return TokensView{}, err
	}

	base := s.tokensBase(scope)
	now := time.Now().Unix()

	rows := make([]TokenRow, 0, len(tokens))
	for _, t := range tokens {
		rows = append(rows, s.tokenRowFor(scope, t, now, status))
	}

	var total int64
	for _, n := range counts {
		total += n
	}

	chips := []StatusChip{{
		Status: "",
		Label:  "All",
		Count:  total,
		Active: status == "",
		URL:    base,
	}}
	for _, name := range token.Statuses {
		chips = append(chips, StatusChip{
			Status: name,
			Label:  name,
			Count:  counts[name],
			Active: status == name,
			URL:    base + "?status=" + url.QueryEscape(name),
		})
	}

	var moreURL string
	if next.Set() {
		query := url.Values{}
		if status != "" {
			query.Set("status", status)
		}
		query.Set("cursor", next.String())
		moreURL = base + "/rows?" + query.Encode()
	}

	project, env := scope.Project, scope.Env
	ceiling := s.limits.Ceiling()
	return TokensView{
		Layout:        s.layoutFor(r, "Tokens · "+project.Name, &project, &env, scope.Envs, "tokens"),
		Rows:          rows,
		Chips:         chips,
		NewToken:      q.newToken,
		NewTokenID:    q.newTokenID,
		Error:         q.errMsg,
		MoreURL:       moreURL,
		Status:        status,
		Form:          form,
		TTLUnits:      ttl.Units,
		MaxTTLSeconds: int64(ceiling / time.Second),
		MaxTTLLabel:   ttl.Human(ceiling),
		Total:         total,
	}, nil
}

func (s *Server) tokenRowFor(scope envScope, t model.Token, now int64, filter string) TokenRow {
	uses := strconv.FormatInt(t.UsedCount, 10) + " / ∞"
	if t.MaxUses != nil {
		uses = fmt.Sprintf("%d / %d", t.UsedCount, *t.MaxUses)
	}

	return TokenRow{
		Project:  scope.Project.Slug,
		Env:      scope.Env.Slug,
		Token:    t,
		Status:   token.StatusOf(t, now),
		Filter:   filter,
		Uses:     uses,
		Expires:  formatTime(t.ExpiresAt),
		Created:  formatTime(t.CreatedAt),
		LastUsed: formatTimePtr(t.LastUsedAt),
	}
}

func (s *Server) tokensPage(w http.ResponseWriter, r *http.Request) {
	scope, ok := s.resolveEnv(w, r)
	if !ok {
		return
	}
	view, err := s.tokensView(r, tokensQuery{scope: scope, status: r.URL.Query().Get("status")})
	if err != nil {
		internalError(w, "list tokens", err)
		return
	}
	// A filter chip is a real navigation to this same URL, so htmx gets the
	// panel and the address bar gets a view somebody can send to a colleague.
	s.renderListing(w, r, "tokens.html", "tokens_panel", view)
}

// tokenRows answers "Load more" with the next page of rows plus a fresh
// trigger, so paging never re-renders the form or the chips above it.
func (s *Server) tokenRows(w http.ResponseWriter, r *http.Request) {
	scope, ok := s.resolveEnv(w, r)
	if !ok {
		return
	}
	query := r.URL.Query()
	view, err := s.tokensView(r, tokensQuery{
		scope:  scope,
		status: query.Get("status"),
		cursor: query.Get("cursor"),
	})
	if err != nil {
		internalError(w, "list tokens", err)
		return
	}
	s.renderFragment(w, http.StatusOK, "token_rows", view)
}

func (s *Server) createToken(w http.ResponseWriter, r *http.Request) {
	scope, ok := s.resolveEnv(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}

	status := r.FormValue("status")

	// Everything the operator typed, kept together so a rejection can hand it
	// straight back rather than clearing the form.
	form := TokenForm{
		Payload:  r.FormValue("payload"),
		TTLValue: r.FormValue("ttlValue"),
		TTLUnit:  r.FormValue("ttlUnit"),
		MaxUses:  r.FormValue("maxUses"),
	}

	fail := func(msg string) {
		s.renderTokensPanel(w, r, tokensQuery{
			scope: scope, status: status, errMsg: msg, form: &form,
		}, http.StatusUnprocessableEntity)
	}

	payload, err := token.ValidatePayload(json.RawMessage(form.Payload))
	if err != nil {
		fail(err.Error())
		return
	}

	// The unit is applied here rather than in the browser, so the form works
	// with JavaScript switched off and the ceiling is enforced in one place.
	ttl, err := s.limits.ParseTTL(form.TTLValue, form.TTLUnit)
	if err != nil {
		fail(err.Error())
		return
	}

	// An empty maxUses field means "no limit", which is the difference between
	// a season pass and a single-use one — so it is a deliberate blank, not a
	// missing value to complain about.
	var maxUses *int64
	if raw := strings.TrimSpace(form.MaxUses); raw != "" {
		n, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			fail(token.ErrMaxUses.Error())
			return
		}
		maxUses = &n
	}
	if err := token.ValidateMaxUses(maxUses); err != nil {
		fail(err.Error())
		return
	}

	id, err := token.NewID()
	if err != nil {
		internalError(w, "generate token id", err)
		return
	}
	value, err := token.Generate()
	if err != nil {
		internalError(w, "generate token", err)
		return
	}

	created, err := s.db.CreateToken(r.Context(), scope.Env.ID, id, value, payload,
		maxUses, time.Now().Add(ttl).Unix())
	if err != nil {
		internalError(w, "create token", err)
		return
	}

	s.renderTokensPanel(w, r, tokensQuery{
		scope: scope, status: status, newToken: created.Value, newTokenID: created.ID,
	}, http.StatusOK)
}

// tokenDetail expands one row: the payload, and a button that will fetch the
// token itself.
func (s *Server) tokenDetail(w http.ResponseWriter, r *http.Request) {
	scope, ok := s.resolveEnv(w, r)
	if !ok {
		return
	}

	found, err := s.db.GetToken(r.Context(), scope.Env.ID, r.PathValue("id"))
	if errors.Is(err, db.ErrNotFound) {
		http.Error(w, "token not found", http.StatusNotFound)
		return
	}
	if err != nil {
		internalError(w, "get token", err)
		return
	}

	// Reading a token here does not spend it. Nothing on this path touches
	// used_count; a single-use token looked at in the panel is still unused.
	row := s.tokenRowFor(scope, found, time.Now().Unix(), r.URL.Query().Get("status"))
	row.Detail = &TokenDetail{Payload: prettyJSON(found.PayloadJSON)}

	s.renderFragment(w, http.StatusOK, "token_group", row)
}

// tokenRow collapses an expanded row back down.
func (s *Server) tokenRow(w http.ResponseWriter, r *http.Request) {
	scope, ok := s.resolveEnv(w, r)
	if !ok {
		return
	}

	found, err := s.db.GetToken(r.Context(), scope.Env.ID, r.PathValue("id"))
	if errors.Is(err, db.ErrNotFound) {
		http.Error(w, "token not found", http.StatusNotFound)
		return
	}
	if err != nil {
		internalError(w, "get token", err)
		return
	}

	s.renderFragment(w, http.StatusOK, "token_group",
		s.tokenRowFor(scope, found, time.Now().Unix(), r.URL.Query().Get("status")))
}

// revealToken returns the plaintext token for one row.
//
// It is a separate request on purpose. Until the operator clicks, the token is
// not in the HTML the browser holds — so a listing left open on a screen, or
// captured by a screenshot tool, contains prefixes and nothing else.
func (s *Server) revealToken(w http.ResponseWriter, r *http.Request) {
	scope, ok := s.resolveEnv(w, r)
	if !ok {
		return
	}

	found, err := s.db.GetToken(r.Context(), scope.Env.ID, r.PathValue("id"))
	if errors.Is(err, db.ErrNotFound) {
		http.Error(w, "token not found", http.StatusNotFound)
		return
	}
	if err != nil {
		internalError(w, "get token", err)
		return
	}

	value, err := s.db.GetTokenValue(r.Context(), scope.Env.ID, found.ID)
	if err != nil {
		internalError(w, "get token value", err)
		return
	}

	row := s.tokenRowFor(scope, found, time.Now().Unix(), r.URL.Query().Get("status"))
	row.Detail = &TokenDetail{Payload: prettyJSON(found.PayloadJSON), Value: value}

	s.renderFragment(w, http.StatusOK, "token_group", row)
}

func (s *Server) revokeToken(w http.ResponseWriter, r *http.Request) {
	scope, ok := s.resolveEnv(w, r)
	if !ok {
		return
	}

	id := r.PathValue("id")
	if _, err := s.db.RevokeToken(r.Context(), scope.Env.ID, id); err != nil && !errors.Is(err, db.ErrNotFound) {
		internalError(w, "revoke token", err)
		return
	}

	// The row is re-read rather than patched in place, so what comes back is
	// the token as the database now has it — including the status, which is
	// derived and not something this handler should be computing by hand.
	found, err := s.db.GetToken(r.Context(), scope.Env.ID, id)
	if errors.Is(err, db.ErrNotFound) {
		http.Error(w, "token not found", http.StatusNotFound)
		return
	}
	if err != nil {
		internalError(w, "get token", err)
		return
	}

	s.renderFragment(w, http.StatusOK, "token_group",
		s.tokenRowFor(scope, found, time.Now().Unix(), r.URL.Query().Get("status")))
}

func (s *Server) deleteToken(w http.ResponseWriter, r *http.Request) {
	scope, ok := s.resolveEnv(w, r)
	if !ok {
		return
	}
	if err := s.db.DeleteToken(r.Context(), scope.Env.ID, r.PathValue("id")); err != nil &&
		!errors.Is(err, db.ErrNotFound) {
		internalError(w, "delete token", err)
		return
	}
	s.renderTokensPanel(w, r, tokensQuery{
		scope: scope, status: r.URL.Query().Get("status"),
	}, http.StatusOK)
}

func (s *Server) renderTokensPanel(w http.ResponseWriter, r *http.Request, q tokensQuery, code int) {
	view, err := s.tokensView(r, q)
	if err != nil {
		internalError(w, "list tokens", err)
		return
	}
	s.renderFragment(w, code, "tokens_panel", view)
}

// prettyJSON re-indents a stored payload for display. The stored form is
// compact; a payload is meant to be read here, not counted in bytes.
//
// Invalid JSON cannot reach this — everything is validated on the way in — but
// if it somehow did, showing it as-is beats showing nothing.
func prettyJSON(raw string) string {
	var buf bytes.Buffer
	if err := json.Indent(&buf, []byte(raw), "", "  "); err != nil {
		return raw
	}
	return buf.String()
}
