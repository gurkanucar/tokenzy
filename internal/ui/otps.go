package ui

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"tokenzy/internal/db"
	"tokenzy/internal/model"
	"tokenzy/internal/otp"
	"tokenzy/internal/ttl"
)

// OTPRow is one code in the table.
type OTPRow struct {
	Project string
	Env     string
	OTP     model.OTP
	Status  string
	// Filter carries the active listing query, so an action taken from a row
	// returns to the view it was taken from.
	Filter OTPFilterState
	// Attempts reads "2 / 5" — the number that says how close this code is to
	// locking itself.
	Attempts string
	Expires  string
	Created  string
	Settled  string
	// Detail is set only on an expanded row.
	Detail *OTPDetail
}

// OTPDetail is the expanded view under a row.
type OTPDetail struct {
	// Code is filled in only after the operator has asked to see it. Until
	// then it is not in the page at all.
	Code string
}

// OTPFilterState is the listing's current query, carried through every
// fragment so filters survive a row action.
type OTPFilterState struct {
	Status     string
	Type       string
	Identifier string
}

// Query renders the filter as a URL query string, ready to append.
func (f OTPFilterState) Query() string {
	q := url.Values{}
	if f.Status != "" {
		q.Set("status", f.Status)
	}
	if f.Type != "" {
		q.Set("type", f.Type)
	}
	if f.Identifier != "" {
		q.Set("identifier", f.Identifier)
	}
	if len(q) == 0 {
		return ""
	}
	return "?" + q.Encode()
}

// OTPForm is the state of the issue form, handed back on a rejected submission
// so a typo does not cost the operator everything they typed.
type OTPForm struct {
	Type        string
	Identifier  string
	Length      string
	TTLValue    string
	TTLUnit     string
	MaxAttempts string
}

func defaultOTPForm() OTPForm {
	return OTPForm{
		Type:        "password_reset",
		Identifier:  "",
		Length:      strconv.Itoa(otp.DefaultLength),
		TTLValue:    "5",
		TTLUnit:     ttl.DefaultUnit,
		MaxAttempts: strconv.FormatInt(otp.DefaultAttempts, 10),
	}
}

// OTPsView backs otps.html and its fragments.
type OTPsView struct {
	Layout
	Rows  []OTPRow
	Chips []StatusChip
	Types []string
	// NewCode is set exactly once, on the response to an issuance.
	NewCode   string
	NewCodeID string
	// Reused reports that the issue form handed back a code that already
	// existed rather than making a new one.
	Reused bool
	Error  string
	// MoreURL loads the next page; empty when the listing is exhausted.
	MoreURL string
	Filter  OTPFilterState
	Form    OTPForm
	// TTLUnits populates the lifetime unit dropdown, shared with tokens.
	TTLUnits      []ttl.Unit
	MaxTTLSeconds int64
	MaxTTLLabel   string
	MinLength     int
	MaxLength     int
	MinAttempts   int64
	MaxAttempts   int64
	Total         int64
}

func (s *Server) otpsBase(scope envScope) string {
	return fmt.Sprintf("/ui/p/%s/%s/otps", scope.Project.Slug, scope.Env.Slug)
}

// otpsQuery is everything that shapes a rendering of the codes page.
type otpsQuery struct {
	scope     envScope
	filter    OTPFilterState
	cursor    string
	newCode   string
	newCodeID string
	reused    bool
	errMsg    string
	form      *OTPForm
}

func (s *Server) otpsView(r *http.Request, q otpsQuery) (OTPsView, error) {
	scope := q.scope
	filter := q.filter
	if filter.Status != "" && !otp.ValidStatus(filter.Status) {
		filter.Status = ""
	}

	form := defaultOTPForm()
	if q.form != nil {
		form = *q.form
	}

	otps, next, err := s.db.ListOTPs(r.Context(), scope.Env.ID, db.OTPFilter{
		Status:     filter.Status,
		Type:       filter.Type,
		Identifier: filter.Identifier,
		Limit:      pageSize,
		Cursor:     db.ParseCursor(q.cursor),
	})
	if err != nil {
		return OTPsView{}, err
	}

	counts, err := s.db.CountOTPsByStatus(r.Context(), scope.Env.ID)
	if err != nil {
		return OTPsView{}, err
	}
	types, err := s.db.ListOTPTypes(r.Context(), scope.Env.ID)
	if err != nil {
		return OTPsView{}, err
	}

	base := s.otpsBase(scope)
	now := time.Now().Unix()

	rows := make([]OTPRow, 0, len(otps))
	for _, o := range otps {
		rows = append(rows, s.otpRowFor(scope, o, now, filter))
	}

	var total int64
	for _, n := range counts {
		total += n
	}

	// The chips keep whatever type and identifier are already filtered, so
	// narrowing by status does not throw away the search that got you here.
	chipFilter := filter
	chipFilter.Status = ""
	chips := []StatusChip{{
		Label:  "All",
		Count:  total,
		Active: filter.Status == "",
		URL:    base + chipFilter.Query(),
	}}
	for _, name := range otp.Statuses {
		chipFilter.Status = name
		chips = append(chips, StatusChip{
			Status: name,
			Label:  name,
			Count:  counts[name],
			Active: filter.Status == name,
			URL:    base + chipFilter.Query(),
		})
	}

	var moreURL string
	if next.Set() {
		query := url.Values{}
		if filter.Status != "" {
			query.Set("status", filter.Status)
		}
		if filter.Type != "" {
			query.Set("type", filter.Type)
		}
		if filter.Identifier != "" {
			query.Set("identifier", filter.Identifier)
		}
		query.Set("cursor", next.String())
		moreURL = base + "/rows?" + query.Encode()
	}

	ceiling := s.otpLimits.Ceiling()
	project, env := scope.Project, scope.Env
	return OTPsView{
		Layout:        s.layoutFor(r, "One-time codes · "+project.Name, &project, &env, scope.Envs, "otps"),
		Rows:          rows,
		Chips:         chips,
		Types:         types,
		NewCode:       q.newCode,
		NewCodeID:     q.newCodeID,
		Reused:        q.reused,
		Error:         q.errMsg,
		MoreURL:       moreURL,
		Filter:        filter,
		Form:          form,
		TTLUnits:      ttl.Units,
		MaxTTLSeconds: int64(ceiling / time.Second),
		MaxTTLLabel:   ttl.Human(ceiling),
		MinLength:     otp.MinLength,
		MaxLength:     otp.MaxLength,
		MinAttempts:   otp.MinAttempts,
		MaxAttempts:   otp.MaxAttempts,
		Total:         total,
	}, nil
}

func (s *Server) otpRowFor(scope envScope, o model.OTP, now int64, filter OTPFilterState) OTPRow {
	status := otp.StatusOf(o, now)

	settled := "—"
	switch {
	case o.RevokedAt != nil:
		settled = formatTime(*o.RevokedAt)
	case o.ConsumedAt != nil:
		settled = formatTime(*o.ConsumedAt)
	}

	return OTPRow{
		Project:  scope.Project.Slug,
		Env:      scope.Env.Slug,
		OTP:      o,
		Status:   status,
		Filter:   filter,
		Attempts: fmt.Sprintf("%d / %d", o.AttemptCount, o.MaxAttempts),
		Expires:  formatTime(o.ExpiresAt),
		Created:  formatTime(o.CreatedAt),
		Settled:  settled,
	}
}

// filterFrom reads the listing query out of a request.
func otpFilterFrom(r *http.Request) OTPFilterState {
	q := r.URL.Query()
	return OTPFilterState{
		Status:     q.Get("status"),
		Type:       strings.TrimSpace(q.Get("type")),
		Identifier: strings.TrimSpace(q.Get("identifier")),
	}
}

func (s *Server) otpsPage(w http.ResponseWriter, r *http.Request) {
	scope, ok := s.resolveEnv(w, r)
	if !ok {
		return
	}
	view, err := s.otpsView(r, otpsQuery{scope: scope, filter: otpFilterFrom(r)})
	if err != nil {
		internalError(w, "list otps", err)
		return
	}
	s.renderListing(w, r, "otps.html", "otps_panel", view)
}

func (s *Server) otpRows(w http.ResponseWriter, r *http.Request) {
	scope, ok := s.resolveEnv(w, r)
	if !ok {
		return
	}
	view, err := s.otpsView(r, otpsQuery{
		scope:  scope,
		filter: otpFilterFrom(r),
		cursor: r.URL.Query().Get("cursor"),
	})
	if err != nil {
		internalError(w, "list otps", err)
		return
	}
	s.renderFragment(w, http.StatusOK, "otp_rows", view)
}

func (s *Server) createOTP(w http.ResponseWriter, r *http.Request) {
	scope, ok := s.resolveEnv(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}

	filter := OTPFilterState{
		Status:     r.FormValue("status"),
		Type:       strings.TrimSpace(r.FormValue("filterType")),
		Identifier: strings.TrimSpace(r.FormValue("filterIdentifier")),
	}
	form := OTPForm{
		Type:        strings.TrimSpace(r.FormValue("type")),
		Identifier:  strings.TrimSpace(r.FormValue("identifier")),
		Length:      strings.TrimSpace(r.FormValue("length")),
		TTLValue:    r.FormValue("ttlValue"),
		TTLUnit:     r.FormValue("ttlUnit"),
		MaxAttempts: strings.TrimSpace(r.FormValue("maxAttempts")),
	}

	fail := func(msg string) {
		s.renderOTPsPanel(w, r, otpsQuery{
			scope: scope, filter: filter, errMsg: msg, form: &form,
		}, http.StatusUnprocessableEntity)
	}

	if !model.ValidOTPType(form.Type) {
		fail(model.ErrInvalidOTPType.Error())
		return
	}
	if !model.ValidIdentifier(form.Identifier) {
		fail(model.ErrInvalidIdentifier.Error())
		return
	}

	length, err := parseOptionalInt(form.Length)
	if err != nil {
		fail(otp.ErrLength.Error())
		return
	}
	resolvedLength, err := otp.ResolveLength(length)
	if err != nil {
		fail(err.Error())
		return
	}

	attempts, err := parseOptionalInt(form.MaxAttempts)
	if err != nil {
		fail(otp.ErrAttempts.Error())
		return
	}
	resolvedAttempts, err := otp.ResolveAttempts(attempts)
	if err != nil {
		fail(err.Error())
		return
	}

	ttl, err := s.otpLimits.ParseTTL(form.TTLValue, form.TTLUnit)
	if err != nil {
		fail(err.Error())
		return
	}

	id, err := otp.NewID()
	if err != nil {
		internalError(w, "generate otp id", err)
		return
	}
	code, err := otp.GenerateCode(resolvedLength)
	if err != nil {
		internalError(w, "generate otp code", err)
		return
	}

	issued, reused, err := s.db.GenerateOTP(r.Context(), scope.Env.ID, id, db.OTPRequest{
		Type:        form.Type,
		Identifier:  form.Identifier,
		Code:        code,
		MaxAttempts: resolvedAttempts,
		ExpiresAt:   time.Now().Add(ttl).Unix(),
	})
	if err != nil {
		internalError(w, "generate otp", err)
		return
	}

	s.renderOTPsPanel(w, r, otpsQuery{
		scope: scope, filter: filter,
		newCode: issued.Code, newCodeID: issued.ID, reused: reused,
	}, http.StatusOK)
}

// parseOptionalInt reads a form field that may legitimately be blank.
func parseOptionalInt(raw string) (*int64, error) {
	if raw == "" {
		return nil, nil
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return nil, err
	}
	return &n, nil
}

func (s *Server) otpDetail(w http.ResponseWriter, r *http.Request) {
	scope, o, ok := s.resolveOTP(w, r)
	if !ok {
		return
	}

	// Reading does not spend: nothing on this path touches consumed_at or the
	// attempt counter.
	row := s.otpRowFor(scope, o, time.Now().Unix(), otpFilterFrom(r))
	row.Detail = &OTPDetail{}
	s.renderFragment(w, http.StatusOK, "otp_group", row)
}

func (s *Server) otpRow(w http.ResponseWriter, r *http.Request) {
	scope, o, ok := s.resolveOTP(w, r)
	if !ok {
		return
	}
	s.renderFragment(w, http.StatusOK, "otp_group",
		s.otpRowFor(scope, o, time.Now().Unix(), otpFilterFrom(r)))
}

// revealOTP returns the code for one row.
//
// A separate request on purpose: until the operator clicks, the code is not in
// the HTML the browser holds, so a listing left open on a screen shows attempt
// counters and nothing anyone could use.
func (s *Server) revealOTP(w http.ResponseWriter, r *http.Request) {
	scope, o, ok := s.resolveOTP(w, r)
	if !ok {
		return
	}

	code, err := s.db.GetOTPCode(r.Context(), scope.Env.ID, o.ID)
	if err != nil {
		internalError(w, "get otp code", err)
		return
	}

	row := s.otpRowFor(scope, o, time.Now().Unix(), otpFilterFrom(r))
	row.Detail = &OTPDetail{Code: code}
	s.renderFragment(w, http.StatusOK, "otp_group", row)
}

func (s *Server) revokeOTP(w http.ResponseWriter, r *http.Request) {
	scope, o, ok := s.resolveOTP(w, r)
	if !ok {
		return
	}

	if _, err := s.db.RevokeOTP(r.Context(), scope.Env.ID, o.ID); err != nil &&
		!errors.Is(err, db.ErrNotFound) {
		internalError(w, "revoke otp", err)
		return
	}

	// Re-read rather than patch in place, so the row reflects what the database
	// now holds — including the status, which is derived.
	updated, err := s.db.GetOTP(r.Context(), scope.Env.ID, o.ID)
	if err != nil {
		internalError(w, "get otp", err)
		return
	}
	s.renderFragment(w, http.StatusOK, "otp_group",
		s.otpRowFor(scope, updated, time.Now().Unix(), otpFilterFrom(r)))
}

func (s *Server) deleteOTP(w http.ResponseWriter, r *http.Request) {
	scope, ok := s.resolveEnv(w, r)
	if !ok {
		return
	}
	if err := s.db.DeleteOTP(r.Context(), scope.Env.ID, r.PathValue("id")); err != nil &&
		!errors.Is(err, db.ErrNotFound) {
		internalError(w, "delete otp", err)
		return
	}
	s.renderOTPsPanel(w, r, otpsQuery{scope: scope, filter: otpFilterFrom(r)}, http.StatusOK)
}

// resolveOTP loads the {id} code, scoped to the environment in the path.
func (s *Server) resolveOTP(w http.ResponseWriter, r *http.Request) (envScope, model.OTP, bool) {
	scope, ok := s.resolveEnv(w, r)
	if !ok {
		return envScope{}, model.OTP{}, false
	}

	o, err := s.db.GetOTP(r.Context(), scope.Env.ID, r.PathValue("id"))
	if errors.Is(err, db.ErrNotFound) {
		http.Error(w, "code not found", http.StatusNotFound)
		return envScope{}, model.OTP{}, false
	}
	if err != nil {
		internalError(w, "get otp", err)
		return envScope{}, model.OTP{}, false
	}
	return scope, o, true
}

func (s *Server) renderOTPsPanel(w http.ResponseWriter, r *http.Request, q otpsQuery, code int) {
	view, err := s.otpsView(r, q)
	if err != nil {
		internalError(w, "list otps", err)
		return
	}
	s.renderFragment(w, code, "otps_panel", view)
}
