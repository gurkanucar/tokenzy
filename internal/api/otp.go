package api

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"tokenzy/internal/db"
	"tokenzy/internal/httpx"
	"tokenzy/internal/model"
	"tokenzy/internal/otp"
)

// OTP serves one-time code issuance and validation.
type OTP struct {
	DB     *db.DB
	Limits otp.Limits
}

// Register mounts the two halves behind different scopes.
//
// Issuing needs write, because whoever issues a code is the party that will
// send it by SMS or email — always a backend. Validating needs only consume, so
// the check can happen wherever the user typed the code.
func (o *OTP) Register(mux *http.ServeMux, requireWrite, requireConsume func(http.Handler) http.Handler) {
	mux.Handle("POST /v1/otp", requireWrite(http.HandlerFunc(o.generate)))
	mux.Handle("POST /v1/otp/validate", requireConsume(http.HandlerFunc(o.validate)))
}

type generateRequest struct {
	Type       string `json:"type"`
	Identifier string `json:"identifier"`
	// Pointers so an absent field takes the default rather than reading as 0,
	// which for maxAttempts would mean "no attempts allowed" and for length
	// would mean "no digits".
	Length      *int64 `json:"length"`
	TTLSeconds  int64  `json:"ttlSeconds"`
	MaxAttempts *int64 `json:"maxAttempts"`
}

type generateResponse struct {
	ID         string `json:"id"`
	Type       string `json:"type"`
	Identifier string `json:"identifier"`
	Code       string `json:"code"`
	ExpiresAt  string `json:"expiresAt"`
	// Attempts left, not attempts used: on a reused code the caller needs to
	// know how much room is left, not how much has been spent.
	MaxAttempts int64 `json:"maxAttempts"`
	// Reused reports that a live code already existed and was returned instead
	// of a new one. When it is true, expiresAt is the original issuance's — a
	// resend does not extend the life of a code.
	Reused bool `json:"reused"`
}

func (o *OTP) generate(w http.ResponseWriter, r *http.Request) {
	ac, ok := requireAuth(w, r)
	if !ok {
		return
	}

	var req generateRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	// Trimmed and otherwise untouched. Not lowercased: deciding that two
	// spellings of an address are the same person is a judgement this service
	// has no business making, and getting it wrong would silently merge two
	// people's codes.
	otpType := strings.TrimSpace(req.Type)
	identifier := strings.TrimSpace(req.Identifier)

	if !model.ValidOTPType(otpType) {
		httpx.WriteError(w, http.StatusBadRequest, httpx.CodeInvalidRequest, model.ErrInvalidOTPType.Error())
		return
	}
	if !model.ValidIdentifier(identifier) {
		httpx.WriteError(w, http.StatusBadRequest, httpx.CodeInvalidRequest, model.ErrInvalidIdentifier.Error())
		return
	}

	length, err := otp.ResolveLength(req.Length)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, httpx.CodeInvalidRequest, err.Error())
		return
	}
	maxAttempts, err := otp.ResolveAttempts(req.MaxAttempts)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, httpx.CodeInvalidRequest, err.Error())
		return
	}
	ttl, err := o.Limits.ValidateTTL(req.TTLSeconds)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, httpx.CodeInvalidRequest, err.Error())
		return
	}

	id, err := otp.NewID()
	if err != nil {
		internalError(w, "generate otp id", err)
		return
	}
	code, err := otp.GenerateCode(length)
	if err != nil {
		internalError(w, "generate otp code", err)
		return
	}

	// The code and id built above are only used if no live code exists; the
	// database decides that, inside a transaction, so that two simultaneous
	// requests for the same identifier cannot each insert one.
	issued, reused, err := o.DB.GenerateOTP(r.Context(), ac.Environment.ID, id, db.OTPRequest{
		Type:        otpType,
		Identifier:  identifier,
		Code:        code,
		MaxAttempts: maxAttempts,
		ExpiresAt:   time.Now().Add(ttl).Unix(),
	})
	if err != nil {
		internalError(w, "generate otp", err)
		return
	}

	status := http.StatusCreated
	if reused {
		status = http.StatusOK
	}
	httpx.WriteJSON(w, status, generateResponse{
		ID:          issued.ID,
		Type:        issued.Type,
		Identifier:  issued.Identifier,
		Code:        issued.Code,
		ExpiresAt:   rfc3339(issued.ExpiresAt),
		MaxAttempts: issued.MaxAttempts,
		Reused:      reused,
	})
}

type validateRequest struct {
	Type       string `json:"type"`
	Identifier string `json:"identifier"`
	Code       string `json:"code"`
}

type validateResponse struct {
	Valid      bool   `json:"valid"`
	Type       string `json:"type"`
	Identifier string `json:"identifier"`
}

func (o *OTP) validate(w http.ResponseWriter, r *http.Request) {
	ac, ok := requireAuth(w, r)
	if !ok {
		return
	}

	var req validateRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	otpType := strings.TrimSpace(req.Type)
	identifier := strings.TrimSpace(req.Identifier)
	code := strings.TrimSpace(req.Code)

	// A missing field is a mistake in the caller's code rather than a failed
	// check, so it says so. Nothing is revealed: the answer does not depend on
	// any code that exists.
	if otpType == "" || identifier == "" || code == "" {
		httpx.WriteError(w, http.StatusBadRequest, httpx.CodeInvalidRequest,
			"'type', 'identifier' and 'code' are all required")
		return
	}

	consumed, err := o.DB.ValidateOTP(r.Context(), ac.Environment.ID, otpType, identifier, code)

	if errors.Is(err, db.ErrNotFound) {
		// One answer for every failure: wrong code, expired, already used,
		// cancelled, locked out, or no code ever issued for this identifier.
		//
		// Distinguishing them would tell somebody probing an address whether it
		// has a reset in flight — which is exactly the fact worth hiding. The
		// panel has the real answer for whoever is entitled to it.
		httpx.WriteJSON(w, http.StatusOK, struct {
			Valid bool   `json:"valid"`
			Error string `json:"error"`
		}{Valid: false, Error: "invalid_code"})
		return
	}
	if err != nil {
		internalError(w, "validate otp", err)
		return
	}

	httpx.WriteJSON(w, http.StatusOK, validateResponse{
		Valid:      true,
		Type:       consumed.Type,
		Identifier: consumed.Identifier,
	})
}

// Management.

// ManageOTP serves the administrative endpoints under /v1/manage/otps.
type ManageOTP struct {
	DB *db.DB
}

// Register mounts management behind the admin-scope middleware.
func (m *ManageOTP) Register(mux *http.ServeMux, requireAdmin func(http.Handler) http.Handler) {
	handle := func(pattern string, h http.HandlerFunc) {
		mux.Handle(pattern, requireAdmin(h))
	}
	handle("GET /v1/manage/otps", m.list)
	handle("GET /v1/manage/otps/{id}", m.get)
	handle("POST /v1/manage/otps/{id}/revoke", m.revoke)
	handle("DELETE /v1/manage/otps/{id}", m.delete)
}

// otpSummary is what a listing returns: no code, structurally.
type otpSummary struct {
	ID           string  `json:"id"`
	Type         string  `json:"type"`
	Identifier   string  `json:"identifier"`
	Status       string  `json:"status"`
	AttemptCount int64   `json:"attemptCount"`
	MaxAttempts  int64   `json:"maxAttempts"`
	ExpiresAt    string  `json:"expiresAt"`
	CreatedAt    string  `json:"createdAt"`
	ConsumedAt   *string `json:"consumedAt"`
	RevokedAt    *string `json:"revokedAt"`
}

type otpDetail struct {
	otpSummary
	Code string `json:"code"`
}

type otpListResponse struct {
	OTPs       []otpSummary `json:"otps"`
	NextCursor string       `json:"nextCursor"`
}

func summariseOTP(o model.OTP, now int64) otpSummary {
	return otpSummary{
		ID:           o.ID,
		Type:         o.Type,
		Identifier:   o.Identifier,
		Status:       otp.StatusOf(o, now),
		AttemptCount: o.AttemptCount,
		MaxAttempts:  o.MaxAttempts,
		ExpiresAt:    rfc3339(o.ExpiresAt),
		CreatedAt:    rfc3339(o.CreatedAt),
		ConsumedAt:   rfc3339Ptr(o.ConsumedAt),
		RevokedAt:    rfc3339Ptr(o.RevokedAt),
	}
}

func (m *ManageOTP) list(w http.ResponseWriter, r *http.Request) {
	ac, ok := requireAuth(w, r)
	if !ok {
		return
	}

	query := r.URL.Query()
	filter := db.OTPFilter{
		Status:     query.Get("status"),
		Type:       strings.TrimSpace(query.Get("type")),
		Identifier: strings.TrimSpace(query.Get("identifier")),
		Limit:      defaultPageSize,
		Cursor:     db.ParseCursor(query.Get("cursor")),
	}
	if filter.Status != "" && !otp.ValidStatus(filter.Status) {
		httpx.WriteError(w, http.StatusBadRequest, httpx.CodeInvalidRequest,
			"'status' must be one of active, consumed, expired, locked, revoked")
		return
	}
	if raw := query.Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 {
			httpx.WriteError(w, http.StatusBadRequest, httpx.CodeInvalidRequest,
				"'limit' must be a positive integer")
			return
		}
		filter.Limit = n
	}

	otps, next, err := m.DB.ListOTPs(r.Context(), ac.Environment.ID, filter)
	if err != nil {
		internalError(w, "list otps", err)
		return
	}

	now := time.Now().Unix()
	summaries := make([]otpSummary, 0, len(otps))
	for _, o := range otps {
		summaries = append(summaries, summariseOTP(o, now))
	}

	httpx.WriteJSON(w, http.StatusOK, otpListResponse{
		OTPs:       summaries,
		NextCursor: next.String(),
	})
}

// get returns one code in full. Reading is not spending: this does not touch
// consumed_at or attempt_count, so a code inspected here is exactly as usable
// afterwards as it was before.
func (m *ManageOTP) get(w http.ResponseWriter, r *http.Request) {
	ac, ok := requireAuth(w, r)
	if !ok {
		return
	}

	id := r.PathValue("id")
	found, err := m.DB.GetOTP(r.Context(), ac.Environment.ID, id)
	if errors.Is(err, db.ErrNotFound) {
		httpx.WriteError(w, http.StatusNotFound, httpx.CodeNotFound, "otp not found")
		return
	}
	if err != nil {
		internalError(w, "get otp", err)
		return
	}

	code, err := m.DB.GetOTPCode(r.Context(), ac.Environment.ID, id)
	if err != nil {
		internalError(w, "get otp code", err)
		return
	}

	httpx.WriteJSON(w, http.StatusOK, otpDetail{
		otpSummary: summariseOTP(found, time.Now().Unix()),
		Code:       code,
	})
}

func (m *ManageOTP) revoke(w http.ResponseWriter, r *http.Request) {
	ac, ok := requireAuth(w, r)
	if !ok {
		return
	}

	id := r.PathValue("id")
	revoked, err := m.DB.RevokeOTP(r.Context(), ac.Environment.ID, id)

	if errors.Is(err, db.ErrNotFound) {
		// Either it does not exist here, or it was already revoked.
		existing, getErr := m.DB.GetOTP(r.Context(), ac.Environment.ID, id)
		if errors.Is(getErr, db.ErrNotFound) {
			httpx.WriteError(w, http.StatusNotFound, httpx.CodeNotFound, "otp not found")
			return
		}
		if getErr != nil {
			internalError(w, "get otp", getErr)
			return
		}
		httpx.WriteJSON(w, http.StatusOK, summariseOTP(existing, time.Now().Unix()))
		return
	}
	if err != nil {
		internalError(w, "revoke otp", err)
		return
	}

	httpx.WriteJSON(w, http.StatusOK, summariseOTP(revoked, time.Now().Unix()))
}

func (m *ManageOTP) delete(w http.ResponseWriter, r *http.Request) {
	ac, ok := requireAuth(w, r)
	if !ok {
		return
	}

	err := m.DB.DeleteOTP(r.Context(), ac.Environment.ID, r.PathValue("id"))
	switch {
	case errors.Is(err, db.ErrNotFound):
		httpx.WriteError(w, http.StatusNotFound, httpx.CodeNotFound, "otp not found")
	case err != nil:
		internalError(w, "delete otp", err)
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}
