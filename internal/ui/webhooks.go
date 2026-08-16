package ui

import (
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"tokenzy/internal/db"
	"tokenzy/internal/model"
	"tokenzy/internal/webhook"
)

// DeliveryRow is one line of a webhook's delivery history.
type DeliveryRow struct {
	Delivery model.WebhookDelivery
	Created  string
	State    string
	Detail   string
}

// WebhookRow is one webhook card.
type WebhookRow struct {
	Project string
	Env     string
	Hook    model.Webhook
	Created string
	Events  string
	// HeaderList is the header map rendered back as "Name: value" lines, sorted
	// so the card does not reshuffle itself between page loads.
	HeaderList []string
	Deliveries []DeliveryRow
}

// WebhookForm carries a rejected submission back to the operator, so a typo in
// one header does not cost them the rest of the form.
type WebhookForm struct {
	URL     string
	Label   string
	Headers string
	Events  map[string]bool
	Payload bool
}

// WebhooksView backs webhooks.html and the "webhooks_panel" fragment.
type WebhooksView struct {
	Layout
	Rows      []WebhookRow
	AllEvents []string
	Form      WebhookForm
	Error     string
	Notice    string
}

func (s *Server) webhooksView(r *http.Request, scope envScope, errMsg, notice string,
	form *WebhookForm) (WebhooksView, error) {

	hooks, err := s.db.ListWebhooks(r.Context(), scope.Env.ID)
	if err != nil {
		return WebhooksView{}, err
	}

	rows := make([]WebhookRow, 0, len(hooks))
	for _, h := range hooks {
		events := "all events"
		if len(h.Events) > 0 {
			events = strings.Join(h.Events, ", ")
		}

		row := WebhookRow{
			Project:    scope.Project.Slug,
			Env:        scope.Env.Slug,
			Hook:       h,
			Created:    formatTime(h.CreatedAt),
			Events:     events,
			HeaderList: headerLines(h.Headers),
		}

		if s.webhooks != nil {
			deliveries, err := s.webhooks.DeliveryHistory(r.Context(), h.ID)
			if err != nil {
				return WebhooksView{}, err
			}
			for _, d := range deliveries {
				row.Deliveries = append(row.Deliveries, deliveryRow(d))
			}
		}
		rows = append(rows, row)
	}

	shown := WebhookForm{Events: map[string]bool{}}
	if form != nil {
		shown = *form
		if shown.Events == nil {
			shown.Events = map[string]bool{}
		}
	}

	project, env := scope.Project, scope.Env
	return WebhooksView{
		Layout:    s.layoutFor(r, "Webhooks · "+project.Name, &project, &env, scope.Envs, "webhooks"),
		Rows:      rows,
		AllEvents: model.WebhookEvents,
		Form:      shown,
		Error:     errMsg,
		Notice:    notice,
	}, nil
}

// headerLines renders a header map for display, sorted by name.
func headerLines(headers map[string]string) []string {
	if len(headers) == 0 {
		return nil
	}
	names := make([]string, 0, len(headers))
	for name := range headers {
		names = append(names, name)
	}
	sort.Strings(names)

	lines := make([]string, 0, len(names))
	for _, name := range names {
		lines = append(lines, name+": "+headers[name])
	}
	return lines
}

// deliveryRow turns a delivery into the three things worth showing: when, how
// it ended, and why if it went wrong.
func deliveryRow(d model.WebhookDelivery) DeliveryRow {
	row := DeliveryRow{Delivery: d, Created: formatTime(d.CreatedAt)}

	switch {
	case d.Delivered():
		row.State = "delivered"
		if d.StatusCode != nil {
			row.Detail = strconv.FormatInt(*d.StatusCode, 10)
		}
	case d.Pending():
		row.State = "retrying"
		row.Detail = "attempt " + strconv.FormatInt(d.Attempt, 10) + " · next " + formatTimePtr(d.NextRetryAt)
	default:
		row.State = "failed"
		row.Detail = d.Error
	}
	return row
}

func (s *Server) webhooksPage(w http.ResponseWriter, r *http.Request) {
	scope, ok := s.resolveEnv(w, r)
	if !ok {
		return
	}
	view, err := s.webhooksView(r, scope, "", "", nil)
	if err != nil {
		internalError(w, "list webhooks", err)
		return
	}
	s.renderPage(w, http.StatusOK, "webhooks.html", view)
}

func (s *Server) createWebhook(w http.ResponseWriter, r *http.Request) {
	scope, ok := s.resolveEnv(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}

	form := WebhookForm{
		URL:     strings.TrimSpace(r.FormValue("url")),
		Label:   strings.TrimSpace(r.FormValue("label")),
		Headers: r.FormValue("headers"),
		Events:  map[string]bool{},
		Payload: r.FormValue("includePayload") == "1",
	}
	for _, e := range r.Form["events"] {
		form.Events[strings.TrimSpace(e)] = true
	}

	fail := func(msg string) {
		s.renderWebhooksPanel(w, r, scope, msg, "", &form, http.StatusUnprocessableEntity)
	}

	if err := webhook.ValidateURL(form.URL); err != nil {
		fail(err.Error())
		return
	}

	// No selection means every event. Anything unrecognised is rejected rather
	// than dropped, so a typo in a subscription is not silently a webhook that
	// never fires.
	events := []string{}
	for _, e := range r.Form["events"] {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if !model.ValidWebhookEvent(e) {
			fail("Unknown event: " + e)
			return
		}
		events = append(events, e)
	}

	headers, err := webhook.ParseHeaders(form.Headers)
	if err != nil {
		fail("Headers: " + err.Error())
		return
	}

	secret, err := webhook.NewSecret()
	if err != nil {
		internalError(w, "generate webhook secret", err)
		return
	}

	_, err = s.db.CreateWebhook(r.Context(), scope.Env.ID, form.URL, secret, events,
		headers, form.Label, form.Payload)
	if err != nil {
		internalError(w, "create webhook", err)
		return
	}

	s.renderWebhooksPanel(w, r, scope, "",
		"Webhook created. Copy the signing secret into your receiver.", nil, http.StatusOK)
}

func (s *Server) toggleWebhook(w http.ResponseWriter, r *http.Request) {
	scope, hook, ok := s.resolveWebhook(w, r)
	if !ok {
		return
	}

	if err := s.db.SetWebhookEnabled(r.Context(), hook.ID, scope.Env.ID, !hook.Enabled()); err != nil {
		internalError(w, "toggle webhook", err)
		return
	}
	s.renderWebhooksPanel(w, r, scope, "", "", nil, http.StatusOK)
}

// testWebhook queues a synthetic delivery so a receiver can be checked without
// waiting for a real token event. It goes through the same queue as everything
// else, so a passing test means real deliveries will work too.
func (s *Server) testWebhook(w http.ResponseWriter, r *http.Request) {
	scope, hook, ok := s.resolveWebhook(w, r)
	if !ok {
		return
	}
	if s.webhooks == nil {
		s.renderWebhooksPanel(w, r, scope, "Webhook delivery is not running.", "", nil, http.StatusOK)
		return
	}

	if err := s.webhooks.Test(r.Context(), hook); err != nil {
		internalError(w, "test webhook", err)
		return
	}
	s.renderWebhooksPanel(w, r, scope, "",
		"Test delivery queued — refresh to see the result.", nil, http.StatusOK)
}

func (s *Server) deleteWebhook(w http.ResponseWriter, r *http.Request) {
	scope, hook, ok := s.resolveWebhook(w, r)
	if !ok {
		return
	}
	if err := s.db.DeleteWebhook(r.Context(), hook.ID, scope.Env.ID); err != nil &&
		!errors.Is(err, db.ErrNotFound) {
		internalError(w, "delete webhook", err)
		return
	}
	s.renderWebhooksPanel(w, r, scope, "", "", nil, http.StatusOK)
}

// resolveWebhook loads the {id} webhook, scoped to the environment in the path
// so an id from elsewhere cannot be reached by editing the URL.
func (s *Server) resolveWebhook(w http.ResponseWriter, r *http.Request) (envScope, model.Webhook, bool) {
	scope, ok := s.resolveEnv(w, r)
	if !ok {
		return envScope{}, model.Webhook{}, false
	}

	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "invalid webhook id", http.StatusBadRequest)
		return envScope{}, model.Webhook{}, false
	}

	hook, err := s.db.GetWebhook(r.Context(), id, scope.Env.ID)
	if errors.Is(err, db.ErrNotFound) {
		http.Error(w, "webhook not found", http.StatusNotFound)
		return envScope{}, model.Webhook{}, false
	}
	if err != nil {
		internalError(w, "get webhook", err)
		return envScope{}, model.Webhook{}, false
	}
	return scope, hook, true
}

func (s *Server) renderWebhooksPanel(w http.ResponseWriter, r *http.Request, scope envScope,
	errMsg, notice string, form *WebhookForm, status int) {

	view, err := s.webhooksView(r, scope, errMsg, notice, form)
	if err != nil {
		internalError(w, "list webhooks", err)
		return
	}
	s.renderFragment(w, status, "webhooks_panel", view)
}
