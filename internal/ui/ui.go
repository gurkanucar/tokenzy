// Package ui serves the embedded HTMX admin panel. Every endpoint here returns
// HTML — full pages on navigation, fragments on HTMX requests — and is guarded
// by a session cookie rather than an API key.
package ui

import (
	"bytes"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"time"

	"tokenzy/internal/auth"
	"tokenzy/internal/db"
	"tokenzy/internal/model"
	"tokenzy/internal/token"
	"tokenzy/internal/webhook"
)

// LoginPath is where anonymous visitors are sent.
const LoginPath = "/ui/login"

// pageFiles are the templates that define a "content" block.
var pageFiles = []string{
	"login.html",
	"projects.html",
	"project.html",
	"tokens.html",
	"keys.html",
	"webhooks.html",
}

// Server holds the parsed template sets and the dependencies handlers need.
type Server struct {
	db       *db.DB
	sessions *auth.Sessions
	limits   token.Limits
	// webhooks powers the panel's Test button. Nil when delivery is not running.
	webhooks *webhook.Dispatcher

	// pages maps a page file to a template set of base + partials + that page,
	// so every page can define "content" without colliding with the others.
	pages map[string]*template.Template
	// frags renders partials on their own, for HTMX responses.
	frags *template.Template
}

// New parses the embedded templates. files is the root FS containing the
// "templates" directory.
// assetVersion is appended to static asset URLs so a changed stylesheet is
// actually fetched rather than served from a browser cache that was told it
// could keep the old one for an hour.
func New(database *db.DB, sessions *auth.Sessions, dispatcher *webhook.Dispatcher,
	limits token.Limits, files fs.FS, assetVersion string) (*Server, error) {

	s := &Server{
		db:       database,
		sessions: sessions,
		limits:   limits,
		webhooks: dispatcher,
		pages:    make(map[string]*template.Template, len(pageFiles)),
	}

	funcs := template.FuncMap{
		"asset": func(name string) string {
			return "/static/" + name + "?v=" + assetVersion
		},
	}

	for _, name := range pageFiles {
		t, err := template.New(name).Funcs(funcs).ParseFS(files,
			"templates/base.html", "templates/partials.html", "templates/"+name)
		if err != nil {
			return nil, fmt.Errorf("parse page %s: %w", name, err)
		}
		s.pages[name] = t
	}

	frags, err := template.New("partials.html").Funcs(funcs).ParseFS(files, "templates/partials.html")
	if err != nil {
		return nil, fmt.Errorf("parse partials: %w", err)
	}
	s.frags = frags

	return s, nil
}

// Register mounts the UI. Everything under /ui/ except the login endpoints
// requires a session.
func (s *Server) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/ui/projects", http.StatusSeeOther)
	})
	mux.HandleFunc("GET /ui/login", s.loginForm)
	mux.HandleFunc("POST /ui/login", s.loginSubmit)
	mux.HandleFunc("POST /ui/logout", s.logout)

	protected := http.NewServeMux()
	protected.HandleFunc("GET /ui/{$}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/ui/projects", http.StatusSeeOther)
	})

	// Projects and environments.
	protected.HandleFunc("GET /ui/projects", s.projectsPage)
	protected.HandleFunc("POST /ui/projects", s.createProject)
	protected.HandleFunc("DELETE /ui/p/{slug}", s.deleteProject)
	protected.HandleFunc("GET /ui/p/{slug}", s.projectPage)
	protected.HandleFunc("POST /ui/p/{slug}/environments", s.createEnvironment)
	protected.HandleFunc("DELETE /ui/p/{slug}/{env}", s.deleteEnvironment)

	// Tokens.
	protected.HandleFunc("GET /ui/p/{slug}/{env}/tokens", s.tokensPage)
	protected.HandleFunc("POST /ui/p/{slug}/{env}/tokens", s.createToken)
	protected.HandleFunc("GET /ui/p/{slug}/{env}/tokens/rows", s.tokenRows)
	protected.HandleFunc("GET /ui/p/{slug}/{env}/tokens/{id}", s.tokenDetail)
	protected.HandleFunc("GET /ui/p/{slug}/{env}/tokens/{id}/row", s.tokenRow)
	protected.HandleFunc("GET /ui/p/{slug}/{env}/tokens/{id}/reveal", s.revealToken)
	protected.HandleFunc("POST /ui/p/{slug}/{env}/tokens/{id}/revoke", s.revokeToken)
	protected.HandleFunc("DELETE /ui/p/{slug}/{env}/tokens/{id}", s.deleteToken)

	// API keys.
	protected.HandleFunc("GET /ui/p/{slug}/{env}/keys", s.keysPage)
	protected.HandleFunc("POST /ui/p/{slug}/{env}/keys", s.createKey)
	protected.HandleFunc("POST /ui/p/{slug}/{env}/keys/{id}/revoke", s.revokeKey)
	protected.HandleFunc("DELETE /ui/p/{slug}/{env}/keys/{id}", s.deleteKey)

	// Webhooks.
	protected.HandleFunc("GET /ui/p/{slug}/{env}/webhooks", s.webhooksPage)
	protected.HandleFunc("POST /ui/p/{slug}/{env}/webhooks", s.createWebhook)
	protected.HandleFunc("POST /ui/p/{slug}/{env}/webhooks/{id}/toggle", s.toggleWebhook)
	protected.HandleFunc("POST /ui/p/{slug}/{env}/webhooks/{id}/test", s.testWebhook)
	protected.HandleFunc("DELETE /ui/p/{slug}/{env}/webhooks/{id}", s.deleteWebhook)

	mux.Handle("/ui/", s.sessions.RequireLogin(LoginPath, protected))
}

// Layout is the chrome every page shares.
type Layout struct {
	Title   string
	User    string
	Project *model.Project
	Env     *model.Environment
	Envs    []model.Environment
	Tab     string
}

// LoginView backs login.html.
type LoginView struct {
	Layout
	Username string
	Error    string
	NoUsers  bool
}

func (s *Server) loginForm(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.sessions.Current(r.Context(), r); ok {
		http.Redirect(w, r, "/ui/projects", http.StatusSeeOther)
		return
	}
	count, err := s.db.CountUsers(r.Context())
	if err != nil {
		log.Printf("ui: count users: %v", err)
	}
	s.renderPage(w, http.StatusOK, "login.html", LoginView{
		Layout:  Layout{Title: "Sign in"},
		NoUsers: count == 0,
	})
}

func (s *Server) loginSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	username := r.FormValue("username")
	password := r.FormValue("password")

	fail := func() {
		count, _ := s.db.CountUsers(r.Context())
		s.renderPage(w, http.StatusUnauthorized, "login.html", LoginView{
			Layout:   Layout{Title: "Sign in"},
			Username: username,
			Error:    "Incorrect username or password.",
			NoUsers:  count == 0,
		})
	}

	user, err := s.db.GetUserByUsername(r.Context(), username)
	if errors.Is(err, db.ErrNotFound) {
		fail()
		return
	}
	if err != nil {
		log.Printf("ui: lookup user: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	ok, err := auth.VerifyPassword(password, user.PasswordHash)
	if err != nil {
		log.Printf("ui: verify password for %q: %v", username, err)
	}
	if !ok {
		fail()
		return
	}

	if err := s.sessions.Start(r.Context(), w, r, user.ID); err != nil {
		log.Printf("ui: start session: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/ui/projects", http.StatusSeeOther)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if err := s.sessions.End(r.Context(), w, r); err != nil {
		log.Printf("ui: end session: %v", err)
	}
	http.Redirect(w, r, LoginPath, http.StatusSeeOther)
}

// Rendering helpers.

func (s *Server) renderPage(w http.ResponseWriter, status int, page string, data any) {
	t, ok := s.pages[page]
	if !ok {
		log.Printf("ui: unknown page %q", page)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Render into a buffer so a template error cannot emit a half-written page.
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, "base", data); err != nil {
		log.Printf("ui: render %s: %v", page, err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	w.Write(buf.Bytes())
}

// isHTMX reports whether the request came from htmx rather than a plain
// navigation.
func isHTMX(r *http.Request) bool { return r.Header.Get("HX-Request") == "true" }

// renderListing answers a listing URL with the panel fragment for htmx and the
// full page for a normal navigation. The filter controls point at the same URL
// the address bar shows, so a filtered view stays shareable and reloadable —
// without this the chips would swap an entire HTML document into the panel.
func (s *Server) renderListing(w http.ResponseWriter, r *http.Request, page, fragment string, data any) {
	if isHTMX(r) {
		s.renderFragment(w, http.StatusOK, fragment, data)
		return
	}
	s.renderPage(w, http.StatusOK, page, data)
}

func (s *Server) renderFragment(w http.ResponseWriter, status int, name string, data any) {
	var buf bytes.Buffer
	if err := s.frags.ExecuteTemplate(&buf, name, data); err != nil {
		log.Printf("ui: render fragment %s: %v", name, err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	w.Write(buf.Bytes())
}

// layoutFor builds the shared chrome for a request inside a project.
func (s *Server) layoutFor(r *http.Request, title string, p *model.Project, e *model.Environment,
	envs []model.Environment, tab string) Layout {

	l := Layout{Title: title, Project: p, Env: e, Envs: envs, Tab: tab}
	if user, ok := auth.UserFromContext(r.Context()); ok {
		l.User = user.Username
	}
	return l
}

// envScope is the resolved project/environment pair a page operates on.
type envScope struct {
	Project model.Project
	Env     model.Environment
	Envs    []model.Environment
}

// resolveProject loads the project named by the {slug} path value.
func (s *Server) resolveProject(w http.ResponseWriter, r *http.Request) (model.Project, bool) {
	project, err := s.db.GetProjectBySlug(r.Context(), r.PathValue("slug"))
	if errors.Is(err, db.ErrNotFound) {
		http.Error(w, "project not found", http.StatusNotFound)
		return model.Project{}, false
	}
	if err != nil {
		log.Printf("ui: get project: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return model.Project{}, false
	}
	return project, true
}

// resolveEnv loads the {slug}/{env} pair plus the sibling environments used by
// the environment switcher.
func (s *Server) resolveEnv(w http.ResponseWriter, r *http.Request) (envScope, bool) {
	project, ok := s.resolveProject(w, r)
	if !ok {
		return envScope{}, false
	}

	env, err := s.db.GetEnvironment(r.Context(), project.ID, r.PathValue("env"))
	if errors.Is(err, db.ErrNotFound) {
		http.Error(w, "environment not found", http.StatusNotFound)
		return envScope{}, false
	}
	if err != nil {
		log.Printf("ui: get environment: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return envScope{}, false
	}

	envs, err := s.db.ListEnvironments(r.Context(), project.ID)
	if err != nil {
		log.Printf("ui: list environments: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return envScope{}, false
	}

	return envScope{Project: project, Env: env, Envs: envs}, true
}

// formatTime renders a stored unix timestamp for display.
func formatTime(ts int64) string {
	if ts == 0 {
		return ""
	}
	return time.Unix(ts, 0).Local().Format("2006-01-02 15:04")
}

// formatTimePtr renders an optional timestamp, with an em dash for "never".
func formatTimePtr(ts *int64) string {
	if ts == nil {
		return "—"
	}
	return formatTime(*ts)
}

// internalError logs and responds; used by the mutation handlers.
func internalError(w http.ResponseWriter, what string, err error) {
	log.Printf("ui: %s: %v", what, err)
	http.Error(w, "internal error", http.StatusInternalServerError)
}
