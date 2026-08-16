// Command tokenzy is a single-binary token service: SQLite storage, a JSON API
// for issuing and redeeming opaque tokens, and an embedded HTMX admin panel.
//
// A token carries a JSON payload the service never interprets. It is issued
// with a lifetime and an optional usage limit, redeemed once or many times,
// and can be cancelled by id at any point. What the payload means is entirely
// the caller's business.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"tokenzy/internal/api"
	"tokenzy/internal/auth"
	"tokenzy/internal/cleanup"
	"tokenzy/internal/db"
	"tokenzy/internal/model"
	"tokenzy/internal/token"
	"tokenzy/internal/ui"
	"tokenzy/internal/webhook"
)

// Environment variables read by serve. They exist for deployments where
// running an interactive command is awkward.
const (
	envAdminUsername     = "TOKENZY_ADMIN_USERNAME"
	envAdminPassword     = "TOKENZY_ADMIN_PASSWORD"
	envAdminPasswordFile = "TOKENZY_ADMIN_PASSWORD_FILE"
	envSeedData          = "TOKENZY_SEED_DATA"
	envMaxTTL            = "TOKENZY_MAX_TTL"
	envRetentionExpired  = "TOKENZY_RETENTION_EXPIRED"
	envRetentionConsumed = "TOKENZY_RETENTION_CONSUMED"
	envRetentionDelivery = "TOKENZY_RETENTION_DELIVERIES"
	envCleanupInterval   = "TOKENZY_CLEANUP_INTERVAL"
)

// defaultEnvFile is loaded at startup when present; TOKENZY_ENV_FILE overrides
// the path.
const defaultEnvFile = ".env"

const usage = `tokenzy — opaque tokens carrying a JSON payload

Usage:
  tokenzy serve [-port 8080] [-db ./data.db]
  tokenzy admin-create -username admin [-db ./data.db] [-reset]

Commands:
  serve          Start the HTTP server (JSON API + admin panel)
  admin-create   Create an admin account; the password is read from the terminal

Environment variables (serve):
  TOKENZY_ADMIN_USERNAME       Account created at startup if it does not exist
  TOKENZY_ADMIN_PASSWORD       Its password (at least 8 characters)
  TOKENZY_ADMIN_PASSWORD_FILE  Read the password from a file instead; takes
                               precedence over TOKENZY_ADMIN_PASSWORD and keeps
                               the secret out of the process environment
  TOKENZY_SEED_DATA            Insert the demo project into an empty database.
                               Default: 1 (enabled). Set to 0 to turn it off.
  TOKENZY_MAX_TTL              Longest lifetime a caller may request.
                               Default: 2160h (90 days)
  TOKENZY_RETENTION_EXPIRED    How long expired tokens are kept. Default: 24h
  TOKENZY_RETENTION_CONSUMED   How long spent and revoked tokens are kept.
                               Default: 72h
  TOKENZY_RETENTION_DELIVERIES How long settled webhook deliveries are kept.
                               Default: 24h
  TOKENZY_CLEANUP_INTERVAL     How often the cleanup sweep runs. Default: 10m

  Durations are Go duration strings: 90s, 15m, 24h, 720h.

  An existing account is never modified; use admin-create -reset to change a
  password. A .env file in the working directory is loaded at startup
  (TOKENZY_ENV_FILE overrides the path); real environment variables win over it.

Note: the database stores tokens in plaintext, so the file and every backup of
it are secret material. Permission them accordingly.
`

func main() {
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	log.SetPrefix("tokenzy: ")

	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}

	envFile := os.Getenv("TOKENZY_ENV_FILE")
	if envFile == "" {
		envFile = defaultEnvFile
	}
	if err := loadDotEnv(envFile); err != nil {
		log.Fatal(err)
	}

	var err error
	switch os.Args[1] {
	case "serve":
		err = cmdServe(os.Args[2:])
	case "admin-create":
		err = cmdAdminCreate(os.Args[2:])
	case "help", "-h", "--help":
		fmt.Print(usage)
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}

	if err != nil {
		log.Fatal(err)
	}
}

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	port := fs.Int("port", 8080, "port to listen on")
	host := fs.String("host", "", "address to bind (empty = all interfaces)")
	dbPath := fs.String("db", "./data.db", "SQLite database file")
	if err := fs.Parse(args); err != nil {
		return err
	}

	limits, err := tokenLimits()
	if err != nil {
		return err
	}
	cleanupCfg, err := cleanupConfig()
	if err != nil {
		return err
	}

	database, err := db.Open(*dbPath)
	if err != nil {
		return err
	}
	defer database.Close()

	reportDatabaseState(database)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := database.Migrate(ctx); err != nil {
		return err
	}
	if err := seedDemoData(ctx, database); err != nil {
		return err
	}
	if err := bootstrapAdmin(ctx, database); err != nil {
		return err
	}

	// Background work runs for the lifetime of the server.
	background, stopBackground := context.WithCancel(context.Background())
	defer stopBackground()

	// Webhook delivery. The db layer calls Notify after each committed token
	// change; nothing on the request path blocks on a receiver.
	dispatcher := webhook.New(database)
	go dispatcher.Run(background)
	database.OnTokenEvent = dispatcher.Notify

	// Cleanup. Tokens are stored in plaintext, so removing the ones that are
	// finished with is hygiene rather than housekeeping.
	go cleanup.New(database, cleanupCfg).Run(background)

	go startSessionJanitor(background, database)

	handler, err := buildHandler(database, dispatcher, limits)
	if err != nil {
		return err
	}

	addr := fmt.Sprintf("%s:%d", *host, *port)
	srv := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		log.Printf("listening on http://localhost:%d  (db: %s)", *port, database.Path)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-errCh:
		return err
	case <-quit:
		log.Print("shutting down…")
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutdownCancel()
	return srv.Shutdown(shutdownCtx)
}

// tokenLimits reads the configurable input ceilings.
func tokenLimits() (token.Limits, error) {
	maxTTL, err := envDuration(envMaxTTL, token.DefaultMaxTTL)
	if err != nil {
		return token.Limits{}, err
	}
	if maxTTL > token.AbsoluteMaxTTL {
		log.Printf("%s is above the hard ceiling of %s and has been capped there",
			envMaxTTL, token.AbsoluteMaxTTL)
	}
	return token.NewLimits(maxTTL), nil
}

// cleanupConfig reads the retention windows.
func cleanupConfig() (cleanup.Config, error) {
	cfg := cleanup.DefaultConfig()
	var err error

	if cfg.Interval, err = envDuration(envCleanupInterval, cfg.Interval); err != nil {
		return cfg, err
	}
	if cfg.ExpiredRetention, err = envDuration(envRetentionExpired, cfg.ExpiredRetention); err != nil {
		return cfg, err
	}
	if cfg.ConsumedRetention, err = envDuration(envRetentionConsumed, cfg.ConsumedRetention); err != nil {
		return cfg, err
	}
	if cfg.DeliveryRetention, err = envDuration(envRetentionDelivery, cfg.DeliveryRetention); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// reportDatabaseState says, on every start, whether an existing database was
// found or a new one is being created.
//
// This exists because losing the database is silent otherwise: a container
// recreated without its volume comes up with an empty file, migrations run, and
// the result is indistinguishable from a healthy first install — except that
// every token ever issued has quietly stopped working.
func reportDatabaseState(database *db.DB) {
	if database.Fresh {
		log.Printf("no database found at %s — creating a new one. "+
			"If this is a redeploy rather than a first install, the volume holding "+
			"the database did not survive: the previous data is gone and every token "+
			"issued from it is now invalid.", database.Path)
		return
	}
	log.Printf("opened existing database at %s", database.Path)
}

// seedDemoData inserts the demo project unless it is switched off. It only
// touches a database with no projects in it, so restarts never duplicate rows
// and real data is never overwritten.
func seedDemoData(ctx context.Context, database *db.DB) error {
	enabled, err := envBool(envSeedData, true)
	if err != nil {
		return err
	}
	if !enabled {
		return nil
	}

	seeded, err := database.Seed(ctx)
	if err != nil {
		return err
	}
	if seeded {
		log.Printf("demo project inserted (set %s=0 to disable). "+
			"It holds no tokens and no API keys — create those from the panel.", envSeedData)
	}
	return nil
}

// loadDotEnv reads KEY=VALUE lines from path into the process environment. A
// missing file is not an error — the file is a convenience, not a config source
// the service depends on.
//
// Variables already set in the real environment are left alone, so an explicit
// `TOKENZY_ADMIN_PASSWORD=… ./tokenzy serve` and a container's env_file both
// win over the file on disk.
func loadDotEnv(path string) error {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("could not read %s: %w", path, err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for lineNo := 1; scanner.Scan(); lineNo++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")

		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return fmt.Errorf("%s:%d: expected 'KEY=value'", path, lineNo)
		}
		key = strings.TrimSpace(key)
		if key == "" {
			return fmt.Errorf("%s:%d: empty key", path, lineNo)
		}
		if _, alreadySet := os.LookupEnv(key); alreadySet {
			continue
		}
		if err := os.Setenv(key, unquote(strings.TrimSpace(value))); err != nil {
			return fmt.Errorf("%s:%d: %w", path, lineNo, err)
		}
	}
	return scanner.Err()
}

// unquote strips one layer of matching quotes. Values are otherwise taken
// literally, so a '#' inside a value stays part of the value.
func unquote(s string) string {
	if len(s) >= 2 {
		first, last := s[0], s[len(s)-1]
		if (first == '"' && last == '"') || (first == '\'' && last == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

// envBool reads a boolean environment variable, falling back to def when it is
// unset or empty. An unrecognised value is an error rather than a silent false.
func envBool(name string, def bool) (bool, error) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return def, nil
	}
	switch strings.ToLower(raw) {
	case "1", "true", "yes", "y", "on":
		return true, nil
	case "0", "false", "no", "n", "off":
		return false, nil
	}
	return false, fmt.Errorf("%s: expected a boolean (1/0, true/false, yes/no), got %q", name, raw)
}

// envDuration reads a Go duration, falling back to def when unset.
//
// A bad value stops the start rather than being ignored. These variables set
// how long secrets live; silently falling back to a default because of a typo
// is the kind of thing nobody notices until it matters.
func envDuration(name string, def time.Duration) (time.Duration, error) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return def, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("%s: expected a duration such as 15m, 24h or 720h, got %q", name, raw)
	}
	if d <= 0 {
		return 0, fmt.Errorf("%s: must be greater than zero, got %q", name, raw)
	}
	return d, nil
}

// bootstrapAdmin creates the admin account from the environment when that
// account is not there yet.
//
// An existing account is never touched: a restart must not silently undo a
// password changed with admin-create -reset, and it must not resurrect a
// password that has since been rotated.
func bootstrapAdmin(ctx context.Context, database *db.DB) error {
	username := strings.TrimSpace(os.Getenv(envAdminUsername))
	password, err := adminPasswordFromEnv()
	if err != nil {
		return err
	}

	if username == "" && password == "" {
		// Nothing configured: fall back to the CLI, but say so if the panel
		// would be unreachable.
		if count, err := database.CountUsers(ctx); err == nil && count == 0 {
			log.Printf("no admin account exists — run 'tokenzy admin-create -username admin' "+
				"or set %s / %s", envAdminUsername, envAdminPassword)
		}
		return nil
	}
	if username == "" || password == "" {
		return fmt.Errorf("%s and %s (or %s) must be set together",
			envAdminUsername, envAdminPassword, envAdminPasswordFile)
	}
	if !model.ValidUsername(username) {
		return fmt.Errorf("%s: %w", envAdminUsername, model.ErrInvalidUsername)
	}
	if !model.ValidPassword(password) {
		return fmt.Errorf("%s: %w", envAdminPassword, model.ErrInvalidPassword)
	}

	switch _, err := database.GetUserByUsername(ctx, username); {
	case err == nil:
		log.Printf("admin %q already exists, password left unchanged "+
			"(to change it: tokenzy admin-create -username %s -reset)", username, username)
		return nil
	case !errors.Is(err, db.ErrNotFound):
		return err
	}

	hash, err := auth.HashPassword(password)
	if err != nil {
		return err
	}
	if _, err := database.CreateUser(ctx, username, hash); err != nil {
		if errors.Is(err, db.ErrDuplicate) {
			return nil
		}
		return err
	}

	log.Printf("admin %q created from the environment", username)
	return nil
}

// adminPasswordFromEnv prefers the file form, so the secret can stay out of the
// process environment (and out of `docker inspect`).
func adminPasswordFromEnv() (string, error) {
	if path := strings.TrimSpace(os.Getenv(envAdminPasswordFile)); path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("could not read %s: %w", envAdminPasswordFile, err)
		}
		return strings.TrimRight(string(data), "\r\n"), nil
	}
	return os.Getenv(envAdminPassword), nil
}

// buildHandler wires the three surfaces onto one mux: static assets, the JSON
// API (API key auth) and the admin UI (session auth).
func buildHandler(database *db.DB, dispatcher *webhook.Dispatcher, limits token.Limits) (http.Handler, error) {
	mux := http.NewServeMux()

	// Embedded static assets.
	staticSub, err := fs.Sub(staticFS, "static")
	if err != nil {
		return nil, fmt.Errorf("static assets: %w", err)
	}
	mux.Handle("GET /static/", http.StripPrefix("/static/",
		cacheControl(http.FileServerFS(staticSub))))

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintln(w, "ok")
	})

	// JSON API. Each surface is mounted behind the least scope that can do its
	// job, which is what makes the scopes mean anything.
	apiAuth := &auth.APIAuthenticator{DB: database}

	consume := &api.Consume{DB: database}
	consume.Register(mux, apiAuth.Require(model.ScopeConsume))

	tokens := &api.Tokens{DB: database, Limits: limits}
	tokens.Register(mux, apiAuth.Require(model.ScopeWrite))

	manage := &api.Manage{DB: database}
	manage.Register(mux, apiAuth.Require(model.ScopeAdmin))

	// Admin UI.
	sessions := &auth.Sessions{DB: database}
	uiServer, err := ui.New(database, sessions, dispatcher, limits, templatesFS)
	if err != nil {
		return nil, err
	}
	uiServer.Register(mux)

	return requestLog(mux), nil
}

// startSessionJanitor prunes expired sessions hourly.
func startSessionJanitor(ctx context.Context, database *db.DB) {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		if err := database.DeleteExpiredSessions(ctx); err != nil && ctx.Err() == nil {
			log.Printf("session cleanup: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func cacheControl(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=3600")
		next.ServeHTTP(w, r)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// requestLog records method, path, status and duration — and nothing else.
//
// The omission is the point. Tokens travel in request bodies precisely so that
// they stay out of logs like this one, and query strings are left out for the
// same reason: the moment a token appears in a log line it is in a file that
// gets shipped, aggregated and kept far longer than the token itself lives.
func requestLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		log.Printf("%s %s %d %s", r.Method, r.URL.Path, rec.status,
			time.Since(start).Round(time.Millisecond))
	})
}

func cmdAdminCreate(args []string) error {
	fs := flag.NewFlagSet("admin-create", flag.ExitOnError)
	username := fs.String("username", "", "admin username (required)")
	dbPath := fs.String("db", "./data.db", "SQLite database file")
	reset := fs.Bool("reset", false, "change the password if the account already exists")
	if err := fs.Parse(args); err != nil {
		return err
	}

	name := strings.TrimSpace(*username)
	if !model.ValidUsername(name) {
		return model.ErrInvalidUsername
	}

	database, err := db.Open(*dbPath)
	if err != nil {
		return err
	}
	defer database.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := database.Migrate(ctx); err != nil {
		return err
	}

	password, err := readPassword()
	if err != nil {
		return err
	}
	if !model.ValidPassword(password) {
		return model.ErrInvalidPassword
	}

	hash, err := auth.HashPassword(password)
	if err != nil {
		return err
	}

	_, err = database.CreateUser(ctx, name, hash)
	if errors.Is(err, db.ErrDuplicate) {
		if !*reset {
			return fmt.Errorf("%q already exists; pass -reset to change its password", name)
		}
		if err := database.SetUserPassword(ctx, name, hash); err != nil {
			return err
		}
		fmt.Printf("Password updated for %q.\n", name)
		return nil
	}
	if err != nil {
		return err
	}

	fmt.Printf("%q created. Sign in at /ui/login.\n", name)
	return nil
}

// readPassword prompts twice, without echo when stdin is a terminal.
func readPassword() (string, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		// Piped input: read a single line.
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && line == "" {
			return "", fmt.Errorf("could not read password: %w", err)
		}
		return strings.TrimRight(line, "\r\n"), nil
	}

	fmt.Print("Password: ")
	first, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return "", fmt.Errorf("could not read password: %w", err)
	}

	fmt.Print("Password (again): ")
	second, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return "", fmt.Errorf("could not read password: %w", err)
	}

	if string(first) != string(second) {
		return "", errors.New("passwords did not match")
	}
	return string(first), nil
}
