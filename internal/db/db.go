// Package db owns the SQLite connections, the migration runner and every
// query in the service. Reads go through a small pool, writes through a single
// connection so they serialise at the application level.
package db

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"tokenzy/internal/model"

	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// Sentinel errors returned by the query helpers. Handlers map these onto
// status codes.
var (
	ErrNotFound  = errors.New("not found")
	ErrDuplicate = errors.New("already exists")
)

// pragmas is appended to both DSNs so every connection in both handles gets
// the same settings. modernc.org/sqlite applies these on connection open.
const pragmas = "_pragma=journal_mode(WAL)&_pragma=busy_timeout(10000)&" +
	"_pragma=synchronous(NORMAL)&_pragma=foreign_keys(ON)"

// writeTxLock starts every write transaction with BEGIN IMMEDIATE.
//
// Without it a write transaction begins deferred: the first statement is
// usually a SELECT, so it takes a read lock and only tries to upgrade to a
// write lock when the first INSERT or UPDATE runs. SQLite deliberately does not
// apply busy_timeout to that upgrade — waiting there could deadlock — so under
// concurrent readers the upgrade fails outright with SQLITE_BUSY and the
// request turns into a 500.
//
// Taking the write lock up front instead means the busy_timeout above applies,
// and contention becomes a short wait rather than an error.
const writeTxLock = "&_txlock=immediate"

// dbFileMode is what the database file is created with: owner only.
//
// The file holds plaintext tokens, so it is secret material. SQLite creates it
// with 0644 minus the umask, which on a default umask is world-readable; that
// is tightened right after Open. Its backups deserve the same treatment, and
// nothing here can enforce that.
const dbFileMode os.FileMode = 0o600

// rowScanner is satisfied by both *sql.Row and *sql.Rows, so a scan helper can
// serve a single lookup and a listing.
type rowScanner interface {
	Scan(dest ...any) error
}

// DB holds the read pool and the single-writer handle.
type DB struct {
	Read  *sql.DB
	Write *sql.DB
	Path  string

	// Fresh reports that no usable database file was there when Open ran, so
	// this process is starting from nothing. Worth surfacing: on a redeploy it
	// means the volume holding the database did not survive, and without a
	// signal that failure looks exactly like a healthy first install.
	Fresh bool

	// OnTokenEvent, when set, is called after a committed token change. It is
	// how webhook delivery is triggered without this package knowing anything
	// about webhooks or HTTP. It must not block: the caller is still on the
	// request path.
	//
	// The token passed in never carries its plaintext value.
	OnTokenEvent func(envID int64, eventType string, tok model.Token)
}

// emitTokenEvent reports a committed change. Called after the write has
// landed, never before: an event for a change that did not happen is worse
// than a missing one.
func (d *DB) emitTokenEvent(envID int64, eventType string, tok model.Token) {
	if d.OnTokenEvent == nil {
		return
	}
	// Belt and braces: nothing downstream should ever see a plaintext token,
	// and clearing it here means no future caller can leak one by accident.
	tok.Value = ""
	d.OnTokenEvent(envID, eventType, tok)
}

// Open opens (and creates if missing) the SQLite database at path.
func Open(dbPath string) (*DB, error) {
	abs, err := filepath.Abs(dbPath)
	if err != nil {
		return nil, fmt.Errorf("resolve db path: %w", err)
	}
	dsn := "file:" + abs + "?" + pragmas

	// Checked before the first connection, which is what creates the file. A
	// zero-byte file counts as fresh too: some platforms pre-create the path
	// when mounting it, and an empty file is an empty database either way.
	fresh := true
	if info, statErr := os.Stat(abs); statErr == nil && info.Size() > 0 {
		fresh = false
	}

	read, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open read handle: %w", err)
	}
	read.SetMaxOpenConns(8)
	read.SetMaxIdleConns(8)
	read.SetConnMaxLifetime(time.Hour)

	write, err := sql.Open("sqlite", dsn+writeTxLock)
	if err != nil {
		read.Close()
		return nil, fmt.Errorf("open write handle: %w", err)
	}
	// A single writer connection: SQLite allows only one writer anyway, so
	// serialising here turns write contention into a queue instead of lock
	// errors. It is not sufficient on its own — see writeTxLock above.
	write.SetMaxOpenConns(1)
	write.SetMaxIdleConns(1)
	write.SetConnMaxLifetime(time.Hour)

	d := &DB{Read: read, Write: write, Path: abs, Fresh: fresh}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := write.PingContext(ctx); err != nil {
		d.Close()
		return nil, fmt.Errorf("ping db: %w", err)
	}
	if err := read.PingContext(ctx); err != nil {
		d.Close()
		return nil, fmt.Errorf("ping db: %w", err)
	}

	// The ping above has created the file if it was missing, so the permissions
	// can be tightened now. The WAL and shared-memory files inherit the main
	// file's mode from SQLite itself.
	if err := restrictPermissions(abs); err != nil {
		d.Close()
		return nil, err
	}

	return d, nil
}

// restrictPermissions narrows the database file to its owner.
//
// A failure here stops the start rather than being logged and shrugged off.
// The file holds plaintext tokens, so serving from a store whose permissions
// could not be set is serving secrets from somewhere possibly world-readable —
// and a warning in a startup log is exactly the kind of thing nobody reads
// until afterwards. The message says what to do instead.
//
// Only the main file is chmod'ed here; SQLite creates the -wal and -shm
// alongside it with the same mode, and they may not exist yet at this point.
func restrictPermissions(abs string) error {
	for _, suffix := range []string{"", "-wal", "-shm"} {
		p := abs + suffix
		if _, err := os.Stat(p); errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err := os.Chmod(p, dbFileMode); err != nil {
			return fmt.Errorf("could not restrict permissions on %s to %#o: %w — "+
				"this file stores tokens in plaintext, so it must not be left readable "+
				"by other users. Move the database to a filesystem that supports file "+
				"permissions, or fix the ownership of the directory it lives in",
				p, dbFileMode, err)
		}
	}
	return nil
}

// Close closes both handles.
func (d *DB) Close() error {
	var first error
	if d.Read != nil {
		if err := d.Read.Close(); err != nil {
			first = err
		}
	}
	if d.Write != nil {
		if err := d.Write.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// Migrate applies every embedded migration that has not run yet, in filename
// order, each inside its own transaction.
func (d *DB) Migrate(ctx context.Context) error {
	const createTable = `CREATE TABLE IF NOT EXISTS schema_migrations (
		name       TEXT PRIMARY KEY,
		applied_at INTEGER NOT NULL
	)`
	if _, err := d.Write.ExecContext(ctx, createTable); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

	files, err := fs.Glob(migrationsFS, "migrations/*.sql")
	if err != nil {
		return fmt.Errorf("list migrations: %w", err)
	}
	sort.Strings(files)

	for _, file := range files {
		name := path.Base(file)

		var applied int
		err := d.Write.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM schema_migrations WHERE name = ?`, name).Scan(&applied)
		if err != nil {
			return fmt.Errorf("check migration %s: %w", name, err)
		}
		if applied > 0 {
			continue
		}

		content, err := migrationsFS.ReadFile(file)
		if err != nil {
			return fmt.Errorf("read migration %s: %w", name, err)
		}

		tx, err := d.Write.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("begin migration %s: %w", name, err)
		}
		for _, stmt := range splitStatements(string(content)) {
			if _, err := tx.ExecContext(ctx, stmt); err != nil {
				tx.Rollback()
				return fmt.Errorf("apply migration %s: %w", name, err)
			}
		}
		_, err = tx.ExecContext(ctx,
			`INSERT INTO schema_migrations (name, applied_at) VALUES (?, ?)`, name, now())
		if err != nil {
			tx.Rollback()
			return fmt.Errorf("record migration %s: %w", name, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit migration %s: %w", name, err)
		}
	}
	return nil
}

// splitStatements breaks a migration file into individual statements. It
// understands single-quoted string literals and `--` line comments, which is
// everything the migrations in this repo use.
func splitStatements(src string) []string {
	var (
		out     []string
		cur     strings.Builder
		inStr   bool
		inLnCmt bool
	)
	runes := []rune(src)
	for i := 0; i < len(runes); i++ {
		c := runes[i]
		switch {
		case inLnCmt:
			if c == '\n' {
				inLnCmt = false
				cur.WriteRune(c)
			}
			continue
		case inStr:
			cur.WriteRune(c)
			if c == '\'' {
				// '' is an escaped quote inside a literal.
				if i+1 < len(runes) && runes[i+1] == '\'' {
					i++
					cur.WriteRune('\'')
				} else {
					inStr = false
				}
			}
			continue
		case c == '-' && i+1 < len(runes) && runes[i+1] == '-':
			inLnCmt = true
			i++
			continue
		case c == '\'':
			inStr = true
			cur.WriteRune(c)
			continue
		case c == ';':
			if s := strings.TrimSpace(cur.String()); s != "" {
				out = append(out, s)
			}
			cur.Reset()
			continue
		}
		cur.WriteRune(c)
	}
	if s := strings.TrimSpace(cur.String()); s != "" {
		out = append(out, s)
	}
	return out
}

// now returns the current unix timestamp, the only time representation stored.
func now() int64 { return time.Now().Unix() }

// isUniqueViolation reports whether err is a UNIQUE constraint failure.
func isUniqueViolation(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}

// nullableInt64 reads a column that may be NULL into a pointer.
func nullableInt64(v sql.NullInt64) *int64 {
	if !v.Valid {
		return nil
	}
	value := v.Int64
	return &value
}

// arg turns a *int64 into something the driver will bind, mapping nil to NULL.
func arg(v *int64) any {
	if v == nil {
		return nil
	}
	return *v
}
