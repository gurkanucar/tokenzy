// Package cleanup removes tokens the service is finished with.
//
// It is the second of two defences, never the first. The consume query checks
// expires_at itself, so a token whose time has passed cannot be spent even if
// this job has been stopped for a week. What the job adds is hygiene: because
// tokens are stored in plaintext, every row that outlives its purpose is a
// secret sitting in a file for no reason, and the database and its backups are
// only as small a target as this job keeps them.
package cleanup

import (
	"context"
	"log"
	"time"

	"tokenzy/internal/db"
)

const (
	// DefaultInterval is how often the sweep runs.
	DefaultInterval = 10 * time.Minute

	// DefaultExpiredRetention keeps expired tokens around for a week. Long
	// enough to answer "what happened to that link?", short enough that a dead
	// secret is not kept for a month.
	DefaultExpiredRetention = 7 * 24 * time.Hour

	// DefaultConsumedRetention keeps spent and revoked tokens for a month. They
	// are the record of who used what and when, which is worth more than the
	// expired ones and is worth keeping longer.
	DefaultConsumedRetention = 30 * 24 * time.Hour

	// DefaultDeliveryRetention keeps settled webhook deliveries. They are an
	// operational log, not evidence.
	DefaultDeliveryRetention = 7 * 24 * time.Hour

	// batchSize bounds one DELETE. Working in batches keeps the single write
	// connection available to real requests: a backlog of a million rows
	// becomes a series of short locks rather than one long one.
	batchSize = 1000

	// maxBatchesPerSweep stops a very large backlog from monopolising the
	// writer for a whole interval. Whatever is left is picked up next time.
	maxBatchesPerSweep = 20
)

// Config holds the retention windows, all overridable per deployment.
type Config struct {
	Interval          time.Duration
	ExpiredRetention  time.Duration
	ConsumedRetention time.Duration
	DeliveryRetention time.Duration
}

// DefaultConfig returns the built-in windows.
func DefaultConfig() Config {
	return Config{
		Interval:          DefaultInterval,
		ExpiredRetention:  DefaultExpiredRetention,
		ConsumedRetention: DefaultConsumedRetention,
		DeliveryRetention: DefaultDeliveryRetention,
	}
}

// withDefaults fills in anything left at zero, so a partially configured Config
// is still usable.
func (c Config) withDefaults() Config {
	d := DefaultConfig()
	if c.Interval <= 0 {
		c.Interval = d.Interval
	}
	if c.ExpiredRetention <= 0 {
		c.ExpiredRetention = d.ExpiredRetention
	}
	if c.ConsumedRetention <= 0 {
		c.ConsumedRetention = d.ConsumedRetention
	}
	if c.DeliveryRetention <= 0 {
		c.DeliveryRetention = d.DeliveryRetention
	}
	return c
}

// Job sweeps the database on a timer.
type Job struct {
	db  *db.DB
	cfg Config
}

// New builds a job. Call Run to start it.
func New(database *db.DB, cfg Config) *Job {
	return &Job{db: database, cfg: cfg.withDefaults()}
}

// Run sweeps immediately and then on every tick, until ctx is cancelled.
func (j *Job) Run(ctx context.Context) {
	ticker := time.NewTicker(j.cfg.Interval)
	defer ticker.Stop()

	for {
		j.Sweep(ctx)

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// Sweep runs one round of deletions. Exported so it can be driven directly in
// a test rather than by waiting on a ticker.
func (j *Job) Sweep(ctx context.Context) {
	now := time.Now()

	expired := j.drain(ctx, "expired tokens", func(ctx context.Context) (int64, error) {
		return j.db.DeleteExpiredTokens(ctx, now.Add(-j.cfg.ExpiredRetention).Unix(), batchSize)
	})
	settled := j.drain(ctx, "spent tokens", func(ctx context.Context) (int64, error) {
		return j.db.DeleteSettledTokens(ctx, now.Add(-j.cfg.ConsumedRetention).Unix(), batchSize)
	})
	deliveries := j.drain(ctx, "webhook deliveries", func(ctx context.Context) (int64, error) {
		return j.db.DeleteOldDeliveries(ctx, now.Add(-j.cfg.DeliveryRetention).Unix(), batchSize)
	})

	if total := expired + settled + deliveries; total > 0 {
		log.Printf("cleanup: removed %d expired and %d spent tokens, %d delivery records",
			expired, settled, deliveries)
	}
}

// drain calls delete repeatedly until it stops finding work, a batch comes
// back short, or the per-sweep cap is reached.
func (j *Job) drain(ctx context.Context, what string, delete func(context.Context) (int64, error)) int64 {
	var total int64
	for i := 0; i < maxBatchesPerSweep; i++ {
		if ctx.Err() != nil {
			return total
		}
		n, err := delete(ctx)
		if err != nil {
			if ctx.Err() == nil {
				log.Printf("cleanup: %s: %v", what, err)
			}
			return total
		}
		total += n
		if n < batchSize {
			return total
		}
	}
	log.Printf("cleanup: %s: stopped at the per-sweep cap with work remaining", what)
	return total
}
