package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"time"
)

// TimescaleDB support.
//
// When the timescaledb extension is installed on the PostgreSQL server, fortigate_logs becomes a hypertable:
//   - one chunk per day, so retention drops whole chunks (instant, no bloat, no VACUUM debt) instead of a huge DELETE;
//   - chunks older than compressAfter are compressed (columnar), typically several times smaller;
//   - every query, UPDATE (NPS / mappings / re-classify) and COPY keeps working unchanged.
//
// Conversion is automatic only for an EMPTY table (a fresh install, e.g. the new Linux server). A table that already
// holds rows is left as it is and a warning is logged; see deploy/linux/migrate-existing-table.sql.
// Set LOGSIKKA_TIMESCALE=off to keep plain PostgreSQL even when the extension is available.

const chunkInterval = "1 day"

func compressDays() int {
	if n := int(compressAfterDays.Load()); n > 0 {
		return n
	}
	return 2
}

func timeZoneName() string {
	n, off := time.Now().Zone()
	return fmt.Sprintf("%s (UTC%+.1f)", n, float64(off)/3600)
}

// setupTimescale returns true when fortigate_logs is (now) a hypertable.
func (d *Database) setupTimescale(ctx context.Context) (bool, error) {
	if strings.EqualFold(os.Getenv("LOGSIKKA_TIMESCALE"), "off") || strings.EqualFold(os.Getenv("FORTILOG_TIMESCALE"), "off") {
		return false, nil
	}
	var available bool
	if err := d.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_available_extensions WHERE name='timescaledb')`).Scan(&available); err != nil || !available {
		return false, err
	}
	if _, err := d.pool.Exec(ctx, `CREATE EXTENSION IF NOT EXISTS timescaledb`); err != nil {
		return false, fmt.Errorf("create extension timescaledb (is it in shared_preload_libraries?): %w", err)
	}
	if hyper, err := d.isHypertable(ctx); err != nil || hyper {
		if hyper {
			err = d.timescalePolicies(ctx)
		}
		return hyper, err
	}
	var hasRows bool
	if err := d.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM fortigate_logs)`).Scan(&hasRows); err != nil {
		return false, err
	}
	if hasRows {
		log.Printf("timescaledb is installed but fortigate_logs already holds rows: staying on a plain table. " +
			"Run deploy/linux/migrate-existing-table.sql in a maintenance window to convert it.")
		return false, nil
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	steps := []string{
		// a hypertable's unique keys must include the time column; id stays unique in practice (bigserial)
		`ALTER TABLE fortigate_logs DROP CONSTRAINT IF EXISTS fortigate_logs_pkey`,
		`CREATE INDEX IF NOT EXISTS idx_fgt_id ON fortigate_logs(id)`,
	}
	// the "background" indexes are built now, on the empty table (CONCURRENTLY is not allowed on hypertables)
	for _, q := range backgroundIndexes {
		steps = append(steps, strings.Replace(q, "CONCURRENTLY ", "", 1))
	}
	steps = append(steps,
		`SELECT create_hypertable('fortigate_logs', 'event_time', chunk_time_interval => INTERVAL '`+chunkInterval+`')`,
		`ALTER TABLE fortigate_logs SET (timescaledb.compress, timescaledb.compress_segmentby = 'device_name', timescaledb.compress_orderby = 'event_time DESC, id DESC')`,
	)
	for _, q := range steps {
		if _, err = tx.Exec(ctx, q); err != nil {
			return false, fmt.Errorf("%s: %w", q, err)
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return false, err
	}
	log.Printf("fortigate_logs converted to a TimescaleDB hypertable (%s chunks)", chunkInterval)
	return true, d.timescalePolicies(ctx)
}

func (d *Database) isHypertable(ctx context.Context) (bool, error) {
	var ok bool
	err := d.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM timescaledb_information.hypertables WHERE hypertable_name='fortigate_logs')`).Scan(&ok)
	return ok, err
}

// timescalePolicies (re)sets the compression job to the configured age. Retention is NOT a Timescale job: the
// collector drops chunks itself so the retention_days setting stays the single source of truth.
func (d *Database) timescalePolicies(ctx context.Context) error {
	days := compressDays()
	var cur *string
	_ = d.pool.QueryRow(ctx, `SELECT config->>'compress_after' FROM timescaledb_information.jobs
		WHERE hypertable_name='fortigate_logs' AND proc_name='policy_compression' LIMIT 1`).Scan(&cur)
	want := fmt.Sprintf("%d days", days)
	if cur != nil && (*cur == want || (days == 1 && *cur == "1 day")) {
		return nil
	}
	if _, err := d.pool.Exec(ctx, `SELECT remove_compression_policy('fortigate_logs', if_exists => true)`); err != nil {
		return err
	}
	if _, err := d.pool.Exec(ctx, fmt.Sprintf(`SELECT add_compression_policy('fortigate_logs', INTERVAL '%d days')`, days)); err != nil {
		return err
	}
	log.Printf("timescaledb: day chunks are compressed when older than %d day(s)", days)
	return nil
}
