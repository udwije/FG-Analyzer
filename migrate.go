package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

// v5.14.1: a database upgrade that never holds up the start.
//
// Until v5.14 the whole schema was sent as one batch on every start. PostgreSQL runs such a batch as one transaction,
// and statements like "ALTER TABLE fortigate_logs ADD COLUMN IF NOT EXISTS ..." or "CREATE INDEX IF NOT EXISTS ..."
// lock the table BEFORE they find out there is nothing to do. On a TimescaleDB hypertable that lock has to wait for
// every chunk, so a compression job (or any long query) on the log table kept the collector in "database not
// connected" for as long as it ran, and the locks were held until the end of the batch.
//
// Now every statement is checked first (column, index, table or constraint already there?) and only what is missing
// runs, one statement at a time, each with a 15-second lock timeout. If a table is busy, the log says which session
// holds it (and how to end it), and the step is retried.

type migStep struct {
	sql   string
	check string // SQL returning true when the step is already in place ("" = always run)
	table string // the table the step locks (for the "waiting for" message)
	label string
}

// dbStep: the upgrade step in progress, for the status page ("" when none).
var dbStep atomic.Value

func dbStepText() string {
	s, _ := dbStep.Load().(string)
	return s
}

var (
	reComment   = regexp.MustCompile(`(?m)^\s*--[^\n]*\n`)
	reAddCol    = regexp.MustCompile(`(?is)^ALTER TABLE (\w+) ADD COLUMN IF NOT EXISTS (\w+)`)
	reDropCon   = regexp.MustCompile(`(?is)^ALTER TABLE (\w+) DROP CONSTRAINT IF EXISTS (\w+)`)
	reIndex     = regexp.MustCompile(`(?is)^CREATE (?:UNIQUE )?INDEX IF NOT EXISTS (\w+) ON (\w+)`)
	reTable     = regexp.MustCompile(`(?is)^CREATE TABLE IF NOT EXISTS (\w+)`)
	reDropIndex = regexp.MustCompile(`(?is)^DROP INDEX IF EXISTS (\w+)`)
	reFunc      = regexp.MustCompile(`(?is)^CREATE OR REPLACE FUNCTION (\w+)\(.*?\$fn\$(.*)\$fn\$\s*$`)
	reIdent     = regexp.MustCompile(`^\w+$`)
)

func sqlStr(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

// migrationSteps splits the schema into statements and works out how to tell whether each one is already done.
func migrationSteps(schema string) []migStep {
	var out []migStep
	for _, raw := range strings.Split(schema, ";\n") {
		s := strings.TrimSpace(reComment.ReplaceAllString(raw+"\n", ""))
		if s == "" {
			continue
		}
		st := migStep{sql: s, label: firstWords(s, 6)}
		switch {
		case reAddCol.MatchString(s):
			m := reAddCol.FindStringSubmatch(s)
			st.table, st.label = m[1], "add column "+m[1]+"."+m[2]
			st.check = `SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = ` +
				sqlStr(m[1]) + ` AND column_name = ` + sqlStr(m[2]) + `)`
		case reDropCon.MatchString(s):
			m := reDropCon.FindStringSubmatch(s)
			st.table, st.label = m[1], "drop constraint "+m[2]
			st.check = `SELECT NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = ` + sqlStr(m[2]) + ` AND conrelid = to_regclass(` + sqlStr(m[1]) + `))`
		case reIndex.MatchString(s):
			m := reIndex.FindStringSubmatch(s)
			st.table, st.label = m[2], "index "+m[1]
			st.check = `SELECT to_regclass(` + sqlStr(m[1]) + `) IS NOT NULL`
		case reTable.MatchString(s):
			m := reTable.FindStringSubmatch(s)
			st.table, st.label = m[1], "table "+m[1]
			st.check = `SELECT to_regclass(` + sqlStr(m[1]) + `) IS NOT NULL`
		case reDropIndex.MatchString(s):
			m := reDropIndex.FindStringSubmatch(s)
			st.label = "drop index " + m[1]
			st.check = `SELECT to_regclass(` + sqlStr(m[1]) + `) IS NULL`
		case reFunc.MatchString(s):
			m := reFunc.FindStringSubmatch(s)
			st.label = "function " + m[1]
			st.check = `SELECT EXISTS (SELECT 1 FROM pg_proc WHERE proname = ` + sqlStr(m[1]) + ` AND prosrc = ` + sqlStr(m[2]) + `)`
		}
		out = append(out, st)
	}
	return out
}

func firstWords(s string, n int) string {
	f := strings.Fields(s)
	if len(f) > n {
		f = f[:n]
	}
	return strings.Join(f, " ")
}

func isLockTimeout(err error) bool {
	var pe *pgconn.PgError
	return errors.As(err, &pe) && pe.Code == "55P03"
}

// Migrate brings the schema up to date, touching only what is missing.
func (d *Database) Migrate(ctx context.Context) error {
	start := time.Now()
	steps := migrationSteps(schemaSQL)
	ran, skipped := 0, 0
	defer dbStep.Store("")
	for i, st := range steps {
		if st.check != "" {
			var done bool
			if err := d.pool.QueryRow(ctx, st.check).Scan(&done); err == nil && done {
				skipped++
				continue
			}
		}
		dbStep.Store(fmt.Sprintf("step %d of %d: %s", i+1, len(steps), st.label))
		if err := d.migrateStep(ctx, st); err != nil {
			return fmt.Errorf("database upgrade (%s): %w", st.label, err)
		}
		ran++
	}
	if ran > 0 {
		log.Printf("database upgrade: %d change(s) applied, %d already in place (%s)", ran, skipped, time.Since(start).Round(time.Millisecond))
	}
	return nil
}

// migrateStep runs one statement with a short lock timeout and retries while the table is busy.
func (d *Database) migrateStep(ctx context.Context, st migStep) error {
	var lastLog time.Time
	for attempt := 1; ; attempt++ {
		err := func() error {
			tx, err := d.pool.Begin(ctx)
			if err != nil {
				return err
			}
			defer tx.Rollback(ctx)
			if _, err = tx.Exec(ctx, `SET LOCAL lock_timeout = '15s'`); err != nil {
				return err
			}
			if _, err = tx.Exec(ctx, st.sql); err != nil {
				return err
			}
			return tx.Commit(ctx)
		}()
		if err == nil || !isLockTimeout(err) {
			return err
		}
		if time.Since(lastLog) >= time.Minute {
			lastLog = time.Now()
			log.Printf("database upgrade: waiting for %s (attempt %d): %s", st.label, attempt, d.lockHolders(ctx, st.table))
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
}

// lockHolders describes the sessions holding locks on a table, for the log.
func (d *Database) lockHolders(ctx context.Context, table string) string {
	if !reIdent.MatchString(table) {
		return "the table is in use"
	}
	c, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	rows, err := d.pool.Query(c, `SELECT DISTINCT a.pid, coalesce(nullif(a.application_name,''), a.backend_type, ''), coalesce(a.state,''),
		coalesce(extract(epoch FROM now() - coalesce(a.query_start, a.backend_start))::bigint, 0), left(regexp_replace(coalesce(a.query,''), '\s+', ' ', 'g'), 100)
		FROM pg_locks l JOIN pg_stat_activity a ON a.pid = l.pid
		WHERE l.granted AND a.pid <> pg_backend_pid() AND (l.relation = to_regclass($1)
			OR l.relation IN (SELECT inhrelid FROM pg_inherits WHERE inhparent = to_regclass($1)))
		ORDER BY 4 DESC LIMIT 3`, table)
	if err != nil {
		return "table " + table + " is in use"
	}
	defer rows.Close()
	var parts []string
	for rows.Next() {
		var pid, secs int64
		var app, state, q string
		if rows.Scan(&pid, &app, &state, &secs, &q) != nil {
			continue
		}
		parts = append(parts, fmt.Sprintf("pid %d (%s, %s, %s): %s", pid, firstNonEmpty(app, "session"), firstNonEmpty(state, "?"), humanDur(secs), q))
	}
	if len(parts) == 0 {
		return "table " + table + " is in use"
	}
	return "table " + table + " is held by " + strings.Join(parts, "; ") +
		". It continues by itself when they finish; to end one now: SELECT pg_terminate_backend(<pid>);"
}

// summaryIndexes: housekeeping on the summary tables, in the background and without blocking writes.
func (d *Database) summaryIndexes() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Hour)
	defer cancel()
	// v5.13 created idx_r1h_dim_hour, which duplicates the primary key (dim, hour, ...): it only slowed down writes
	var pk bool
	if d.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'rollup_1h_pkey')`).Scan(&pk) == nil && pk {
		if _, err := d.pool.Exec(ctx, `DROP INDEX CONCURRENTLY IF EXISTS idx_r1h_dim_hour`); err != nil {
			log.Printf("summary index clean-up: %v", err)
		}
	}
}
