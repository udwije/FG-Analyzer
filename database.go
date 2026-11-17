package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// sem caps concurrent dashboard queries so they never starve the COPY writer
type Database struct {
	pool *pgxpool.Pool
	sem  chan struct{}
	ts   bool // fortigate_logs is a TimescaleDB hypertable
}

func dbURL(c DatabaseConfig) string {
	u := &url.URL{Scheme: "postgres", User: url.UserPassword(c.User, c.Password), Host: fmt.Sprintf("%s:%d", c.Host, c.Port), Path: c.Name}
	q := u.Query()
	q.Set("sslmode", c.SSLMode)
	u.RawQuery = q.Encode()
	return u.String()
}

func OpenDatabase(ctx context.Context, c DatabaseConfig) (*Database, error) {
	pc, err := pgxpool.ParseConfig(dbURL(c))
	if err != nil {
		return nil, err
	}
	pc.MaxConns = c.MaxConnections
	// v5.10: every session uses the collector's time zone, so day / weekday / hour groupings (heat maps, "per day"
	// tables, investigation dates) follow the local clock instead of the PostgreSQL server default (often UTC).
	if tz := sessionTZ(); tz != "" && pc.ConnConfig != nil {
		if pc.ConnConfig.RuntimeParams == nil {
			pc.ConnConfig.RuntimeParams = map[string]string{}
		}
		pc.ConnConfig.RuntimeParams["timezone"] = tz
	}
	// v6.0.1: one extra worker per query at most. Six dashboard queries with three workers each kept 18 processes
	// reading the disk at once; with one helper each the intake and the summaries keep up.
	if pc.ConnConfig != nil {
		if pc.ConnConfig.RuntimeParams == nil {
			pc.ConnConfig.RuntimeParams = map[string]string{}
		}
		if v := os.Getenv("LOGSIKKA_PARALLEL"); v != "" {
			pc.ConnConfig.RuntimeParams["max_parallel_workers_per_gather"] = v
		} else {
			pc.ConnConfig.RuntimeParams["max_parallel_workers_per_gather"] = "1"
		}
	}
	pool, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		return nil, err
	}
	if err = pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	n := int(queryConcurrency.Load())
	if n < 1 {
		n = 6
	}
	d := &Database{pool: pool, sem: make(chan struct{}, n)}
	if err = d.Migrate(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	// TimescaleDB is optional: any problem here is logged and the collector carries on with a plain table.
	if d.ts, err = d.setupTimescale(ctx); err != nil {
		log.Printf("timescaledb setup: %v (continuing with a plain table)", err)
		d.ts, _ = d.isHypertableSafe(ctx)
	}
	_ = d.LoadMappings(ctx)
	go d.summaryIndexes() // v5.14.1
	if !d.ts {
		go d.buildIndexes() // a hypertable already has them, and CONCURRENTLY is not allowed there
	}
	return d, nil
}

func (d *Database) isHypertableSafe(ctx context.Context) (bool, error) {
	var ext bool
	if d.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_extension WHERE extname='timescaledb')`).Scan(&ext) != nil || !ext {
		return false, nil
	}
	return d.isHypertable(ctx)
}

func (d *Database) Close() {
	if d != nil && d.pool != nil {
		d.pool.Close()
	}
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nullIP(s string) any { return nullIfEmpty(s) }

var logColumns = []string{"event_time", "received_at", "source_ip", "device_id", "vdom", "log_id", "log_type", "subtype", "level", "src_ip", "src_port",
	"dst_ip", "dst_port", "protocol", "action", "policy_id", "policy_name", "user_name", "application", "category", "hostname", "url", "sent_bytes",
	"received_bytes", "duration_seconds", "parse_status", "parse_error", "fields", "raw_message", "app_risk", "map_id", "device_name", "src_mac", "ai_tool", "nps_id"}

// InsertBatch writes one COPY batch. A log without a username gets one from, in order:
// a manual mapping, then the NPS (wireless) session that held that IP at that moment.
func (d *Database) InsertBatch(ctx context.Context, records []LogRecord) error {
	d.maybeReconcile()
	rows := make([][]any, 0, len(records))
	for i := range records {
		cleanRecord(&records[i]) // spooled records may come from an older parser
	}
	for _, r := range records {
		fields, _ := json.Marshal(r.Fields)
		var mapID, npsID any
		r.User = cleanLogUser(r) // v5.13: one form per person; non-staff "unauthenticated" guesses dropped
		if r.User == "" && r.SrcIP != "" {
			if m := lookupMapping(r.SrcIP, r.EventTime); m != nil {
				r.User, mapID = m.User, m.ID
			} else if as := lookupAssignment(r.SrcIP, r.SrcMAC, r.Fields["srcname"], r.EventTime); as != nil && as.Type == "person" {
				r.User, mapID = as.Owner, -as.ID // v5.13: permanent assignment (negative id)
			} else if s := npsEngine.userFor(ctx, d, r.SrcIP, r.SrcMAC, r.EventTime); s != nil {
				r.User, npsID = s.User, s.ID
			}
		}
		if r.DeviceName == "" {
			r.DeviceName = r.SourceIP
		}
		rows = append(rows, []any{r.EventTime, r.ReceivedAt, r.SourceIP, r.DeviceID, r.VDOM, r.LogID, r.Type, r.Subtype, r.Level, nullIP(r.SrcIP), r.SrcPort,
			nullIP(r.DstIP), r.DstPort, r.Protocol, r.Action, r.PolicyID, r.PolicyName, r.User, r.Application, r.Category, r.Hostname, r.URL, r.SentBytes,
			r.ReceivedBytes, r.DurationSeconds, r.ParseStatus, r.ParseError, fields, r.Raw, nullIfEmpty(r.AppRisk), mapID, r.DeviceName,
			nullIfEmpty(r.SrcMAC), nullIfEmpty(r.AITool), npsID})
	}
	_, err := d.pool.CopyFrom(ctx, pgx.Identifier{"fortigate_logs"}, logColumns, pgx.CopyFromRows(rows))
	if err == nil {
		noteLateRows(records)
		return nil
	}
	// Fall back to exactly what v2 wrote, so a problem in the v5 extras never stops logs reaching the database.
	log.Printf("insert with v5 columns failed, writing v2 columns only: %v", err)
	core := make([][]any, len(rows))
	for i, r := range rows {
		core[i] = r[:30]
	}
	if _, err2 := d.pool.CopyFrom(ctx, pgx.Identifier{"fortigate_logs"}, logColumns[:30], pgx.CopyFromRows(core)); err2 != nil {
		return fmt.Errorf("%w (v2 columns: %v)", err2, err)
	}
	noteLateRows(records)
	return &partialErr{err}
}

// partialErr: the logs were stored, only the v5 extras (firewall name, AI tag, NPS user) were left out.
type partialErr struct{ err error }

func (p *partialErr) Error() string { return "stored without v5 fields: " + p.err.Error() }

// Retention: on a hypertable whole day-chunks are dropped (instant, no bloat); on a plain table rows are deleted.
func (d *Database) Retention(ctx context.Context, days int) error {
	if d.ts {
		var n int
		rows, err := d.pool.Query(ctx, `SELECT drop_chunks('fortigate_logs', older_than => now() - make_interval(days => $1))`, days)
		if err != nil {
			return err
		}
		for rows.Next() {
			n++
		}
		rows.Close()
		if err = rows.Err(); err != nil {
			return err
		}
		if n > 0 {
			log.Printf("retention: dropped %d day chunk(s) older than %d days", n, days)
		}
	} else if _, err := d.pool.Exec(ctx, "DELETE FROM fortigate_logs WHERE event_time < now() - ($1 * interval '1 day')", days); err != nil {
		return err
	}
	for _, q := range []string{
		"DELETE FROM nps_sessions WHERE coalesce(ended, last_seen) < now() - ($1 * interval '1 day')",
		"DELETE FROM rollup_5m WHERE bucket < now() - ($1 * interval '1 day')",
		"DELETE FROM rollup_1h WHERE hour < now() - ($1 * interval '1 day')",
		"DELETE FROM rollup_ai WHERE hour < now() - ($1 * interval '1 day')",
		"DELETE FROM rollup_excl WHERE hour < now() - ($1 * interval '1 day')",
		"DELETE FROM rollup_evt WHERE hour < now() - ($1 * interval '1 day')",
		"DELETE FROM rollup_1d WHERE day < now() - ($1 * interval '1 day')",
		"DELETE FROM rollup_1d_done WHERE day < now() - ($1 * interval '1 day')",
		"DELETE FROM alerts WHERE last_seen < now() - ($1 * interval '1 day') AND status <> 'open'",
	} {
		if _, err := d.pool.Exec(ctx, q, days+7); err != nil {
			return err
		}
	}
	if _, err := d.pool.Exec(ctx, "DELETE FROM wan_samples WHERE ts < now() - ($1 * interval '1 day')", wanKeepDays()); err != nil {
		return err
	}
	if err := d.wanHealthRetention(ctx); err != nil { // v5.21
		return err
	}
	_, err := d.pool.Exec(ctx, "DELETE FROM audit_log WHERE at < now() - interval '400 days'")
	return err
}

// Spool holds batches the database could not take. maxBytes (spool_max_mb) stops a long database outage from filling
// the disk: past the limit new batches are refused (and reported) rather than written. 0 = no limit.
type Spool struct {
	dir      string
	maxBytes int64
}

var spoolSizeCache struct {
	sync.Mutex
	dir  string
	at   time.Time
	size int64
}

// size is cached for 5 s: during an outage a batch is spooled every second and the folder can hold thousands of files.
func (s Spool) size() int64 {
	c := &spoolSizeCache
	c.Lock()
	defer c.Unlock()
	if c.dir == s.dir && time.Since(c.at) < 5*time.Second {
		return c.size
	}
	n := s.scan()
	c.dir, c.at, c.size = s.dir, time.Now(), n
	return n
}

func (s Spool) scan() int64 {
	files, _ := filepath.Glob(filepath.Join(s.dir, "*.jsonl"))
	var n int64
	for _, f := range files {
		if fi, err := os.Stat(f); err == nil {
			n += fi.Size()
		}
	}
	return n
}

func (s Spool) Write(records []LogRecord) error {
	if err := os.MkdirAll(s.dir, 0750); err != nil {
		return err
	}
	if s.maxBytes > 0 {
		if used := s.size(); used >= s.maxBytes {
			return fmt.Errorf("spool is full (%d MB of %d MB): %d records not saved", used>>20, s.maxBytes>>20, len(records))
		}
	}
	name := filepath.Join(s.dir, fmt.Sprintf("spool-%d.jsonl", time.Now().UnixNano()))
	f, err := os.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(f)
	for _, r := range records {
		if err = enc.Encode(r); err != nil {
			f.Close()
			return err
		}
	}
	if err = f.Close(); err != nil {
		return err
	}
	if fi, e := os.Stat(name); e == nil {
		spoolSizeCache.Lock()
		if spoolSizeCache.dir == s.dir {
			spoolSizeCache.size += fi.Size()
		}
		spoolSizeCache.Unlock()
	}
	return nil
}

func (s Spool) Files() ([]string, error) {
	files, err := filepath.Glob(filepath.Join(s.dir, "spool-*.jsonl"))
	sort.Strings(files)
	return files, err
}

func (s Spool) Read(path string) ([]LogRecord, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	out := []LogRecord{}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var r LogRecord
		if err = json.Unmarshal([]byte(line), &r); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

var idxBusy atomic.Bool

func (d *Database) buildIndexes() {
	if !idxBusy.CompareAndSwap(false, true) { // one builder at a time, even if the connection is re-opened
		return
	}
	defer idxBusy.Store(false)
	for _, q := range backgroundIndexes {
		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Hour)
		// an earlier interrupted CONCURRENTLY build leaves an INVALID index behind: drop and retry
		name := strings.Fields(q)[6] // CREATE INDEX CONCURRENTLY IF NOT EXISTS <name> ...
		var invalid bool
		_ = d.pool.QueryRow(ctx, `SELECT NOT i.indisvalid FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid WHERE c.relname=$1`, name).Scan(&invalid)
		if invalid {
			_, _ = d.pool.Exec(ctx, `DROP INDEX CONCURRENTLY IF EXISTS `+name)
		}
		if _, err := d.pool.Exec(ctx, q); err != nil {
			log.Printf("background index %s: %v", name, err)
		}
		cancel()
	}
}
