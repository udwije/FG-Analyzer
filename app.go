package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5/pgconn"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type App struct {
	store        *ConfigStore
	metrics      Metrics
	started      time.Time
	dbMu         sync.RWMutex
	db           *Database
	queue        chan Envelope
	spool        Spool
	connecting   atomic.Bool // first connection (with schema upgrade) still running
	errMu        sync.Mutex
	lastErr      string
	lastErrAt    time.Time
	lastQ        string // last quarantined record's error
	lastQAt      time.Time
	lastSpoolLog time.Time     // rate limit for the "spool write failed" line
	users        *userStore    // dashboard accounts (<data>/users.json)
	sessions     *sessionStore // signed-in browsers (<data>/sessions.json)
	tlsOn        atomic.Bool   // dashboard served over HTTPS
}

// noteErr keeps the latest write problem for the dashboard and the service log.
func (a *App) noteErr(err error) {
	a.errMu.Lock()
	if err.Error() != a.lastErr || time.Since(a.lastErrAt) > time.Minute {
		log.Printf("database write: %v", err)
	}
	a.lastErr, a.lastErrAt = err.Error(), time.Now()
	a.errMu.Unlock()
}

// noteQuarantine: a single bad record was set aside. The pipeline is healthy, so this is not a "database problem";
// it is counted, logged (at most once a minute) and shown as a warning with the count.
func (a *App) noteQuarantine(err error) {
	a.errMu.Lock()
	defer a.errMu.Unlock()
	if time.Since(a.lastQAt) > time.Minute {
		log.Printf("quarantined a record the database rejected (total %d): %v", a.metrics.Quarantined.Load(), err)
	}
	a.lastQ, a.lastQAt = err.Error(), time.Now()
}

func NewApp(s *ConfigStore) *App {
	c := s.Get()
	onConfigChanged(c)
	npsEngine.configure(c.NPS)
	loadSessionTrack(filepath.Dir(s.path))
	dir := filepath.Dir(s.path)
	users, err := openUsers(dir)
	if err != nil {
		log.Fatalf("accounts: %v", err)
	}
	return &App{store: s, started: time.Now(), queue: make(chan Envelope, c.QueueCapacity), spool: Spool{dir: c.SpoolDirectory, maxBytes: c.SpoolMaxMB << 20},
		users: users, sessions: newSessionStore(filepath.Join(dir, "sessions.json"))}
}

// dataFolder: the folder that holds config.json (accounts and the certificate live next to it)
func (a *App) dataFolder() string { return filepath.Dir(a.store.path) }

func (a *App) getDB() *Database { a.dbMu.RLock(); defer a.dbMu.RUnlock(); return a.db }

func (a *App) setDB(d *Database) {
	a.dbMu.Lock()
	old := a.db
	a.db = d
	a.dbMu.Unlock()
	if old != nil && old != d {
		old.Close()
	}
}

func (a *App) connectDB(ctx context.Context) error {
	c := a.store.Get()
	start := time.Now()
	d, e := OpenDatabase(ctx, c.Database)
	if e != nil {
		return e
	}
	a.setDB(d)
	log.Printf("database connected (%s)", time.Since(start).Round(time.Millisecond)) // v5.14.1
	if err := d.loadAssignments(ctx); err != nil {
		log.Printf("assignments: %v", err)
	}
	if err := d.loadBlocklist(ctx); err != nil { // v5.20
		log.Printf("blocklist: %v", err)
	} else {
		a.blWriteFile()
	}
	return nil
}

func (a *App) Run(ctx context.Context) error {
	c := a.store.Get()
	_ = os.MkdirAll(c.SpoolDirectory, 0750)
	a.connecting.Store(true)
	go func() { // listener and web start at once; logs spool to disk until the database is ready
		defer a.connecting.Store(false)
		if e := a.connectDB(ctx); e != nil {
			log.Printf("database unavailable; spooling enabled: %v", e)
		}
	}()
	errc := make(chan error, 8)
	r := NewReceiver(c, a.queue, &a.metrics)
	go func() { errc <- r.Start(ctx) }()
	go func() { errc <- a.writer(ctx) }()
	go func() { errc <- a.replay(ctx) }()
	go func() { errc <- a.maintenance(ctx) }()
	go func() { errc <- a.serveWeb(ctx) }()
	go func() { errc <- a.npsLoop(ctx) }()
	go func() { errc <- a.rollupLoop(ctx) }()
	go func() { errc <- a.globalWarmer(ctx) }()
	go func() { errc <- a.directoryLoop(ctx) }()
	go func() { errc <- a.detectLoop(ctx) }()
	go func() { errc <- a.wanLoop(ctx) }()       // v5.16
	go func() { errc <- a.blocklistLoop(ctx) }() // v5.20
	go func() { errc <- a.healthLoop(ctx) }()    // v6.0: server health
	select {
	case <-ctx.Done():
		return nil
	case e := <-errc:
		return e
	}
}

// isDataError: PostgreSQL rejected the DATA (class 22 data exception / 23 constraint), not the connection.
// It also covers values the driver refuses to encode (text into an inet column, for example): pgx cancels the COPY
// and the server reports 57014, but it is still one bad record, not a lost connection.
func isDataError(err error) bool {
	if err == nil {
		return false
	}
	var pe *pgconn.PgError
	if errors.As(err, &pe) && (strings.HasPrefix(pe.Code, "22") || strings.HasPrefix(pe.Code, "23")) {
		return true
	}
	return strings.Contains(err.Error(), "unable to encode")
}

// insertResilient stores as many records as possible. A batch rejected because of bad DATA is split in halves until the
// offending record is isolated and moved to <spool>/quarantine, so one malformed line can never block the pipeline.
// It returns the records that were NOT stored (connection problems): only those must be spooled / retried.
func (a *App) insertResilient(ctx context.Context, d *Database, rs []LogRecord) ([]LogRecord, error) {
	err := d.InsertBatch(ctx, rs)
	var pe *partialErr
	if err == nil || errors.As(err, &pe) {
		return nil, err
	}
	if !isDataError(err) || len(rs) == 0 {
		return rs, err
	}
	if len(rs) == 1 {
		a.metrics.Quarantined.Add(1)
		a.metrics.Written.Add(-1) // callers count the whole batch as written; this record was not
		a.noteQuarantine(err)
		if e := (Spool{dir: filepath.Join(a.spool.dir, "quarantine"), maxBytes: 1 << 30}).Write(rs); e != nil {
			log.Printf("CRITICAL quarantine write failed: %v", e)
		}
		return nil, nil
	}
	mid := len(rs) / 2
	f1, e1 := a.insertResilient(ctx, d, rs[:mid])
	f2, e2 := a.insertResilient(ctx, d, rs[mid:])
	if e1 == nil {
		e1 = e2
	}
	return append(f1, f2...), e1
}

func (a *App) writer(ctx context.Context) error {
	c := a.store.Get()
	tick := time.NewTicker(time.Duration(c.BatchIntervalMS) * time.Millisecond)
	defer tick.Stop()
	batch := make([]LogRecord, 0, c.BatchSize)
	flush := func(force bool) {
		if len(batch) == 0 {
			return
		}
		// right after a restart the database is still connecting (schema check, TimescaleDB set-up): keep the logs in memory
		// for those seconds instead of writing thousands of tiny spool files
		if !force && holdForConnect(a.getDB() == nil, a.connecting.Load(), len(batch)) {
			return
		}
		rs := append([]LogRecord(nil), batch...)
		batch = batch[:0]
		d := a.getDB()
		var err error
		failed := rs
		if d == nil {
			err = errors.New("database not connected")
		} else {
			t0 := time.Now()
			failed, err = a.insertResilient(ctx, d, rs)
			noteWrite(time.Since(t0)) // v6.0: write latency on System health
		}
		var pe *partialErr
		if err == nil || errors.As(err, &pe) {
			a.metrics.Written.Add(int64(len(rs)))
			a.metrics.LastWritten.Store(time.Now().Unix())
			if pe != nil {
				a.noteErr(pe)
			}
			return
		}
		a.metrics.Written.Add(int64(len(rs) - len(failed)))
		a.metrics.DBErrors.Add(1)
		a.noteErr(err)
		if e := a.spool.Write(failed); e != nil {
			a.spoolFailed(e, len(failed))
		}
	}
	defer flush(true)
	defer saveSessionTrack(a.dataFolder()) // v5.16: runs after the last flush
	for {
		select {
		case e := <-a.queue:
			r := ParseLog(e.Data, e.Source)
			adjustSessionBytes(&r) // v5.12: bytes of this log, not the session's running total
			if r.ParseStatus != "parsed" {
				a.metrics.ParsePartial.Add(1)
			}
			batch = append(batch, r)
			if len(batch) >= c.BatchSize {
				flush(false)
			}
		case <-tick.C:
			flush(false)
		case <-ctx.Done():
			for {
				select {
				case e := <-a.queue:
					r := ParseLog(e.Data, e.Source)
					adjustSessionBytes(&r)
					batch = append(batch, r)
				default:
					flush(true)
					return nil
				}
			}
		}
	}
}

func (a *App) replay(ctx context.Context) error {
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			if a.connecting.Load() {
				continue
			}
			if a.getDB() == nil {
				cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
				if e := a.connectDB(cctx); e != nil {
					cancel()
					continue
				}
				cancel()
			}
			files, _ := a.spool.Files()
			spoolBacklog.Store(int64(len(files)))
			fails := 0
			for i, f := range files {
				spoolBacklog.Store(int64(len(files) - i))
				rs, e := a.spool.Read(f)
				if e != nil {
					log.Printf("spool read %s: %v", f, e)
					continue
				}
				failed, e := a.insertResilient(ctx, a.getDB(), rs)
				var pe *partialErr
				if e != nil && !errors.As(e, &pe) {
					// connection trouble: keep only what was not stored, so a retry cannot create duplicates
					a.metrics.DBErrors.Add(1)
					a.noteErr(e)
					a.metrics.Written.Add(int64(len(rs) - len(failed)))
					if len(failed) < len(rs) {
						if we := a.spool.Write(failed); we == nil {
							_ = os.Remove(f)
						}
					}
					// One failing spool file must not tear down the live connection: while the connection is down every new
					// log goes to the spool, so a file that fails every 15 s used to keep the collector disconnected for hours.
					// Reconnect only when the database really does not answer.
					if d := a.getDB(); d == nil {
						break
					} else if pctx, pcancel := context.WithTimeout(ctx, 5*time.Second); d.pool.Ping(pctx) != nil {
						pcancel()
						a.setDB(nil)
						break
					} else {
						pcancel()
					}
					if fails++; fails >= 3 {
						break // the database answers but keeps refusing these files: try again at the next tick
					}
					continue
				}
				a.metrics.Written.Add(int64(len(rs)))
				_ = os.Remove(f)
			}
			if rest, _ := a.spool.Files(); len(rest) < len(files) {
				spoolBacklog.Store(int64(len(rest)))
			}
		case <-ctx.Done():
			return nil
		}
	}
}

func (a *App) maintenance(ctx context.Context) error {
	t := time.NewTicker(24 * time.Hour)
	defer t.Stop()
	first := time.After(3 * time.Minute) // also at start-up: a service restarted more often than daily must still prune
	run := func() {
		if d := a.getDB(); d != nil {
			if err := d.Retention(ctx, a.store.Get().RetentionDays); err != nil {
				log.Printf("retention failed: %v", err)
				a.noteErr(fmt.Errorf("retention: %w", err))
			}
		}
	}
	for {
		select {
		case <-first:
			run()
		case <-t.C:
			run()
		case <-ctx.Done():
			return nil
		}
	}
}

func (a *App) status() map[string]any {
	c := a.store.Get()
	files, _ := a.spool.Files()
	return map[string]any{"uptime_seconds": int64(time.Since(a.started).Seconds()), "received": a.metrics.Received.Load(), "written": a.metrics.Written.Load(),
		"skipped": a.metrics.Skipped.Load(), "udp_dropped": a.metrics.UDPDropped.Load(), "tcp_waits": a.metrics.TCPWaits.Load(), "spool_lost": a.metrics.SpoolLost.Load(), "spool_backlog": spoolBacklog.Load(), "db_errors": a.metrics.DBErrors.Load(),
		"parse_partial": a.metrics.ParsePartial.Load(), "quarantined": a.metrics.Quarantined.Load(), "active_connections": a.metrics.ActiveConnections.Load(), "queue_depth": len(a.queue),
		"queue_capacity": cap(a.queue), "spool_files": len(files), "database_connected": a.getDB() != nil, "database_connecting": a.connecting.Load(), "database_step": dbStepText(), "listen": c.ListenAddress,
		"firewalls": sourceStatus(c), "last_received": a.metrics.LastReceived.Load(), "last_written": a.metrics.LastWritten.Load(),
		"last_db_error": a.lastErrText(), "last_quarantine": a.lastQText(), "keep_subtypes": c.KeepSubtypes, "refused": refusedSenders(), "nps_enabled": c.NPS.Enabled, "now": time.Now().Unix(),
		"summaries": rollupInfo(), "timescale": a.getDB() != nil && a.getDB().ts}
}

func dataDir() string {
	if v := os.Getenv("PROGRAMDATA"); v != "" {
		return firstExisting(filepath.Join(v, "LogSikka"), filepath.Join(v, "FortiLogCollector"))
	}
	d, _ := os.UserConfigDir()
	if d == "" {
		d = "."
	}
	return filepath.Join(d, "LogSikka")
}

func writeJSON(path string, v any) error {
	b, e := json.MarshalIndent(v, "", "  ")
	if e != nil {
		return e
	}
	return os.WriteFile(path, b, 0600)
}

var _ = writeJSON

func (a *App) lastQText() map[string]any {
	a.errMu.Lock()
	defer a.errMu.Unlock()
	if a.lastQ == "" {
		return nil
	}
	return map[string]any{"error": a.lastQ, "at": a.lastQAt.Unix()}
}

func (a *App) lastErrText() map[string]any {
	a.errMu.Lock()
	defer a.errMu.Unlock()
	if a.lastErr == "" {
		return nil
	}
	return map[string]any{"error": a.lastErr, "at": a.lastErrAt.Unix()}
}

// holdMax: how many records the writer keeps in memory while the database connects (about 3.5 minutes at 270/s).
const holdMax = 60000

// holdForConnect: keep the batch in memory while the first database connection is still being made.
func holdForConnect(dbMissing, connecting bool, n int) bool {
	return dbMissing && connecting && n < holdMax
}

// spoolBacklog is the number of spool files waiting to be replayed. While it is large the dashboard warmer and the
// re-summarising of old hours pause, so the replay gets the disk.
var spoolBacklog atomic.Int64

const backlogBusy = 200

// spoolFailed counts records that could not be saved anywhere and logs it at most once a minute.
func (a *App) spoolFailed(err error, n int) {
	a.metrics.SpoolLost.Add(int64(n))
	a.errMu.Lock()
	defer a.errMu.Unlock()
	if time.Since(a.lastSpoolLog) > time.Minute {
		a.lastSpoolLog = time.Now()
		log.Printf("CRITICAL spool write failed: %v (%d records not saved since start)", err, a.metrics.SpoolLost.Load())
	}
}
