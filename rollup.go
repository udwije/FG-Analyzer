package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
)

// Rollups: small summary tables the All logs dashboard reads instead of scanning millions of raw rows.
//
//   rollup_5m  per 5 minutes x firewall x log type x subtype x level: counts, blocked, bytes, user coverage.
//              Answers the totals, the timeline, log types, subtypes, severity and the firewall table.
//   rollup_1h  per hour x firewall x log type x dimension x value: counts, blocked, bytes.
//              Answers every "top" list (sources, users, destinations, services, policies, apps, countries...).
//              Busy dimensions keep the top values per hour only (2,000 by events, 500 by data, 500 by blocks;
//              20,000 for source IPs and users), so long-range top-10 lists are exact in practice.
//
// The collector keeps them current: the last 15 minutes of rollup_5m every minute, the current hour of rollup_1h
// every 5 minutes, hours touched by late logs / mappings / re-classify on demand, and older data is back-filled
// (newest first, up to 31 days) a few hours per minute. Raw rows are still used for drill-downs (any filter other
// than firewall and log type), for ranges under 3 hours, and for periods the back-fill has not reached yet.

const (
	rollupBackfillDays = 31
	rollupDirtyMax     = 24 * 14
)

type rollupStatus struct {
	mu        sync.Mutex
	covered   time.Time // oldest hour that is summarised (back-fill progress)
	complete  bool      // back-fill reached the oldest log (or the 31-day limit)
	known     bool      // state loaded from the database
	extra     time.Time // v5.7: web categories and high-risk apps are summarised back to here
	extraOK   bool
	ai        time.Time // v5.10: the AI summary (rollup_ai) reaches back to here
	aiOK      bool
	evt       time.Time // v5.11: the sign-in summary (rollup_evt) reaches back to here
	evtOK     bool
	rb        time.Time // v5.12: hours from here on carry traffic directions and corrected data volumes
	rbOK      bool
	mp        time.Time // v5.13: user-mapping dimensions (nouser_src, ipuser) reach back to here
	mpOK      bool
	e514      time.Time // v5.14: the sign-in summary holds "via" and "target" back to here
	e514OK    bool
	lastRun   time.Time
	lastErr   string
	lastErrAt time.Time
	dirty     map[time.Time]bool
}

var roll = &rollupStatus{dirty: map[time.Time]bool{}}

// hourStart uses local time so hours line up with the clock on the wall (Sri Lanka is UTC+5:30).
func hourStart(t time.Time) time.Time {
	t = t.In(time.Local)
	return time.Date(t.Year(), t.Month(), t.Day(), t.Hour(), 0, 0, 0, time.Local)
}

// markRollupDirty queues the hours between from and to for re-summarising (late logs, mappings, re-classify).
func markRollupDirty(from, to time.Time) {
	limit := hourStart(time.Now().AddDate(0, 0, -rollupBackfillDays))
	h := hourStart(from)
	if h.Before(limit) {
		h = limit
	}
	roll.mu.Lock()
	defer roll.mu.Unlock()
	for ; h.Before(to) && len(roll.dirty) < rollupDirtyMax; h = h.Add(time.Hour) {
		roll.dirty[h] = true
	}
}

func (s *rollupStatus) nextDirty() (time.Time, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var best time.Time
	for h := range s.dirty {
		if best.IsZero() || h.After(best) {
			best = h
		}
	}
	if best.IsZero() {
		return best, false
	}
	delete(s.dirty, best)
	return best, true
}

func (s *rollupStatus) setErr(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastRun = time.Now()
	if err != nil && !errors.Is(err, context.Canceled) {
		s.lastErr, s.lastErrAt = err.Error(), time.Now()
		log.Printf("rollup: %v", err)
	}
}

// covers: rollups can answer a period starting at hour h.
func (s *rollupStatus) covers(h time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.known && (s.complete || !h.Before(s.covered))
}

func rollupInfo() map[string]any {
	roll.mu.Lock()
	defer roll.mu.Unlock()
	out := map[string]any{"ready": roll.known, "complete": roll.complete, "pending_hours": len(roll.dirty), "ai_complete": roll.aiOK,
		"signins_complete": roll.evtOK, "directions_complete": roll.rbOK, "mapping_complete": roll.mpOK}
	if !roll.rb.IsZero() {
		out["directions_from"] = roll.rb.Unix()
	}
	if !roll.ai.IsZero() {
		out["ai_from"] = roll.ai.Unix()
	}
	if !roll.covered.IsZero() {
		out["covered_from"] = roll.covered.Unix()
	}
	if !roll.lastRun.IsZero() {
		out["last_run"] = roll.lastRun.Unix()
	}
	if roll.lastErr != "" {
		out["last_error"], out["last_error_at"] = roll.lastErr, roll.lastErrAt.Unix()
	}
	return out
}

// noteLateRows queues the hours of logs that arrived after their hour was summarised (spool replay, FortiGate
// buffering after an outage).
func noteLateRows(records []LogRecord) {
	edge := hourStart(time.Now()).Add(-time.Hour)
	var lo, hi time.Time
	for _, r := range records {
		if r.EventTime.Before(edge) {
			if lo.IsZero() || r.EventTime.Before(lo) {
				lo = r.EventTime
			}
			if r.EventTime.After(hi) {
				hi = r.EventTime
			}
		}
	}
	if !lo.IsZero() {
		markRollupDirty(lo, hi.Add(time.Nanosecond))
	}
}

// ---------------------------------------------------------------- building the summaries

const fwExpr = `coalesce(nullif(device_name,''), host(source_ip))`
const ltExpr = `coalesce(nullif(log_type,''),'(none)')`

func (d *Database) rollup5m(ctx context.Context, from, to time.Time) error {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `DELETE FROM rollup_5m WHERE bucket >= $1 AND bucket < $2`, from, to); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO rollup_5m (bucket, fw, log_type, subtype, level, zone, cnt, blk, byt, snt, usr, nps, mp, last_event)
		SELECT to_timestamp(floor(extract(epoch FROM event_time)/300)*300), `+fwExpr+`, `+ltExpr+`, coalesce(nullif(subtype,''),'(none)'), coalesce(level,''), z,
			count(*), count(*) FILTER (WHERE `+blockedExpr+`), coalesce(sum(fl_sent(log_id, fields, sent_bytes)+fl_rcvd(log_id, fields, received_bytes)),0)::bigint, coalesce(sum(`+epSentSQL("z")+`),0)::bigint,
			count(*) FILTER (WHERE coalesce(user_name,'') <> ''), count(*) FILTER (WHERE nps_id IS NOT NULL), count(*) FILTER (WHERE map_id IS NOT NULL), max(event_time)
		FROM (SELECT *, `+zoneSQL()+` AS z FROM fortigate_logs WHERE event_time >= $1 AND event_time < $2) r
		GROUP BY 1, 2, 3, 4, 5, 6`, from, to); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (d *Database) rollup1h(ctx context.Context, h time.Time) error {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `DELETE FROM rollup_1h WHERE hour = $1`, h); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO rollup_1h (dim, hour, fw, log_type, name, cnt, blk, byt, snt)
		SELECT dim, $1::timestamptz, fw, lt, name, cnt, blk, byt, snt FROM (
		  SELECT g.*, row_number() OVER (PARTITION BY dim, fw, lt ORDER BY cnt DESC) AS rc,
		              row_number() OVER (PARTITION BY dim, fw, lt ORDER BY byt DESC) AS rb,
		              row_number() OVER (PARTITION BY dim, fw, lt ORDER BY blk DESC) AS rk
		  FROM (
		    SELECT fw, lt,
		      CASE WHEN GROUPING(src) = 0 THEN 'src_ip' WHEN GROUPING(usr) = 0 THEN 'user' WHEN GROUPING(app) = 0 THEN 'application'
		           WHEN GROUPING(svc) = 0 THEN 'service' WHEN GROUPING(pol) = 0 THEN 'policy' WHEN GROUPING(ctry) = 0 THEN 'country'
		           WHEN GROUPING(act) = 0 THEN 'action' WHEN GROUPING(tool) = 0 THEN 'tool' WHEN GROUPING(msg) = 0 THEN 'msg'
		           WHEN GROUPING(cat) = 0 THEN 'category' WHEN GROUPING(rapp) = 0 THEN 'riskapp'
		           WHEN GROUPING(iusr) = 0 THEN 'inet_user' WHEN GROUPING(isrc) = 0 THEN 'inet_src' WHEN GROUPING(idst) = 0 THEN 'inet_dest'
		           WHEN GROUPING(asrc) = 0 THEN 'adv_src' WHEN GROUPING(adst) = 0 THEN 'adv_dest' WHEN GROUPING(asvc) = 0 THEN 'adv_svc' ELSE 'dest' END AS dim,
		      coalesce(src, usr, app, svc, pol, ctry, act, tool, msg, cat, rapp, iusr, isrc, idst, asrc, adst, asvc, dst) AS name,
		      count(*) AS cnt, count(*) FILTER (WHERE isblk) AS blk, coalesce(sum(byts),0)::bigint AS byt, coalesce(sum(sn),0)::bigint AS snt
		    FROM (SELECT CASE WHEN dev THEN NULL ELSE x0.src END AS src, CASE WHEN dev THEN NULL ELSE x0.dst END AS dst, x0.fw, x0.lt, x0.isblk, x0.byts, x0.sn,
		            x0.usr, x0.app, x0.svc, x0.pol, x0.ctry, x0.act, x0.tool, x0.msg, x0.cat, x0.rapp,
		            CASE WHEN inet THEN x0.usr END AS iusr, CASE WHEN inet THEN x0.src END AS isrc, CASE WHEN inet THEN x0.dst END AS idst,
		            CASE WHEN dev THEN x0.src END AS asrc, CASE WHEN dev THEN x0.dst END AS adst, CASE WHEN dev THEN x0.svc END AS asvc FROM (SELECT `+fwExpr+` AS fw, `+ltExpr+` AS lt, coalesce(`+blockedExpr+`, false) AS isblk,
		            coalesce(fl_sent(log_id, fields, sent_bytes)+fl_rcvd(log_id, fields, received_bytes),0) AS byts, `+epSentSQL("z")+` AS sn,
		            z IN `+deviceZones+` AS dev, host(src_ip) AS src, nullif(user_name,'') AS usr, nullif(application,'') AS app, nullif(fields->>'service','') AS svc,
		            coalesce(nullif(policy_name,''), nullif(policy_id,0)::text) AS pol, nullif(fields->>'dstcountry','') AS ctry,
		            nullif(action,'') AS act, ai_tool AS tool, CASE WHEN log_type = 'event' THEN nullif(fields->>'logdesc','') END AS msg,
		            nullif(category,'') AS cat, CASE WHEN app_risk IN ('high','critical') THEN nullif(application,'') END AS rapp,
		            coalesce(nullif(hostname,''), host(dst_ip)) AS dst, z = 'internet' AS inet
		          FROM (SELECT *, `+zoneSQL()+` AS z FROM fortigate_logs WHERE event_time >= $1 AND event_time < $2) r) x0) x
		    GROUP BY GROUPING SETS ((fw,lt,src),(fw,lt,usr),(fw,lt,app),(fw,lt,svc),(fw,lt,pol),(fw,lt,ctry),(fw,lt,act),(fw,lt,tool),(fw,lt,msg),(fw,lt,cat),(fw,lt,rapp),(fw,lt,iusr),(fw,lt,isrc),(fw,lt,idst),(fw,lt,asrc),(fw,lt,adst),(fw,lt,asvc),(fw,lt,dst))
		  ) g WHERE name IS NOT NULL
		) t WHERE rc <= CASE WHEN dim IN ('src_ip','user','inet_user','inet_src') THEN 20000 ELSE 2000 END OR rb <= 500 OR rk <= 500`, h, h.Add(time.Hour)); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// rollupHour re-summarises one whole hour (all summary tables).
func (d *Database) rollupHour(ctx context.Context, h time.Time) error {
	if err := d.rollup5m(ctx, h, h.Add(time.Hour)); err != nil {
		return err
	}
	if err := d.rollup1h(ctx, h); err != nil {
		return err
	}
	if err := d.rollupAIHour(ctx, h); err != nil {
		return err
	}
	if err := d.rollupEvtHour(ctx, h); err != nil {
		return err
	}
	if err := d.rollupMapHour(ctx, h); err != nil {
		return err
	}
	d.invalidateDay(ctx, h)
	if e := exclCur.Load(); e.active() {
		return d.exclHour(ctx, h, e)
	}
	return nil
}

func (d *Database) rollupLoadState(ctx context.Context) error {
	var live *time.Time
	_ = d.pool.QueryRow(ctx, `SELECT upto FROM rollup_state WHERE name='live'`).Scan(&live)
	cur := hourStart(time.Now())
	// v5.12: the state is read without holding roll.mu (a failed insert used to return with the lock held, which
	// froze the summaries and the status page)
	state := func(name string) (time.Time, error) {
		var t *time.Time
		_ = d.pool.QueryRow(ctx, `SELECT upto FROM rollup_state WHERE name=$1`, name).Scan(&t)
		if t != nil {
			return hourStart(*t), nil
		}
		if _, err := d.pool.Exec(ctx, `INSERT INTO rollup_state(name, upto) VALUES ($1, $2) ON CONFLICT (name) DO NOTHING`, name, cur); err != nil {
			return time.Time{}, err
		}
		return cur, nil
	}
	vals := map[string]time.Time{}
	for _, n := range []string{"backfill", "extra", "ai", "evt", "r516", "map", "evt514"} {
		t, err := state(n)
		if err != nil {
			return err
		}
		vals[n] = t
	}
	// hours the service was not running for: summarise them again
	if live != nil && live.Before(cur.Add(-time.Hour)) {
		markRollupDirty(*live, cur)
	}
	roll.mu.Lock()
	roll.extra, roll.ai, roll.evt, roll.rb, roll.mp, roll.e514 = vals["extra"], vals["ai"], vals["evt"], vals["r516"], vals["map"], vals["evt514"]
	roll.covered, roll.known = vals["backfill"], true
	roll.mu.Unlock()
	return nil
}

func (d *Database) setState(ctx context.Context, name string, t time.Time) error {
	_, err := d.pool.Exec(ctx, `INSERT INTO rollup_state(name, upto) VALUES ($1, $2) ON CONFLICT (name) DO UPDATE SET upto = EXCLUDED.upto`, name, t)
	return err
}

// rollupBackfill summarises up to n older hours, newest first, until the oldest log or the 31-day limit.
func (d *Database) rollupBackfill(ctx context.Context, n int) error {
	roll.mu.Lock()
	covered, complete := roll.covered, roll.complete
	roll.mu.Unlock()
	if complete {
		return nil
	}
	var oldest *time.Time
	if err := d.pool.QueryRow(ctx, `SELECT min(event_time) FROM fortigate_logs`).Scan(&oldest); err != nil {
		return err
	}
	if oldest == nil { // nothing stored yet: every period is "covered"
		roll.mu.Lock()
		roll.complete = true
		roll.mu.Unlock()
		return nil
	}
	floor := hourStart(time.Now().AddDate(0, 0, -rollupBackfillDays))
	if hourStart(*oldest).After(floor) {
		floor = hourStart(*oldest)
	}
	for i := 0; i < n && covered.After(floor); i++ {
		h := covered.Add(-time.Hour)
		if err := d.rollupHour(ctx, h); err != nil {
			return err
		}
		if err := d.setState(ctx, "backfill", h); err != nil {
			return err
		}
		covered = h
		roll.mu.Lock()
		roll.covered = h
		roll.mu.Unlock()
	}
	if !covered.After(floor) {
		roll.mu.Lock()
		roll.complete = true
		roll.mu.Unlock()
		log.Printf("rollup: summaries are complete back to %s", covered.Format("2006-01-02 15:04"))
	}
	return nil
}

func (d *Database) rollupTick(ctx context.Context, lastHourly *time.Time) error {
	now := time.Now()
	// 1. totals and timeline: the last 15 minutes, every minute
	end := now.Truncate(5 * time.Minute).Add(5 * time.Minute)
	if err := d.rollup5m(ctx, end.Add(-20*time.Minute), end); err != nil {
		return fmt.Errorf("5-minute summary: %w", err)
	}
	// 2. top lists: the current hour every 5 minutes, and the previous hour once more just after the hour
	if now.Sub(*lastHourly) >= 5*time.Minute {
		cur := hourStart(now)
		if err := d.rollup1h(ctx, cur); err != nil {
			return fmt.Errorf("hourly summary: %w", err)
		}
		if err := d.rollupAIHour(ctx, cur); err != nil {
			return fmt.Errorf("AI summary: %w", err)
		}
		if err := d.rollupEvtHour(ctx, cur); err != nil {
			return fmt.Errorf("sign-in summary: %w", err)
		}
		if err := d.rollupMapHour(ctx, cur); err != nil {
			return fmt.Errorf("mapping summary: %w", err)
		}
		d.exclLive(ctx, cur, false)
		if now.Sub(cur) < 15*time.Minute {
			if err := d.rollupHour(ctx, cur.Add(-time.Hour)); err != nil {
				return fmt.Errorf("hourly summary: %w", err)
			}
		}
		if err := d.setState(ctx, "live", cur); err != nil {
			return err
		}
		*lastHourly = now
	}
	// while the spool is being replayed every batch re-dirties old hours: summarise them once, after the replay
	if spoolBacklog.Load() > backlogBusy {
		return nil
	}
	// v6.0.1: the work below reads whole hours of raw logs. While dashboards are being used it waits (the live
	// summaries above still run), so the two never fight over the disk.
	if dashboardsBusy() {
		bgPaused.Store(time.Now().Unix())
		return nil
	}
	// 3. hours changed by late logs, mappings or re-classify
	for i := 0; i < 4; i++ {
		h, ok := roll.nextDirty()
		if !ok {
			break
		}
		if err := d.rollupHour(ctx, h); err != nil {
			markRollupDirty(h, h.Add(time.Hour))
			return fmt.Errorf("re-summarising %s: %w", h.Format("2006-01-02 15:04"), err)
		}
	}
	// 4. older data
	if err := d.rollupBackfill(ctx, 3); err != nil {
		return err
	}
	// 5. v5.7: web categories and high-risk apps for hours summarised by an older version
	if err := d.rollupExtraBackfill(ctx, 6); err != nil {
		return err
	}
	// 6. v5.10: the AI summary for hours summarised by an older version
	if err := d.rollupAIBackfill(ctx, 8); err != nil {
		return err
	}
	// 7. v5.12: re-summarise history once (traffic directions, corrected volumes; includes sign-ins)
	if err := d.rollupRebuild(ctx, 2); err != nil {
		return err
	}
	// 8. v5.11: sign-ins and configuration changes, when the rebuild has already passed (or for very old data)
	if err := d.rollupEvtBackfill(ctx, 12); err != nil {
		return err
	}
	// 9. v5.10: executive summary exclusions for hours the current rules have not been applied to
	if err := d.exclBackfill(ctx, 3); err != nil {
		return err
	}
	// 10. v5.13: user-mapping dimensions for older hours, then the daily summary of finished days
	if err := d.rollupMapBackfill(ctx, 6); err != nil {
		return err
	}
	if err := d.rollupDays(ctx, 2); err != nil {
		return err
	}
	// 11. v5.14: sign-ins of the last 48 hours once more, with how the firewall was reached
	return d.rollupEvtRefresh(ctx, 12)
}

func (a *App) rollupLoop(ctx context.Context) error {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	var lastHourly time.Time
	var loadedFor *Database
	wait := time.After(15 * time.Second)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-wait:
		case <-t.C:
		}
		d := a.getDB()
		if d == nil {
			continue
		}
		rctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
		var err error
		if loadedFor != d {
			if err = d.rollupLoadState(rctx); err == nil {
				loadedFor = d
			}
		}
		if err == nil {
			err = d.rollupTick(rctx, &lastHourly)
		}
		cancel()
		roll.setErr(err)
	}
}

// ---------------------------------------------------------------- reading the summaries

// rollupEligible: only firewall and log type filters, and at least 3 hours (shorter periods use 1-minute raw data).
func rollupEligible(f Filter) bool {
	if f.Q != "" || f.Scope != "" || f.Subtype != "" || f.Outcome != "" || f.Action != "" || f.Extra != "" {
		return false
	}
	for _, v := range []string{f.User, f.Src, f.Dst, f.Category, f.App, f.Host, f.Risk, f.Tool, f.Level, f.Service, f.Msg, f.Policy} {
		if strings.TrimSpace(v) != "" {
			return false
		}
	}
	return f.To.Sub(f.From) >= 3*time.Hour && roll.covers(hourStart(f.From))
}

func rollWhere(f Filter, timeCol string, from, to time.Time) (string, []any) {
	args := []any{from, to}
	conds := []string{timeCol + " >= $1", timeCol + " < $2"}
	if f.Type != "" {
		conds = append(conds, "log_type = "+addArg(&args, f.Type))
	}
	if c := textCond(&args, f.FW, true, "fw"); c != "" {
		conds = append(conds, c)
	}
	if f.Endpoint { // v5.16: endpoint view leaves device traffic out
		conds = append(conds, "zone NOT IN "+deviceZones)
	}
	return strings.Join(conds, " AND "), args
}

func (d *Database) globalOverviewRollup(ctx context.Context, f Filter, step int64) (map[string]any, error) {
	rel, args := rollWhere(f, "bucket", f.From, f.To)
	release, err := d.acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	q := `SELECT GROUPING(b,t,st,lv,fw)::int, b, t, st, lv, fw,
		sum(cnt)::bigint, sum(blk)::bigint, sum(byt)::bigint, sum(snt)::bigint, sum(usr)::bigint, sum(nps)::bigint, sum(mp)::bigint, max(last_event)
	FROM (SELECT (floor(extract(epoch FROM bucket)/{S})*{S})::bigint AS b, log_type AS t, subtype AS st, nullif(level,'') AS lv, fw,
		cnt, blk, byt, snt, usr, nps, mp, last_event FROM rollup_5m WHERE ` + rel + `) x
	GROUP BY GROUPING SETS ((b),(t),(t,st),(lv),(fw),())`
	rows, err := d.pool.Query(ctx, strings.ReplaceAll(q, "{S}", strconv.FormatInt(step, 10)), args...)
	if err != nil {
		return nil, err
	}
	return scanGlobalOverview(rows, f, step)
}

func (d *Database) prevTotalsRollup(ctx context.Context, f Filter) (map[string]int64, error) {
	span := f.To.Sub(f.From)
	rel, args := rollWhere(f, "bucket", f.From.Add(-span), f.From)
	release, err := d.acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	var total, blk, byt int64
	err = d.pool.QueryRow(ctx, `SELECT coalesce(sum(cnt),0)::bigint, coalesce(sum(blk),0)::bigint, coalesce(sum(byt),0)::bigint FROM rollup_5m WHERE `+rel, args...).Scan(&total, &blk, &byt)
	return map[string]int64{"total": total, "blocked": blk, "bytes": byt, "riskNB": 0}, err
}

// topRollup mirrors TopOrder: the busiest values of one dimension plus the number of distinct values.
// blockedOnly lists values by blocked events (count = blocked events, as the raw "blocked" filter does).
func (d *Database) topRollup(ctx context.Context, dim string, f Filter, from, to time.Time, limit int, order string, blockedOnly bool) ([]map[string]any, int64, error) {
	args := []any{}
	d.loadDaysDone(ctx)
	src := rollSource(f, from, to, []string{dim}, &args, false) // v5.13: finished days from rollup_1d
	release, err := d.acquire(ctx)
	if err != nil {
		return nil, 0, err
	}
	defer release()
	col := map[string]string{"cnt": "cnt", "byt": "byt", "snt": "snt"}[order]
	if col == "" {
		col = "cnt"
	}
	having := ""
	if blockedOnly {
		col, having = "blk", " WHERE blk > 0"
	}
	lim := addArg(&args, limit)
	rows, err := d.pool.Query(ctx, `SELECT name, cnt, blk, byt, snt, count(*) OVER () FROM (
		SELECT name, sum(cnt)::bigint AS cnt, sum(blk)::bigint AS blk, sum(byt)::bigint AS byt, sum(snt)::bigint AS snt
		FROM `+src+` GROUP BY name) t`+having+` ORDER BY `+col+` DESC, name LIMIT `+lim, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []map[string]any{}
	var groups int64
	for rows.Next() {
		var name string
		var c, b, y, s int64
		if err = rows.Scan(&name, &c, &b, &y, &s, &groups); err != nil {
			return nil, 0, err
		}
		if blockedOnly {
			out = append(out, map[string]any{"name": name, "count": b, "blocked": b, "bytes": int64(0), "sent": int64(0)})
		} else {
			out = append(out, map[string]any{"name": name, "count": c, "blocked": b, "bytes": y, "sent": s})
		}
	}
	return out, groups, rows.Err()
}

// globalFromRollups answers the whole All logs dashboard from the summaries. Totals and the timeline start at
// the 5-minute mark, top lists at the hour (both reported back so the page can say so).
func (d *Database) globalFromRollups(ctx context.Context, f Filter) (map[string]any, error) {
	gf := f
	gf.From = f.From.Truncate(5 * time.Minute)
	fromH := hourStart(f.From)
	step := bucketSeconds(gf)
	if step < 300 {
		step = 300
	}
	out := map[string]any{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	var firstErr error
	put := func(k string, v any, e error) {
		mu.Lock()
		defer mu.Unlock()
		if e != nil {
			if firstErr == nil {
				firstErr = e
			}
			return
		}
		if m, ok := v.(map[string]any); ok && k == "" {
			for kk, vv := range m {
				out[kk] = vv
			}
			return
		}
		out[k] = v
	}
	wg.Add(2)
	go func() { defer wg.Done(); res, e := d.globalOverviewRollup(ctx, gf, step); put("", res, e) }()
	go func() { defer wg.Done(); res, e := d.prevTotalsRollup(ctx, gf); put("prev", res, e) }()
	type job struct {
		key, dim, order string
		n               int
		blocked         bool
	}
	jobs := []job{{"sources", "src_ip", "cnt", 10, false}, {"users", "user", "cnt", 10, false}, {"dests", "dest", "cnt", 10, false},
		{"services", "service", "cnt", 10, false}, {"policies", "policy", "cnt", 10, false}, {"apps", "application", "cnt", 10, false},
		{"countries", "country", "byt", 10, false}, {"whereData", "dest", "byt", 10, false}, {"uploaders", "src_ip", "snt", 10, false},
		{"mostBlocked", "dest", "cnt", 10, true}, {"blockedSources", "src_ip", "cnt", 10, true}, {"actions", "action", "cnt", 10, false},
		{"aiTools", "tool", "cnt", 8, false},
		// v5.10 widgets
		{"categories", "category", "cnt", 10, false}, {"riskApps", "riskapp", "cnt", 10, false}, {"usersData", "user", "byt", 10, false},
		// v5.12: internet traffic only
		{"usersInet", "inet_user", "byt", 10, false}, {"uploadersInet", "inet_src", "snt", 10, false}, {"whereInet", "inet_dest", "byt", 10, false}}
	if f.Type == "" || f.Type == "event" {
		jobs = append(jobs, job{"messages", "msg", "cnt", 12, false})
	}
	if !f.Endpoint { // v5.16: Advanced view: what the network devices themselves send, and duplicates
		jobs = append(jobs, job{"advSources", "adv_src", "cnt", 12, false}, job{"advDests", "adv_dest", "cnt", 12, false},
			job{"advServices", "adv_svc", "cnt", 12, false})
	}
	wg.Add(2)
	go func() { defer wg.Done(); res, e := d.heatRollup(ctx, gf); put("heat", res, e) }()
	go func() { defer wg.Done(); res, e := d.zonesRollup(ctx, gf, step); put("", res, e) }()
	for _, j := range jobs {
		wg.Add(1)
		go func(j job) {
			defer wg.Done()
			rows, groups, e := d.topRollup(ctx, j.dim, f, fromH, f.To, j.n, j.order, j.blocked)
			if e == nil {
				put(j.key+"Groups", groups, nil)
			}
			put(j.key, rows, e)
		}(j)
	}
	wg.Wait()
	if firstErr != nil {
		return nil, firstErr
	}
	out["mode"], out["listsFrom"] = "summary", fromH
	out["directionsComplete"] = inetCovers(fromH)
	return out, nil
}

// scanGlobalOverview reads the GROUPING SETS result shared by the raw and the summary queries.
func scanGlobalOverview(rows pgx.Rows, f Filter, step int64) (map[string]any, error) {
	defer rows.Close()
	var tot gAgg
	series := []Bucket{}
	types, subtypes, levels, fws := []map[string]any{}, []map[string]any{}, []map[string]any{}, []map[string]any{}
	for rows.Next() {
		var g int
		var b *int64
		var t, st, lv, fw *string
		var last *time.Time // NULL when the period has no logs (the grand-total row still comes back)
		var cnt, blk, byt, snt, usr, nps, mp *int64
		if err := rows.Scan(&g, &b, &t, &st, &lv, &fw, &cnt, &blk, &byt, &snt, &usr, &nps, &mp, &last); err != nil {
			return nil, err
		}
		v := func(p *int64) int64 {
			if p == nil {
				return 0
			}
			return *p
		}
		x := gAgg{v(cnt), v(blk), v(byt), v(snt), v(usr), v(nps), v(mp)}
		row := func(name string) map[string]any {
			return map[string]any{"name": name, "count": x.cnt, "blocked": x.blk, "bytes": x.byt, "sent": x.snt, "users": x.usr, "last": last}
		}
		switch g {
		case 15:
			if b != nil {
				series = append(series, Bucket{T: *b, Total: x.cnt, Blocked: x.blk, Bytes: x.byt, Sent: x.snt})
			}
		case 23:
			if t != nil {
				types = append(types, row(*t))
			}
		case 19:
			if t != nil && st != nil {
				m := row(*st)
				m["type"] = *t
				subtypes = append(subtypes, m)
			}
		case 29:
			if lv != nil {
				levels = append(levels, row(*lv))
			}
		case 30:
			if fw != nil {
				fws = append(fws, row(*fw))
			}
		case 31:
			tot = x
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sort.Slice(series, func(i, j int) bool { return series[i].T < series[j].T })
	byCount := func(l []map[string]any) []map[string]any {
		sort.Slice(l, func(i, j int) bool { return l[i]["count"].(int64) > l[j]["count"].(int64) })
		return l
	}
	sevRank := map[string]int{"emergency": 0, "alert": 1, "critical": 2, "error": 3, "warning": 4, "notice": 5, "information": 6, "debug": 7}
	rank := func(m map[string]any) int {
		if r, ok := sevRank[m["name"].(string)]; ok {
			return r
		}
		return 9
	}
	sort.Slice(levels, func(i, j int) bool { return rank(levels[i]) < rank(levels[j]) })
	return map[string]any{"total": tot.cnt, "blocked": tot.blk, "bytes": tot.byt, "sent": tot.snt, "userKnown": tot.usr, "userNPS": tot.nps, "userMapped": tot.mp,
		"step": step, "from": f.From, "to": f.To, "series": series, "types": byCount(types), "subtypes": byCount(subtypes), "levels": levels, "firewalls": byCount(fws)}, nil
}

// ---------------------------------------------------------------- v5.7 extra dimensions

// rollupExtraHour adds web categories and high-risk applications to an hour summarised before v5.7.
func (d *Database) rollupExtraHour(ctx context.Context, h time.Time) error {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `DELETE FROM rollup_1h WHERE hour = $1 AND dim IN ('category','riskapp')`, h); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO rollup_1h (dim, hour, fw, log_type, name, cnt, blk, byt, snt)
		SELECT dim, $1::timestamptz, fw, lt, name, cnt, blk, byt, snt FROM (
		  SELECT g.*, row_number() OVER (PARTITION BY dim, fw, lt ORDER BY cnt DESC) AS rc FROM (
		    SELECT fw, lt, CASE WHEN GROUPING(cat) = 0 THEN 'category' ELSE 'riskapp' END AS dim, coalesce(cat, rapp) AS name,
		      count(*) AS cnt, count(*) FILTER (WHERE isblk) AS blk, coalesce(sum(byts),0)::bigint AS byt, coalesce(sum(sn),0)::bigint AS snt
		    FROM (SELECT `+fwExpr+` AS fw, `+ltExpr+` AS lt, coalesce(`+blockedExpr+`, false) AS isblk,
		            coalesce(fl_sent(log_id, fields, sent_bytes)+fl_rcvd(log_id, fields, received_bytes),0) AS byts, fl_sent(log_id, fields, sent_bytes) AS sn,
		            nullif(category,'') AS cat, CASE WHEN app_risk IN ('high','critical') THEN nullif(application,'') END AS rapp
		          FROM fortigate_logs WHERE event_time >= $1 AND event_time < $2 AND (coalesce(category,'') <> '' OR app_risk IN ('high','critical'))) x
		    GROUP BY GROUPING SETS ((fw,lt,cat),(fw,lt,rapp))
		  ) g WHERE name IS NOT NULL
		) t WHERE rc <= 2000`, h, h.Add(time.Hour)); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (d *Database) rollupExtraBackfill(ctx context.Context, n int) error {
	roll.mu.Lock()
	cur, done := roll.extra, roll.extraOK
	roll.mu.Unlock()
	if done || cur.IsZero() {
		return nil
	}
	var oldest *time.Time
	if err := d.pool.QueryRow(ctx, `SELECT min(bucket) FROM rollup_5m`).Scan(&oldest); err != nil {
		return err
	}
	floor := hourStart(time.Now().AddDate(0, 0, -rollupBackfillDays))
	if oldest != nil && hourStart(*oldest).After(floor) {
		floor = hourStart(*oldest)
	}
	for i := 0; i < n && cur.After(floor); i++ {
		h := cur.Add(-time.Hour)
		if err := d.rollupExtraHour(ctx, h); err != nil {
			return fmt.Errorf("categories for %s: %w", h.Format("2006-01-02 15:04"), err)
		}
		if err := d.setState(ctx, "extra", h); err != nil {
			return err
		}
		cur = h
		roll.mu.Lock()
		roll.extra = h
		roll.mu.Unlock()
	}
	if !cur.After(floor) {
		roll.mu.Lock()
		roll.extraOK = true
		roll.mu.Unlock()
	}
	return nil
}

// extraCovers: web categories / high-risk apps are in the summaries for a period starting at h.
func extraCovers(h time.Time) bool {
	roll.mu.Lock()
	defer roll.mu.Unlock()
	return roll.known && (roll.extraOK || !h.Before(roll.extra))
}

// bgPaused: when the history work last waited for the dashboards (for System health).
var bgPaused atomic.Int64
