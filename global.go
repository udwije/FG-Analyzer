package main

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Global dashboard: every log type from every firewall (traffic, UTM, event).

type gAgg struct{ cnt, blk, byt, snt, usr, nps, mp int64 }

func (d *Database) GlobalOverview(ctx context.Context, f Filter) (map[string]any, error) {
	rel, args := f.where()
	release, err := d.acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	step := bucketSeconds(f)
	q := `SELECT GROUPING(b,t,st,lv,fw)::int, b, t, st, lv, fw,
		count(*), count(*) FILTER (WHERE blk), coalesce(sum(byt),0)::bigint, coalesce(sum(snt),0)::bigint,
		count(*) FILTER (WHERE usr), count(*) FILTER (WHERE np), count(*) FILTER (WHERE mp), max(event_time)
	FROM (SELECT event_time, (floor(extract(epoch FROM event_time)/{S})*{S})::bigint AS b, coalesce(nullif(log_type,''),'(none)') AS t,
		coalesce(nullif(subtype,''),'(none)') AS st, nullif(level,'') AS lv, coalesce(nullif(device_name,''), host(source_ip)) AS fw,
		coalesce(` + blockedExpr + `, false) AS blk, coalesce(fl_sent(log_id, fields, sent_bytes)+fl_rcvd(log_id, fields, received_bytes),0) AS byt, fl_sent(log_id, fields, sent_bytes) AS snt,
		coalesce(user_name,'') <> '' AS usr, nps_id IS NOT NULL AS np, map_id IS NOT NULL AS mp
		FROM fortigate_logs WHERE ` + rel + `) x
	GROUP BY GROUPING SETS ((b),(t),(t,st),(lv),(fw),())`
	rows, err := d.pool.Query(ctx, strings.ReplaceAll(q, "{S}", strconv.FormatInt(step, 10)), args...)
	if err != nil {
		return nil, err
	}
	return scanGlobalOverview(rows, f, step)
}

// computeGlobal answers the All logs dashboard: from the summaries when the filter allows it, otherwise from raw rows.
func (d *Database) computeGlobal(ctx context.Context, f Filter) (map[string]any, error) {
	if rollupEligible(f) {
		return d.globalFromRollups(ctx, f)
	}
	return d.globalRaw(ctx, f)
}

func (d *Database) globalRaw(ctx context.Context, f Filter) (map[string]any, error) {
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
	go func() { defer wg.Done(); res, e := d.GlobalOverview(ctx, f); put("", res, e) }()
	go func() { defer wg.Done(); res, e := d.PrevTotals(ctx, f); put("prev", res, e) }()
	blocked := f
	blocked.Outcome = "blocked"
	riskF := f
	riskF.Extra = "app_risk IN ('high','critical')"
	wg.Add(2)
	go func() { defer wg.Done(); res, e := d.heatRaw(ctx, f); put("heat", res, e) }()
	go func() { defer wg.Done(); res, e := d.zonesRaw(ctx, f, bucketSeconds(f)); put("", res, e) }()
	inetF := inetFilter(f)
	events := f
	if events.Type == "" {
		events.Type = "event"
	}
	type job struct {
		key, dim string
		f        Filter
		order    string
		n        int
	}
	jobs := []job{{"sources", "src_ip", f, "cnt", 10}, {"users", "user", f, "cnt", 10}, {"dests", "dest", f, "cnt", 10},
		{"services", "service", f, "cnt", 10}, {"policies", "policy", f, "cnt", 10}, {"apps", "application", f, "cnt", 10},
		{"countries", "country", f, "byt", 10}, {"whereData", "dest", f, "byt", 10}, {"uploaders", "src_ip", f, "snt", 10},
		{"mostBlocked", "dest", blocked, "cnt", 10}, {"blockedSources", "src_ip", blocked, "cnt", 10}, {"actions", "action", f, "cnt", 10},
		{"aiTools", "tool", f, "cnt", 8},
		// v5.10 widgets
		{"categories", "category", f, "cnt", 10}, {"riskApps", "application", riskF, "cnt", 10}, {"usersData", "user", f, "byt", 10},
		{"usersInet", "user", inetF, "byt", 10}, {"uploadersInet", "src_ip", inetF, "snt", 10}, {"whereInet", "dest", inetF, "byt", 10}}
	if events.Type == "event" {
		jobs = append(jobs, job{"messages", "msg", events, "cnt", 12})
	}
	for _, j := range jobs {
		wg.Add(1)
		go func(j job) {
			defer wg.Done()
			rows, groups, e := d.TopOrder(ctx, j.dim, j.f, j.n, j.order)
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
	out["mode"], out["directionsComplete"] = "raw", true
	return out, nil
}

// lastGlobalView: when the All logs page was last requested. The warmer only works while someone is using it.
var lastGlobalView atomic.Int64

const warmIdleSeconds = 1800

func (a *App) handleGlobal(w http.ResponseWriter, r *http.Request) {
	lastGlobalView.Store(time.Now().Unix())
	d := a.dbOrFail(w)
	if d == nil {
		return
	}
	f := parseFilter(r)
	f.Endpoint = r.URL.Query().Get("view") != "all" // v5.16: device traffic only in the Advanced view
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	v, err := cached("global?"+r.URL.RawQuery, 45*time.Second, func() (any, error) { return d.computeGlobal(ctx, f) })
	if err != nil {
		queryErr(w, err)
		return
	}
	jsonOut(w, map[string]any{"data": v, "collectors": sourceStatus(a.store.Get()), "now": time.Now().Unix(), "summaries": rollupInfo()})
}

// globalWarmer keeps the four main periods of the All logs page ready, so opening or refreshing it is instant.
// The keys match what the page asks for when no filter is set ("hours=6" ...).
func (a *App) globalWarmer(ctx context.Context) error {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
		d := a.getDB()
		if d == nil || spoolBacklog.Load() > backlogBusy {
			continue
		}
		a.aiWarm(ctx, d) // v5.13: the default AI views too, while the AI tabs are in use
		if time.Now().Unix()-lastGlobalView.Load() > warmIdleSeconds {
			continue
		}
		for _, h := range []int{1, 6, 24, 168} {
			now := time.Now()
			f := Filter{From: now.Add(-time.Duration(h) * time.Hour), To: now.Add(time.Minute), Endpoint: true}
			if h > 6 && !rollupEligible(f) {
				continue // a raw 24 h / 7 day scan every 30 s would cost more than it saves; wait for the summaries
			}
			c, cancel := context.WithTimeout(ctx, 60*time.Second)
			v, err := d.computeGlobal(c, f)
			cancel()
			if err == nil {
				cachePut("global?hours="+strconv.Itoa(h), v)
			}
		}
	}
}

// ---------------------------------------------------------------- v5.10: activity by weekday and hour

// heat rows: [weekday (0 = Sunday), hour, events, blocked], in the collector's time zone.
func scanHeat(rows interface {
	Next() bool
	Scan(...any) error
	Err() error
	Close()
}) ([][4]int64, error) {
	defer rows.Close()
	out := [][4]int64{}
	for rows.Next() {
		var d, h int
		var c, b int64
		if err := rows.Scan(&d, &h, &c, &b); err != nil {
			return nil, err
		}
		out = append(out, [4]int64{int64(d), int64(h), c, b})
	}
	return out, rows.Err()
}

func (d *Database) heatRaw(ctx context.Context, f Filter) ([][4]int64, error) {
	rel, args := f.where()
	release, err := d.acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	rows, err := d.pool.Query(ctx, `SELECT extract(dow FROM event_time)::int, extract(hour FROM event_time)::int, count(*),
		count(*) FILTER (WHERE `+blockedExpr+`) FROM fortigate_logs WHERE `+rel+` GROUP BY 1, 2`, args...)
	if err != nil {
		return nil, err
	}
	return scanHeat(rows)
}

func (d *Database) heatRollup(ctx context.Context, f Filter) ([][4]int64, error) {
	rel, args := rollWhere(f, "bucket", f.From, f.To)
	release, err := d.acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	rows, err := d.pool.Query(ctx, `SELECT extract(dow FROM bucket)::int, extract(hour FROM bucket)::int, coalesce(sum(cnt),0)::bigint,
		coalesce(sum(blk),0)::bigint FROM rollup_5m WHERE `+rel+` GROUP BY 1, 2`, args...)
	if err != nil {
		return nil, err
	}
	return scanHeat(rows)
}
