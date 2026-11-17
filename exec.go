package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

// Executive summary: a management view of the network for a week or a month.
//
// Almost everything comes from the summary tables (rollup_5m / rollup_1h), so a 30-day summary builds in seconds.
// Only three small, index-backed raw queries are used: admin / VPN sign-in events (event logs), AI users per tool
// (AI partial index) and the usernames behind the few "unusual" devices (last 24 h of the period).
// The status (green / amber / red) follows the thresholds in Settings > Executive summary, and the text is generated
// from fixed templates so it is predictable and can be checked against the numbers.

type execPeriod struct {
	Key, Label string
	From, To   time.Time
	PFrom, PTo time.Time // previous period of the same length
}

func execPeriodFor(r *http.Request) (execPeriod, error) {
	q := r.URL.Query()
	now := time.Now().In(time.Local)
	day := func(t time.Time) time.Time { return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.Local) }
	p := execPeriod{Key: q.Get("period")}
	switch p.Key {
	case "", "7d":
		p.Key, p.Label, p.To, p.From = "7d", "Last 7 days", now, hourStart(now.AddDate(0, 0, -7))
	case "30d":
		p.Label, p.To, p.From = "Last 30 days", now, hourStart(now.AddDate(0, 0, -30))
	case "lastweek": // Monday to Sunday
		wd := (int(now.Weekday()) + 6) % 7
		p.To = day(now).AddDate(0, 0, -wd)
		p.From = p.To.AddDate(0, 0, -7)
		p.Label = "Last week"
	case "lastmonth":
		p.To = time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.Local)
		p.From = p.To.AddDate(0, -1, 0)
		p.Label = p.From.Format("January 2006")
	case "thismonth":
		p.From = time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.Local)
		p.To = now
		p.Label = p.From.Format("January 2006") + " (to date)"
	case "custom":
		a, e1 := time.Parse(time.RFC3339, q.Get("from"))
		b, e2 := time.Parse(time.RFC3339, q.Get("to"))
		if e1 != nil || e2 != nil || !b.After(a) {
			return p, specErr("choose a valid From and To")
		}
		if b.Sub(a) > 92*24*time.Hour {
			return p, specErr("an executive summary covers at most 92 days")
		}
		p.From, p.To, p.Label = a.In(time.Local), b.In(time.Local), "Custom period"
	default:
		return p, specErr("unknown period %q", p.Key)
	}
	span := p.To.Sub(p.From)
	p.PTo, p.PFrom = p.From, p.From.Add(-span)
	return p, nil
}

type execTotals struct {
	Events     int64 `json:"events"`
	Blocked    int64 `json:"blocked"`
	Bytes      int64 `json:"bytes"`
	Sent       int64 `json:"sent"`
	UserEvents int64 `json:"user_events"`
	Users      int64 `json:"users"`
	Devices    int64 `json:"devices"`
	AIEvents   int64 `json:"ai_events"`
	AISent     int64 `json:"ai_sent"`
	AITools    int64 `json:"ai_tools"`
	AdminFail  int64 `json:"admin_fail"`
	// v5.12: data by direction (see execv512.go). Inet = internet + inbound.
	InetBytes int64               `json:"inet_bytes"`
	InetSent  int64               `json:"inet_sent"`
	InBytes   int64               `json:"in_bytes"`
	IntBytes  int64               `json:"int_bytes"`
	IntSent   int64               `json:"int_sent"`
	FwBytes   int64               `json:"fw_bytes"`
	PendBytes int64               `json:"pending_bytes"` // traffic summarised before v5.12, direction not known yet
	Zones     map[string][2]int64 `json:"zones"`         // per direction: total bytes, upload
}

// totals from the summaries for [from, to)
func (d *Database) execTotals(ctx context.Context, from, to time.Time) (execTotals, error) {
	var t execTotals
	err := d.pool.QueryRow(ctx, `SELECT coalesce(sum(cnt),0)::bigint, coalesce(sum(blk),0)::bigint, coalesce(sum(byt),0)::bigint,
		coalesce(sum(snt),0)::bigint, coalesce(sum(usr),0)::bigint FROM rollup_5m WHERE bucket >= $1 AND bucket < $2 AND zone NOT IN `+deviceZones, from, to).
		Scan(&t.Events, &t.Blocked, &t.Bytes, &t.Sent, &t.UserEvents)
	if err != nil {
		return t, err
	}
	// devices = internal source addresses only; internet hosts reaching a published service are not "your devices"
	d.loadDaysDone(ctx)
	pa := []any{}
	src := rollSource(Filter{}, hourStart(from), to, []string{"user"}, &pa, false)
	var users []string
	rows, err := d.pool.Query(ctx, `SELECT DISTINCT name FROM `+src, pa...)
	if err != nil {
		return t, err
	}
	for rows.Next() {
		var n string
		if rows.Scan(&n) == nil {
			users = append(users, n)
		}
	}
	rows.Close()
	t.Users = countPeople(users) // v5.13: verified staff (or plausible people when no staff list is loaded)
	pa = []any{}
	src = rollSource(Filter{}, hourStart(from), to, []string{"src_ip", "tool"}, &pa, false)
	err = d.pool.QueryRow(ctx, `SELECT count(DISTINCT name) FILTER (WHERE CASE WHEN dim='src_ip' THEN name::inet <<= ANY(`+localNetsSQL()+`) ELSE false END),
		coalesce(sum(cnt) FILTER (WHERE dim='tool'),0)::bigint, coalesce(sum(snt) FILTER (WHERE dim='tool'),0)::bigint,
		count(DISTINCT name) FILTER (WHERE dim='tool') FROM `+src, pa...).
		Scan(&t.Devices, &t.AIEvents, &t.AISent, &t.AITools)
	if err != nil {
		return t, err
	}
	z, err := d.execZones(ctx, from, to)
	if err == nil {
		applyZones(&t, z)
	}
	return t, err
}

// ---------------------------------------------------------------- result

type execCheck struct {
	Key    string `json:"key"`
	Label  string `json:"label"`
	Status string `json:"status"` // ok, amber, red, na
	Value  string `json:"value"`
	Detail string `json:"detail"`
}

type execFinding struct {
	Status string `json:"status"` // amber, red
	Title  string `json:"title"`
	Detail string `json:"detail"`
	Action string `json:"action"`
}

type ExecSummary struct {
	Org        string           `json:"org"`
	Period     map[string]any   `json:"period"`
	Generated  time.Time        `json:"generated"`
	Status     string           `json:"status"`
	Headline   string           `json:"headline"`
	Cur        execTotals       `json:"cur"`
	Prev       *execTotals      `json:"prev"` // nil when the previous period is not (fully) in the database
	PrevNote   string           `json:"prev_note,omitempty"`
	Story      []string         `json:"story"`
	Findings   []execFinding    `json:"findings"`
	Checks     []execCheck      `json:"checks"`
	Series     []map[string]any `json:"series"` // per day (or hour for short periods)
	SeriesUnit string           `json:"series_unit"`
	Firewalls  []map[string]any `json:"firewalls"`
	Types      []map[string]any `json:"types"`
	Subtypes   []map[string]any `json:"subtypes"`
	Categories []map[string]any `json:"categories"`
	RiskApps   []map[string]any `json:"risk_apps"`
	AI         []map[string]any `json:"ai"`
	Signins    map[string]any   `json:"signins"`
	Devices    []map[string]any `json:"devices"`
	Top        map[string]any   `json:"top"` // appendix lists
	Notes      []string         `json:"notes"`
	Excl       map[string]any   `json:"exclusions"` // v5.10: what was left out, and how much of the period it covers
	Collector  map[string]any   `json:"collector"`  // v5.11: how much of the period LogSikka was collecting
	WAN        []map[string]any `json:"wan"`        // v5.16: WAN links over SNMPv3
	WANPage    map[string]any   `json:"wan_page"`   // v5.21: internet circuits page (usage, data, quality, tunnels, incidents)
	TookMS     int64            `json:"took_ms"`
}

func pctChange(cur, prev int64) (float64, bool) {
	if prev <= 0 {
		return 0, false
	}
	return 100 * float64(cur-prev) / float64(prev), true
}

func humanBytes(n int64) string {
	f, u := float64(n), []string{"B", "KB", "MB", "GB", "TB", "PB"}
	i := 0
	for f >= 1024 && i < len(u)-1 {
		f /= 1024
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%d B", n)
	}
	return fmt.Sprintf("%.1f %s", f, u[i])
}

func humanCount(n int64) string {
	switch {
	case n >= 1e9:
		return fmt.Sprintf("%.1f billion", float64(n)/1e9)
	case n >= 1e6:
		return fmt.Sprintf("%.1f million", float64(n)/1e6)
	}
	return num(n)
}

func trendWord(p float64, ok bool, up, down string) string {
	if !ok {
		return ""
	}
	if math.Abs(p) < 5 {
		return "about the same as the previous period"
	}
	if p > 0 {
		return fmt.Sprintf("%s %.0f%% on the previous period", up, p)
	}
	return fmt.Sprintf("%s %.0f%% on the previous period", down, -p)
}

func isPublicIP(s string) bool {
	a, err := netip.ParseAddr(s)
	return err == nil && !(a.IsUnspecified() || isLocalIP(s))
}

func rank(s string) int { return map[string]int{"ok": 0, "na": 0, "amber": 1, "red": 2}[s] }

// ---------------------------------------------------------------- building it

func (a *App) buildExec(ctx context.Context, d *Database, p execPeriod, ex *execExcl) (*ExecSummary, error) {
	start := time.Now()
	cfg := a.store.Get()
	th := cfg.Exec
	th.defaults()
	if !roll.covers(hourStart(p.From)) {
		roll.mu.Lock()
		cov := roll.covered
		roll.mu.Unlock()
		return nil, specErr("the summaries are still being built back to %s; choose a period that starts after that, or try again later",
			cov.Format("2 Jan 2006 15:04"))
	}
	out := &ExecSummary{Org: firstNonEmpty(th.OrgName, "Network"), Generated: time.Now(), Story: []string{}, Findings: []execFinding{},
		Checks: []execCheck{}, Notes: []string{}, Top: map[string]any{}, Devices: []map[string]any{}, AI: []map[string]any{},
		Period: map[string]any{"key": p.Key, "label": p.Label, "from": p.From, "to": p.To, "prev_from": p.PFrom, "prev_to": p.PTo}}
	f := Filter{From: p.From, To: p.To, Endpoint: true}
	var mu sync.Mutex
	var wg sync.WaitGroup
	var G map[string]any
	var fatal error
	warn := func(what string, err error) {
		if err == nil {
			return
		}
		log.Printf("executive summary: %s: %v", what, err)
		mu.Lock()
		out.Notes = append(out.Notes, what+" could not be included this time ("+shortErr(err)+").")
		mu.Unlock()
	}
	run := func(fn func()) { wg.Add(1); go func() { defer wg.Done(); fn() }() }

	run(func() {
		g, err := d.globalFromRollups(ctx, f)
		mu.Lock()
		G = g
		if err != nil {
			fatal = err
		}
		mu.Unlock()
	})
	run(func() {
		t, err := d.execTotals(ctx, p.From, p.To)
		if err != nil {
			mu.Lock()
			fatal = err
			mu.Unlock()
			return
		}
		mu.Lock()
		out.Cur = t
		mu.Unlock()
	})
	run(func() { // previous period: only when the database holds all of it
		var oldest *time.Time
		if err := d.pool.QueryRow(ctx, `SELECT min(bucket) FROM rollup_5m`).Scan(&oldest); err != nil {
			warn("The comparison with the previous period", err)
			return
		}
		if oldest == nil || oldest.After(p.PFrom.Add(time.Hour)) || !roll.covers(hourStart(p.PFrom)) {
			mu.Lock()
			out.PrevNote = "No comparison: the previous period is older than the stored logs."
			mu.Unlock()
			return
		}
		t, err := d.execTotals(ctx, p.PFrom, p.PTo)
		if err != nil {
			warn("The comparison with the previous period", err)
			return
		}
		mu.Lock()
		out.Prev = &t
		mu.Unlock()
	})
	run(func() {
		s, u, err := d.execSeries(ctx, p.From, p.To)
		if err == nil {
			err = d.execZoneSeries(ctx, s, u, p.From, p.To)
		}
		warn("The activity chart", err)
		mu.Lock()
		out.Series, out.SeriesUnit = s, u
		mu.Unlock()
	})
	run(func() {
		l, col, err := d.execAvailability(ctx, p.From, p.To, cfg)
		warn("Firewall availability", err)
		mu.Lock()
		out.Firewalls, out.Collector = l, col
		mu.Unlock()
	})
	run(func() {
		c, r, note, err := d.execCategories(ctx, p.From, p.To)
		warn("Web categories", err)
		mu.Lock()
		out.Categories, out.RiskApps = c, r
		if note != "" {
			out.Notes = append(out.Notes, note)
		}
		mu.Unlock()
	})
	run(func() {
		s, err := d.execSignins(ctx, p)
		warn("Sign-in events", err)
		mu.Lock()
		out.Signins = s
		mu.Unlock()
	})
	if wc := cfg.WAN; len(wanLinks(wc)) > 0 {
		run(func() {
			l, err := d.wanStats(ctx, wc, p.From, p.To)
			warn("WAN links", err)
			mu.Lock()
			out.WAN = l
			mu.Unlock()
		})
		run(func() {
			m, err := d.execWAN(ctx, wc, p.From, p.To)
			warn("Internet circuits", err)
			mu.Lock()
			out.WANPage = m
			mu.Unlock()
		})
	}
	run(func() {
		l, err := d.execAI(ctx, p.From, p.To)
		warn("AI tool details", err)
		mu.Lock()
		out.AI = l
		mu.Unlock()
	})
	wg.Wait()
	if fatal != nil {
		return nil, fatal
	}
	if out.Signins != nil {
		out.Cur.AdminFail, _ = out.Signins["failed"].(int64)
		if out.Prev != nil {
			out.Prev.AdminFail, _ = out.Signins["prev_failed"].(int64)
		}
	}

	// lists from the dashboard summaries
	list := func(k string) []map[string]any {
		if l, ok := G[k].([]map[string]any); ok {
			return l
		}
		return []map[string]any{}
	}
	out.Types, out.Subtypes = list("types"), list("subtypes")
	for _, k := range []string{"sources", "users", "dests", "apps", "policies", "services", "countries", "whereData", "uploaders", "mostBlocked", "blockedSources", "messages"} {
		out.Top[k] = list(k)
	}
	out.Excl = map[string]any{"active": ex.active(), "applied": false}
	if ex.active() {
		if err := a.execApplyExcl(ctx, d, out, p, f, ex); err != nil {
			warn("The exclusions", err)
		}
	}
	if err := d.execTopLists(ctx, out, p, f, ex, th); err != nil {
		warn("Top lists", err)
	}
	if out.Cur.Bytes > 0 && out.Cur.PendBytes*100 > out.Cur.Bytes {
		roll.mu.Lock()
		rb := roll.rb
		roll.mu.Unlock()
		out.Notes = append(out.Notes, fmt.Sprintf("Traffic directions (internet / internal) and corrected data volumes are being recalculated for data before %s; until then %d%% of the data in this period has no direction and older volumes may be too high.",
			rb.In(time.Local).Format("2 Jan 15:04"), pct(out.Cur.PendBytes, out.Cur.Bytes)))
	}
	// "New" needs the period before: when the stored logs start inside this period, every tool would look new
	if out.Prev == nil {
		for _, t := range out.AI {
			t["new"] = false
		}
	}
	if len(out.AI) == 0 { // fall back to the summary list (no per-tool user counts)
		for _, t := range list("aiTools") {
			out.AI = append(out.AI, map[string]any{"name": t["name"], "events": t["count"], "sent": t["sent"], "blocked": t["blocked"]})
		}
	}

	// unusual devices: blocked connections per day above the threshold
	days := math.Max(1, p.To.Sub(p.From).Hours()/24)
	var ips []string
	blockedSources, _ := out.Top["blockedSources"].([]map[string]any)
	for _, s := range blockedSources {
		b, _ := s["blocked"].(int64)
		if float64(b)/days >= float64(th.DeviceBlocksDay) {
			ips = append(ips, fmt.Sprint(s["name"]))
			out.Devices = append(out.Devices, map[string]any{"ip": s["name"], "blocked": b, "per_day": int64(float64(b) / days)})
		}
	}
	if len(ips) > 0 {
		users, top, err := d.execDeviceInfo(ctx, ips, p.To)
		warn("Usernames for unusual devices", err)
		for _, dv := range out.Devices {
			ip := fmt.Sprint(dv["ip"])
			dv["user"], dv["top"] = users[ip], top[ip]
		}
	}

	a.execAssess(out, th, p, days)
	out.TookMS = time.Since(start).Milliseconds()
	return out, nil
}

func shortErr(err error) string {
	s := err.Error()
	if errors.Is(err, context.DeadlineExceeded) {
		return "took too long"
	}
	if len(s) > 120 {
		s = s[:120] + "…"
	}
	return s
}

// execSeries: activity per day (per hour for periods up to 2 days), with download / upload.
func (d *Database) execSeries(ctx context.Context, from, to time.Time) ([]map[string]any, string, error) {
	unit := "day"
	if to.Sub(from) <= 48*time.Hour {
		unit = "hour"
	}
	rows, err := d.pool.Query(ctx, `SELECT date_trunc($3::text, bucket, $4::text), sum(cnt)::bigint, sum(blk)::bigint, sum(byt)::bigint, sum(snt)::bigint
		FROM rollup_5m WHERE bucket >= $1 AND bucket < $2 AND zone NOT IN `+deviceZones+` GROUP BY 1 ORDER BY 1`, from, to, unit, reportTZ())
	if err != nil {
		return nil, unit, err
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var t time.Time
		var c, b, y, s int64
		if err = rows.Scan(&t, &c, &b, &y, &s); err != nil {
			return nil, unit, err
		}
		out = append(out, map[string]any{"t": t, "events": c, "blocked": b, "down": y - s, "up": s})
	}
	return out, unit, rows.Err()
}

func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

// execCategoriesRaw: web categories and allowed high / critical risk applications, from the summaries when they hold
// them (v5.7+ or after the background fill), otherwise from the web filter / application control logs.
func (d *Database) execCategoriesRaw(ctx context.Context, from, to time.Time) (cats, risk []map[string]any, note string, err error) {
	scan := func(q string, args ...any) ([]map[string]any, error) {
		rows, err := d.pool.Query(ctx, q, args...)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		out := []map[string]any{}
		for rows.Next() {
			var n string
			var c, b int64
			if err = rows.Scan(&n, &c, &b); err != nil {
				return nil, err
			}
			out = append(out, map[string]any{"name": n, "count": c, "blocked": b})
		}
		return out, rows.Err()
	}
	if extraCovers(hourStart(from)) {
		// v5.11: web filter categories are on security (utm) logs; traffic logs carry application categories (Network.Service ...)
		q := `SELECT name, sum(cnt)::bigint, sum(blk)::bigint FROM rollup_1h WHERE dim = $3 AND log_type = 'utm' AND hour >= $1 AND hour < $2 GROUP BY 1 ORDER BY 2 DESC LIMIT 60`
		if cats, err = scan(q, hourStart(from), to, "category"); err != nil {
			return
		}
		risk, err = scan(`SELECT name, sum(cnt)::bigint, sum(blk)::bigint FROM rollup_1h WHERE dim = 'riskapp' AND hour >= $1 AND hour < $2
			GROUP BY 1 HAVING sum(cnt) > sum(blk) ORDER BY sum(cnt) - sum(blk) DESC LIMIT 15`, hourStart(from), to)
		return
	}
	// raw, bounded: web filter and app control logs only (subtype index), 60 s
	c2, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	cats, err = scan(`SELECT category, count(*), count(*) FILTER (WHERE `+blockedExpr+`) FROM fortigate_logs
		WHERE subtype = 'webfilter' AND event_time >= $1 AND event_time < $2 AND coalesce(category,'') <> '' GROUP BY 1 ORDER BY 2 DESC LIMIT 60`, from, to)
	if err == nil {
		risk, err = scan(`SELECT application, count(*), count(*) FILTER (WHERE `+blockedExpr+`) FROM fortigate_logs
			WHERE subtype = 'app-ctrl' AND event_time >= $1 AND event_time < $2 AND app_risk IN ('high','critical') AND coalesce(application,'') <> ''
			GROUP BY 1 HAVING count(*) > count(*) FILTER (WHERE `+blockedExpr+`) ORDER BY 2 DESC LIMIT 15`, from, to)
	}
	if err != nil && c2.Err() != nil {
		note = "Web categories and risky applications are still being added to the summaries for this period; they will appear within a few hours."
		return nil, nil, note, nil
	}
	return
}

// execSigninsRaw: sign-ins and configuration changes from the raw event logs (when the event summary does not cover the period).
func (d *Database) execSigninsRaw(ctx context.Context, p execPeriod) (map[string]any, error) {
	const failed = `(fields->>'logdesc' ILIKE '%login fail%' OR fields->>'logdesc' ILIKE '%authentication fail%'
		OR (action ILIKE '%login%' AND fields->>'status' IN ('failed','failure','fail')) OR (subtype = 'vpn' AND (fields->>'status' ILIKE 'fail%' OR action ILIKE '%fail%')))`
	const success = `(fields->>'logdesc' ILIKE '%login success%' OR (action ILIKE '%login%' AND fields->>'status' = 'success'))`
	const cfgchg = `(fields->>'cfgpath' IS NOT NULL OR fields->>'logdesc' ILIKE '%configured%')`
	c2, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	out := map[string]any{}
	var f, s, c, fv, fa, prev int64
	if err := d.pool.QueryRow(c2, `SELECT count(*) FILTER (WHERE `+failed+`), count(*) FILTER (WHERE `+success+`), count(*) FILTER (WHERE `+cfgchg+`),
		count(*) FILTER (WHERE `+failed+` AND subtype = 'vpn'), count(*) FILTER (WHERE `+failed+` AND subtype <> 'vpn')
		FROM fortigate_logs WHERE log_type = 'event' AND event_time >= $1 AND event_time < $2`, p.From, p.To).Scan(&f, &s, &c, &fv, &fa); err != nil {
		return nil, err
	}
	_ = d.pool.QueryRow(c2, `SELECT count(*) FROM fortigate_logs WHERE log_type = 'event' AND event_time >= $1 AND event_time < $2 AND `+failed, p.PFrom, p.PTo).Scan(&prev)
	out["failed"], out["success"], out["config_changes"], out["failed_vpn"], out["failed_admin"], out["prev_failed"] = f, s, c, fv, fa, prev
	rows, err := d.pool.Query(c2, `SELECT coalesce(host(src_ip), fields->>'remip', fields->>'ui', '?'), coalesce(nullif(fields->>'user',''), nullif(user_name,''), '?'),
		CASE WHEN subtype = 'vpn' THEN 'VPN' ELSE 'Admin' END, coalesce(nullif(device_name,''), host(source_ip)), count(*), max(event_time)
		FROM fortigate_logs WHERE log_type = 'event' AND event_time >= $1 AND event_time < $2 AND `+failed+`
		GROUP BY 1, 2, 3, 4 ORDER BY 5 DESC LIMIT 15`, p.From, p.To)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	top := []map[string]any{}
	var internet int64
	for rows.Next() {
		var src, user, kind, fw string
		var n int64
		var last time.Time
		if err = rows.Scan(&src, &user, &kind, &fw, &n, &last); err != nil {
			return out, err
		}
		pub := isPublicIP(src)
		if pub {
			internet += n
		}
		top = append(top, map[string]any{"source": src, "user": user, "kind": kind, "fw": fw, "count": n, "last": last, "internet": pub})
	}
	out["top"], out["from_internet"] = top, internet
	cr, err := d.pool.Query(c2, `SELECT coalesce(nullif(fields->>'user',''), '?'), coalesce(nullif(device_name,''), host(source_ip)), count(*), max(event_time)
		FROM fortigate_logs WHERE log_type = 'event' AND event_time >= $1 AND event_time < $2 AND `+cfgchg+` GROUP BY 1, 2 ORDER BY 3 DESC LIMIT 10`, p.From, p.To)
	if err != nil {
		return out, err
	}
	defer cr.Close()
	changes := []map[string]any{}
	for cr.Next() {
		var user, fw string
		var n int64
		var last time.Time
		if err = cr.Scan(&user, &fw, &n, &last); err != nil {
			return out, err
		}
		changes = append(changes, map[string]any{"user": user, "fw": fw, "count": n, "last": last})
	}
	out["changes"] = changes
	return out, cr.Err()
}

// execAI: per AI tool, events, people, devices, upload, and whether it was first seen in this period.
func (d *Database) execAI(ctx context.Context, from, to time.Time) ([]map[string]any, error) {
	c2, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	q := `SELECT ai_tool, count(*), count(*) FILTER (WHERE ` + blockedExpr + `), count(DISTINCT nullif(user_name,'')),
		count(DISTINCT src_ip), coalesce(sum(fl_sent(log_id, fields, sent_bytes)),0)::bigint FROM fortigate_logs
		WHERE ai_tool IS NOT NULL AND event_time >= $1 AND event_time < $2 GROUP BY 1 ORDER BY 2 DESC LIMIT 15`
	if aiCovers(hourStart(from)) { // v5.10: from the AI summary instead of decompressing weeks of raw logs
		q, from = execAISummarySQL, hourStart(from)
	}
	rows, err := d.pool.Query(c2, q, from, to)
	if err != nil {
		return nil, err
	}
	out := []map[string]any{}
	names := []string{}
	for rows.Next() {
		var n string
		var c, b, u, s, up int64
		if err = rows.Scan(&n, &c, &b, &u, &s, &up); err != nil {
			rows.Close()
			return nil, err
		}
		names = append(names, n)
		out = append(out, map[string]any{"name": n, "events": c, "blocked": b, "users": u, "devices": s, "sent": up})
	}
	rows.Close()
	if err = rows.Err(); err != nil || len(names) == 0 {
		return out, err
	}
	first := map[string]time.Time{}
	fr, err := d.pool.Query(c2, `SELECT name, min(hour) FROM rollup_1h WHERE dim = 'tool' AND name = ANY($1) GROUP BY 1`, names)
	if err != nil {
		return out, nil
	}
	defer fr.Close()
	for fr.Next() {
		var n string
		var t time.Time
		if fr.Scan(&n, &t) == nil {
			first[n] = t
		}
	}
	for _, o := range out {
		if t, ok := first[o["name"].(string)]; ok {
			o["first_seen"] = t
			o["new"] = !t.Before(hourStart(from))
		}
	}
	return out, nil
}

const execAISummarySQL = `SELECT tool, sum(cnt)::bigint, sum(blk)::bigint, count(DISTINCT nullif(usr,'')), count(DISTINCT nullif(src,'')),
	sum(snt)::bigint FROM rollup_ai WHERE hour >= $1 AND hour < $2 GROUP BY 1 ORDER BY 2 DESC LIMIT 15`

// ---------------------------------------------------------------- status, findings and the story

func (a *App) execAssess(o *ExecSummary, th ExecConfig, p execPeriod, days float64) {
	c, pv := o.Cur, o.Prev
	add := func(k, label, st, val, det string) {
		o.Checks = append(o.Checks, execCheck{k, label, st, val, det})
	}
	find := func(st, title, det, act string) {
		o.Findings = append(o.Findings, execFinding{st, title, det, act})
	}
	chg := func(get func(execTotals) int64) (float64, bool) {
		if pv == nil {
			return 0, false
		}
		return pctChange(get(c), get(*pv))
	}

	// 0. v5.11: the collector itself (no firewall at all sent logs: LogSikka, its database or the network was down)
	if cg, _ := o.Collector["longest_gap"].(int64); o.Collector != nil {
		cst := "ok"
		switch {
		case cg >= int64(th.QuietRedHours)*3600:
			cst = "red"
		case cg >= int64(th.QuietAmberMin)*60:
			cst = "amber"
		}
		cov, _ := o.Collector["coverage"].(float64)
		add("collector", "Log collection running", cst, fmt.Sprintf("%.1f%% of the time", cov),
			ifStr(cg >= 600, "longest stop "+humanDur(cg)+" (no firewall's logs were received)", "no interruptions"))
		if cst != "ok" {
			when := ""
			if t, ok := o.Collector["longest_gap_at"].(time.Time); ok {
				when = " from " + t.In(time.Local).Format("2 Jan 15:04")
			}
			find(cst, "Logs were not collected for "+humanDur(cg)+when,
				"No firewall's logs reached LogSikka during that time, so it is missing from every figure in this report. Firewall availability does not count it.",
				"Check the LogSikka server, its database and the network path from the firewalls; consider an alert when no logs arrive for 15 minutes.")
		}
	}
	// 1. firewalls reporting (only the monitored ones: listed in Settings and not ignored)
	st, worst, worstName := "ok", int64(0), ""
	monitored := []map[string]any{}
	for _, f := range o.Firewalls {
		if m, ok := f["monitored"].(bool); ok && !m {
			continue
		}
		monitored = append(monitored, f)
		g, _ := f["longest_gap"].(int64)
		if g > worst {
			worst, worstName = g, fmt.Sprint(f["name"])
		}
	}
	switch {
	case worst >= int64(th.QuietRedHours)*3600:
		st = "red"
	case worst >= int64(th.QuietAmberMin)*60:
		st = "amber"
	}
	val := fmt.Sprintf("%d of %d reporting", countWhere(monitored, func(f map[string]any) bool { q, _ := f["quiet"].(int64); return q < int64(th.QuietAmberMin)*60 }), len(monitored))
	add("firewalls", "Firewalls sending logs", st, val, ifStr(worst > 0 && st != "ok", fmt.Sprintf("%s was silent for %s", worstName, humanDur(worst)), "No silent periods"))
	if st != "ok" {
		find(st, worstName+" stopped sending logs for "+humanDur(worst),
			"While a firewall is silent, nothing it handles is recorded or visible in these reports.",
			"Check the firewall's log settings and its connection to the log server, and confirm it is healthy.")
	}

	// 2. blocked activity
	bp, bok := chg(func(t execTotals) int64 { return t.Blocked })
	st = "ok"
	if bok && bp >= float64(th.BlockedUpRed) {
		st = "red"
	} else if bok && bp >= float64(th.BlockedUpAmber) {
		st = "amber"
	} else if !bok {
		st = "na"
	}
	share := pct(c.Blocked, c.Events)
	add("blocked", "Activity blocked by security policy", st, fmt.Sprintf("%d%% of activity", share), ifStr(bok, trendWord(bp, bok, "up", "down"), "no previous period to compare"))
	if st == "amber" || st == "red" {
		det := fmt.Sprintf("Blocked activity rose %.0f%% to %s.", bp, humanCount(c.Blocked))
		if bs, ok := o.Top["blockedSources"].([]map[string]any); ok && len(bs) > 0 {
			b0, _ := bs[0]["blocked"].(int64)
			det += fmt.Sprintf(" The largest single source is %v with %d%% of all blocks.", bs[0]["name"], pct(b0, c.Blocked))
		}
		find(st, "Blocked activity increased sharply", det, "Review the devices behind the increase (see Security posture); it is often one misconfigured or infected device.")
	}

	// 3. sign-ins
	st = "ok"
	var inet int64
	if o.Signins != nil {
		inet, _ = o.Signins["from_internet"].(int64)
		switch {
		case c.AdminFail >= int64(th.AdminFailRed):
			st = "red"
		case c.AdminFail >= int64(th.AdminFailAmber) || inet > 0:
			st = "amber"
		}
		add("signins", "Failed admin and VPN sign-ins", st, num(c.AdminFail), ifStr(inet > 0, fmt.Sprintf("%s from internet addresses", num(inet)), "none from the internet"))
		if st != "ok" {
			det := fmt.Sprintf("%s failed sign-in attempts to firewall administration or VPN.", num(c.AdminFail))
			if inet > 0 {
				det += fmt.Sprintf(" %s came from addresses on the internet.", num(inet))
			}
			find(st, "Repeated failed sign-ins", det, "Restrict administrative access to trusted addresses, make sure MFA is on for VPN, and block the repeat sources.")
		}
	} else {
		add("signins", "Failed admin and VPN sign-ins", "na", "–", "not available")
	}

	// 4. risky applications allowed
	n := len(o.RiskApps)
	st = "ok"
	if n >= th.RiskAppsRed {
		st = "red"
	} else if n >= th.RiskAppsAmber {
		st = "amber"
	}
	names := []string{}
	for i, r := range o.RiskApps {
		if i < 4 {
			names = append(names, fmt.Sprint(r["name"]))
		}
	}
	add("riskapps", "High-risk applications allowed", st, num(int64(n)), ifStr(n > 0, strings.Join(names, ", "), "none"))
	if st != "ok" {
		find(st, fmt.Sprintf("%d high-risk application%s allowed", n, plural(n)), "Allowed: "+strings.Join(names, ", ")+".",
			"Decide with the business owners whether each is needed; block the rest in application control.")
	}

	// 5. AI uploads
	ap, aok := chg(func(t execTotals) int64 { return t.AISent })
	st = "ok"
	newBig := []string{}
	for _, t := range o.AI {
		if nw, _ := t["new"].(bool); nw {
			if s, _ := t["sent"].(int64); s > 100<<20 {
				newBig = append(newBig, fmt.Sprint(t["name"]))
			}
		}
	}
	if (aok && ap >= float64(th.AIUploadUpAmber)) || len(newBig) > 0 {
		st = "amber"
	}
	add("ai", "Data uploaded to AI tools", st, humanBytes(c.AISent), ifStr(aok, trendWord(ap, aok, "up", "down"), "no previous period to compare"))
	if st == "amber" {
		det := fmt.Sprintf("%s was uploaded to AI tools", humanBytes(c.AISent))
		if aok {
			det += fmt.Sprintf(", %.0f%% more than the previous period", ap)
		}
		det += "."
		if len(newBig) > 0 {
			det += " New tools with large uploads: " + strings.Join(newBig, ", ") + "."
		}
		find(st, "More data is going to AI tools", det, "Confirm the AI tools in use are approved, and remind staff not to paste confidential documents into unapproved tools.")
	}

	// 6. unusual devices
	st = "ok"
	if len(o.Devices) > 0 {
		st = "amber"
	}
	add("devices", "Devices with unusual blocked activity", st, num(int64(len(o.Devices))), fmt.Sprintf("more than %s blocks a day", num(int64(th.DeviceBlocksDay))))
	if st == "amber" {
		l := []string{}
		for i, dv := range o.Devices {
			if i < 3 {
				who := fmt.Sprint(dv["ip"])
				if u, _ := dv["user"].(string); u != "" {
					who += " (" + u + ")"
				}
				l = append(l, who)
			}
		}
		find("amber", fmt.Sprintf("%d device%s keep trying blocked connections", len(o.Devices), plural(len(o.Devices))),
			"Mostly: "+strings.Join(l, ", ")+". Constant blocked attempts usually mean unwanted software, malware or a misconfiguration.",
			"Have IT check these devices and remove or reconfigure the software responsible.")
	}

	// 7. visibility (informational: amber below 50% of activity tied to a person)
	uk := pct(c.UserEvents, c.Events)
	st = "ok"
	if uk < 50 {
		st = "amber"
	}
	add("visibility", "Activity linked to a named user", st, fmt.Sprintf("%d%%", uk), "the rest can only be traced to a device")

	o.Status = "ok"
	for _, k := range o.Checks {
		if rank(k.Status) > rank(o.Status) {
			o.Status = k.Status
		}
	}
	sort.SliceStable(o.Findings, func(i, j int) bool { return rank(o.Findings[i].Status) > rank(o.Findings[j].Status) })
	switch o.Status {
	case "red":
		o.Headline = fmt.Sprintf("Action needed: %d issue%s require%s attention.", len(o.Findings), plural(len(o.Findings)), ifStr(len(o.Findings) == 1, "s", ""))
	case "amber":
		o.Headline = fmt.Sprintf("Network operating normally. %d item%s need%s attention.", len(o.Findings), plural(len(o.Findings)), ifStr(len(o.Findings) == 1, "s", ""))
	default:
		o.Headline = "Network healthy: nothing needs attention this period."
	}

	// story
	ep, eok := chg(func(t execTotals) int64 { return t.Events })
	s := fmt.Sprintf("%s network events were recorded across %d firewall%s", humanCount(c.Events), len(monitored), plural(len(monitored)))
	if w := trendWord(ep, eok, "up", "down"); w != "" {
		s += ", " + w
	}
	o.Story = append(o.Story, s+".")
	s = fmt.Sprintf("%d%% of activity was blocked by security policy", share)
	if w := trendWord(bp, bok, "blocked activity is up", "blocked activity is down"); w != "" {
		s += "; " + w
	}
	o.Story = append(o.Story, s+".")
	if c.InetBytes > 0 && c.PendBytes*100 <= c.Bytes {
		s = fmt.Sprintf("Internet traffic was %s: %s downloaded and %s uploaded, by %s people on %s internal devices.",
			humanBytes(c.InetBytes), humanBytes(c.InetBytes-c.InetSent), humanBytes(c.InetSent), num(c.Users), num(c.Devices))
		if c.IntBytes > 0 {
			s += fmt.Sprintf(" A further %s stayed inside the network (internal only)", humanBytes(c.IntBytes))
			if c.FwBytes > 0 {
				s += fmt.Sprintf(" and %s was to and from the firewalls themselves", humanBytes(c.FwBytes))
			}
			s += "."
		}
	} else {
		s = fmt.Sprintf("%s of data passed through the firewalls: %s downloaded and %s uploaded, by %s people on %s internal devices.",
			humanBytes(c.Bytes), humanBytes(c.Bytes-c.Sent), humanBytes(c.Sent), num(c.Users), num(c.Devices))
	}
	o.Story = append(o.Story, s)
	if len(o.AI) > 0 {
		var tot int64
		for _, t := range o.AI {
			e, _ := t["events"].(int64)
			tot += e
		}
		top := o.AI[0]
		e0, _ := top["events"].(int64)
		n := int(c.AITools)
		if n < len(o.AI) {
			n = len(o.AI)
		}
		if c.AIEvents > tot {
			tot = c.AIEvents
		}
		s = fmt.Sprintf("%d AI tool%s were used; %v accounts for %d%% of AI activity", n, plural(n), top["name"], pct(e0, tot))
		nw := []string{}
		for _, t := range o.AI {
			if b, _ := t["new"].(bool); b {
				nw = append(nw, fmt.Sprint(t["name"]))
			}
		}
		if len(nw) > 0 && len(nw) < len(o.AI) {
			s += ". New this period: " + strings.Join(nw, ", ")
		}
		o.Story = append(o.Story, s+".")
	}
	if len(o.Categories) > 0 {
		var tot int64
		for _, x := range o.Categories {
			v, _ := x["count"].(int64)
			tot += v
		}
		v0, _ := o.Categories[0]["count"].(int64)
		o.Story = append(o.Story, fmt.Sprintf("The most visited type of website was %v (%d%% of web visits).", o.Categories[0]["name"], pct(v0, tot)))
	}
	if o.Signins != nil {
		cc, _ := o.Signins["config_changes"].(int64)
		if cc > 0 {
			o.Story = append(o.Story, fmt.Sprintf("%s firewall configuration change%s were recorded.", num(cc), plural(int(cc))))
		}
	}
}

func countWhere(l []map[string]any, f func(map[string]any) bool) int {
	n := 0
	for _, x := range l {
		if f(x) {
			n++
		}
	}
	return n
}

func ifStr(c bool, a, b string) string {
	if c {
		return a
	}
	return b
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func humanDur(s int64) string {
	switch {
	case s >= 86400:
		return fmt.Sprintf("%.1f days", float64(s)/86400)
	case s >= 3600:
		return fmt.Sprintf("%.1f hours", float64(s)/3600)
	}
	return fmt.Sprintf("%d minutes", s/60)
}

// ---------------------------------------------------------------- HTTP

func (a *App) handleExec(w http.ResponseWriter, r *http.Request) {
	d := a.dbOrFail(w)
	if d == nil {
		return
	}
	p, err := execPeriodFor(r)
	if err != nil {
		reportErr(w, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 150*time.Second)
	defer cancel()
	ex := exclCur.Load()
	if r.URL.Query().Get("excl") == "0" || !ex.active() {
		ex = &execExcl{}
	}
	key := fmt.Sprintf("exec?%s|%d|%d|%s", p.Key, p.From.Unix()/600, p.To.Unix()/600, ex.sig) // rolling periods: 10-minute cache
	v, err := cached(key, 10*time.Minute, func() (any, error) { return a.buildExec(ctx, d, p, ex) })
	if err != nil {
		reportErr(w, err)
		return
	}
	a.audit(r, "exec_summary", p.Key)
	jsonOut(w, v)
}
