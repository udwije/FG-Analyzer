package main

import (
	"context"
	"fmt"
	"log"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// v5.13: speed for the AI tabs, User mapping, Reports and the executive report.
//
//   - rollup_1d: one row per day x firewall x log type x dimension x value, built from rollup_1h once a day is over.
//     Every "top" list over 7 or 30 days used to add up 168-720 hourly rows per value (up to 20,000 source IPs and
//     users per hour and firewall); full days now come from one daily row and only the partial days at the edges
//     from the hourly table. Used by the All logs and executive top lists, the report builder and the filter boxes.
//   - The AI tabs use the AI summary from 1 hour up (was: over 12 hours). Up to 12 hours the timeline is still read
//     from the raw AI logs (5-minute detail), so the chart stays sharp while the lists come from the summary.
//   - The default AI views (6 h, 24 h, 7 days for the AI source in use) are kept ready in the background while the
//     AI tabs are used, like the All logs page.
//   - User mapping: "IP addresses without a username" and "seen with" come from two new hourly dimensions
//     (nouser_src, ipuser) instead of scanning every raw log of the period; the mapping list no longer counts the
//     rows of every mapping on each visit; the NPS session list counts events only when you search for an IP or user.
//   - Filter-box suggestions come from the summaries (the user list asked for 30 days of raw logs on every visit).

// ---------------------------------------------------------------- daily summary

func dayStart(t time.Time) time.Time {
	t = t.In(time.Local)
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.Local)
}

var daysDone = struct {
	sync.Mutex
	m      map[int64]bool
	loaded time.Time
}{m: map[int64]bool{}}

func (d *Database) loadDaysDone(ctx context.Context) {
	daysDone.Lock()
	fresh := time.Since(daysDone.loaded) < time.Minute
	daysDone.Unlock()
	if fresh {
		return
	}
	rows, err := d.pool.Query(ctx, `SELECT day FROM rollup_1d_done`)
	if err != nil {
		return
	}
	defer rows.Close()
	m := map[int64]bool{}
	for rows.Next() {
		var t time.Time
		if rows.Scan(&t) == nil {
			m[t.Unix()] = true
		}
	}
	daysDone.Lock()
	daysDone.m, daysDone.loaded = m, time.Now()
	daysDone.Unlock()
}

func dayIsDone(t time.Time) bool {
	daysDone.Lock()
	defer daysDone.Unlock()
	return daysDone.m[t.Unix()]
}

// invalidateDay: an hour of this day was summarised again; the day row is rebuilt by the background job.
func (d *Database) invalidateDay(ctx context.Context, h time.Time) {
	day := dayStart(h)
	if !day.Before(dayStart(time.Now())) {
		return
	}
	daysDone.Lock()
	delete(daysDone.m, day.Unix())
	daysDone.Unlock()
	_, _ = d.pool.Exec(ctx, `DELETE FROM rollup_1d_done WHERE day = $1`, day)
}

const rollup1dInsert = `INSERT INTO rollup_1d (dim, day, fw, log_type, name, cnt, blk, byt, snt)
	SELECT dim, $1::timestamptz, fw, log_type, name, cnt, blk, byt, snt FROM (
		SELECT g.*, row_number() OVER (PARTITION BY dim, fw, log_type ORDER BY cnt DESC) AS rc,
			row_number() OVER (PARTITION BY dim, fw, log_type ORDER BY byt DESC) AS rb,
			row_number() OVER (PARTITION BY dim, fw, log_type ORDER BY blk DESC) AS rk
		FROM (SELECT dim, fw, log_type, name, sum(cnt)::bigint AS cnt, sum(blk)::bigint AS blk, sum(byt)::bigint AS byt, sum(snt)::bigint AS snt
			FROM rollup_1h WHERE hour >= $1 AND hour < $2 GROUP BY 1, 2, 3, 4) g
	) t WHERE rc <= CASE WHEN dim IN ('src_ip','user','inet_user','inet_src','nouser_src','ipuser') THEN 30000 ELSE 5000 END OR rb <= 2000 OR rk <= 2000`

func (d *Database) rollupDay(ctx context.Context, day time.Time) error {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `DELETE FROM rollup_1d WHERE day = $1`, day); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, rollup1dInsert, day, day.AddDate(0, 0, 1)); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO rollup_1d_done(day, built) VALUES ($1, now()) ON CONFLICT (day) DO UPDATE SET built = now()`, day); err != nil {
		return err
	}
	if err = tx.Commit(ctx); err != nil {
		return err
	}
	daysDone.Lock()
	daysDone.m[day.Unix()] = true
	daysDone.Unlock()
	return nil
}

// rollupDays builds up to n finished days that are not (or no longer) summarised, newest first. A day is only built
// once its hours are summarised (back-fill and the v5.12 rebuild have passed it).
func (d *Database) rollupDays(ctx context.Context, n int) error {
	d.loadDaysDone(ctx)
	floor, err := d.backfillFloor(ctx)
	if err != nil {
		return err
	}
	today := dayStart(time.Now())
	built := 0
	for day := today.AddDate(0, 0, -1); !day.Before(dayStart(floor)) && built < n; day = day.AddDate(0, 0, -1) {
		if dayIsDone(day) {
			continue
		}
		if !roll.covers(day) || !inetCovers(day) {
			break // older hours are still being (re)summarised: build the day afterwards
		}
		if err := d.rollupDay(ctx, day); err != nil {
			return fmt.Errorf("daily summary %s: %w", day.Format("2006-01-02"), err)
		}
		built++
	}
	return nil
}

// rollSource returns a sub-select over the summaries for [from, to): rollup_1d for finished days that lie fully inside
// the range, rollup_1h for the rest. Columns: hour, fw, log_type, dim, name, cnt, blk, byt, snt. Only the firewall and
// log type filters of f are applied (like rollWhere). When hourly is true, days are never used (per-hour buckets).
func rollSource(f Filter, from, to time.Time, dims []string, args *[]any, hourly bool) string {
	var days []time.Time
	if !hourly {
		for day := dayStart(from); day.Before(to); day = day.AddDate(0, 0, 1) {
			if !day.Before(from) && !day.AddDate(0, 0, 1).After(to) && dayIsDone(day) {
				days = append(days, day)
			}
		}
	}
	extra := func() string {
		c := ""
		if f.Type != "" {
			c += " AND log_type = " + addArg(args, f.Type)
		}
		if t := textCond(args, f.FW, true, "fw"); t != "" {
			c += " AND " + t
		}
		if len(dims) == 1 {
			c += " AND dim = " + addArg(args, dims[0])
		} else if len(dims) > 1 {
			c += " AND dim = ANY(" + addArg(args, dims) + "::text[])"
		}
		return c
	}
	// hour intervals: [from, to) minus the days used
	type iv struct{ a, b time.Time }
	ivs := []iv{}
	cur := from
	for _, day := range days {
		if day.After(cur) {
			ivs = append(ivs, iv{cur, day})
		}
		cur = day.AddDate(0, 0, 1)
	}
	if to.After(cur) {
		ivs = append(ivs, iv{cur, to})
	}
	parts := []string{}
	if len(days) > 0 {
		ds := make([]string, len(days))
		for i, x := range days {
			ds[i] = x.Format(time.RFC3339)
		}
		parts = append(parts, `SELECT day AS hour, fw, log_type, dim, name, cnt, blk, byt, snt FROM rollup_1d WHERE day = ANY(`+addArg(args, ds)+`::text[]::timestamptz[])`+extra())
	}
	if len(ivs) > 0 {
		or := []string{}
		for _, x := range ivs {
			or = append(or, "(hour >= "+addArg(args, x.a)+" AND hour < "+addArg(args, x.b)+")")
		}
		parts = append(parts, `SELECT hour, fw, log_type, dim, name, cnt, blk, byt, snt FROM rollup_1h WHERE (`+strings.Join(or, " OR ")+`)`+extra())
	}
	if len(parts) == 0 {
		return `(SELECT now() AS hour, ''::text AS fw, ''::text AS log_type, ''::text AS dim, ''::text AS name, 0::bigint AS cnt, 0::bigint AS blk, 0::bigint AS byt, 0::bigint AS snt WHERE false) rs`
	}
	return "(" + strings.Join(parts, " UNION ALL ") + ") rs"
}

// ---------------------------------------------------------------- mapping dimensions (hourly)

// rollupMapHour adds, for one hour, the internal devices whose logs had no username (nouser_src) and which
// username the firewall reported on each address (ipuser = "ip user"). The User mapping tab reads these.
func (d *Database) rollupMapHour(ctx context.Context, h time.Time) error {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `DELETE FROM rollup_1h WHERE hour = $1 AND dim IN ('nouser_src','ipuser')`, h); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO rollup_1h (dim, hour, fw, log_type, name, cnt, blk, byt, snt)
		SELECT dim, $1::timestamptz, fw, lt, name, cnt, blk, byt, snt FROM (
		  SELECT g.*, row_number() OVER (PARTITION BY dim, fw, lt ORDER BY cnt DESC) AS rc FROM (
		    SELECT fw, lt, CASE WHEN GROUPING(nu) = 0 THEN 'nouser_src' ELSE 'ipuser' END AS dim, coalesce(nu, iu) AS name,
		      count(*) AS cnt, count(*) FILTER (WHERE isblk) AS blk, coalesce(sum(byts),0)::bigint AS byt, coalesce(sum(sn),0)::bigint AS snt
		    FROM (SELECT `+fwExpr+` AS fw, `+ltExpr+` AS lt, coalesce(`+blockedExpr+`, false) AS isblk,
		            `+sentSQL+`+`+rcvdSQL+` AS byts, `+sentSQL+` AS sn,
		            CASE WHEN coalesce(user_name,'') = '' AND src_ip <<= ANY(`+localNetsSQL()+`) THEN host(src_ip) END AS nu,
		            CASE WHEN coalesce(user_name,'') <> '' AND map_id IS NULL AND nps_id IS NULL AND src_ip IS NOT NULL
		                 THEN host(src_ip) || ' ' || left(user_name, 100) END AS iu
		          FROM fortigate_logs WHERE event_time >= $1 AND event_time < $2 AND src_ip IS NOT NULL) x
		    GROUP BY GROUPING SETS ((fw,lt,nu),(fw,lt,iu))
		  ) g WHERE name IS NOT NULL
		) t WHERE rc <= 20000`, h, h.Add(time.Hour)); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (d *Database) rollupMapBackfill(ctx context.Context, n int) error {
	roll.mu.Lock()
	cur, done := roll.mp, roll.mpOK
	roll.mu.Unlock()
	if done || cur.IsZero() {
		return nil
	}
	floor, err := d.backfillFloor(ctx)
	if err != nil {
		return err
	}
	for i := 0; i < n && cur.After(floor); i++ {
		h := cur.Add(-time.Hour)
		if err := d.rollupMapHour(ctx, h); err != nil {
			return fmt.Errorf("mapping summary for %s: %w", h.Format("2006-01-02 15:04"), err)
		}
		d.invalidateDay(ctx, h)
		if err := d.setState(ctx, "map", h); err != nil {
			return err
		}
		cur = h
		roll.mu.Lock()
		roll.mp = h
		roll.mu.Unlock()
	}
	if !cur.After(floor) {
		roll.mu.Lock()
		if !roll.mpOK {
			log.Printf("rollup: user-mapping summaries are complete back to %s", cur.Format("2006-01-02 15:04"))
		}
		roll.mpOK = true
		roll.mu.Unlock()
	}
	return nil
}

func mapCovers(h time.Time) bool {
	roll.mu.Lock()
	defer roll.mu.Unlock()
	return roll.known && (roll.mpOK || !h.Before(roll.mp))
}

// mappingOverviewRollup answers the User mapping tab from the summaries.
func (d *Database) mappingOverviewRollup(ctx context.Context, f Filter) (map[string]any, error) {
	fromH := hourStart(f.From)
	release, err := d.acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	rel, args := rollWhere(f, "bucket", f.From.Truncate(5*time.Minute), f.To)
	var total, known, manual, nps int64
	if err = d.pool.QueryRow(ctx, `SELECT coalesce(sum(cnt),0)::bigint, coalesce(sum(usr),0)::bigint, coalesce(sum(mp),0)::bigint, coalesce(sum(nps),0)::bigint
		FROM rollup_5m WHERE `+rel, args...).Scan(&total, &known, &manual, &nps); err != nil {
		return nil, err
	}
	a2 := []any{}
	src := rollSource(f, fromH, f.To, []string{"nouser_src"}, &a2, true)
	rows, err := d.pool.Query(ctx, `SELECT name, sum(cnt)::bigint, count(DISTINCT date_trunc('day', hour)), min(hour), max(hour) + interval '1 hour'
		FROM `+src+` GROUP BY name ORDER BY 2 DESC LIMIT 60`, a2...)
	if err != nil {
		return nil, err
	}
	list := []map[string]any{}
	ips := []string{}
	for rows.Next() {
		var ip string
		var ev, days int64
		var first, last time.Time
		if err = rows.Scan(&ip, &ev, &days, &first, &last); err != nil {
			rows.Close()
			return nil, err
		}
		if last.After(f.To) {
			last = f.To
		}
		list = append(list, map[string]any{"ip": ip, "events": ev, "days": days, "first": first, "last": last, "observed": []map[string]any{}})
		ips = append(ips, ip)
	}
	rows.Close()
	if len(ips) > 0 {
		a3 := []any{}
		src = rollSource(f, fromH, f.To, []string{"ipuser"}, &a3, true)
		obs, err := d.pool.Query(ctx, `SELECT split_part(name, ' ', 1), substr(name, strpos(name, ' ') + 1), sum(cnt)::bigint, min(hour), max(hour) + interval '1 hour'
			FROM `+src+` WHERE split_part(name, ' ', 1) = ANY(`+addArg(&a3, ips)+`::text[]) GROUP BY 1, 2 ORDER BY 3 DESC`, a3...)
		if err != nil {
			return nil, err
		}
		defer obs.Close()
		idx := map[string]int{}
		for i, ip := range ips {
			idx[ip] = i
		}
		for obs.Next() {
			var ip, user string
			var c int64
			var first, last time.Time
			if err = obs.Scan(&ip, &user, &c, &first, &last); err != nil {
				return nil, err
			}
			i, ok := idx[ip]
			if !ok {
				continue
			}
			o := list[i]["observed"].([]map[string]any)
			if len(o) < 4 {
				list[i]["observed"] = append(o, map[string]any{"user": user, "events": c, "first": first, "last": last})
			}
		}
	}
	return map[string]any{"unmapped": list, "total": total, "userKnown": known, "userMapped": manual, "userNPS": nps, "from": f.From, "to": f.To,
		"mode": "summary"}, nil
}

// mappingSimple: the User mapping filter only uses what the summaries hold.
func mappingSimple(f Filter) bool {
	g := f
	g.User = ""
	return filterIsSimple(g) && mapCovers(hourStart(f.From)) && f.To.Sub(f.From) >= time.Hour
}

// ---------------------------------------------------------------- filter-box suggestions

var facetDims = map[string]string{"user": "user", "src_ip": "src_ip", "application": "application", "action": "action", "country": "country",
	"tool": "tool", "service": "service", "policy": "policy", "msg": "msg", "category": "category", "hostname": "dest", "dest": "dest"}

func (d *Database) facetsRollup(ctx context.Context, field string, f Filter) ([]map[string]any, bool, error) {
	dim, ok := facetDims[field]
	if !ok || f.Scope != "" || f.Subtype != "" || !roll.covers(hourStart(f.From)) {
		return nil, false, nil
	}
	d.loadDaysDone(ctx)
	rows, _, err := d.topRollup(ctx, dim, Filter{Type: f.Type}, hourStart(f.From), f.To, 100, "cnt", false)
	return rows, true, err
}

// ---------------------------------------------------------------- AI: short periods, warmer

// aiSeriesRaw reads only the AI timeline (and the per-tool timeline) from the raw AI logs, for periods up to 12 hours.
func (d *Database) aiSeriesRaw(ctx context.Context, f Filter, step int64) ([]Bucket, map[string]map[int64]int64, error) {
	rel, args := f.where()
	release, err := d.acquire(ctx)
	if err != nil {
		return nil, nil, err
	}
	defer release()
	s := strconv.FormatInt(step, 10)
	rows, err := d.pool.Query(ctx, `SELECT GROUPING(ap)::int, b, ap, count(*), count(*) FILTER (WHERE blk), coalesce(sum(byt),0)::bigint FROM (
		SELECT (floor(extract(epoch FROM event_time)/`+s+`)*`+s+`)::bigint AS b, ai_tool AS ap, coalesce(`+blockedExpr+`, false) AS blk,
			`+sentSQL+`+`+rcvdSQL+` AS byt FROM fortigate_logs WHERE `+rel+` AND ai_tool IS NOT NULL) x
		GROUP BY GROUPING SETS ((b), (ap, b))`, args...)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	series := []Bucket{}
	per := map[string]map[int64]int64{}
	for rows.Next() {
		var g int
		var b, c, k, y int64
		var ap *string
		if err = rows.Scan(&g, &b, &ap, &c, &k, &y); err != nil {
			return nil, nil, err
		}
		if g == 1 {
			series = append(series, Bucket{T: b, Total: c, Blocked: k, Bytes: y})
		} else if ap != nil {
			if per[*ap] == nil {
				per[*ap] = map[int64]int64{}
			}
			per[*ap][b] = c
		}
	}
	sort.Slice(series, func(i, j int) bool { return series[i].T < series[j].T })
	return series, per, rows.Err()
}

// aiLiveTimeline replaces the hourly timeline of a summary answer with the 1- or 5-minute one from the raw logs.
func (d *Database) aiLiveTimeline(ctx context.Context, f Filter, out map[string]any) error {
	step := bucketSeconds(f)
	series, per, err := d.aiSeriesRaw(ctx, f, step)
	if err != nil {
		return err
	}
	t0 := f.From.Unix() / step * step
	n := int((f.To.Unix()-t0)/step) + 1
	if n > 700 {
		n = 700
	}
	out["series"], out["step"], out["origin"] = series, step, t0
	if apps, ok := out["apps"].([]map[string]any); ok {
		for i, a := range apps {
			if i >= 12 {
				break
			}
			sp := make([]int64, n)
			for b, v := range per[fmt.Sprint(a["name"])] {
				if k := int((b - t0) / step); k >= 0 && k < n {
					sp[k] = v
				}
			}
			a["spark"] = sp
		}
	}
	return nil
}

// AI warmer: the default AI views of the AI source in use, while the AI tabs were used in the last 30 minutes.
var lastAIView atomic.Int64
var lastAIScope atomic.Value // string

func (a *App) aiWarm(ctx context.Context, d *Database) {
	if time.Now().Unix()-lastAIView.Load() > warmIdleSeconds {
		return
	}
	scope, _ := lastAIScope.Load().(string)
	if scope == "" {
		return
	}
	for _, h := range []int{6, 24, 168} {
		now := time.Now()
		f := Filter{From: now.Add(-time.Duration(h) * time.Hour), To: now.Add(time.Minute), Scope: scope}
		if ok, _ := aiRollupUsable(f); !ok {
			continue
		}
		c, cancel := context.WithTimeout(ctx, 60*time.Second)
		v, err := d.computeInsights(c, f)
		cancel()
		if err == nil {
			cachePut("insights?hours="+strconv.Itoa(h)+"&scope="+scope, v)
		}
	}
}
