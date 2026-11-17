package main

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"
)

// v5.10: AI summary (rollup_ai).
//
// The AI tabs used to scan the raw logs for every refresh: on a TimescaleDB server with compression after 2 days a
// 7-day AI view had to decompress five day-chunks and often hit the 90 s limit ("query timed out"). rollup_ai keeps,
// per hour, every AI-tagged combination of firewall, log type, subtype, tool, user, device, destination, action,
// category, risk, application and country with its counts and bytes. AI rows are a small share of all logs, so the
// table stays small, and almost every AI filter (tool, user, IP or subnet, destination, category, risk, outcome...)
// can still be answered from it exactly. Periods under 3 hours, the free-text search and filters the summary does
// not hold (destination IP, service, policy, severity, event message) still read the raw logs.
//
// It is kept current with the other summaries (current hour every 5 minutes, hours touched by late logs, mappings
// or re-classify on demand) and filled back for hours summarised by an older version, newest first.

const aiRollupInsert = `INSERT INTO rollup_ai (hour, fw, log_type, sub, tool, usr, src, dest, act, cat, risk, app, country,
		cnt, blk, byt, snt, gen, nps, mp, fe, le)
	SELECT $1::timestamptz, ` + fwExpr + `, ` + ltExpr + `, coalesce(subtype,''), ai_tool, coalesce(user_name,''), coalesce(host(src_ip),''),
		coalesce(nullif(hostname,''), host(dst_ip), ''), coalesce(action,''), coalesce(category,''), coalesce(app_risk,''),
		coalesce(application,''), coalesce(fields->>'dstcountry',''),
		count(*), count(*) FILTER (WHERE ` + blockedExpr + `), coalesce(sum(fl_sent(log_id, fields, sent_bytes)+fl_rcvd(log_id, fields, received_bytes)),0)::bigint, coalesce(sum(fl_sent(log_id, fields, sent_bytes)),0)::bigint,
		count(*) FILTER (WHERE ` + genericExpr + `), count(*) FILTER (WHERE nps_id IS NOT NULL), count(*) FILTER (WHERE map_id IS NOT NULL),
		min(event_time), max(event_time)
	FROM fortigate_logs WHERE ai_tool IS NOT NULL AND event_time >= $1 AND event_time < $2
	GROUP BY 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13`

// rollupAIHour (re)builds one hour of the AI summary.
func (d *Database) rollupAIHour(ctx context.Context, h time.Time) error {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `DELETE FROM rollup_ai WHERE hour = $1`, h); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, aiRollupInsert, h, h.Add(time.Hour)); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// rollupAIBackfill builds the AI summary for hours summarised before v5.10, newest first.
func (d *Database) rollupAIBackfill(ctx context.Context, n int) error {
	roll.mu.Lock()
	cur, done := roll.ai, roll.aiOK
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
		if err := d.rollupAIHour(ctx, h); err != nil {
			return fmt.Errorf("AI summary for %s: %w", h.Format("2006-01-02 15:04"), err)
		}
		if err := d.setState(ctx, "ai", h); err != nil {
			return err
		}
		cur = h
		roll.mu.Lock()
		roll.ai = h
		roll.mu.Unlock()
	}
	if !cur.After(floor) {
		roll.mu.Lock()
		if !roll.aiOK {
			log.Printf("rollup: AI summaries are complete back to %s", cur.Format("2006-01-02 15:04"))
		}
		roll.aiOK = true
		roll.mu.Unlock()
	}
	return nil
}

// aiCovers: the AI summary holds a period starting at hour h.
func aiCovers(h time.Time) bool {
	roll.mu.Lock()
	defer roll.mu.Unlock()
	return roll.known && (roll.aiOK || !h.Before(roll.ai))
}

// ---------------------------------------------------------------- reading it

// aiRollWhere turns a dashboard filter into a WHERE clause over rollup_ai. ok is false (with the reason) when the
// filter needs something the summary does not hold.
func aiRollWhere(f Filter, from, to time.Time) (string, []any, string) {
	if strings.TrimSpace(f.Q) != "" {
		return "", nil, "the search box looks inside every log line"
	}
	if f.Extra != "" {
		return "", nil, "this view needs the raw logs"
	}
	for _, x := range []struct{ v, why string }{{f.Dst, "destination IP"}, {f.Service, "service"}, {f.Policy, "policy"}, {f.Level, "severity"}, {f.Msg, "event message"}} {
		if strings.TrimSpace(x.v) != "" {
			return "", nil, "the " + x.why + " filter is not in the AI summary"
		}
	}
	args := []any{from, to}
	conds := []string{"hour >= $1", "hour < $2"}
	switch f.Scope {
	case "ai":
		conds = append(conds, "log_type = 'utm'")
	case "aitraffic":
		conds = append(conds, "log_type = 'traffic'")
	case "aiall":
	default:
		return "", nil, "not an AI view"
	}
	add := func(c string) {
		if c != "" {
			conds = append(conds, c)
		}
	}
	if f.Type != "" {
		add("log_type = " + addArg(&args, f.Type))
	}
	if f.Subtype != "" {
		add("sub = " + addArg(&args, f.Subtype))
	}
	add(textCond(&args, f.FW, true, "fw"))
	add(textCond(&args, f.Tool, true, "tool"))
	add(textCond(&args, f.User, true, "nullif(usr,'')"))
	add(ipCond(&args, f.Src, "nullif(src,'')::inet"))
	add(textCond(&args, f.Category, true, "nullif(cat,'')"))
	add(textCond(&args, f.App, true, "nullif(app,'')"))
	add(textCond(&args, f.Risk, true, "nullif(risk,'')"))
	add(textCond(&args, f.Host, true, "nullif(dest,'')"))
	switch f.Outcome {
	case "blocked":
		add("blk > 0")
	case "allowed":
		add("blk = 0")
	}
	if a := strings.TrimSpace(f.Action); a != "" {
		neg := strings.HasPrefix(a, "!")
		list := strings.Split(strings.TrimPrefix(a, "!"), ",")
		for i := range list {
			list[i] = strings.TrimSpace(list[i])
		}
		c := "act = ANY(" + addArg(&args, list) + "::text[])"
		if neg {
			c = "NOT (" + c + ")"
		}
		add(c)
	}
	return strings.Join(conds, " AND "), args, ""
}

// aiRollupUsable: can the AI summary answer this filter? why explains the raw fallback on the page.
func aiRollupUsable(f Filter) (bool, string) {
	if f.To.Sub(f.From) < time.Hour {
		return false, "periods under 1 hour are read from the raw logs (1-minute detail)"
	}
	if !aiCovers(hourStart(f.From)) {
		roll.mu.Lock()
		c := roll.ai
		roll.mu.Unlock()
		return false, "the AI summaries are still being built back (now at " + c.Format("2 Jan 15:04") + ")"
	}
	if _, _, why := aiRollWhere(f, f.From, f.To); why != "" {
		return false, why
	}
	return true, ""
}

// aiStep: hourly buckets up to 8 days, daily beyond. origin is the local start of the first bucket.
func aiStep(f Filter) (step int64, bucketSQL string, origin int64) {
	if f.To.Sub(f.From) <= 8*24*time.Hour {
		return 3600, "extract(epoch FROM hour)::bigint", hourStart(f.From).Unix()
	}
	l := f.From.In(time.Local)
	return 86400, "extract(epoch FROM date_trunc('day', hour))::bigint", time.Date(l.Year(), l.Month(), l.Day(), 0, 0, 0, 0, time.Local).Unix()
}

const aiRiskRank = `CASE risk WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'elevated' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END`

// aiOverviewSQL mirrors the raw Insights query (same columns, same GROUPING SETS) over rollup_ai.
func aiOverviewSQL(where, bucket string) string {
	return `SELECT GROUPING(b,a,r,c,dw,hr,ap)::int, b, a, r, c, dw, hr, ap,
		coalesce(sum(cnt),0)::bigint, coalesce(sum(blk),0)::bigint, coalesce(sum(byt),0)::bigint,
		coalesce(sum(gen),0)::bigint, coalesce(sum(gen) FILTER (WHERE blk = 0),0)::bigint,
		coalesce(sum(cnt) FILTER (WHERE risk IN ('elevated','high','critical') AND blk = 0),0)::bigint,
		coalesce(sum(cnt) FILTER (WHERE app ~* '(^|[._ -])(dns|doh)([._ -]|$)'),0)::bigint, coalesce(sum(cnt) FILTER (WHERE app ILIKE 'quic%'),0)::bigint,
		coalesce(sum(cnt) FILTER (WHERE cat ~* '^(p2p|proxy|remote)'),0)::bigint, coalesce(sum(cnt) FILTER (WHERE sub = 'app-ctrl'),0)::bigint,
		coalesce(sum(cnt) FILTER (WHERE usr <> ''),0)::bigint, coalesce(max(rk),0)::bigint, coalesce(sum(mp),0)::bigint, coalesce(sum(nps),0)::bigint
	FROM (SELECT ` + bucket + ` AS b, nullif(act,'') AS a, nullif(risk,'') AS r, nullif(cat,'') AS c,
		extract(dow FROM hour)::int AS dw, extract(hour FROM hour)::int AS hr, nullif(tool,'') AS ap,
		cnt, blk, byt, gen, risk, app, cat, sub, usr, mp, nps, ` + aiRiskRank + ` AS rk
		FROM rollup_ai WHERE ` + where + `) x
	GROUP BY GROUPING SETS ((b),(a),(r),(c),(dw,hr),(ap),(ap,b),())`
}

// aiTopSQL: busiest values of one column (count, blocked, bytes, upload) and the number of distinct values.
func aiTopSQL(where, name, cond, order string, limitArg string) string {
	return `SELECT name, cnt, blk, byt, snt, count(*) OVER (), rk FROM (
		SELECT ` + name + ` AS name, sum(cnt)::bigint AS cnt, sum(blk)::bigint AS blk, sum(byt)::bigint AS byt, sum(snt)::bigint AS snt,
		coalesce(max(` + aiRiskRank + `),0)::bigint AS rk
		FROM rollup_ai WHERE ` + where + cond + ` GROUP BY 1) t WHERE name IS NOT NULL ORDER BY ` + order + ` DESC, name LIMIT ` + limitArg
}

func (d *Database) aiTop(ctx context.Context, where string, args []any, name, cond, order string, limit int) ([]map[string]any, int64, error) {
	release, err := d.acquire(ctx)
	if err != nil {
		return nil, 0, err
	}
	defer release()
	a := append(append([]any{}, args...), limit)
	rows, err := d.pool.Query(ctx, aiTopSQL(where, name, cond, order, fmt.Sprintf("$%d", len(a))), a...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []map[string]any{}
	var groups int64
	for rows.Next() {
		var n string
		var c, b, y, s, rk int64
		if err = rows.Scan(&n, &c, &b, &y, &s, &groups, &rk); err != nil {
			return nil, 0, err
		}
		out = append(out, map[string]any{"name": n, "count": c, "blocked": b, "bytes": y, "sent": s, "risk": rk})
	}
	return out, groups, rows.Err()
}

// aiUserToolsSQL: for the 15 busiest people, how much they used each AI tool.
func aiUserToolsSQL(where string) string {
	return `SELECT usr, tool, sum(cnt)::bigint, sum(blk)::bigint, sum(snt)::bigint FROM rollup_ai WHERE ` + where + ` AND usr IN (
		SELECT usr FROM rollup_ai WHERE ` + where + ` AND usr <> '' GROUP BY 1 ORDER BY sum(cnt) DESC LIMIT 15) GROUP BY 1, 2 ORDER BY 1, 3 DESC`
}

// userToolsRawSQL is the same over the raw logs (rel already holds the AI scope).
func userToolsRawSQL(rel string) string {
	return `SELECT user_name, ai_tool, count(*), count(*) FILTER (WHERE ` + blockedExpr + `), coalesce(sum(fl_sent(log_id, fields, sent_bytes)),0)::bigint FROM fortigate_logs
		WHERE ` + rel + ` AND ai_tool IS NOT NULL AND coalesce(user_name,'') <> '' AND user_name IN (
		SELECT user_name FROM fortigate_logs WHERE ` + rel + ` AND ai_tool IS NOT NULL AND coalesce(user_name,'') <> '' GROUP BY 1 ORDER BY count(*) DESC LIMIT 15)
		GROUP BY 1, 2 ORDER BY 1, 3 DESC`
}

func (d *Database) scanUserTools(ctx context.Context, q string, args []any) ([]map[string]any, error) {
	release, err := d.acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	rows, err := d.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var u, t string
		var c, b, s int64
		if err = rows.Scan(&u, &t, &c, &b, &s); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{"user": u, "tool": t, "count": c, "blocked": b, "sent": s})
	}
	return out, rows.Err()
}

const aiToolUsageSQL = `SELECT tool, sum(cnt)::bigint, sum(blk)::bigint, count(DISTINCT nullif(usr,'')), count(DISTINCT nullif(src,'')),
	min(coalesce(fe, hour)), max(coalesce(le, hour)) FROM rollup_ai WHERE %s GROUP BY 1 ORDER BY 2 DESC LIMIT 30`

// aiToolUsage: per tool, people, devices and whether it is new (first seen in the summary inside this period).
func (d *Database) aiToolUsage(ctx context.Context, where string, args []any, from time.Time) ([]map[string]any, error) {
	release, err := d.acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	rows, err := d.pool.Query(ctx, fmt.Sprintf(aiToolUsageSQL, where), args...)
	if err != nil {
		return nil, err
	}
	out := []map[string]any{}
	names := []string{}
	for rows.Next() {
		var t string
		var c, b, u, s int64
		var first, last time.Time
		if err = rows.Scan(&t, &c, &b, &u, &s, &first, &last); err != nil {
			rows.Close()
			return nil, err
		}
		names = append(names, t)
		out = append(out, map[string]any{"name": t, "count": c, "blocked": b, "users": u, "sources": s, "first": first, "last": last})
	}
	rows.Close()
	if err = rows.Err(); err != nil || len(names) == 0 {
		return out, err
	}
	ever, err := d.firstSeenTools(ctx, names)
	if err != nil {
		return out, nil // only the "New" badge is missing
	}
	for _, o := range out {
		if e, ok := ever[o["name"].(string)]; ok {
			o["firstEver"] = e
			o["isNew"] = !e.Before(from)
		}
	}
	return out, nil
}

// firstSeenTools: when each tool was first seen, from the summaries (cheap) instead of every stored AI log.
func (d *Database) firstSeenTools(ctx context.Context, names []string) (map[string]time.Time, error) {
	out := map[string]time.Time{}
	rows, err := d.pool.Query(ctx, `SELECT tool, min(coalesce(fe, hour)) FROM rollup_ai WHERE tool = ANY($1) GROUP BY 1
		UNION ALL SELECT name, min(hour) FROM rollup_1h WHERE dim = 'tool' AND name = ANY($1) GROUP BY 1`, names)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var n string
		var t time.Time
		if err = rows.Scan(&n, &t); err != nil {
			return nil, err
		}
		if e, ok := out[n]; !ok || t.Before(e) {
			out[n] = t
		}
	}
	return out, rows.Err()
}

// aiInsightsRollup answers the AI tabs (same keys as the raw /api/insights) from rollup_ai.
func (d *Database) aiInsightsRollup(ctx context.Context, f Filter) (map[string]any, error) {
	fromH := hourStart(f.From)
	where, args, why := aiRollWhere(f, fromH, f.To)
	if why != "" {
		return nil, specErr("%s", why)
	}
	tf := f
	tf.Scope = "aitraffic" // uploads come from traffic logs (security events carry no byte counts)
	twhere, targs, _ := aiRollWhere(tf, fromH, f.To)
	span := f.To.Sub(fromH)
	pwhere, pargs, _ := aiRollWhere(f, fromH.Add(-span), fromH)
	step, bucket, origin := aiStep(f)

	out := map[string]any{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	var firstErr error
	put := func(m map[string]any, err error) {
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			return
		}
		for k, v := range m {
			out[k] = v
		}
	}
	run := func(fn func() (map[string]any, error)) {
		wg.Add(1)
		go func() { defer wg.Done(); put(fn()) }()
	}
	run(func() (map[string]any, error) {
		release, err := d.acquire(ctx)
		if err != nil {
			return nil, err
		}
		defer release()
		rows, err := d.pool.Query(ctx, aiOverviewSQL(where, bucket), args...)
		if err != nil {
			return nil, err
		}
		return scanInsights(rows, f, step, origin, "tool", true)
	})
	run(func() (map[string]any, error) {
		release, err := d.acquire(ctx)
		if err != nil {
			return nil, err
		}
		defer release()
		var total, blk, byt, rh int64
		err = d.pool.QueryRow(ctx, `SELECT coalesce(sum(cnt),0)::bigint, coalesce(sum(blk),0)::bigint, coalesce(sum(byt),0)::bigint,
			coalesce(sum(cnt) FILTER (WHERE risk IN ('elevated','high','critical') AND blk = 0),0)::bigint FROM rollup_ai WHERE `+pwhere, pargs...).Scan(&total, &blk, &byt, &rh)
		return map[string]any{"prev": map[string]int64{"total": total, "blocked": blk, "bytes": byt, "riskNB": rh}}, err
	})
	run(func() (map[string]any, error) {
		l, err := d.aiToolUsage(ctx, where, args, f.From)
		return map[string]any{"toolUsage": l}, err
	})
	run(func() (map[string]any, error) {
		l, err := d.scanUserTools(ctx, aiUserToolsSQL(where), args)
		return map[string]any{"userTools": l}, err
	})
	type job struct {
		key, name, cond, order string
		traffic                bool
	}
	jobs := []job{{"users", "nullif(usr,'')", "", "cnt", false}, {"sources", "nullif(src,'')", "", "cnt", false}, {"hosts", "nullif(dest,'')", "", "cnt", false},
		{"mostBlocked", "nullif(dest,'')", " AND blk > 0", "cnt", false}, {"blockedUsers", "nullif(usr,'')", " AND blk > 0", "cnt", false},
		{"needsReview", "nullif(app,'')", " AND blk = 0 AND (gen > 0 OR risk IN ('elevated','high','critical'))", "cnt", false},
		// data volumes come from traffic logs: web filter / app control events carry no byte counts
		{"whereData", "nullif(dest,'')", "", "byt", true}, {"countries", "nullif(country,'')", "", "byt", true},
		{"aiUploaders", "nullif(usr,'')", "", "snt", true}, {"aiUploadSources", "nullif(src,'')", "", "snt", true}, {"aiToolData", "nullif(tool,'')", "", "snt", true}}
	for _, j := range jobs {
		j := j
		run(func() (map[string]any, error) {
			w, a := where, args
			if j.traffic {
				w, a = twhere, targs
			}
			l, g, err := d.aiTop(ctx, w, a, j.name, j.cond, j.order, 8)
			return map[string]any{j.key: l, j.key + "Groups": g}, err
		})
	}
	wg.Wait()
	if firstErr != nil {
		return nil, firstErr
	}
	out["mode"], out["listsFrom"] = "summary", fromH
	out["from"], out["to"] = f.From, f.To
	return out, nil
}
