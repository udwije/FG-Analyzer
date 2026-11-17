package main

import (
	"context"
	"errors"
	"log"
	"regexp"

	"fmt"
	"github.com/jackc/pgx/v5"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Traffic the firewall can only label with a generic protocol name is "not identified".
const genericExpr = `application ~* '^(ssl|tls|quic|unknown)([_.+ -]|$)'`
const riskHighExpr = `app_risk IN ('elevated','high','critical')`
const riskRank = `CASE app_risk WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'elevated' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END`

type agg struct{ cnt, blk, byt, gen, genNB, rhNB, dns, quic, rem, actl, usr, rk, mp, nps int64 }

type appRow struct {
	Name                        string  `json:"name"`
	Count, Blocked, Bytes, Risk int64   `json:"-"`
	Spark                       []int64 `json:"spark,omitempty"`
}

func (a appRow) MarshalMap() map[string]any {
	return map[string]any{"name": a.Name, "count": a.Count, "blocked": a.Blocked, "bytes": a.Bytes, "risk": a.Risk, "spark": a.Spark}
}

// Insights answers every dashboard tile, chart and finding in ONE grouped pass over the filtered rows.
func (d *Database) Insights(ctx context.Context, f Filter) (map[string]any, error) {
	rel, args := f.where()
	release, err := d.acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	step := bucketSeconds(f)
	appCol, appKey := "application", "app"
	if f.Scope != "" {
		appCol, appKey = "ai_tool", "tool" // AI views group by tool (ChatGPT = web filter + app control + traffic)
	}
	q := `SELECT GROUPING(b,a,r,c,dw,hr,ap)::int, b, a, r, c, dw, hr, ap,
		count(*), count(*) FILTER (WHERE blk), coalesce(sum(by),0)::bigint,
		count(*) FILTER (WHERE gen), count(*) FILTER (WHERE gen AND NOT blk), count(*) FILTER (WHERE rh AND NOT blk),
		count(*) FILTER (WHERE dns), count(*) FILTER (WHERE quic), count(*) FILTER (WHERE rem),
		count(*) FILTER (WHERE actl), count(*) FILTER (WHERE usr), coalesce(max(rk),0)::bigint, count(*) FILTER (WHERE mp), count(*) FILTER (WHERE np)
	FROM (SELECT (floor(extract(epoch FROM event_time)/{S})*{S})::bigint AS b, nullif(action,'') AS a, nullif(app_risk,'') AS r,
		nullif(category,'') AS c, extract(dow FROM event_time)::int AS dw, extract(hour FROM event_time)::int AS hr, nullif({APP},'') AS ap,
		coalesce(` + blockedExpr + `, false) AS blk, coalesce(fl_sent(log_id, fields, sent_bytes)+fl_rcvd(log_id, fields, received_bytes),0) AS by,
		coalesce(` + genericExpr + `, false) AS gen, coalesce(` + riskHighExpr + `, false) AS rh,
		coalesce(application ~* '(^|[._ -])(dns|doh)([._ -]|$)', false) AS dns, coalesce(application ILIKE 'quic%', false) AS quic,
		coalesce(category ~* '^(p2p|proxy|remote)', false) AS rem, subtype = 'app-ctrl' AS actl, coalesce(user_name,'') <> '' AS usr, map_id IS NOT NULL AS mp, nps_id IS NOT NULL AS np,
		` + riskRank + ` AS rk
		FROM fortigate_logs WHERE ` + rel + `) x
	GROUP BY GROUPING SETS ((b),(a),(r),(c),(dw,hr),(ap),(ap,b),())`
	rows, err := d.pool.Query(ctx, strings.NewReplacer("{S}", strconv.FormatInt(step, 10), "{APP}", appCol).Replace(q), args...)
	if err != nil {
		return nil, err
	}
	return scanInsights(rows, f, step, f.From.Unix()/step*step, appKey, f.Scope != "")
}

// scanInsights reads the GROUPING SETS result shared by the raw query and the AI summary query (v5.10).
// t0 is the start of the first time bucket (the summaries use local hours / days).
func scanInsights(rows pgx.Rows, f Filter, step, t0 int64, appKey string, ai bool) (map[string]any, error) {
	defer rows.Close()
	var err error
	n := int((f.To.Unix()-t0)/step) + 1
	if n > 700 {
		n = 700
	}
	var tot agg
	series, actions, risks, cats, heat := []Bucket{}, []map[string]any{}, []map[string]any{}, []map[string]any{}, [][3]int64{}
	apps := []appRow{}
	appSeries := map[string]map[int64]int64{}
	for rows.Next() {
		var g int
		var b *int64
		var a, r, c, ap *string
		var dw, hr *int
		var x agg
		if err = rows.Scan(&g, &b, &a, &r, &c, &dw, &hr, &ap, &x.cnt, &x.blk, &x.byt, &x.gen, &x.genNB, &x.rhNB, &x.dns, &x.quic, &x.rem, &x.actl, &x.usr, &x.rk, &x.mp, &x.nps); err != nil {
			return nil, err
		}
		row := func(name string) map[string]any {
			return map[string]any{"name": name, "count": x.cnt, "blocked": x.blk, "bytes": x.byt, "risk": x.rk}
		}
		switch g {
		case 63:
			if b != nil {
				series = append(series, Bucket{T: *b, Total: x.cnt, Blocked: x.blk, Bytes: x.byt})
			}
		case 95:
			if a != nil {
				actions = append(actions, row(*a))
			}
		case 111:
			if r != nil {
				risks = append(risks, row(*r))
			}
		case 119:
			if c != nil {
				cats = append(cats, row(*c))
			}
		case 121:
			if dw != nil && hr != nil {
				heat = append(heat, [3]int64{int64(*dw), int64(*hr), x.cnt})
			}
		case 126:
			if ap != nil {
				apps = append(apps, appRow{Name: *ap, Count: x.cnt, Blocked: x.blk, Bytes: x.byt, Risk: x.rk})
			}
		case 62:
			if ap != nil && b != nil {
				if appSeries[*ap] == nil {
					appSeries[*ap] = map[int64]int64{}
				}
				appSeries[*ap][*b] = x.cnt
			}
		case 127:
			tot = x
		}
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	sort.Slice(series, func(i, j int) bool { return series[i].T < series[j].T })
	sort.Slice(apps, func(i, j int) bool { return apps[i].Count > apps[j].Count })
	byCount := func(l []map[string]any, k int) []map[string]any {
		sort.Slice(l, func(i, j int) bool { return l[i]["count"].(int64) > l[j]["count"].(int64) })
		if len(l) > k {
			l = l[:k]
		}
		return l
	}
	if len(apps) > 25 {
		apps = apps[:25]
	}
	appOut := []map[string]any{}
	for i := range apps {
		if i < 12 {
			apps[i].Spark = make([]int64, n)
			for bk, v := range appSeries[apps[i].Name] {
				if k := int((bk - t0) / step); k >= 0 && k < n {
					apps[i].Spark[k] = v
				}
			}
		}
		appOut = append(appOut, apps[i].MarshalMap())
	}
	return map[string]any{
		"total": tot.cnt, "blocked": tot.blk, "bytes": tot.byt, "appctrl": tot.actl, "userKnown": tot.usr, "userMapped": tot.mp, "userNPS": tot.nps, "appKey": appKey,
		"generic": tot.gen, "genericNB": tot.genNB, "riskNB": tot.rhNB,
		"step": step, "from": f.From, "to": f.To, "series": series, "apps": appOut,
		"action": byCount(actions, 10), "risk": byCount(risks, 6), "category": byCount(cats, 8), "heat": heat,
		"findings": findings(tot, apps, ai), "origin": t0,
	}, nil
}

func (d *Database) PrevTotals(ctx context.Context, f Filter) (map[string]int64, error) {
	span := f.To.Sub(f.From)
	f.To, f.From = f.From, f.From.Add(-span)
	rel, args := f.where()
	release, err := d.acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	var total, blk, byt, rh int64
	err = d.pool.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE `+blockedExpr+`), coalesce(sum(fl_sent(log_id, fields, sent_bytes)+fl_rcvd(log_id, fields, received_bytes)),0)::bigint,
		count(*) FILTER (WHERE `+riskHighExpr+` AND NOT coalesce(`+blockedExpr+`,false)) FROM fortigate_logs WHERE `+rel, args...).Scan(&total, &blk, &byt, &rh)
	return map[string]int64{"total": total, "blocked": blk, "bytes": byt, "riskNB": rh}, err
}

func pct(a, b int64) int64 {
	if b == 0 {
		return 0
	}
	return (a*100 + b/2) / b
}

// findings turns the counts into plain-language cards: what happened, why it matters, what to do.
func findings(t agg, apps []appRow, ai bool) []map[string]any {
	out := []map[string]any{}
	add := func(sev, title, detail, action string) {
		out = append(out, map[string]any{"sev": sev, "title": title, "detail": detail, "action": action})
	}
	names := func(keep func(appRow) bool) string {
		var l []string
		for _, a := range apps {
			if keep(a) && len(l) < 4 {
				l = append(l, a.Name)
			}
		}
		return strings.Join(l, ", ")
	}
	if t.actl > 0 && !ai {
		if p := pct(t.gen, t.actl); p >= 25 {
			sev := "med"
			if p >= 50 {
				sev = "high"
			}
			add(sev, fmt.Sprintf("%d%% of application-control events were not identified", p),
				fmt.Sprintf("%s events carry only a generic label such as %s. The firewall cannot say what the traffic is.", num(t.gen), names(func(a appRow) bool { return genericName(a.Name) })),
				"Turn on certificate inspection. Look the site up in the web filter logs, then block its category.")
		}
	}
	if t.cnt > 0 {
		if p := pct(t.cnt-t.usr, t.cnt); p >= 20 {
			add("med", fmt.Sprintf("%d%% of events have no username", p), fmt.Sprintf("%s events could not be tied to a person, so user reports are incomplete.", num(t.cnt-t.usr)),
				"Check that NPS user mapping is on (Settings) for wireless users, or map the busiest IP addresses in the User mapping tab.")
		}
	}
	if t.rhNB > 0 {
		add("high", fmt.Sprintf("%s events from elevated or high-risk apps were not blocked", num(t.rhNB)),
			"Seen: "+names(func(a appRow) bool { return a.Risk >= 3 && a.Blocked < a.Count }),
			"Review these apps and block the ones with no business use.")
	}
	if t.dns > 0 {
		add("high", "Public DNS or DNS over HTTPS in use", fmt.Sprintf("%s events. This skips your DNS filter.", num(t.dns)),
			"Allow DNS to the FortiGate only. Deny public DNS servers and DNS over HTTPS.")
	}
	if t.rem > 0 {
		add("med", "Remote access, proxy or peer-to-peer tools in use", fmt.Sprintf("%s events. These can bypass policy or move large files.", num(t.rem)),
			"Block them unless a team has approved them.")
	}
	if t.quic > 0 {
		add("med", "QUIC in use", fmt.Sprintf("%s events. QUIC hides web traffic from inspection.", num(t.quic)),
			"Block QUIC. Browsers then fall back to normal TLS, which can be inspected.")
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i]["sev"] == "high" && out[j]["sev"] != "high" })
	return out
}

// genericRe is genericExpr in Go: the live tag, the stored tag and the dashboards must agree on what "generic" means.
var genericRe = regexp.MustCompile(`(?i)^(ssl|tls|quic|unknown)([_.+ -]|$)`)

func genericName(s string) bool { return genericRe.MatchString(strings.TrimSpace(s)) }

func num(n int64) string {
	s := strconv.FormatInt(n, 10)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}

// Investigate lists, for whatever the filter selects (usually one IP or user), the daily app/destination
// visits and which usernames were seen.
func (d *Database) Investigate(ctx context.Context, f Filter) (map[string]any, error) {
	rel, args := f.where()
	release, err := d.acquire(ctx)
	if err != nil {
		return nil, err
	}
	released := false
	defer func() {
		if !released {
			release()
		}
	}()
	rows, err := d.pool.Query(ctx, `SELECT (event_time::date)::text, coalesce(nullif(application,''),'-'), coalesce(nullif(hostname,''), host(dst_ip), '-'), count(*),
		count(*) FILTER (WHERE `+blockedExpr+`) FROM fortigate_logs WHERE `+rel+` GROUP BY 1,2,3 ORDER BY 1 DESC, 4 DESC LIMIT 400`, args...)
	if err != nil {
		return nil, err
	}
	daily := []map[string]any{}
	for rows.Next() {
		var day, app, host string
		var c, b int64
		if err = rows.Scan(&day, &app, &host, &c, &b); err != nil {
			rows.Close()
			return nil, err
		}
		daily = append(daily, map[string]any{"day": day, "app": app, "host": host, "count": c, "blocked": b})
	}
	rows.Close()
	ids, err := d.pool.Query(ctx, `SELECT coalesce(nullif(user_name,''),'(none)'), count(*), min(event_time), max(event_time), count(*) FILTER (WHERE map_id IS NOT NULL),
		count(*) FILTER (WHERE nps_id IS NOT NULL) FROM fortigate_logs WHERE `+rel+` GROUP BY 1 ORDER BY 2 DESC LIMIT 20`, args...)
	if err != nil {
		return nil, err
	}
	defer ids.Close()
	users := []map[string]any{}
	for ids.Next() {
		var u string
		var c, mc, nc int64
		var first, last time.Time
		if err = ids.Scan(&u, &c, &first, &last, &mc, &nc); err != nil {
			return nil, err
		}
		users = append(users, map[string]any{"user": u, "count": c, "first": first, "last": last, "mapped": mc, "nps": nc})
	}
	if err = ids.Err(); err != nil {
		return nil, err
	}
	ids.Close()
	release()
	released = true
	// who held this IP (or where this user was) according to NPS
	sessions := []map[string]any{}
	if f.Src != "" || f.User != "" {
		ip, user := "", ""
		if normIP(strings.TrimLeft(f.Src, "=!")) != "" {
			ip = f.Src
		} else if f.User != "" {
			user = f.User
		}
		if ip != "" || user != "" {
			if sessions, err = d.SessionsFor(ctx, f.From, f.To, ip, user, 100); err != nil {
				return nil, err
			}
		}
	}
	return map[string]any{"daily": daily, "identities": users, "sessions": sessions}, nil
}

// handlers --------------------------------------------------------------

func (a *App) handleInsights(w http.ResponseWriter, r *http.Request) {
	d := a.dbOrFail(w)
	if d == nil {
		return
	}
	f := parseFilter(r)
	if f.Scope != "" {
		lastAIView.Store(time.Now().Unix())
		lastAIScope.Store(f.Scope)
	}
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	v, err := cached("insights?"+r.URL.RawQuery, 30*time.Second, func() (any, error) { return d.computeInsights(ctx, f) })
	if err != nil {
		queryErr(w, err)
		return
	}
	jsonOut(w, v)
}

// computeInsights answers the AI tabs: from the AI summary whenever it can answer the filter, from the raw logs
// otherwise (or on error). v5.13: up to 12 hours the timeline is read from the raw AI logs (5-minute detail).
func (d *Database) computeInsights(ctx context.Context, f Filter) (any, error) {
	{
		why := ""
		if f.Scope != "" {
			var ok bool
			if ok, why = aiRollupUsable(f); ok {
				res, err := d.aiInsightsRollup(ctx, f)
				if err == nil && f.To.Sub(f.From) <= 12*time.Hour {
					if e := d.aiLiveTimeline(ctx, f, res); e != nil {
						log.Printf("AI timeline: %v", e)
					}
				}
				if err == nil {
					return res, nil
				}
				if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
					// v6.0.1: the summary was too slow (or the page went away): reading the raw logs would be far slower
					// still and piles up on the disk. Say so instead.
					return nil, err
				}
				log.Printf("AI summary: %v (reading the raw logs instead)", err)
				why = "the AI summary could not answer (" + shortErr(err) + ")"
			}
		}
		blocked, review := f, f
		blocked.Outcome = "blocked"
		review.Outcome, review.Extra = "allowed", genericExpr+" OR "+riskHighExpr
		type job struct {
			key, dim string
			f        Filter
			order    string
		}
		jobs := []job{{"users", "user", f, "cnt"}, {"sources", "src_ip", f, "cnt"}, {"hosts", "hostname", f, "cnt"},
			{"mostBlocked", "dest", blocked, "cnt"}, {"needsReview", "application", review, "cnt"}, {"whereData", "dest", f, "byt"}, {"countries", "country", f, "byt"}}
		if f.Scope != "" {
			// data sent to AI tools comes from traffic logs (security events carry no byte counts)
			tf := f
			tf.Scope = "aitraffic"
			jobs = append(jobs, job{"aiUploaders", "user", tf, "snt"}, job{"aiUploadSources", "src_ip", tf, "snt"}, job{"aiToolData", "tool", tf, "snt"},
				job{"blockedUsers", "user", blocked, "cnt"})
			// v5.10: "Where the data went" and "Data by country" also from traffic logs (they showed 0 B for AI events)
			for i := range jobs {
				if jobs[i].key == "whereData" || jobs[i].key == "countries" {
					jobs[i].f = tf
				}
			}
		}
		var mu sync.Mutex
		var wg sync.WaitGroup
		var firstErr error
		out := map[string]any{}
		fail := func(e error) {
			mu.Lock()
			if firstErr == nil {
				firstErr = e
			}
			mu.Unlock()
		}
		run := func(fn func() (string, any, error)) {
			wg.Add(1)
			go func() {
				defer wg.Done()
				k, v, e := fn()
				if e != nil {
					fail(e)
					return
				}
				mu.Lock()
				if m, ok := v.(map[string]any); ok && k == "" {
					for kk, vv := range m {
						out[kk] = vv
					}
				} else {
					out[k] = v
				}
				mu.Unlock()
			}()
		}
		run(func() (string, any, error) { res, e := d.Insights(ctx, f); return "", res, e })
		run(func() (string, any, error) { res, e := d.PrevTotals(ctx, f); return "prev", res, e })
		if f.Scope != "" {
			run(func() (string, any, error) { res, e := d.ToolUsage(ctx, f); return "toolUsage", res, e })
			run(func() (string, any, error) {
				rel, args := f.where()
				res, e := d.scanUserTools(ctx, userToolsRawSQL(rel), args)
				return "userTools", res, e
			})
		}
		for _, j := range jobs {
			j := j
			run(func() (string, any, error) {
				rows, groups, e := d.TopOrder(ctx, j.dim, j.f, 8, j.order)
				if e != nil {
					return "", nil, e
				}
				return "", map[string]any{j.key: rows, j.key + "Groups": groups}, nil
			})
		}
		wg.Wait()
		out["mode"], out["modeNote"] = "raw", why
		return out, firstErr
	}
}

func (a *App) handleInvestigate(w http.ResponseWriter, r *http.Request) {
	d := a.dbOrFail(w)
	if d == nil {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	v, err := d.Investigate(ctx, parseFilter(r))
	if err != nil {
		queryErr(w, err)
		return
	}
	jsonOut(w, v)
}

// ToolUsage: per AI tool, how many people and devices used it, and whether it is new (first ever seen in this period).
func (d *Database) ToolUsage(ctx context.Context, f Filter) ([]map[string]any, error) {
	rel, args := f.where()
	release, err := d.acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	rows, err := d.pool.Query(ctx, `SELECT ai_tool, count(*), count(*) FILTER (WHERE `+blockedExpr+`), count(DISTINCT nullif(user_name,'')), count(DISTINCT src_ip),
		min(event_time), max(event_time) FROM fortigate_logs WHERE `+rel+` AND ai_tool IS NOT NULL GROUP BY 1 ORDER BY 2 DESC LIMIT 30`, args...)
	if err != nil {
		return nil, err
	}
	out := []map[string]any{}
	names := []string{}
	for rows.Next() {
		var t string
		var c, b, u, sIP int64
		var first, last time.Time
		if err = rows.Scan(&t, &c, &b, &u, &sIP, &first, &last); err != nil {
			rows.Close()
			return nil, err
		}
		names = append(names, t)
		out = append(out, map[string]any{"name": t, "count": c, "blocked": b, "users": u, "sources": sIP, "first": first, "last": last})
	}
	rows.Close()
	if err = rows.Err(); err != nil || len(names) == 0 {
		return out, err
	}
	// v5.10: "first ever seen" comes from the summaries. It used to be min(event_time) over every stored AI log,
	// which on a compressed TimescaleDB table decompressed the whole retention period on each refresh.
	ever, err := d.firstSeenTools(ctx, names)
	if err != nil {
		return out, nil
	}
	for _, o := range out {
		if e, ok := ever[o["name"].(string)]; ok && e.Before(o["first"].(time.Time)) {
			o["firstEver"] = e
		} else {
			o["firstEver"] = o["first"]
		}
		o["isNew"] = !o["firstEver"].(time.Time).Before(f.From)
	}
	return out, nil
}
