package main

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

// v5.16: AI usage report. Every AI tool seen in the period (not a top 5 or 10), who uses it, departments, data
// uploaded, blocked attempts, new tools, risk, the trend against the previous period and plain recommendations.
// Built from the AI summary (rollup_ai), so a 30-day report takes seconds. Printable like the executive report.

type aiTool struct {
	Name      string     `json:"name"`
	Events    int64      `json:"events"`
	Blocked   int64      `json:"blocked"`
	Users     int64      `json:"users"`
	Devices   int64      `json:"devices"`
	Sent      int64      `json:"sent"`
	Recv      int64      `json:"recv"`
	Risk      int64      `json:"risk"`
	PrevEv    *int64     `json:"prev_events,omitempty"`
	PrevSent  *int64     `json:"prev_sent,omitempty"`
	FirstEver *time.Time `json:"first_ever,omitempty"`
	New       bool       `json:"new"`
	Depts     int        `json:"depts"`
	TopUsers  []aiUser   `json:"top_users"`
	Unknown   int64      `json:"unknown_events"`
}

type aiUser struct {
	User    string   `json:"user"`
	Display string   `json:"display,omitempty"`
	Dept    string   `json:"dept,omitempty"`
	Events  int64    `json:"events"`
	Blocked int64    `json:"blocked"`
	Sent    int64    `json:"sent"`
	Tools   []string `json:"tools,omitempty"`
}

func (a *App) handleAIReport(w http.ResponseWriter, r *http.Request) {
	d := a.dbOrFail(w)
	if d == nil {
		return
	}
	p, err := execPeriodFor(r)
	if err != nil {
		reportErr(w, err)
		return
	}
	if !aiCovers(hourStart(p.From)) {
		roll.mu.Lock()
		c := roll.ai
		roll.mu.Unlock()
		jsonError(w, http.StatusBadRequest, "the AI summary is still being built back to "+c.Format("2 Jan 2006 15:04")+"; choose a period that starts after that")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
	defer cancel()
	// v5.17: the executive summary exclusions apply here too (toggle on the report)
	ex := exclCur.Load()
	if r.URL.Query().Get("excl") == "0" || !ex.active() {
		ex = &execExcl{}
	}
	key := fmt.Sprintf("aireport?%s|%d|%d|%s", p.Key, p.From.Unix()/600, p.To.Unix()/600, ex.sig)
	v, err := cached(key, 10*time.Minute, func() (any, error) { return a.buildAIReport(ctx, d, p, ex) })
	if err != nil {
		reportErr(w, err)
		return
	}
	a.audit(r, "ai_report", p.Key)
	jsonOut(w, v)
}

func (a *App) buildAIReport(ctx context.Context, d *Database, p execPeriod, ex *execExcl) (map[string]any, error) {
	start := time.Now()
	if ex == nil {
		ex = &execExcl{}
	}
	xc := aiExclSQL(ex)
	from, to := hourStart(p.From), p.To
	pfrom, pto := hourStart(p.PFrom), hourStart(p.From)
	th := a.store.Get().Exec
	out := map[string]any{"org": firstNonEmpty(th.OrgName, "Network"), "generated": time.Now(),
		"period": map[string]any{"key": p.Key, "label": p.Label, "from": p.From, "to": p.To, "prev_from": p.PFrom, "prev_to": p.PTo}}
	// totals, now and before
	tot := func(a, b time.Time) (map[string]int64, error) {
		var ev, blk, users, devs, sent, tools int64
		err := d.pool.QueryRow(ctx, `SELECT coalesce(sum(cnt),0)::bigint, coalesce(sum(blk),0)::bigint, count(DISTINCT nullif(usr,'')),
			count(DISTINCT nullif(src,'')), coalesce(sum(snt) FILTER (WHERE log_type = 'traffic'),0)::bigint, count(DISTINCT tool)
			FROM rollup_ai WHERE hour >= $1 AND hour < $2`+xc+``, a, b).Scan(&ev, &blk, &users, &devs, &sent, &tools)
		return map[string]int64{"events": ev, "blocked": blk, "users": users, "devices": devs, "sent": sent, "tools": tools}, err
	}
	cur, err := tot(from, to)
	if err != nil {
		return nil, err
	}
	out["cur"] = cur
	if aiCovers(pfrom) {
		if prev, err := tot(pfrom, pto); err == nil && prev["events"] > 0 {
			out["prev"] = prev
		}
	}
	// every tool
	rows, err := d.pool.Query(ctx, `SELECT tool, sum(cnt)::bigint, sum(blk)::bigint, count(DISTINCT nullif(usr,'')), count(DISTINCT nullif(src,'')),
		coalesce(sum(snt) FILTER (WHERE log_type = 'traffic'),0)::bigint, coalesce(sum(byt - snt) FILTER (WHERE log_type = 'traffic'),0)::bigint,
		coalesce(max(`+aiRiskRank+`),0)::bigint, coalesce(sum(cnt) FILTER (WHERE usr = ''),0)::bigint
		FROM rollup_ai WHERE hour >= $1 AND hour < $2`+xc+` GROUP BY 1 ORDER BY 2 DESC`, from, to)
	if err != nil {
		return nil, err
	}
	tools := []*aiTool{}
	byName := map[string]*aiTool{}
	for rows.Next() {
		t := &aiTool{TopUsers: []aiUser{}}
		if err = rows.Scan(&t.Name, &t.Events, &t.Blocked, &t.Users, &t.Devices, &t.Sent, &t.Recv, &t.Risk, &t.Unknown); err != nil {
			rows.Close()
			return nil, err
		}
		tools = append(tools, t)
		byName[t.Name] = t
	}
	rows.Close()
	names := make([]string, 0, len(tools))
	for _, t := range tools {
		names = append(names, t.Name)
	}
	if _, ok := out["prev"]; ok {
		if pr, err := d.pool.Query(ctx, `SELECT tool, sum(cnt)::bigint, coalesce(sum(snt) FILTER (WHERE log_type = 'traffic'),0)::bigint
			FROM rollup_ai WHERE hour >= $1 AND hour < $2`+xc+` GROUP BY 1`, pfrom, pto); err == nil {
			for pr.Next() {
				var n string
				var e, s int64
				if pr.Scan(&n, &e, &s) == nil {
					if t := byName[n]; t != nil {
						ee, ss := e, s
						t.PrevEv, t.PrevSent = &ee, &ss
					}
				}
			}
			pr.Close()
		}
		for _, t := range tools {
			if t.PrevEv == nil {
				z := int64(0)
				t.PrevEv, t.PrevSent = &z, &z
			}
		}
	}
	if len(names) > 0 {
		if ever, err := d.firstSeenTools(ctx, names); err == nil {
			_, comparable := out["prev"]
			for n, e := range ever {
				if t := byName[n]; t != nil {
					ee := e
					t.FirstEver = &ee
					t.New = comparable && !e.Before(from)
				}
			}
		}
	}
	// people x tools (every pair): people list, departments and each tool's busiest users
	ur, err := d.pool.Query(ctx, `SELECT usr, tool, sum(cnt)::bigint, sum(blk)::bigint, coalesce(sum(snt) FILTER (WHERE log_type = 'traffic'),0)::bigint
		FROM rollup_ai WHERE hour >= $1 AND hour < $2`+xc+` AND usr <> '' GROUP BY 1, 2`, from, to)
	if err != nil {
		return nil, err
	}
	people := map[string]*aiUser{}
	type pt struct {
		u, t    string
		e, b, s int64
	}
	var pairs []pt
	for ur.Next() {
		var x pt
		if ur.Scan(&x.u, &x.t, &x.e, &x.b, &x.s) == nil {
			pairs = append(pairs, x)
		}
	}
	ur.Close()
	deptTools := map[string]map[string]bool{}
	type dagg struct {
		users         map[string]bool
		ev, blk, sent int64
	}
	depts := map[string]*dagg{}
	toolDepts := map[string]map[string]bool{}
	for _, x := range pairs {
		cu := canonUser(x.u)
		if cu == "" {
			cu = x.u
		}
		pu := people[cu]
		if pu == nil {
			pu = &aiUser{User: cu}
			if s := staffOf(cu); s != nil {
				pu.Display, pu.Dept = s.Display, s.Dept
			}
			people[cu] = pu
		}
		pu.Events += x.e
		pu.Blocked += x.b
		pu.Sent += x.s
		pu.Tools = append(pu.Tools, x.t)
		dn := firstNonEmpty(pu.Dept, "(no department)")
		da := depts[dn]
		if da == nil {
			da = &dagg{users: map[string]bool{}}
			depts[dn] = da
		}
		da.users[cu] = true
		da.ev += x.e
		da.blk += x.b
		da.sent += x.s
		if deptTools[dn] == nil {
			deptTools[dn] = map[string]bool{}
		}
		deptTools[dn][x.t] = true
		if toolDepts[x.t] == nil {
			toolDepts[x.t] = map[string]bool{}
		}
		toolDepts[x.t][dn] = true
		if t := byName[x.t]; t != nil {
			t.TopUsers = append(t.TopUsers, aiUser{User: cu, Display: pu.Display, Dept: pu.Dept, Events: x.e, Blocked: x.b, Sent: x.s})
		}
	}
	for _, t := range tools {
		sort.Slice(t.TopUsers, func(i, j int) bool { return t.TopUsers[i].Events > t.TopUsers[j].Events })
		if len(t.TopUsers) > 5 {
			t.TopUsers = t.TopUsers[:5]
		}
		t.Depts = len(toolDepts[t.Name])
	}
	pl := make([]*aiUser, 0, len(people))
	for _, u := range people {
		sort.Strings(u.Tools)
		pl = append(pl, u)
	}
	sort.Slice(pl, func(i, j int) bool { return pl[i].Events > pl[j].Events })
	byUpload := append([]*aiUser{}, pl...)
	sort.Slice(byUpload, func(i, j int) bool { return byUpload[i].Sent > byUpload[j].Sent })
	byBlocked := []*aiUser{}
	for _, u := range pl {
		if u.Blocked > 0 {
			byBlocked = append(byBlocked, u)
		}
	}
	sort.Slice(byBlocked, func(i, j int) bool { return byBlocked[i].Blocked > byBlocked[j].Blocked })
	cut := func(l []*aiUser, n int) []*aiUser {
		if len(l) > n {
			return l[:n]
		}
		return l
	}
	dl := []map[string]any{}
	for n, x := range depts {
		tl := []string{}
		for t := range deptTools[n] {
			tl = append(tl, t)
		}
		sort.Strings(tl)
		dl = append(dl, map[string]any{"name": n, "users": len(x.users), "events": x.ev, "blocked": x.blk, "sent": x.sent, "tools": tl})
	}
	sort.Slice(dl, func(i, j int) bool { return dl[i]["events"].(int64) > dl[j]["events"].(int64) })
	out["tools"], out["people"], out["uploaders"], out["blocked_people"], out["departments"] = tools, cut(pl, 60), cut(byUpload, 15), cut(byBlocked, 15), dl
	out["people_total"] = len(pl)
	out["staff_list"] = directoryLoaded()
	// per day and tool
	unit := "day"
	if to.Sub(from) <= 48*time.Hour {
		unit = "hour"
	}
	sr, err := d.pool.Query(ctx, `SELECT date_trunc($3::text, hour, $4::text), tool, sum(cnt)::bigint, coalesce(sum(snt) FILTER (WHERE log_type = 'traffic'),0)::bigint
		FROM rollup_ai WHERE hour >= $1 AND hour < $2`+xc+` GROUP BY 1, 2 ORDER BY 1`, from, to, unit, reportTZ())
	if err == nil {
		series := []map[string]any{}
		for sr.Next() {
			var t time.Time
			var n string
			var c, s int64
			if sr.Scan(&t, &n, &c, &s) == nil {
				series = append(series, map[string]any{"t": t, "tool": n, "events": c, "sent": s})
			}
		}
		sr.Close()
		out["series"], out["series_unit"] = series, unit
	}
	out["recommendations"] = aiRecommendations(tools, byUpload, cur)
	out["exclusions"] = map[string]any{"active": exclCur.Load().active(), "applied": ex.active(), "rules": ex.describe()}
	out["took_ms"] = time.Since(start).Milliseconds()
	return out, nil
}

func aiRecommendations(tools []*aiTool, uploaders []*aiUser, cur map[string]int64) []map[string]string {
	out := []map[string]string{}
	add := func(sev, title, detail, action string) {
		out = append(out, map[string]string{"status": sev, "title": title, "detail": detail, "action": action})
	}
	var nw, risky, tried []string
	for _, t := range tools {
		if t.New && t.Users > 0 {
			nw = append(nw, t.Name)
		}
		if t.Risk >= 4 && t.Blocked < t.Events {
			risky = append(risky, t.Name)
		}
		if t.Blocked > 0 && t.Users >= 3 && t.Blocked*2 >= t.Events {
			tried = append(tried, fmt.Sprintf("%s (%d people)", t.Name, t.Users))
		}
	}
	if len(nw) > 0 {
		add("amber", fmt.Sprintf("%d AI tool%s used for the first time", len(nw), plural(len(nw))), "New this period: "+joinList(nw, 8)+".",
			"Check each against the AI policy: approve it, or block it in the web filter / application control.")
	}
	if len(risky) > 0 {
		add("red", "High-risk AI applications are allowed", "Allowed although FortiGuard rates them high or critical risk: "+joinList(risky, 8)+".",
			"Block them unless a business owner has approved them.")
	}
	var big []string
	for _, u := range uploaders {
		if u.Sent >= 100<<20 {
			big = append(big, fmt.Sprintf("%s (%s)", firstNonEmpty(u.Display, u.User), humanBytes(u.Sent)))
		}
	}
	if len(big) > 0 {
		add("amber", "Large uploads to AI tools", "More than 100 MB uploaded by: "+joinList(big, 6)+". Large uploads usually mean documents or data pasted or attached.",
			"Confirm with these people what was shared, and remind staff which tools are approved for company data.")
	}
	if len(tried) > 0 {
		add("amber", "People keep trying blocked AI tools", "Mostly blocked but repeatedly tried: "+strings.Join(tried, ", ")+".",
			"Offer an approved alternative; repeated attempts show a real need.")
	}
	if cur["events"] > 0 {
		var unknown int64
		for _, t := range tools {
			unknown += t.Unknown
		}
		if p := pct(unknown, cur["events"]); p >= 20 {
			add("amber", fmt.Sprintf("%d%% of AI use has no username", p), "That activity can only be traced to a device.",
				"Assign the busiest devices to people (Devices & people), or extend FSSO / NPS user identification.")
		}
	}
	return out
}

// aiExclSQL: " AND NOT (...)" over rollup_ai for the executive summary exclusions (v5.17). Values are validated by
// parseExcl (prefixes, host patterns [a-z0-9*._-], subtypes) and quoted; usernames are quoted.
func aiExclSQL(e *execExcl) string {
	if !e.active() {
		return ""
	}
	lit := func(l []string) string {
		q := make([]string, len(l))
		for i, s := range l {
			q[i] = sqlStr(s)
		}
		return "ARRAY[" + strings.Join(q, ",") + "]::text[]"
	}
	const ipRe = `'^[0-9a-fA-F:.]+$'`
	var parts []string
	if len(e.Src) > 0 {
		parts = append(parts, "(src ~ "+ipRe+" AND src::inet <<= ANY("+lit(prefixStrings(e.Src))+"::inet[]))")
	}
	if len(e.Dst) > 0 {
		parts = append(parts, "(dest ~ "+ipRe+" AND dest::inet <<= ANY("+lit(prefixStrings(e.Dst))+"::inet[]))")
	}
	if len(e.Hosts) > 0 {
		likes := make([]string, len(e.Hosts))
		for i, h := range e.Hosts {
			likes[i] = likePattern(h)
		}
		parts = append(parts, "lower(dest) LIKE ANY("+lit(likes)+")")
	}
	if len(e.Users) > 0 {
		parts = append(parts, "lower(usr) = ANY("+lit(e.Users)+")")
	}
	if len(e.Subtypes) > 0 {
		parts = append(parts, "sub = ANY("+lit(e.Subtypes)+")")
	}
	if len(parts) == 0 {
		return ""
	}
	return " AND NOT coalesce(" + strings.Join(parts, " OR ") + ", false)"
}
