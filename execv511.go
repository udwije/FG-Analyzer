package main

import (
	"context"
	"fmt"
	"log"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"time"
)

// v5.11: executive summary fixes found on the first production reports.
//
//   - Sign-ins and configuration changes were read from the raw event logs (7-30 days, mostly compressed chunks)
//     and timed out, so the report showed "–" everywhere. They now come from a small hourly summary (rollup_evt).
//   - A collector / database outage made every firewall look "silent" for the same hours. Outages are now detected
//     (no firewall at all sent logs) and reported once; firewall availability only counts the time LogSikka was
//     collecting.
//   - Availability and the "firewalls sending logs" check only consider the firewalls in Settings > Firewalls (when
//     the list is filled) and never the ones listed under "Ignore in availability checks" (renamed / retired devices).
//   - Web categories: FortiGuard placeholders (unscanned, unknown, unrated) and application categories (Network.Service,
//     General.Interest ...) no longer crowd out the real website categories.
//   - Destinations and countries: internal addresses, short host names and your own domains are left out of
//     "Most used destinations"; the private-address pseudo-country "Reserved" is left out of the countries.
//   - Devices are counted on internal addresses only; internet hosts that reach a published service are not
//     "your devices".
//   - Unusual devices: the user and main blocked destination come from the newest logs of each device (index lookup)
//     instead of an aggregate over a whole day, which timed out for devices with hundreds of thousands of blocks.

// ---------------------------------------------------------------- event summary (sign-ins, configuration changes)

const evtFailed = `(fields->>'logdesc' ILIKE '%login fail%' OR fields->>'logdesc' ILIKE '%authentication fail%'
	OR (action ILIKE '%login%' AND fields->>'status' IN ('failed','failure','fail')) OR (subtype = 'vpn' AND (fields->>'status' ILIKE 'fail%' OR action ILIKE '%fail%')))`
const evtSuccess = `(fields->>'logdesc' ILIKE '%login success%' OR (action ILIKE '%login%' AND fields->>'status' = 'success'))`
const evtCfg = `(fields->>'cfgpath' IS NOT NULL OR fields->>'logdesc' ILIKE '%configured%')`

const evtRollupInsert = `INSERT INTO rollup_evt (hour, fw, kind, src, usr, via, tgt, cnt, last_at)
	SELECT $1::timestamptz, fw, kind, src, usr, via, tgt, count(*), max(event_time) FROM (
		SELECT event_time, ` + fwExpr + ` AS fw,
			CASE WHEN ` + evtFailed + ` THEN CASE WHEN subtype = 'vpn' THEN 'failed_vpn' ELSE 'failed_admin' END
			     WHEN ` + evtSuccess + ` THEN 'success' WHEN ` + evtCfg + ` THEN 'cfg' END AS kind,
			left(coalesce(host(src_ip), nullif(fields->>'remip',''), nullif(fields->>'ui',''), '?'), 200) AS src,
			left(coalesce(nullif(fields->>'user',''), nullif(user_name,''), '?'), 200) AS usr,
			left(` + viaSQL + `, 40) AS via, left(` + tgtSQL + `, 100) AS tgt
		FROM fortigate_logs WHERE log_type = 'event' AND event_time >= $1 AND event_time < $2) x
	WHERE kind IS NOT NULL GROUP BY 2, 3, 4, 5, 6, 7`

func (d *Database) rollupEvtHour(ctx context.Context, h time.Time) error {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `DELETE FROM rollup_evt WHERE hour = $1`, h); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, evtRollupInsert, h, h.Add(time.Hour)); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// rollupEvtBackfill builds the event summary for hours summarised before v5.11, newest first.
func (d *Database) rollupEvtBackfill(ctx context.Context, n int) error {
	roll.mu.Lock()
	cur, done := roll.evt, roll.evtOK
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
		if err := d.rollupEvtHour(ctx, h); err != nil {
			return fmt.Errorf("sign-in summary for %s: %w", h.Format("2006-01-02 15:04"), err)
		}
		if err := d.setState(ctx, "evt", h); err != nil {
			return err
		}
		cur = h
		roll.mu.Lock()
		roll.evt = h
		roll.mu.Unlock()
	}
	if !cur.After(floor) {
		roll.mu.Lock()
		if !roll.evtOK {
			log.Printf("rollup: sign-in summaries are complete back to %s", cur.Format("2006-01-02 15:04"))
		}
		roll.evtOK = true
		roll.mu.Unlock()
	}
	return nil
}

// backfillFloor: the oldest hour a background fill has to reach (oldest summarised data, at most 31 days back).
func (d *Database) backfillFloor(ctx context.Context) (time.Time, error) {
	var oldest *time.Time
	if err := d.pool.QueryRow(ctx, `SELECT min(bucket) FROM rollup_5m`).Scan(&oldest); err != nil {
		return time.Time{}, err
	}
	floor := hourStart(time.Now().AddDate(0, 0, -rollupBackfillDays))
	if oldest != nil && hourStart(*oldest).After(floor) {
		floor = hourStart(*oldest)
	}
	return floor, nil
}

func evtCovers(h time.Time) bool {
	roll.mu.Lock()
	defer roll.mu.Unlock()
	return roll.known && (roll.evtOK || !h.Before(roll.evt))
}

// execSignins: from the event summary when it covers the period, otherwise from the raw logs (older behaviour).
func (d *Database) execSignins(ctx context.Context, p execPeriod) (map[string]any, error) {
	from := hourStart(p.From)
	if !evtCovers(from) {
		return d.execSigninsRaw(ctx, p)
	}
	out := map[string]any{}
	var fa, fv, ok, cfg int64
	if err := d.pool.QueryRow(ctx, `SELECT coalesce(sum(cnt) FILTER (WHERE kind='failed_admin'),0)::bigint, coalesce(sum(cnt) FILTER (WHERE kind='failed_vpn'),0)::bigint,
		coalesce(sum(cnt) FILTER (WHERE kind='success'),0)::bigint, coalesce(sum(cnt) FILTER (WHERE kind='cfg'),0)::bigint
		FROM rollup_evt WHERE hour >= $1 AND hour < $2`, from, p.To).Scan(&fa, &fv, &ok, &cfg); err != nil {
		return nil, err
	}
	out["failed"], out["failed_admin"], out["failed_vpn"], out["success"], out["config_changes"] = fa+fv, fa, fv, ok, cfg
	if evtCovers(hourStart(p.PFrom)) {
		var prev int64
		if err := d.pool.QueryRow(ctx, `SELECT coalesce(sum(cnt),0)::bigint FROM rollup_evt WHERE kind LIKE 'failed%' AND hour >= $1 AND hour < $2`,
			hourStart(p.PFrom), from).Scan(&prev); err == nil {
			out["prev_failed"] = prev
		}
	}
	rows, err := d.pool.Query(ctx, `SELECT src, usr, kind, fw, sum(cnt)::bigint, max(last_at) FROM rollup_evt
		WHERE kind LIKE 'failed%' AND hour >= $1 AND hour < $2 GROUP BY 1, 2, 3, 4 ORDER BY 5 DESC LIMIT 15`, from, p.To)
	if err != nil {
		return out, err
	}
	top := []map[string]any{}
	for rows.Next() {
		var src, usr, kind, fw string
		var n int64
		var last time.Time
		if err = rows.Scan(&src, &usr, &kind, &fw, &n, &last); err != nil {
			rows.Close()
			return out, err
		}
		k := "Admin"
		if kind == "failed_vpn" {
			k = "VPN"
		}
		top = append(top, map[string]any{"source": src, "user": usr, "kind": k, "fw": fw, "count": n, "last": last, "internet": isPublicIP(src)})
	}
	rows.Close()
	var inet int64
	if err = d.pool.QueryRow(ctx, `SELECT coalesce(sum(cnt),0)::bigint FROM rollup_evt WHERE kind LIKE 'failed%' AND hour >= $1 AND hour < $2
		AND CASE WHEN src ~ '^[0-9a-fA-F:.]+$' THEN NOT (src::inet <<= ANY(`+localNetsSQL()+`)) ELSE false END`, from, p.To).Scan(&inet); err != nil {
		return out, err
	}
	out["top"], out["from_internet"] = top, inet
	cr, err := d.pool.Query(ctx, `SELECT usr, fw, sum(cnt)::bigint, max(last_at) FROM rollup_evt WHERE kind = 'cfg' AND hour >= $1 AND hour < $2
		GROUP BY 1, 2 ORDER BY 3 DESC LIMIT 10`, from, p.To)
	if err != nil {
		return out, err
	}
	defer cr.Close()
	changes := []map[string]any{}
	for cr.Next() {
		var usr, fw string
		var n int64
		var last time.Time
		if err = cr.Scan(&usr, &fw, &n, &last); err != nil {
			return out, err
		}
		changes = append(changes, map[string]any{"user": usr, "fw": fw, "count": n, "last": last})
	}
	out["changes"] = changes
	return out, cr.Err()
}

// ---------------------------------------------------------------- web categories

// placeholderCat: FortiGuard values that are not a category of website.
var placeholderCat = regexp.MustCompile(`(?i)^(unscanned|unknown|unrated|not rated|n/?a|none|-|\(none\))$`)

// appCategory: FortiGuard application-control categories (Network.Service, General.Interest, Storage.Backup ...).
var appCategory = regexp.MustCompile(`^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$`)

func (d *Database) execCategories(ctx context.Context, from, to time.Time) ([]map[string]any, []map[string]any, string, error) {
	cats, risk, note, err := d.execCategoriesRaw(ctx, from, to)
	if err != nil {
		return cats, risk, note, err
	}
	merged := map[string]map[string]any{}
	order := []string{}
	for _, c := range cats {
		n := strings.TrimSpace(fmt.Sprint(c["name"]))
		if n == "" || placeholderCat.MatchString(n) || appCategory.MatchString(n) {
			continue
		}
		k := strings.ToLower(n)
		if m, ok := merged[k]; ok {
			m["count"] = m["count"].(int64) + c["count"].(int64)
			m["blocked"] = m["blocked"].(int64) + c["blocked"].(int64)
			continue
		}
		merged[k] = map[string]any{"name": n, "count": c["count"], "blocked": c["blocked"]}
		order = append(order, k)
	}
	out := []map[string]any{}
	for _, k := range order {
		out = append(out, merged[k])
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i]["count"].(int64) > out[j]["count"].(int64) })
	if len(out) > 12 {
		out = out[:12]
	}
	return out, risk, note, nil
}

// ---------------------------------------------------------------- firewall availability and collector outages

// execAvailability: per firewall, the share of the time LogSikka was collecting during which the firewall sent logs,
// its longest silence (collector outages do not count), and how long ago it last sent. The second result describes
// the collector itself: the share of the period with logs from any firewall and the longest outage.
func (d *Database) execAvailability(ctx context.Context, from, to time.Time, cfg Config) ([]map[string]any, map[string]any, error) {
	now := time.Now()
	end := to
	if end.After(now) {
		end = now
	}
	endB := end.Unix() / 300 * 300 // the bucket still filling is not counted
	var oldest *time.Time
	if err := d.pool.QueryRow(ctx, `SELECT min(bucket) FROM rollup_5m`).Scan(&oldest); err != nil {
		return nil, nil, err
	}
	startB := from.Unix() / 300 * 300
	if oldest != nil && oldest.Unix() > startB {
		startB = oldest.Unix() / 300 * 300
	}
	rows, err := d.pool.Query(ctx, `SELECT fw, extract(epoch FROM bucket)::bigint, sum(cnt)::bigint FROM rollup_5m
		WHERE bucket >= $1 AND bucket < $2 GROUP BY 1, 2 ORDER BY 1, 2`, time.Unix(startB, 0), time.Unix(endB, 0))
	if err != nil {
		return nil, nil, err
	}
	type fwData struct {
		buckets map[int64]bool
		events  int64
		first   int64
		last    int64
	}
	fws := map[string]*fwData{}
	global := map[int64]bool{}
	for rows.Next() {
		var fw string
		var b, c int64
		if err = rows.Scan(&fw, &b, &c); err != nil {
			rows.Close()
			return nil, nil, err
		}
		f := fws[fw]
		if f == nil {
			f = &fwData{buckets: map[int64]bool{}, first: b}
			fws[fw] = f
		}
		f.buckets[b], f.events, f.last = true, f.events+c, b
		global[b] = true
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return nil, nil, err
	}
	g := make([]int64, 0, len(global))
	for b := range global {
		g = append(g, b)
	}
	sort.Slice(g, func(i, j int) bool { return g[i] < g[j] })

	slots := (endB - startB) / 300
	col := map[string]any{"slots": slots, "covered": len(g)}
	var longest, longestAt, prev int64 = 0, 0, startB - 300
	for _, b := range append(append([]int64{}, g...), endB) {
		if gap := b - prev - 300; gap > longest {
			longest, longestAt = gap, prev+300
		}
		prev = b
	}
	if slots > 0 {
		col["coverage"] = float64(int64(len(g))*1000/slots) / 10
		col["missing_seconds"] = (slots - int64(len(g))) * 300
		col["longest_gap"] = longest
		if longest > 0 {
			col["longest_gap_at"] = time.Unix(longestAt, 0)
		}
	}

	ignored := map[string]bool{}
	for _, n := range cfg.Exec.IgnoreFirewalls {
		ignored[strings.ToLower(strings.TrimSpace(n))] = true
	}
	configured := map[string]bool{}
	for _, f := range cfg.Firewalls {
		configured[strings.ToLower(f.Name)], configured[strings.ToLower(f.IP)] = true, true
	}
	monitored := func(name string) bool {
		n := strings.ToLower(name)
		return !ignored[n] && (len(configured) == 0 || configured[n])
	}
	out := []map[string]any{}
	for name, f := range fws {
		if ignored[strings.ToLower(name)] {
			continue
		}
		n, run, maxRun := 0, int64(0), int64(0)
		for _, b := range g {
			if f.buckets[b] {
				n++
				run = 0
			} else if run++; run > maxRun {
				maxRun = run
			}
		}
		avail := 0.0
		if len(g) > 0 {
			avail = float64(int64(n)*1000/int64(len(g))) / 10
		}
		quiet := now.Unix() - (f.last + 300)
		if quiet < 0 {
			quiet = 0
		}
		out = append(out, map[string]any{"name": name, "events": f.events, "availability": avail, "longest_gap": maxRun * 300, "quiet": quiet,
			"first": time.Unix(f.first, 0), "last": time.Unix(f.last+300, 0), "monitored": monitored(name)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i]["events"].(int64) > out[j]["events"].(int64) })
	seen := map[string]bool{}
	for name := range fws {
		seen[strings.ToLower(name)] = true
	}
	span := endB - startB
	for _, f := range cfg.Firewalls {
		if !seen[strings.ToLower(f.Name)] && !seen[strings.ToLower(f.IP)] && !ignored[strings.ToLower(f.Name)] {
			out = append(out, map[string]any{"name": f.Name, "events": int64(0), "availability": 0.0, "longest_gap": span, "quiet": span, "missing": true, "monitored": true})
		}
	}
	return out, col, nil
}

// ---------------------------------------------------------------- unusual devices

// execDeviceInfo: for each device, the newest username and the destination it most often tried in its newest blocked
// logs (index src_ip + event_time, at most 2,000 rows per device), from the last 24 hours of the period.
func (d *Database) execDeviceInfo(ctx context.Context, ips []string, to time.Time) (map[string]string, map[string]string, error) {
	c2, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	if len(ips) > 10 {
		ips = ips[:10]
	}
	users, dests := map[string]string{}, map[string]string{}
	rows, err := d.pool.Query(c2, `SELECT ip,
		(SELECT user_name FROM fortigate_logs WHERE src_ip = ip::inet AND event_time >= $2 AND event_time < $3 AND coalesce(user_name,'') <> ''
			ORDER BY event_time DESC LIMIT 1),
		(SELECT d FROM (SELECT coalesce(nullif(hostname,''), host(dst_ip)) || coalesce(':' || nullif(dst_port,0)::text, '') AS d FROM fortigate_logs
			WHERE src_ip = ip::inet AND event_time >= $2 AND event_time < $3 AND `+blockedExpr+` ORDER BY event_time DESC LIMIT 2000) s
			WHERE d IS NOT NULL GROUP BY d ORDER BY count(*) DESC LIMIT 1)
		FROM unnest($1::text[]) AS ip`, ips, to.Add(-24*time.Hour), to)
	if err != nil {
		return users, dests, err
	}
	defer rows.Close()
	for rows.Next() {
		var ip string
		var u, dst *string
		if err = rows.Scan(&ip, &u, &dst); err != nil {
			return users, dests, err
		}
		if u != nil {
			users[ip] = *u
		}
		if dst != nil {
			dests[ip] = *dst
		}
	}
	return users, dests, rows.Err()
}

// ---------------------------------------------------------------- top lists for management

// internalDest: a destination that is part of your own network (internal address, short host name, own domain).
func internalDest(name string, domains []string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" {
		return false
	}
	if _, err := netip.ParseAddr(n); err == nil {
		return isLocalIP(n)
	}
	if !strings.Contains(n, ".") {
		return true // NetBIOS / internal short names (CKI-HO-MOBILE)
	}
	for _, d := range domains {
		d = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(d)), "*.")
		if d != "" && (n == d || strings.HasSuffix(n, "."+d)) {
			return true
		}
	}
	return false
}

// execTopLists re-reads the lists whose values must be filtered: exclusions (sources, destinations, users),
// internal destinations and the private-address pseudo-country "Reserved". The management lists of users, devices
// and destinations by data use internet traffic only (v5.12). It reads 80 values and keeps 10.
func (d *Database) execTopLists(ctx context.Context, out *ExecSummary, p execPeriod, f Filter, ex *execExcl, th ExecConfig) error {
	fromH := hourStart(p.From)
	hideInt := !th.ShowInternalDests
	var srcDrop, userDrop, destDrop func(string) bool
	keep := func(string) bool { return false }
	srcDrop, userDrop, destDrop = keep, keep, keep
	if ex.active() {
		if len(ex.Src) > 0 {
			srcDrop = ex.matchSrc
		}
		if len(ex.Users) > 0 {
			userDrop = ex.matchUser
		}
	}
	destDrop = func(n string) bool {
		return (ex.active() && len(ex.Dst)+len(ex.Hosts) > 0 && ex.matchDest(n)) || (hideInt && internalDest(n, th.InternalDomains))
	}
	inet := inetCovers(fromH)
	pick := func(inetDim, allDim string) string {
		if inet {
			return inetDim
		}
		return allDim
	}
	type rl struct {
		key, dim, order string
		blocked         bool
		drop            func(string) bool
	}
	lists := []rl{
		{"countries", "country", "byt", false, func(n string) bool { return strings.EqualFold(n, "Reserved") }},
		{"sources", "src_ip", "cnt", false, srcDrop}, {"blockedSources", "src_ip", "cnt", true, srcDrop},
		{"uploaders", pick("inet_src", "src_ip"), "snt", false, srcDrop},
		{"devicesData", pick("inet_src", "src_ip"), "byt", false, srcDrop},
		{"dests", pick("inet_dest", "dest"), "cnt", false, destDrop}, {"mostBlocked", "dest", "cnt", true, destDrop},
		{"whereData", pick("inet_dest", "dest"), "byt", false, destDrop},
		{"users", "user", "cnt", false, userDrop},
		{"usersData", pick("inet_user", "user"), "byt", false, userDrop},
	}
	for _, r := range lists {
		l, _, err := d.topRollup(ctx, r.dim, f, fromH, p.To, 80, r.order, r.blocked)
		if err != nil {
			return err
		}
		kept := []map[string]any{}
		for _, x := range l {
			if !r.drop(fmt.Sprint(x["name"])) && len(kept) < 10 {
				kept = append(kept, x)
			}
		}
		out.Top[r.key] = kept
	}
	out.Top["inetLists"] = inet
	return nil
}
