package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

// v5.13: detections. Every 5 minutes a few rules run over the summaries (no raw scans) and raise alerts. Repeats of
// the same thing on the same day update one alert (count, last seen) instead of creating new ones. An alert can be
// acknowledged (seen, keep counting) or ignored (stays quiet for that key).

type AlertConfig struct {
	Enabled        bool  `json:"enabled"`
	BruteForce     int   `json:"brute_force"`      // failed admin / VPN sign-ins from one source in one hour
	SprayUsers     int   `json:"spray_users"`      // different accounts tried from one source in one hour
	WorkStart      int   `json:"work_start"`       // hour of day; configuration changes outside the working day are reported
	WorkEnd        int   `json:"work_end"`         //
	WorkWeekend    bool  `json:"work_weekend"`     // Saturday and Sunday are working days
	SilentMin      int   `json:"silent_min"`       // a monitored firewall sending nothing for this long
	BlockedPerHour int   `json:"blocked_per_hour"` // blocked connections from one internal device in one hour
	UploadMB       int64 `json:"upload_mb"`        // data sent to the internet by one device in one hour
	UnknownGB      int64 `json:"unknown_gb"`       // data of a device without a user or assignment in a day
	// v5.21: WAN links
	WANBusyPct    int     `json:"wan_busy_pct"`    // a circuit above this share of its capacity ...
	WANBusyMin    int     `json:"wan_busy_min"`    // ... for this many minutes
	WANLossPct    float64 `json:"wan_loss_pct"`    // SD-WAN member packet loss over 15 minutes
	TunnelDownMin int     `json:"tunnel_down_min"` // an IPsec tunnel that was up today, down this long
	FWLoadPct     int     `json:"fw_load_pct"`     // firewall CPU or memory over 15 minutes
}

func (c *AlertConfig) defaults() {
	set := func(v *int, d int) {
		if *v <= 0 {
			*v = d
		}
	}
	set(&c.BruteForce, 10)
	set(&c.SprayUsers, 5)
	set(&c.SilentMin, 15)
	set(&c.BlockedPerHour, 2000)
	if c.WorkEnd <= 0 || c.WorkEnd > 24 {
		c.WorkStart, c.WorkEnd = 8, 18
	}
	if c.UploadMB <= 0 {
		c.UploadMB = 2048
	}
	if c.UnknownGB <= 0 {
		c.UnknownGB = 5
	}
	w := c.wan()
	c.WANBusyPct, c.WANBusyMin, c.WANLossPct, c.TunnelDownMin, c.FWLoadPct = w.BusyPct, w.BusyMin, w.LossPct, w.TunnelDownMin, w.LoadPct
}

type alertHit struct {
	key, kind, sev, title, detail, subject string
	first, last                            time.Time
	count                                  int64
	fw, via, sources                       string   // v5.14: firewall(s), how they were reached, source addresses
	supersede                              []string // v5.14: older alert keys this one replaces (status is carried over)
}

func (d *Database) upsertAlert(ctx context.Context, h alertHit) error {
	if h.supersede == nil {
		h.supersede = []string{}
	}
	_, err := d.pool.Exec(ctx, `WITH old AS (DELETE FROM alerts WHERE key = ANY($13::text[]) AND key <> $1 RETURNING status, ack_by, first_seen)
		INSERT INTO alerts(key, kind, severity, title, detail, subject, first_seen, last_seen, count, status, fw, via, sources, ack_by)
		SELECT $1, $2, $3, $4, $5, $6, least($7::timestamptz, (SELECT min(first_seen) FROM old)), $8, $9,
			coalesce((SELECT CASE WHEN bool_and(status = 'ignored') THEN 'ignored' WHEN bool_and(status <> 'open') THEN 'ack' END FROM old), 'open'),
			$10, $11, $12, (SELECT max(ack_by) FROM old)
		ON CONFLICT (key) DO UPDATE SET detail = EXCLUDED.detail, title = EXCLUDED.title, severity = EXCLUDED.severity, kind = EXCLUDED.kind,
			last_seen = greatest(alerts.last_seen, EXCLUDED.last_seen), first_seen = least(alerts.first_seen, EXCLUDED.first_seen),
			count = greatest(alerts.count, EXCLUDED.count), fw = EXCLUDED.fw, via = EXCLUDED.via, sources = EXCLUDED.sources,
			status = CASE WHEN alerts.status = 'ack' AND EXCLUDED.count > alerts.count * 2 THEN 'open' ELSE alerts.status END`,
		h.key, h.kind, h.sev, h.title, h.detail, h.subject, h.first, h.last, h.count, h.fw, h.via, h.sources, h.supersede)
	return err
}

func dayKey(t time.Time) string { return t.In(time.Local).Format("20060102") }

// detect runs the rules: sign-ins over today (one alert per attacker and day), the rest over the last two hours.
func (a *App) detect(ctx context.Context, d *Database) error {
	cfg := a.store.Get()
	ac := cfg.Alerts
	ac.defaults()
	if !ac.Enabled {
		return nil
	}
	now := time.Now()
	from := hourStart(now).Add(-time.Hour)
	q := func(sql string, args []any, fn func(scan func(...any) error) error) error {
		rows, err := d.pool.Query(ctx, sql, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			if err := fn(rows.Scan); err != nil {
				return err
			}
		}
		return rows.Err()
	}
	// 1-3. sign-ins: password spraying / brute force (merged, grouped by attacker) and success after failures
	siFrom := dayStart(now)
	if from.Before(siFrom) {
		siFrom = from
	}
	// v5.15: the firewall of older alerts is filled first, and one failing rule no longer stops the others
	if err := d.backfillAlertFirewalls(ctx); err != nil {
		log.Printf("alerts: filling in the firewall: %v", err)
	}
	var errs []string
	hits, err := a.signinHits(ctx, d, siFrom, ac)
	if err != nil {
		errs = append(errs, "sign-ins: "+err.Error())
	}
	// 4. configuration changes outside working hours
	err = q(`SELECT usr, fw, hour, sum(cnt)::bigint, max(last_at), coalesce(string_agg(DISTINCT via, ','), '') FROM rollup_evt WHERE kind = 'cfg' AND hour >= $1 GROUP BY 1, 2, 3`, []any{from},
		func(scan func(...any) error) error {
			var usr, fw, vias string
			var h, last time.Time
			var n int64
			if err := scan(&usr, &fw, &h, &n, &last, &vias); err != nil {
				return err
			}
			lh := h.In(time.Local)
			wd := lh.Weekday()
			off := lh.Hour() < ac.WorkStart || lh.Hour() >= ac.WorkEnd || (!ac.WorkWeekend && (wd == time.Saturday || wd == time.Sunday))
			if off {
				vs := map[string]bool{}
				for _, v := range strings.Split(vias, ",") {
					vs[viaLabel(viaCode(v, false), false)] = true
				}
				hits = append(hits, alertHit{key: "cfg:" + usr + ":" + fw + ":" + dayKey(h), kind: "config_offhours", sev: "amber",
					title:   fmt.Sprintf("Configuration changed outside working hours on %s", fw),
					detail:  fmt.Sprintf("%s made %d change(s) at %s. Confirm the change was planned.", usr, n, lh.Format("Mon 2 Jan 15:04")),
					subject: usr, first: h, last: last, count: n, fw: fw, via: strings.Join(sortedKeys(vs), ", ")})
			}
			return nil
		})
	if err != nil {
		errs = append(errs, err.Error())
	}
	// 5. firewalls (and the collector) silent
	monitored := map[string]bool{}
	for _, f := range cfg.Firewalls {
		monitored[f.Name] = true
	}
	ignored := map[string]bool{}
	for _, n := range cfg.Exec.IgnoreFirewalls {
		ignored[strings.ToLower(n)] = true
	}
	lastBy := map[string]time.Time{}
	err = q(`SELECT fw, max(bucket) FROM rollup_5m WHERE bucket > now() - interval '2 days' GROUP BY fw`, nil, func(scan func(...any) error) error {
		var fw string
		var t time.Time
		if err := scan(&fw, &t); err != nil {
			return err
		}
		lastBy[fw] = t.Add(5 * time.Minute)
		return nil
	})
	if err != nil {
		errs = append(errs, err.Error())
	}
	var newest time.Time
	for _, t := range lastBy {
		if t.After(newest) {
			newest = t
		}
	}
	if !newest.IsZero() && now.Sub(newest) > time.Duration(ac.SilentMin)*time.Minute {
		hits = append(hits, alertHit{key: "collector:" + newest.Format("200601021504"), kind: "collector_silent", sev: "red", title: "No logs are reaching LogSikka",
			detail:  fmt.Sprintf("Nothing has been stored from any firewall since %s. Check the LogSikka service, its database and the network path.", newest.In(time.Local).Format("15:04")),
			subject: "LogSikka", first: newest, last: now, count: int64(now.Sub(newest).Minutes())})
	} else {
		for fw, t := range lastBy {
			if (len(monitored) > 0 && !monitored[fw]) || ignored[strings.ToLower(fw)] {
				continue
			}
			if now.Sub(t) > time.Duration(ac.SilentMin)*time.Minute {
				hits = append(hits, alertHit{key: "silent:" + fw + ":" + t.Format("200601021504"), kind: "firewall_silent", sev: "red", title: fw + " stopped sending logs",
					detail:  fmt.Sprintf("No logs from %s since %s. While it is silent, nothing it handles is recorded.", fw, t.In(time.Local).Format("Mon 15:04")),
					subject: fw, first: t, last: now, count: int64(now.Sub(t).Minutes()), fw: fw})
			}
		}
	}
	// 6-7. devices: blocked bursts and large uploads (hourly summaries)
	err = q(`SELECT dim, name, hour, sum(blk)::bigint, sum(snt)::bigint, string_agg(DISTINCT fw, ', ' ORDER BY fw) FROM rollup_1h
		WHERE hour >= $1 AND dim IN ('src_ip','inet_src') GROUP BY 1, 2, 3`,
		[]any{from}, func(scan func(...any) error) error {
			var dim, ip, fws string
			var h time.Time
			var blk, snt int64
			if err := scan(&dim, &ip, &h, &blk, &snt, &fws); err != nil {
				return err
			}
			if !isLocalIP(ip) {
				return nil
			}
			who := deviceName(ip)
			if dim == "src_ip" && blk >= int64(ac.BlockedPerHour) {
				hits = append(hits, alertHit{key: "blk:" + ip + ":" + dayKey(h), kind: "blocked_burst", sev: "amber", title: "Device keeps trying blocked connections: " + who,
					detail:  fmt.Sprintf("%s blocked connections in one hour from %s. This is often unwanted software, malware or a misconfiguration.", num(blk), who),
					subject: ip, first: h, last: h.Add(time.Hour), count: blk, fw: fws})
			}
			if dim == "inet_src" && snt >= ac.UploadMB<<20 {
				hits = append(hits, alertHit{key: "up:" + ip + ":" + dayKey(h), kind: "large_upload", sev: "amber", title: "Large upload to the internet: " + who,
					detail: fmt.Sprintf("%s was sent to the internet in one hour from %s.", humanBytes(snt), who), subject: ip, first: h, last: h.Add(time.Hour),
					count: snt >> 20, fw: fws})
			}
			return nil
		})
	if err != nil {
		errs = append(errs, err.Error())
	}
	// 8. unknown devices with heavy traffic today
	day := dayStart(now)
	err = q(`SELECT name, sum(byt)::bigint, sum(cnt)::bigint, string_agg(DISTINCT fw, ', ' ORDER BY fw) FROM rollup_1h WHERE hour >= $1 AND dim = 'nouser_src'
		GROUP BY name HAVING sum(byt) >= $2`,
		[]any{day, ac.UnknownGB << 30}, func(scan func(...any) error) error {
			var ip, fws string
			var byt, cnt int64
			if err := scan(&ip, &byt, &cnt, &fws); err != nil {
				return err
			}
			if lookupAssignment(ip, "", "", now) != nil {
				return nil
			}
			hits = append(hits, alertHit{key: "unk:" + ip + ":" + dayKey(day), kind: "unknown_heavy", sev: "amber", title: "Busy device with no user: " + ip,
				detail:  fmt.Sprintf("%s of traffic today from %s, and nobody is assigned to it. Assign it in Devices & people.", humanBytes(byt), ip),
				subject: ip, first: day, last: now, count: byt >> 20, fw: fws})
			return nil
		})
	if err != nil {
		errs = append(errs, err.Error())
	}
	// 9. v5.21: WAN links (circuits near capacity, SD-WAN members, tunnels, firewall load, SNMP)
	if wh, err := a.wanHits(ctx, d, ac); err != nil {
		errs = append(errs, "WAN: "+err.Error())
		hits = append(hits, wh...)
	} else {
		hits = append(hits, wh...)
	}
	for _, h := range hits {
		if err := d.upsertAlert(ctx, h); err != nil {
			errs = append(errs, h.key+": "+err.Error())
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

func deviceName(ip string) string {
	if a := lookupAssignment(ip, "", "", time.Now()); a != nil {
		return ip + " (" + a.Owner + ")"
	}
	return ip
}

func (a *App) detectLoop(ctx context.Context) error {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	first := time.After(2 * time.Minute)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-first:
		case <-t.C:
		}
		d := a.getDB()
		if d == nil {
			continue
		}
		c, cancel := context.WithTimeout(ctx, 2*time.Minute)
		if err := a.detect(c, d); err != nil {
			log.Printf("detections: %v", err)
		}
		cancel()
	}
}

// /api/alerts: GET ?status=open|ack|ignored|all, POST {ids:[...], status:"ack"|"ignored"|"open"}
func (a *App) handleAlerts(w http.ResponseWriter, r *http.Request) {
	d := a.dbOrFail(w)
	if d == nil {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	if r.Method == http.MethodPost {
		if roleOf(sessionFrom(r.Context()).Role) < RoleAnalyst {
			jsonError(w, http.StatusForbidden, "viewers cannot change alerts")
			return
		}
		var in struct {
			IDs    []int64 `json:"ids"`
			Status string  `json:"status"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&in); err != nil || (in.Status != "ack" && in.Status != "ignored" && in.Status != "open") {
			jsonError(w, http.StatusBadRequest, "bad request")
			return
		}
		if _, err := d.pool.Exec(ctx, `UPDATE alerts SET status = $2, ack_by = $3, updated = now() WHERE id = ANY($1)`, in.IDs, in.Status, sessionFrom(r.Context()).User); err != nil {
			queryErr(w, err)
			return
		}
		a.audit(r, "alerts_"+in.Status, fmt.Sprint(in.IDs))
		jsonOut(w, map[string]bool{"ok": true})
		return
	}
	st, fwq := r.URL.Query().Get("status"), strings.TrimSpace(r.URL.Query().Get("fw"))
	conds, args := []string{}, []any{}
	if st != "" && st != "all" {
		conds = append(conds, "status = "+addArg(&args, st))
	}
	if fwq != "" { // v5.14: one firewall
		conds = append(conds, addArg(&args, fwq)+" = ANY(string_to_array(fw, ', '))")
	}
	cond := ""
	if len(conds) > 0 {
		cond = " WHERE " + strings.Join(conds, " AND ")
	}
	rows, err := d.pool.Query(ctx, `SELECT id, kind, severity, title, coalesce(detail,''), coalesce(subject,''), first_seen, last_seen, count, status, coalesce(ack_by,''),
		fw, via, sources FROM alerts`+cond+` ORDER BY (status = 'open') DESC, last_seen DESC LIMIT 500`, args...)
	if err != nil {
		queryErr(w, err)
		return
	}
	defer rows.Close()
	list := []map[string]any{}
	cfgNow, now := a.store.Get(), time.Now()
	repeat := d.repeatSources(ctx) // v5.21
	for rows.Next() {
		var id, n int64
		var kind, sev, title, det, subj, status, by, fw, via, srcs string
		var first, last time.Time
		if rows.Scan(&id, &kind, &sev, &title, &det, &subj, &first, &last, &n, &status, &by, &fw, &via, &srcs) != nil {
			continue
		}
		list = append(list, map[string]any{"id": id, "kind": kind, "severity": sev, "title": title, "detail": det, "subject": subj,
			"first": first, "last": last, "count": n, "status": status, "by": by, "fw": fw, "via": via, "sources": srcs,
			"block": blockCandidates(kind, subj, srcs, cfgNow, now, repeat)}) // v5.20, v5.21 repeat attackers
	}
	rows.Close()
	fws := []string{}
	if fr, err := d.pool.Query(ctx, `SELECT DISTINCT x FROM alerts, unnest(string_to_array(fw, ', ')) AS x WHERE fw <> '' ORDER BY 1`); err == nil {
		for fr.Next() {
			var f string
			if fr.Scan(&f) == nil && f != "" {
				fws = append(fws, f)
			}
		}
		fr.Close()
	}
	var open, red int64
	_ = d.pool.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE severity = 'red') FROM alerts WHERE status = 'open'`).Scan(&open, &red)
	jsonOut(w, map[string]any{"alerts": list, "open": open, "open_red": red, "enabled": a.store.Get().Alerts.Enabled, "firewalls": fws})
}
