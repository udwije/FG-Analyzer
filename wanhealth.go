package main

import (
	"context"
	"fmt"
	"log"
	"math"
	"sort"
	"strings"
	"time"
)

// v5.21: WAN health history, WAN alerts, and the figures behind the executive report's "Internet circuits" page.
//
// The FortiGate MIB values read since v5.19 (CPU, memory, sessions, SD-WAN health per member, IPsec tunnels) were
// live only. They are now stored:
//
//	wan_sys  every poll        per firewall: CPU %, memory %, sessions
//	wan_sla  about once a minute  per SD-WAN member and health check: alive, latency, jitter, packet loss
//	wan_vpn  about once a minute  per IPsec tunnel: up / down, traffic in and out (bits per second)
//
// They are kept as long as the WAN samples (Settings > WAN links > Keep).
//
// Link quality = the share of the minutes in which a member was alive, lost less than 2% of the probes and answered
// in under 150 ms. Tunnel uptime = the share of the samples in which the tunnel was up (tunnels that were never up in
// the period, such as dial-up templates, are listed as "never up" and do not count against anything).

const (
	qualityLossPct    = 2.0
	qualityLatencyMS  = 150.0
	wanHealthMaxPairs = 400
)

type wanHealth struct {
	dev  string
	sys  *[3]float64 // cpu, mem, sessions (nil = not read)
	sla  []wanSLA
	vpn  []wanVPN
	tabl bool // the SD-WAN and VPN tables were read in this poll
}

// health returns what this poll read from the FortiGate MIB (called right after pollExtras, under w.mu).
func (w *wanDev) health(fresh bool) wanHealth {
	x := w.extra
	h := wanHealth{dev: w.cfg.Name, tabl: fresh}
	if x.CPU != nil || x.Mem != nil || x.Sessions != nil {
		v := [3]float64{math.NaN(), math.NaN(), math.NaN()}
		if x.CPU != nil {
			v[0] = float64(*x.CPU)
		}
		if x.Mem != nil {
			v[1] = float64(*x.Mem)
		}
		if x.Sessions != nil {
			v[2] = float64(*x.Sessions)
		}
		h.sys = &v
	}
	if fresh {
		h.sla, h.vpn = append([]wanSLA(nil), x.SLA...), append([]wanVPN(nil), x.VPN...)
	}
	return h
}

func nanNull(f float64) any {
	if math.IsNaN(f) {
		return nil
	}
	return f
}

// storeHealth writes one poll's health values.
func (d *Database) storeHealth(ctx context.Context, hs []wanHealth) error {
	var sd []string
	var cpu, mem, ses []any
	var ld, li, lc []string
	var la []bool
	var ll, lj, lp []float64
	var vd, vn []string
	var vu []bool
	var vr, vt []float64
	for _, h := range hs {
		if h.sys != nil {
			sd = append(sd, h.dev)
			cpu, mem, ses = append(cpu, nanNull(h.sys[0])), append(mem, nanNull(h.sys[1])), append(ses, nanNull(h.sys[2]))
		}
		if !h.tabl {
			continue
		}
		for _, s := range h.sla {
			ld, li, lc, la = append(ld, h.dev), append(li, s.Iface), append(lc, s.Name), append(la, s.Alive)
			ll, lj, lp = append(ll, s.Latency), append(lj, s.Jitter), append(lp, s.Loss)
		}
		for i, v := range h.vpn {
			if i >= wanHealthMaxPairs {
				break
			}
			vd, vn, vu, vr, vt = append(vd, h.dev), append(vn, v.Name), append(vu, v.Up), append(vr, v.RxBps), append(vt, v.TxBps)
		}
	}
	if len(sd) > 0 {
		if _, err := d.pool.Exec(ctx, `INSERT INTO wan_sys(ts, dev, cpu, mem, sessions) SELECT now(), * FROM
			unnest($1::text[], $2::float8[], $3::float8[], $4::float8[])`, sd, toFloats(cpu), toFloats(mem), toFloats(ses)); err != nil {
			return err
		}
	}
	if len(ld) > 0 {
		if _, err := d.pool.Exec(ctx, `INSERT INTO wan_sla(ts, dev, iface, chk, alive, latency, jitter, loss) SELECT now(), * FROM
			unnest($1::text[], $2::text[], $3::text[], $4::bool[], $5::float8[], $6::float8[], $7::float8[])`, ld, li, lc, la, ll, lj, lp); err != nil {
			return err
		}
	}
	if len(vd) > 0 {
		if _, err := d.pool.Exec(ctx, `INSERT INTO wan_vpn(ts, dev, tunnel, up, rx, tx) SELECT now(), * FROM
			unnest($1::text[], $2::text[], $3::bool[], $4::float8[], $5::float8[])`, vd, vn, vu, vr, vt); err != nil {
			return err
		}
	}
	return nil
}

// toFloats: NULL for a value the firewall did not give (pgx encodes nil in a []*float64 as NULL).
func toFloats(l []any) []*float64 {
	out := make([]*float64, len(l))
	for i, v := range l {
		if f, ok := v.(float64); ok {
			ff := f
			out[i] = &ff
		}
	}
	return out
}

// ---------------------------------------------------------------- reading it

type slaRow struct {
	Dev      string  `json:"dev"`
	Iface    string  `json:"iface"`
	Check    string  `json:"check"`
	Samples  int64   `json:"samples"`
	AlivePct float64 `json:"alive_pct"`
	Quality  float64 `json:"quality_pct"`
	Latency  float64 `json:"latency_ms"`
	Jitter   float64 `json:"jitter_ms"`
	Loss     float64 `json:"loss_pct"`
	DeadMin  int64   `json:"dead_samples"`
}

type vpnRow struct {
	Dev      string     `json:"dev"`
	Tunnel   string     `json:"tunnel"`
	Samples  int64      `json:"samples"`
	UpPct    float64    `json:"up_pct"`
	Down     int64      `json:"down_samples"`
	Drops    int64      `json:"drops"` // up -> down changes
	RxAvg    float64    `json:"rx_avg"`
	TxAvg    float64    `json:"tx_avg"`
	EverUp   bool       `json:"ever_up"`
	LastDown *time.Time `json:"last_down,omitempty"`
}

func (d *Database) wanSLAStats(ctx context.Context, from, to time.Time) ([]slaRow, error) {
	rows, err := d.pool.Query(ctx, `SELECT dev, iface, chk, count(*), avg(CASE WHEN alive THEN 100 ELSE 0 END)::float8,
		avg(CASE WHEN alive AND loss < $3 AND latency < $4 THEN 100 ELSE 0 END)::float8,
		coalesce(avg(latency) FILTER (WHERE alive),0)::float8, coalesce(avg(jitter) FILTER (WHERE alive),0)::float8,
		coalesce(avg(loss) FILTER (WHERE alive),0)::float8, count(*) FILTER (WHERE NOT alive)
		FROM wan_sla WHERE ts >= $1 AND ts < $2 GROUP BY 1, 2, 3 ORDER BY 1, 2, 3`, from, to, qualityLossPct, qualityLatencyMS)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []slaRow{}
	for rows.Next() {
		var r slaRow
		if err = rows.Scan(&r.Dev, &r.Iface, &r.Check, &r.Samples, &r.AlivePct, &r.Quality, &r.Latency, &r.Jitter, &r.Loss, &r.DeadMin); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (d *Database) wanVPNStats(ctx context.Context, from, to time.Time) ([]vpnRow, error) {
	rows, err := d.pool.Query(ctx, `SELECT dev, tunnel, count(*), avg(CASE WHEN up THEN 100 ELSE 0 END)::float8, count(*) FILTER (WHERE NOT up),
		count(*) FILTER (WHERE prev AND NOT up), coalesce(avg(rx) FILTER (WHERE up),0)::float8, coalesce(avg(tx) FILTER (WHERE up),0)::float8,
		bool_or(up), max(ts) FILTER (WHERE NOT up)
		FROM (SELECT dev, tunnel, ts, up, rx, tx, lag(up) OVER (PARTITION BY dev, tunnel ORDER BY ts) AS prev FROM wan_vpn WHERE ts >= $1 AND ts < $2) x
		GROUP BY 1, 2 ORDER BY 1, 2`, from, to)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []vpnRow{}
	for rows.Next() {
		var r vpnRow
		if err = rows.Scan(&r.Dev, &r.Tunnel, &r.Samples, &r.UpPct, &r.Down, &r.Drops, &r.RxAvg, &r.TxAvg, &r.EverUp, &r.LastDown); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// wanHealthData: everything the WAN links tab shows about health over a period.
func (d *Database) wanHealthData(ctx context.Context, from, to time.Time, poll int) (map[string]any, error) {
	step := wanStep(to.Sub(from), max(poll, 60))
	out := map[string]any{"step": step}
	sys := map[string][][4]float64{}
	rows, err := d.pool.Query(ctx, `SELECT dev, (floor(extract(epoch FROM ts)/$3)*$3)::bigint, coalesce(avg(cpu),'NaN')::float8,
		coalesce(avg(mem),'NaN')::float8, coalesce(avg(sessions),'NaN')::float8 FROM wan_sys WHERE ts >= $1 AND ts < $2 GROUP BY 1, 2 ORDER BY 2`, from, to, step)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var dv string
		var b int64
		var c, m, s float64
		if rows.Scan(&dv, &b, &c, &m, &s) == nil {
			sys[dv] = append(sys[dv], [4]float64{float64(b), jsonNum(c), jsonNum(m), jsonNum(s)})
		}
	}
	rows.Close()
	out["sys"] = sys
	sla := map[string][][5]float64{}
	rows, err = d.pool.Query(ctx, `SELECT dev || '|' || iface || '|' || chk, (floor(extract(epoch FROM ts)/$3)*$3)::bigint,
		coalesce(avg(latency) FILTER (WHERE alive),0)::float8, coalesce(avg(jitter) FILTER (WHERE alive),0)::float8,
		coalesce(avg(loss) FILTER (WHERE alive),100)::float8, avg(CASE WHEN alive THEN 100 ELSE 0 END)::float8
		FROM wan_sla WHERE ts >= $1 AND ts < $2 GROUP BY 1, 2 ORDER BY 2`, from, to, step)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var k string
		var b int64
		var l, j, p, a float64
		if rows.Scan(&k, &b, &l, &j, &p, &a) == nil {
			sla[k] = append(sla[k], [5]float64{float64(b), l, j, p, a})
		}
	}
	rows.Close()
	out["sla_series"] = sla
	if out["sla"], err = d.wanSLAStats(ctx, from, to); err != nil {
		return nil, err
	}
	if out["vpn"], err = d.wanVPNStats(ctx, from, to); err != nil {
		return nil, err
	}
	return out, nil
}

// jsonNum: NaN cannot be sent as JSON; -1 means "not read".
func jsonNum(f float64) float64 {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return -1
	}
	return f
}

// ---------------------------------------------------------------- alerts

// wanAlertConfig: limits for the WAN alerts (Settings > Alerts).
type wanAlertConfig struct {
	BusyPct, BusyMin, TunnelDownMin, LoadPct int
	LossPct                                  float64
}

func (c AlertConfig) wan() wanAlertConfig {
	w := wanAlertConfig{BusyPct: c.WANBusyPct, BusyMin: c.WANBusyMin, TunnelDownMin: c.TunnelDownMin, LoadPct: c.FWLoadPct, LossPct: c.WANLossPct}
	if w.BusyPct <= 0 || w.BusyPct > 100 {
		w.BusyPct = 80
	}
	if w.BusyMin <= 0 {
		w.BusyMin = 15
	}
	if w.TunnelDownMin <= 0 {
		w.TunnelDownMin = 5
	}
	if w.LoadPct <= 0 || w.LoadPct > 100 {
		w.LoadPct = 85
	}
	if w.LossPct <= 0 {
		w.LossPct = 2
	}
	return w
}

// wanHits: circuits running near capacity, SD-WAN members dead or losing packets, IPsec tunnels down, busy firewalls
// and firewalls that stopped answering SNMP. One alert per thing per day.
func (a *App) wanHits(ctx context.Context, d *Database, ac AlertConfig) ([]alertHit, error) {
	cfg := a.store.Get().WAN
	if !cfg.Enabled || len(cfg.Devices) == 0 {
		return nil, nil
	}
	lim := ac.wan()
	now := time.Now()
	var hits []alertHit
	var errs []string
	poll := float64(max(cfg.PollSeconds, 10))
	status := map[string]map[string]any{}
	for _, s := range wanStatus(cfg) {
		status[fmt.Sprint(s["name"])] = s
	}
	// 1. busy circuits: at least BusyMin minutes above BusyPct of the capacity in the last BusyMin + 15 minutes
	win := time.Duration(lim.BusyMin+15) * time.Minute
	type capKey struct{ dev, iface string }
	caps := map[capKey][3]float64{} // down, up (bps), label index
	labels := map[capKey]string{}
	for _, l := range wanLinks(cfg) {
		dn, up := float64(l.Down)*1e6, float64(l.Up)*1e6
		if dn == 0 || up == 0 { // the estimated bandwidth set on the FortiGate interface
			if lv, ok := status[l.Dev]["live"].(map[string]wanLive); ok {
				if x, ok := lv[l.Iface]; ok {
					if dn == 0 {
						dn = float64(x.EstDn) * 1e3
					}
					if up == 0 {
						up = float64(x.EstUp) * 1e3
					}
				}
			}
		}
		if dn > 0 || up > 0 {
			caps[capKey{l.Dev, l.Iface}] = [3]float64{dn, up}
			labels[capKey{l.Dev, l.Iface}] = l.Label
		}
	}
	if len(caps) > 0 {
		rows, err := d.pool.Query(ctx, `SELECT dev, iface, rx, tx FROM wan_samples WHERE ts > now() - $1 * interval '1 second'`, int(win.Seconds()))
		if err != nil {
			errs = append(errs, "busy circuits: "+err.Error())
		} else {
			type cnt struct{ dn, up, n int }
			agg := map[capKey]*cnt{}
			for rows.Next() {
				var k capKey
				var rx, tx float64
				if rows.Scan(&k.dev, &k.iface, &rx, &tx) != nil {
					continue
				}
				c, ok := caps[k]
				if !ok {
					continue
				}
				x := agg[k]
				if x == nil {
					x = &cnt{}
					agg[k] = x
				}
				x.n++
				if c[0] > 0 && rx >= c[0]*float64(lim.BusyPct)/100 {
					x.dn++
				}
				if c[1] > 0 && tx >= c[1]*float64(lim.BusyPct)/100 {
					x.up++
				}
			}
			rows.Close()
			need := int(math.Ceil(float64(lim.BusyMin) * 60 / poll))
			for k, x := range agg {
				for _, dir := range []struct {
					n    int
					name string
				}{{x.dn, "download"}, {x.up, "upload"}} {
					if dir.n < need {
						continue
					}
					mins := int(float64(dir.n) * poll / 60)
					sev := "amber"
					if mins >= 2*lim.BusyMin {
						sev = "red"
					}
					hits = append(hits, alertHit{key: "wanbusy:" + k.dev + ":" + k.iface + ":" + dir.name + ":" + dayKey(now), kind: "wan_busy", sev: sev,
						title:   fmt.Sprintf("%s is running near capacity (%s)", labels[k], dir.name),
						detail:  fmt.Sprintf("%s (%s, %s) carried more than %d%% of its %s capacity for about %d minutes of the last %d. Users notice slow downloads, calls and video.", labels[k], k.iface, k.dev, lim.BusyPct, dir.name, mins, int(win.Minutes())),
						subject: k.dev + " " + k.iface, first: now.Add(-time.Duration(mins) * time.Minute), last: now, count: int64(mins), fw: k.dev, via: "WAN " + k.iface})
				}
			}
		}
	}
	// 2. SD-WAN members: dead for 3 minutes or more, or losing packets, in the last 15 minutes
	rows, err := d.pool.Query(ctx, `SELECT dev, iface, chk, count(*) FILTER (WHERE NOT alive), coalesce(avg(loss) FILTER (WHERE alive),0)::float8,
		coalesce(avg(latency) FILTER (WHERE alive),0)::float8, NOT (array_agg(alive ORDER BY ts DESC))[1], max(ts) FROM wan_sla WHERE ts > now() - interval '15 minutes' GROUP BY 1, 2, 3`)
	if err != nil {
		errs = append(errs, "SD-WAN health: "+err.Error())
	} else {
		for rows.Next() {
			var dev, iface, chk string
			var dead int64
			var loss, lat float64
			var allDead bool // the newest sample: still down
			var last time.Time
			if rows.Scan(&dev, &iface, &chk, &dead, &loss, &lat, &allDead, &last) != nil {
				continue
			}
			switch {
			case dead >= 3:
				det := fmt.Sprintf("The SD-WAN health check %q found %s on %s not answering %d time(s) in the last 15 minutes", chk, iface, dev, dead)
				if allDead {
					det += "; it is still down. SD-WAN rules move traffic to the other members while it is dead."
				} else {
					det += "; it came back, but the link is unstable."
				}
				hits = append(hits, alertHit{key: "wansla:" + dev + ":" + iface + ":" + chk + ":" + dayKey(now), kind: "wan_sla", sev: "red",
					title: fmt.Sprintf("SD-WAN member %s on %s is down", iface, dev), detail: det,
					subject: dev + " " + iface, first: last.Add(-15 * time.Minute), last: last, count: dead, fw: dev, via: "SD-WAN " + iface})
			case loss >= lim.LossPct:
				hits = append(hits, alertHit{key: "wanloss:" + dev + ":" + iface + ":" + chk + ":" + dayKey(now), kind: "wan_sla", sev: "amber",
					title:   fmt.Sprintf("Packet loss on %s (%s)", iface, dev),
					detail:  fmt.Sprintf("The SD-WAN health check %q measured %.1f%% packet loss and %.0f ms latency on %s over the last 15 minutes. Calls and video suffer above %.0f%%.", chk, loss, lat, iface, lim.LossPct),
					subject: dev + " " + iface, first: last.Add(-15 * time.Minute), last: last, count: int64(math.Round(loss * 10)), fw: dev, via: "SD-WAN " + iface})
			}
		}
		rows.Close()
	}
	// 3. IPsec tunnels down for TunnelDownMin minutes that were up earlier today (dial-up templates are never up)
	rows, err = d.pool.Query(ctx, `SELECT dev, tunnel, min(ts) FILTER (WHERE NOT up AND ts > coalesce(last_up, '-infinity')), max(ts), last_up FROM (
		SELECT dev, tunnel, ts, up, max(ts) FILTER (WHERE up) OVER (PARTITION BY dev, tunnel) AS last_up FROM wan_vpn WHERE ts > now() - interval '24 hours') x
		GROUP BY dev, tunnel, last_up HAVING last_up IS NOT NULL AND bool_or(NOT up AND ts > last_up)`)
	if err != nil {
		errs = append(errs, "IPsec tunnels: "+err.Error())
	} else {
		for rows.Next() {
			var dev, tun string
			var since, last, lastUp *time.Time
			if rows.Scan(&dev, &tun, &since, &last, &lastUp) != nil || since == nil || last == nil {
				continue
			}
			down := last.Sub(*since)
			if down < time.Duration(lim.TunnelDownMin)*time.Minute || now.Sub(*last) > 10*time.Minute {
				continue
			}
			hits = append(hits, alertHit{key: "wanvpn:" + dev + ":" + tun + ":" + since.Format("200601021504"), kind: "wan_tunnel", sev: "red",
				title:   fmt.Sprintf("IPsec tunnel %s on %s is down", tun, dev),
				detail:  fmt.Sprintf("The tunnel has been down since %s (%s). The site or service behind it cannot be reached through it.", since.In(time.Local).Format("15:04"), humanDur(int64(down.Seconds()))),
				subject: dev + " " + tun, first: *since, last: *last, count: int64(down.Minutes()), fw: dev, via: "IPsec"})
		}
		rows.Close()
	}
	// 4. busy firewalls: CPU or memory above LoadPct on average over 15 minutes
	rows, err = d.pool.Query(ctx, `SELECT dev, coalesce(avg(cpu),0)::float8, coalesce(avg(mem),0)::float8, max(ts) FROM wan_sys WHERE ts > now() - interval '15 minutes' GROUP BY 1`)
	if err != nil {
		errs = append(errs, "firewall load: "+err.Error())
	} else {
		for rows.Next() {
			var dev string
			var cpu, mem float64
			var last time.Time
			if rows.Scan(&dev, &cpu, &mem, &last) != nil {
				continue
			}
			for _, x := range []struct {
				v    float64
				name string
			}{{cpu, "CPU"}, {mem, "memory"}} {
				if x.v < float64(lim.LoadPct) {
					continue
				}
				sev := "amber"
				if x.v >= 95 {
					sev = "red"
				}
				hits = append(hits, alertHit{key: "fwload:" + dev + ":" + x.name + ":" + dayKey(now), kind: "fw_load", sev: sev,
					title:   fmt.Sprintf("%s %s is high (%.0f%%)", dev, x.name, x.v),
					detail:  fmt.Sprintf("%s averaged %.0f%% %s over the last 15 minutes. A firewall that stays this busy slows every connection and can enter conserve mode.", dev, x.v, x.name),
					subject: dev, first: last.Add(-15 * time.Minute), last: last, count: int64(x.v), fw: dev})
			}
		}
		rows.Close()
	}
	// 5. firewalls not answering SNMP
	hits = append(hits, wanPollHits(cfg, status, now)...)
	if len(errs) > 0 {
		return hits, fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return hits, nil
}

var wanStarted time.Time

// ---------------------------------------------------------------- executive report: internet circuits

// execWAN: per circuit usage, data used, link quality; per firewall tunnel uptime; WAN incidents in the period.
func (d *Database) execWAN(ctx context.Context, c WANConfig, from, to time.Time) (map[string]any, error) {
	out := map[string]any{}
	stats, err := d.wanStats(ctx, c, from, to)
	if err != nil {
		return nil, err
	}
	usage, err := d.wanUsage(ctx, c, from, to)
	if err != nil {
		return nil, err
	}
	for _, s := range stats {
		u, _ := usage[fmt.Sprint(s["dev"])+"|"+fmt.Sprint(s["iface"])].(map[string]any)
		if u != nil {
			s["data_down"], s["data_up"] = u["down"], u["up"]
		}
		delete(s, "by_hour_down")
		delete(s, "by_hour_up")
	}
	out["links"] = stats
	sla, err := d.wanSLAStats(ctx, from, to)
	if err != nil {
		return nil, err
	}
	// one quality figure per member: the worst health check
	type mk struct{ dev, iface string }
	best := map[mk]slaRow{}
	for _, r := range sla {
		k := mk{r.Dev, r.Iface}
		if b, ok := best[k]; !ok || r.Quality < b.Quality {
			best[k] = r
		}
	}
	q := []slaRow{}
	for _, r := range best {
		q = append(q, r)
	}
	sort.Slice(q, func(i, j int) bool { return q[i].Dev+q[i].Iface < q[j].Dev+q[j].Iface })
	out["quality"] = q
	vpn, err := d.wanVPNStats(ctx, from, to)
	if err != nil {
		return nil, err
	}
	type tv struct {
		n, up        int
		upPct        float64
		drops, downS int64
		worst        string
		worstPct     float64
	}
	by := map[string]*tv{}
	for _, v := range vpn {
		if !v.EverUp {
			continue
		}
		x := by[v.Dev]
		if x == nil {
			x = &tv{worstPct: 101}
			by[v.Dev] = x
		}
		x.n++
		x.upPct += v.UpPct
		x.drops += v.Drops
		x.downS += v.Down
		if v.UpPct < x.worstPct {
			x.worst, x.worstPct = v.Tunnel, v.UpPct
		}
	}
	tl := []map[string]any{}
	for dev, x := range by {
		tl = append(tl, map[string]any{"dev": dev, "tunnels": x.n, "uptime_pct": x.upPct / float64(x.n), "drops": x.drops, "worst": x.worst, "worst_pct": x.worstPct})
	}
	sort.Slice(tl, func(i, j int) bool { return tl[i]["dev"].(string) < tl[j]["dev"].(string) })
	out["tunnels"] = tl
	inc := []map[string]any{}
	rows, err := d.pool.Query(ctx, `SELECT kind, severity, title, fw, first_seen, last_seen, count FROM alerts
		WHERE kind IN ('wan_busy','wan_sla','wan_tunnel','fw_load','wan_poll') AND last_seen >= $1 AND first_seen < $2 ORDER BY first_seen DESC LIMIT 40`, from, to)
	if err == nil {
		for rows.Next() {
			var k, s, t, fw string
			var f, l time.Time
			var n int64
			if rows.Scan(&k, &s, &t, &fw, &f, &l, &n) == nil {
				inc = append(inc, map[string]any{"kind": k, "severity": s, "title": t, "fw": fw, "first": f, "last": l, "count": n})
			}
		}
		rows.Close()
	}
	out["incidents"] = inc
	return out, nil
}

// wanHealthRetention: health history is kept as long as the WAN samples.
func (d *Database) wanHealthRetention(ctx context.Context) error {
	for _, t := range []string{"wan_sys", "wan_sla", "wan_vpn"} {
		if _, err := d.pool.Exec(ctx, "DELETE FROM "+t+" WHERE ts < now() - ($1 * interval '1 day')", wanKeepDays()); err != nil {
			return err
		}
	}
	return nil
}

func logWANHealthErr(err error) {
	if err != nil {
		log.Printf("WAN links: storing health values: %v", err)
	}
}

// wanPollHits: firewalls not answering SNMP for 15 minutes (only once they answered before, or 15 minutes after the
// start). Configuration problems (no passphrase, no interfaces) are shown on the tile, not raised as alerts.
func wanPollHits(cfg WANConfig, status map[string]map[string]any, now time.Time) []alertHit {
	var hits []alertHit
	for _, dc := range cfg.Devices {
		s := status[dc.Name]
		e, _ := s["error"].(string)
		if e == "" || strings.HasPrefix(e, "no passphrase") || strings.HasPrefix(e, "no interfaces") || strings.HasPrefix(e, "no authentication") || strings.HasPrefix(e, "no privacy") {
			continue
		}
		ok, _ := s["last_ok"].(time.Time)
		try, _ := s["last_try"].(time.Time)
		since := ok
		if since.IsZero() {
			since = wanStarted
		}
		if since.IsZero() || now.Sub(since) < 15*time.Minute || try.IsZero() {
			continue
		}
		hits = append(hits, alertHit{key: "wanpoll:" + dc.Name + ":" + dayKey(now), kind: "wan_poll", sev: "amber",
			title:   fmt.Sprintf("%s is not answering the WAN monitor", dc.Name),
			detail:  fmt.Sprintf("No SNMP answer from %s (%s) since %s: %s. Circuit usage, SD-WAN health and tunnels of this firewall are not being recorded.", dc.Name, dc.Host, ifStr(ok.IsZero(), "the service started", ok.In(time.Local).Format("Mon 15:04")), e),
			subject: dc.Name, first: since, last: try, count: int64(now.Sub(since).Minutes()), fw: dc.Name, via: "SNMP"})
	}
	return hits
}
