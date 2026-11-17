package main

import (
	"context"
	"fmt"
	"log"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// v5.12: where the traffic goes, and data volumes that match the firewall.
//
// Traffic direction ("zone") of every traffic log:
//
//	internet  an internal address talking to the internet (outbound)
//	inbound   an internet address reaching you (published services, VPN, scans)
//	internal  internal to internal only (LAN to LAN, site to site, servers, backups): never left your network
//	firewall  traffic to or from the firewalls themselves (subtype "local")
//
// Internal addresses are the private ranges plus Settings > Internal networks (for organisations that use public
// ranges inside). rollup_5m keeps the zone, so totals and charts split by direction cost nothing, and rollup_1h keeps
// lists of users, devices and destinations by outbound internet data (inet_user, inet_src, inet_dest).
//
// Data volumes: FortiGate writes a "long-lived session" log (log id 20) every 2 minutes for every open session, with
// the running total in sentbyte / rcvdbyte. Summing those totals counts a 1-hour download 30 times. The collector now
// stores the increment of each log (sentdelta / rcvddelta, or the difference to the previous log of the same session),
// and the summaries read the increment for logs stored before. History is re-summarised in the background.

// ---------------------------------------------------------------- internal networks

var privNets = []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16", "127.0.0.0/8", "fc00::/7", "fe80::/10", "::1/128"}

type localNets struct {
	prefixes []netip.Prefix
	sql      string // literal inet[] (validated prefixes only)
}

var localCur atomic.Pointer[localNets]

func setLocalNets(extra []string) {
	all := append([]string{}, privNets...)
	for _, s := range extra {
		if p, ok := parsePrefix(strings.TrimSpace(s)); ok {
			all = append(all, p.String())
		}
	}
	ln := &localNets{}
	for _, s := range all {
		ln.prefixes = append(ln.prefixes, netip.MustParsePrefix(s))
	}
	ln.sql = "'{" + strings.Join(all, ",") + "}'::inet[]"
	localCur.Store(ln)
}

func init() { setLocalNets(nil) }

func localNetsSQL() string { return localCur.Load().sql }

// isLocalIP: an address inside your network (private ranges or Settings > Internal networks).
func isLocalIP(s string) bool {
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return false
	}
	a = a.Unmap()
	for _, p := range localCur.Load().prefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func validNets(l []string) error {
	for _, s := range l {
		if s = strings.TrimSpace(s); s == "" {
			continue
		}
		if _, ok := parsePrefix(s); !ok {
			return fmt.Errorf("internal networks: %q is not an IP address or subnet", s)
		}
	}
	return nil
}

const multicastSQL = `'{224.0.0.0/4,255.255.255.255/32,ff00::/8}'::inet[]`

// zoneSQL: the direction of a log in fortigate_logs (” for non-traffic logs).
func zoneSQL() string {
	l, inf, tun := localNetsSQL(), infraNetsSQL(), tunnelsSQL()
	// v5.16: "infra" = network devices talking among themselves (routing, VRRP, multicast, the addresses in Settings >
	// Infrastructure); "transit" = an internal session arriving over a site-to-site tunnel, which the sending firewall
	// has already logged (counting it here too would double it).
	return `(CASE WHEN log_type IS DISTINCT FROM 'traffic' THEN '' WHEN subtype = 'local' THEN 'firewall'
		WHEN src_ip IS NULL OR dst_ip IS NULL THEN 'other'
		WHEN protocol IN ('2','88','89','103','112') OR dst_ip <<= ANY(` + multicastSQL + `) OR dst_port IN (179, 646, 3784, 4784)
			OR src_ip <<= ANY(` + inf + `) OR dst_ip <<= ANY(` + inf + `) THEN 'infra'
		WHEN src_ip <<= ANY(` + l + `) THEN CASE WHEN dst_ip <<= ANY(` + l + `) THEN
			CASE WHEN fields->>'srcintf' = ANY(` + tun + `) OR (coalesce(fields->>'vpn','') <> '' AND fields->>'srcintf' = fields->>'vpn') THEN 'transit' ELSE 'internal' END
			ELSE 'internet' END
		ELSE 'inbound' END)`
}

// deviceZones: traffic that is not an endpoint's own (left out of the main dashboards, shown in the Advanced view).
const deviceZones = `('firewall','infra','transit')`

// epSentSQL: what the ENDPOINT sent (v5.16). For a session opened from the internet (inbound) the firewall's
// "sent" is what the internet host sent, i.e. what your server received, so the two directions are swapped.
func epSentSQL(z string) string {
	return `(CASE WHEN ` + z + ` = 'inbound' THEN fl_rcvd(log_id, fields, received_bytes) ELSE fl_sent(log_id, fields, sent_bytes) END)`
}

// Zone labels shared by the API, the dashboard and the report.
var zoneOrder = []string{"internet", "inbound", "internal", "transit", "infra", "firewall", "other", "pending"}

// ---------------------------------------------------------------- data volumes: per-log increments

// SQL: fl_sent / fl_rcvd (schema.go) give the increment of a log stored before v5.12 (log id 20 carries the running
// total in sent_bytes and the increment in fields). New logs already store the increment.
const sentSQL = `fl_sent(log_id, fields, sent_bytes)`
const rcvdSQL = `fl_rcvd(log_id, fields, received_bytes)`

type sessCum struct {
	sent, rcvd int64
	at         int64
}

var sessTrack = struct {
	sync.Mutex
	m     map[string]sessCum
	swept int64
}{m: map[string]sessCum{}}

func numField(f map[string]string, k string) (int64, bool) {
	v, ok := f[k]
	if !ok || v == "" {
		return 0, false
	}
	n, err := strconv.ParseInt(v, 10, 64)
	return n, err == nil && n >= 0
}

// adjustSessionBytes turns the running totals of a traffic log into the bytes of this log only:
//   - the FortiGate's own increment (sentdelta / rcvddelta) when the log has it;
//   - otherwise the difference to the previous statistics log of the same session (log id 20, every 2 minutes);
//   - otherwise (a short session with a single log) the totals as they are.
func adjustSessionBytes(r *LogRecord) {
	if r.Type != "traffic" || r.Fields == nil {
		return
	}
	sid := r.Fields["sessionid"]
	if sid == "" {
		return
	}
	key := r.DeviceName + "|" + r.VDOM + "|" + sid + "|" + r.SrcIP
	cumS, cumR := r.SentBytes, r.ReceivedBytes
	ds, okS := numField(r.Fields, "sentdelta")
	dr, okR := numField(r.Fields, "rcvddelta")
	now := time.Now().Unix()
	sessTrack.Lock()
	defer sessTrack.Unlock()
	prev, had := sessTrack.m[key]
	switch {
	case okS && okR:
		r.SentBytes, r.ReceivedBytes = ds, dr
	case had:
		r.SentBytes, r.ReceivedBytes = max(0, cumS-prev.sent), max(0, cumR-prev.rcvd)
	}
	if r.LogID == "0000000020" {
		sessTrack.m[key] = sessCum{cumS, cumR, now}
	} else if had {
		delete(sessTrack.m, key)
	}
	if now-sessTrack.swept > 60 {
		sessTrack.swept = now
		for k, v := range sessTrack.m {
			if now-v.at > 1800 { // statistics come every 2 minutes; 30 minutes of silence = the session is gone
				delete(sessTrack.m, k)
			}
		}
		if len(sessTrack.m) > 2000000 {
			sessTrack.m = map[string]sessCum{}
		}
	}
}

// ---------------------------------------------------------------- re-summarising history once (v5.12)

// rollupRebuild re-summarises hours summarised before v5.12 (zones, internet lists, corrected volumes), newest first.
func (d *Database) rollupRebuild(ctx context.Context, n int) error {
	roll.mu.Lock()
	cur, done := roll.rb, roll.rbOK
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
		if err := d.rollupHour(ctx, h); err != nil {
			return fmt.Errorf("re-summarising %s: %w", h.Format("2006-01-02 15:04"), err)
		}
		if err := d.setState(ctx, "r516", h); err != nil {
			return err
		}
		cur = h
		roll.mu.Lock()
		roll.rb = h
		roll.mu.Unlock()
	}
	if !cur.After(floor) {
		roll.mu.Lock()
		if !roll.rbOK {
			log.Printf("rollup: traffic directions and corrected data volumes are complete back to %s", cur.Format("2006-01-02 15:04"))
		}
		roll.rbOK = true
		roll.mu.Unlock()
	}
	return nil
}

// inetCovers: the summaries hold traffic directions and internet lists for a period starting at hour h.
func inetCovers(h time.Time) bool {
	roll.mu.Lock()
	defer roll.mu.Unlock()
	return roll.known && (roll.rbOK || !h.Before(roll.rb))
}

// ---------------------------------------------------------------- reading the zones (dashboard)

func scanZones(rows interface {
	Next() bool
	Scan(...any) error
	Err() error
	Close()
}) (map[string]any, error) {
	defer rows.Close()
	tot := map[string]*[4]int64{}
	series := map[string][][3]int64{}
	for rows.Next() {
		var b int64
		var z string
		var c, k, y, s int64
		if err := rows.Scan(&b, &z, &c, &k, &y, &s); err != nil {
			return nil, err
		}
		if z == "" {
			z = "pending"
		}
		if tot[z] == nil {
			tot[z] = &[4]int64{}
		}
		tot[z][0] += c
		tot[z][1] += k
		tot[z][2] += y
		tot[z][3] += s
		series[z] = append(series[z], [3]int64{b, y, s})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	list := []map[string]any{}
	for _, z := range zoneOrder {
		if t := tot[z]; t != nil {
			list = append(list, map[string]any{"name": z, "count": t[0], "blocked": t[1], "bytes": t[2], "sent": t[3]})
		}
	}
	for _, s := range series {
		sort.Slice(s, func(i, j int) bool { return s[i][0] < s[j][0] })
	}
	return map[string]any{"zones": list, "zseries": series}, nil
}

func (d *Database) zonesRollup(ctx context.Context, f Filter, step int64) (map[string]any, error) {
	if f.Type != "" && f.Type != "traffic" {
		return map[string]any{"zones": []map[string]any{}, "zseries": map[string][][3]int64{}}, nil
	}
	rel, args := rollWhere(f, "bucket", f.From, f.To)
	release, err := d.acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	rows, err := d.pool.Query(ctx, `SELECT (floor(extract(epoch FROM bucket)/`+strconv.FormatInt(step, 10)+`)*`+strconv.FormatInt(step, 10)+`)::bigint, zone,
		sum(cnt)::bigint, sum(blk)::bigint, sum(byt)::bigint, sum(snt)::bigint FROM rollup_5m WHERE `+rel+` AND log_type = 'traffic' GROUP BY 1, 2`, args...)
	if err != nil {
		return nil, err
	}
	return scanZones(rows)
}

func (d *Database) zonesRaw(ctx context.Context, f Filter, step int64) (map[string]any, error) {
	if f.Type != "" && f.Type != "traffic" {
		return map[string]any{"zones": []map[string]any{}, "zseries": map[string][][3]int64{}}, nil
	}
	rel, args := f.where()
	release, err := d.acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	s := strconv.FormatInt(step, 10)
	rows, err := d.pool.Query(ctx, `SELECT b, z, count(*), count(*) FILTER (WHERE blk), coalesce(sum(sn+rc),0)::bigint, coalesce(sum(sn),0)::bigint FROM (
		SELECT b, z, blk, CASE WHEN z = 'inbound' THEN rc0 ELSE sn0 END AS sn, CASE WHEN z = 'inbound' THEN sn0 ELSE rc0 END AS rc FROM (
		SELECT (floor(extract(epoch FROM event_time)/`+s+`)*`+s+`)::bigint AS b, `+zoneSQL()+` AS z, coalesce(`+blockedExpr+`, false) AS blk,
			`+sentSQL+` AS sn0, `+rcvdSQL+` AS rc0 FROM fortigate_logs WHERE `+rel+` AND log_type = 'traffic') y) x GROUP BY 1, 2`, args...)
	if err != nil {
		return nil, err
	}
	return scanZones(rows)
}

// inetFilter: a raw-log filter for outbound internet traffic (your users and devices to the internet), the same
// traffic as the inet_* lists of rollup_1h.
func inetFilter(f Filter) Filter {
	g := f
	c := zoneSQL() + ` = 'internet'`
	if g.Extra != "" {
		c = "(" + g.Extra + ") AND " + c
	}
	g.Extra = c
	return g
}

// ---------------------------------------------------------------- executive summary: traffic by direction

type zoneAgg struct{ byt, snt int64 }

// execZones: bytes per direction in [from, to) from rollup_5m, plus the bytes of traffic summarised before v5.12.
func (d *Database) execZones(ctx context.Context, from, to time.Time) (map[string]zoneAgg, error) {
	rows, err := d.pool.Query(ctx, `SELECT zone, coalesce(sum(byt),0)::bigint, coalesce(sum(snt),0)::bigint FROM rollup_5m
		WHERE bucket >= $1 AND bucket < $2 AND log_type = 'traffic' GROUP BY 1`, from, to)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]zoneAgg{}
	for rows.Next() {
		var z string
		var a zoneAgg
		if err = rows.Scan(&z, &a.byt, &a.snt); err != nil {
			return nil, err
		}
		if z == "" {
			z = "pending"
		}
		out[z] = a
	}
	return out, rows.Err()
}

func applyZones(t *execTotals, z map[string]zoneAgg) {
	t.Zones = map[string][2]int64{}
	for k, v := range z {
		t.Zones[k] = [2]int64{v.byt, v.snt}
	}
	t.InetBytes = z["internet"].byt + z["inbound"].byt
	t.InetSent = z["internet"].snt + z["inbound"].snt
	t.InBytes = z["inbound"].byt
	t.IntBytes, t.IntSent = z["internal"].byt, z["internal"].snt
	t.FwBytes = z["firewall"].byt + z["infra"].byt // v5.16: network devices (transit = duplicates, not counted)
	t.PendBytes = z["pending"].byt + z["other"].byt
}

// execZoneSeries adds per-direction bytes to the report series (keys inet_down, inet_up, int_down, int_up, fw).
func (d *Database) execZoneSeries(ctx context.Context, series []map[string]any, unit string, from, to time.Time) error {
	rows, err := d.pool.Query(ctx, `SELECT date_trunc($3::text, bucket, $4::text), zone, sum(byt)::bigint, sum(snt)::bigint
		FROM rollup_5m WHERE bucket >= $1 AND bucket < $2 AND log_type = 'traffic' GROUP BY 1, 2`, from, to, unit, reportTZ())
	if err != nil {
		return err
	}
	defer rows.Close()
	idx := map[int64]map[string]any{}
	for _, s := range series {
		if t, ok := s["t"].(time.Time); ok {
			idx[t.Unix()] = s
			for _, k := range []string{"inet_down", "inet_up", "int_down", "int_up", "fw"} {
				s[k] = int64(0)
			}
		}
	}
	for rows.Next() {
		var t time.Time
		var z string
		var y, sn int64
		if err = rows.Scan(&t, &z, &y, &sn); err != nil {
			return err
		}
		s := idx[t.Unix()]
		if s == nil {
			continue
		}
		switch z {
		case "internet", "inbound":
			s["inet_down"] = s["inet_down"].(int64) + y - sn
			s["inet_up"] = s["inet_up"].(int64) + sn
		case "internal":
			s["int_down"] = s["int_down"].(int64) + y - sn
			s["int_up"] = s["int_up"].(int64) + sn
		case "firewall", "infra":
			s["fw"] = s["fw"].(int64) + y
		}
	}
	return rows.Err()
}
