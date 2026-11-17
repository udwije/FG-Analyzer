package main

import (
	"context"
	"fmt"
	"log"
	"net/netip"
	"sort"
	"strings"
	"time"
)

// v5.14: clearer sign-in alerts.
//
//   - Every alert names the firewall(s) it came from.
//   - Failed sign-ins from one attacker become ONE alert: password spraying and brute force from the same source are
//     merged, and internet sources in the same /24 (IPv6: /64) are grouped, because attackers rotate through
//     neighbouring addresses. Internal sources stay one alert per address.
//   - The alert says how the firewall was reached (HTTPS or SSH admin, SSL or IPsec VPN) and which firewall address
//     (and interface, when the log has it) was targeted. The sign-in summary (rollup_evt) keeps both; the last 48
//     hours are re-summarised once after the upgrade.

// viaSQL: how a sign-in or change reached the firewall, from an event log.
const viaSQL = `(CASE WHEN subtype = 'vpn' THEN coalesce(nullif(lower(fields->>'tunneltype'),''), 'vpn')
	ELSE coalesce(nullif(lower(fields->>'method'),''), lower(substring(fields->>'ui' from '^([A-Za-z]+)')), '') END)`

// tgtSQL: the firewall address that was targeted, with the interface when the log carries it.
const tgtSQL = `(coalesce(host(dst_ip), '') || coalesce(' (' || nullif(fields->>'srcintf','') || ')', ''))`

// viaCode folds the many FortiOS spellings into a few codes.
func viaCode(v string, vpn bool) string {
	v = strings.ToLower(strings.TrimSpace(v))
	switch {
	case v == "https" || v == "http" || v == "ssh" || v == "telnet" || v == "console":
		return v
	case strings.HasPrefix(v, "ssl"):
		return "sslvpn"
	case strings.HasPrefix(v, "ipsec") || v == "ike" || v == "dialup":
		return "ipsec"
	case v == "" || v == "vpn":
		if vpn {
			return "vpn"
		}
		return "admin"
	}
	return v
}

var viaShort = map[string]string{"https": "HTTPS admin", "http": "HTTP admin", "ssh": "SSH admin", "telnet": "Telnet admin",
	"console": "Console", "sslvpn": "SSL VPN", "ipsec": "IPsec VPN", "vpn": "VPN", "admin": "Admin"}

var viaLong = map[string]string{"https": "the HTTPS admin page", "http": "the HTTP admin page", "ssh": "SSH admin",
	"telnet": "Telnet admin", "console": "the console", "sslvpn": "SSL VPN", "ipsec": "IPsec VPN", "vpn": "VPN", "admin": "firewall administration"}

func viaLabel(code string, long bool) string {
	m := viaShort
	if long {
		m = viaLong
	}
	if s, ok := m[code]; ok {
		return s
	}
	return code
}

// sigGroup: the alert group of a sign-in source. Internet addresses are grouped by /24 (IPv6 /64); internal
// addresses and anything that is not an address stay on their own.
func sigGroup(src string) string {
	src = strings.TrimSpace(src)
	a, err := netip.ParseAddr(src)
	if err != nil || isLocalIP(src) {
		return src
	}
	a = a.Unmap()
	bits := 24
	if a.Is6() {
		bits = 64
	}
	p, err := a.Prefix(bits)
	if err != nil {
		return src
	}
	return p.String()
}

// sortedKeys returns the keys of a set, sorted (IP addresses numerically).
func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		if k != "" {
			out = append(out, k)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, e1 := netip.ParseAddr(out[i])
		b, e2 := netip.ParseAddr(out[j])
		if e1 == nil && e2 == nil {
			return a.Less(b)
		}
		return out[i] < out[j]
	})
	return out
}

// joinList joins at most max items, then "and N more".
func joinList(l []string, max int) string {
	if len(l) <= max {
		return strings.Join(l, ", ")
	}
	return strings.Join(l[:max], ", ") + fmt.Sprintf(" and %d more", len(l)-max)
}

func joinAnd(l []string) string {
	switch len(l) {
	case 0:
		return ""
	case 1:
		return l[0]
	}
	return strings.Join(l[:len(l)-1], ", ") + " and " + l[len(l)-1]
}

// rollupEvtRefresh re-summarises the sign-ins of the last 48 hours once (v5.14 adds via and target).
func (d *Database) rollupEvtRefresh(ctx context.Context, n int) error {
	roll.mu.Lock()
	cur, done := roll.e514, roll.e514OK
	roll.mu.Unlock()
	if done || cur.IsZero() {
		return nil
	}
	floor := hourStart(time.Now().Add(-48 * time.Hour))
	if f, err := d.backfillFloor(ctx); err == nil && f.After(floor) {
		floor = f
	}
	for i := 0; i < n && cur.After(floor); i++ {
		h := cur.Add(-time.Hour)
		if err := d.rollupEvtHour(ctx, h); err != nil {
			return fmt.Errorf("sign-in summary for %s: %w", h.Format("2006-01-02 15:04"), err)
		}
		if err := d.setState(ctx, "evt514", h); err != nil {
			return err
		}
		cur = h
		roll.mu.Lock()
		roll.e514 = h
		roll.mu.Unlock()
	}
	if !cur.After(floor) {
		roll.mu.Lock()
		if !roll.e514OK {
			log.Printf("rollup: sign-ins of the last 48 hours now include how the firewall was reached")
		}
		roll.e514OK = true
		roll.mu.Unlock()
	}
	return nil
}

// ---------------------------------------------------------------- sign-in attacks (one alert per attacker)

type siAgg struct {
	group, day            string
	failed, ok            int64
	users                 map[string]bool
	hourFail              map[int64]int64
	hourUsers             map[int64]map[string]bool
	fws, vias, tgts, srcs map[string]bool
	first, last, okLast   time.Time
}

// signinHits groups the failed sign-ins in rollup_evt since from by attacker (source group) and day.
func (a *App) signinHits(ctx context.Context, d *Database, from time.Time, ac AlertConfig) ([]alertHit, error) {
	rows, err := d.pool.Query(ctx, `SELECT src, hour, fw, via, tgt, kind, usr, sum(cnt)::bigint, max(last_at)
		FROM rollup_evt WHERE hour >= $1 AND kind <> 'cfg' GROUP BY 1, 2, 3, 4, 5, 6, 7`, from)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	aggs := map[string]*siAgg{}
	order := []string{}
	for rows.Next() {
		var src, fw, via, tgt, kind, usr string
		var h time.Time
		var n int64
		var last *time.Time
		if err = rows.Scan(&src, &h, &fw, &via, &tgt, &kind, &usr, &n, &last); err != nil {
			return nil, err
		}
		g, day := sigGroup(src), dayKey(h)
		k := g + "|" + day
		x := aggs[k]
		if x == nil {
			x = &siAgg{group: g, day: day, users: map[string]bool{}, hourFail: map[int64]int64{}, hourUsers: map[int64]map[string]bool{},
				fws: map[string]bool{}, vias: map[string]bool{}, tgts: map[string]bool{}, srcs: map[string]bool{}}
			aggs[k] = x
			order = append(order, k)
		}
		lt := h.Add(time.Hour)
		if last != nil {
			lt = *last
		}
		if kind == "success" {
			x.ok += n
			if lt.After(x.okLast) {
				x.okLast = lt
			}
			continue
		}
		x.srcs[src] = true
		x.fws[fw] = true
		x.vias[viaCode(via, kind == "failed_vpn")] = true
		if tgt != "" {
			x.tgts[tgt] = true
		}
		x.failed += n
		hu := h.Unix()
		x.hourFail[hu] += n
		if usr != "" && usr != "?" {
			x.users[usr] = true
			if x.hourUsers[hu] == nil {
				x.hourUsers[hu] = map[string]bool{}
			}
			x.hourUsers[hu][usr] = true
		}
		if x.first.IsZero() || h.Before(x.first) {
			x.first = h
		}
		if lt.After(x.last) {
			x.last = lt
		}
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	var hits []alertHit
	for _, k := range order {
		x := aggs[k]
		if x.failed == 0 {
			continue
		}
		var peakF, peakU int64
		for hu, n := range x.hourFail {
			if n > peakF {
				peakF = n
			}
			if u := int64(len(x.hourUsers[hu])); u > peakU {
				peakU = u
			}
		}
		srcs, fws, users := sortedKeys(x.srcs), sortedKeys(x.fws), sortedKeys(x.users)
		long, short := []string{}, []string{}
		for _, c := range sortedKeys(x.vias) {
			long, short = append(long, viaLabel(c, true)), append(short, viaLabel(c, false))
		}
		public := false
		for _, s := range srcs {
			if isPublicIP(s) {
				public = true
			}
		}
		who := x.group
		if len(srcs) == 1 {
			who = srcs[0]
		} else if len(srcs) > 1 {
			who = fmt.Sprintf("%d addresses in %s", len(srcs), x.group)
		}
		where := "an internal address"
		if public {
			where = "the internet"
		}
		// v5.13 alert keys of the same sources (spraying and brute force were two alerts per address)
		oldKeys := func(prefixes ...string) []string {
			out := []string{}
			for _, s := range srcs {
				for _, p := range prefixes {
					if key := p + s + ":" + x.day; s != x.group || p != "sok:" {
						out = append(out, key)
					}
				}
			}
			return out
		}
		base := alertHit{subject: x.group, first: x.first, last: x.last, fw: strings.Join(fws, ", "), via: strings.Join(short, ", "),
			sources: joinList(srcs, 40)}
		spray, bf := peakU >= int64(ac.SprayUsers), peakF >= int64(ac.BruteForce)
		if spray || bf {
			label := "Brute force"
			switch {
			case spray && bf:
				label = "Password spraying and brute force"
			case spray:
				label = "Password spraying"
			}
			sev := "amber"
			if public || spray || peakF >= int64(ac.BruteForce)*5 {
				sev = "red"
			}
			det := fmt.Sprintf("%s failed sign-ins today from %s, up to %s in one hour. %s different account%s tried",
				num(x.failed), where, num(peakF), num(int64(len(users))), plural(len(users)))
			if len(users) > 0 {
				det += ": " + joinList(users, 12)
			}
			det += "."
			if t := sortedKeys(x.tgts); len(t) > 0 {
				det += " Targeted: " + joinList(t, 4) + "."
			}
			if len(srcs) > 1 {
				det += " Addresses: " + joinList(srcs, 12) + "."
			}
			h := base
			h.key, h.kind, h.sev = "atk:"+x.group+":"+x.day, "signin_attack", sev
			h.title = fmt.Sprintf("%s against %s from %s", label, joinAnd(long), who)
			h.detail, h.count = det, x.failed
			h.supersede = oldKeys("bf:", "spray:")
			hits = append(hits, h)
		}
		if x.failed >= 5 && x.ok > 0 && !x.okLast.Before(x.first) {
			h := base
			h.key, h.kind, h.sev = "sok:"+x.group+":"+x.day, "success_after_fail", "red"
			h.title = fmt.Sprintf("Successful sign-in after %s failures from %s", num(x.failed), who)
			h.detail = fmt.Sprintf("A sign-in to %s succeeded from %s, which had failed %s times today. Check that it was the real account holder.",
				joinAnd(long), who, num(x.failed))
			h.count, h.last = x.ok, x.okLast
			h.supersede = oldKeys("sok:")
			hits = append(hits, h)
		}
	}
	return hits, nil
}

// backfillAlertFirewalls adds the firewall to alerts raised before v5.14 (only rows still without one).
func (d *Database) backfillAlertFirewalls(ctx context.Context) error {
	for _, q := range []string{
		`UPDATE alerts a SET fw = coalesce((SELECT string_agg(DISTINCT e.fw, ', ' ORDER BY e.fw) FROM rollup_evt e
			WHERE e.src = a.subject AND e.hour >= date_trunc('hour', a.first_seen) AND e.hour <= a.last_seen), '')
			WHERE a.fw = '' AND a.kind IN ('bruteforce', 'spray', 'success_after_fail')`,
		`UPDATE alerts SET fw = coalesce(substring(title from ' on (.+)$'), '') WHERE fw = '' AND kind = 'config_offhours'`,
		`UPDATE alerts SET fw = subject WHERE fw = '' AND kind = 'firewall_silent'`,
		// v5.15: merged sign-in alerts and device alerts that still have no firewall
		`UPDATE alerts a SET fw = coalesce((SELECT string_agg(DISTINCT e.fw, ', ' ORDER BY e.fw) FROM rollup_evt e
			WHERE (e.src = a.subject OR e.src = ANY(string_to_array(a.sources, ', '))) AND e.hour >= date_trunc('hour', a.first_seen) - interval '1 hour'
			AND e.hour <= a.last_seen), '') WHERE a.fw = '' AND a.kind IN ('signin_attack', 'success_after_fail', 'bruteforce', 'spray')`,
		`UPDATE alerts a SET fw = coalesce((SELECT string_agg(DISTINCT r.fw, ', ' ORDER BY r.fw) FROM rollup_1h r
			WHERE r.dim IN ('src_ip', 'inet_src', 'nouser_src') AND r.name = a.subject AND r.hour >= date_trunc('hour', a.first_seen) - interval '1 hour'
			AND r.hour <= a.last_seen), '') WHERE a.fw = '' AND a.kind IN ('blocked_burst', 'large_upload', 'unknown_heavy')`,
	} {
		if _, err := d.pool.Exec(ctx, q); err != nil {
			return err
		}
	}
	return nil
}
