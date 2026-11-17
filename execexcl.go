package main

import (
	"context"
	"fmt"
	"math"
	"strings"
	"time"
)

// execApplyExcl removes the excluded traffic (Settings > Executive summary > Exclusions) from a built summary:
// totals, the previous period, the daily / hourly series, the firewall share, log types and subtypes are reduced by
// the per-hour exclusion totals (rollup_excl); the top lists of sources, destinations and users are re-read and
// filtered; people and device counts are re-counted without the excluded sources and users.
func (a *App) execApplyExcl(ctx context.Context, d *Database, out *ExecSummary, p execPeriod, f Filter, ex *execExcl) error {
	info := out.Excl
	info["rules"] = ex.describe()
	info["not_adjusted"] = "AI tools, web categories, applications, policies, services, countries and sign-ins are shown as recorded."
	cov, err := d.exclCoverage(ctx, ex.sig, p.From, p.To)
	if err != nil {
		return err
	}
	info["coverage"] = math.Round(cov*10) / 10
	info["applied"] = true

	// totals
	t, err := d.exclTotals(ctx, ex.sig, p.From, p.To)
	if err != nil {
		return err
	}
	subTotals(&out.Cur, t)
	info["removed"] = map[string]int64{"events": t.cnt, "blocked": t.blk, "bytes": t.byt, "sent": t.snt}
	if out.Prev != nil {
		pt, err := d.exclTotals(ctx, ex.sig, p.PFrom, p.PTo)
		if err != nil {
			return err
		}
		subTotals(out.Prev, pt)
		if pc, err := d.exclCoverage(ctx, ex.sig, p.PFrom, p.PTo); err == nil && pc < 99.5 {
			info["prev_coverage"] = math.Round(pc*10) / 10
			out.Notes = append(out.Notes, fmt.Sprintf("The exclusions cover %.0f%% of the previous period so far, so the comparison may be uneven until the background work finishes.", pc))
		}
	}
	if cov < 99.5 {
		out.Notes = append(out.Notes, fmt.Sprintf("The exclusions cover %.0f%% of this period so far. The remaining hours are being computed in the background and still include the excluded traffic.", cov))
	}

	// v5.12: traffic by direction
	if g, err := d.exclGrouped(ctx, ex.sig, p.From, p.To, "zone"); err == nil {
		sub := func(v *int64, x int64) {
			if *v -= x; *v < 0 {
				*v = 0
			}
		}
		for z, x := range g {
			if v, ok := out.Cur.Zones[z]; ok {
				out.Cur.Zones[z] = [2]int64{max(0, v[0]-x.byt), max(0, v[1]-x.snt)}
			}
			switch z {
			case "internet", "inbound":
				sub(&out.Cur.InetBytes, x.byt)
				sub(&out.Cur.InetSent, x.snt)
				if z == "inbound" {
					sub(&out.Cur.InBytes, x.byt)
				}
			case "internal":
				sub(&out.Cur.IntBytes, x.byt)
				sub(&out.Cur.IntSent, x.snt)
			case "firewall", "infra":
				sub(&out.Cur.FwBytes, x.byt)
			}
		}
	} else {
		return err
	}
	if g, err := d.exclGrouped(ctx, ex.sig, p.From, p.To, out.SeriesUnit+"|zone"); err == nil {
		for _, s := range out.Series {
			tm, ok := s["t"].(time.Time)
			if !ok {
				continue
			}
			k := timeKey(tm)
			for _, z := range []string{"internet", "inbound"} {
				if x, ok := g[k+"|"+z]; ok {
					subInt(s, "inet_down", x.byt-x.snt)
					subInt(s, "inet_up", x.snt)
				}
			}
			if x, ok := g[k+"|internal"]; ok {
				subInt(s, "int_down", x.byt-x.snt)
				subInt(s, "int_up", x.snt)
			}
			for _, z := range []string{"firewall", "infra"} {
				if x, ok := g[k+"|"+z]; ok {
					subInt(s, "fw", x.byt)
				}
			}
		}
	}
	// series
	if g, err := d.exclGrouped(ctx, ex.sig, p.From, p.To, out.SeriesUnit); err == nil {
		for _, s := range out.Series {
			tm, ok := s["t"].(time.Time)
			if !ok {
				continue
			}
			if x, ok := g[timeKey(tm)]; ok {
				subInt(s, "events", x.cnt)
				subInt(s, "blocked", x.blk)
				subInt(s, "down", x.byt-x.snt)
				subInt(s, "up", x.snt)
			}
		}
	} else {
		return err
	}
	// firewalls, log types and subtypes
	if g, err := d.exclGrouped(ctx, ex.sig, p.From, p.To, "fw"); err == nil {
		for _, fw := range out.Firewalls {
			if x, ok := g[fmt.Sprint(fw["name"])]; ok {
				subInt(fw, "events", x.cnt)
			}
		}
	}
	if g, err := d.exclGrouped(ctx, ex.sig, p.From, p.To, "log_type"); err == nil {
		for _, t := range out.Types {
			if x, ok := g[fmt.Sprint(t["name"])]; ok {
				subInt(t, "count", x.cnt)
				subInt(t, "blocked", x.blk)
				subInt(t, "bytes", x.byt)
			}
		}
	}
	if g, err := d.exclGrouped(ctx, ex.sig, p.From, p.To, "subtype"); err == nil {
		for _, t := range out.Subtypes {
			if x, ok := g[fmt.Sprint(t["type"])+"/"+fmt.Sprint(t["name"])]; ok {
				subInt(t, "count", x.cnt)
				subInt(t, "blocked", x.blk)
				subInt(t, "bytes", x.byt)
			}
		}
	}

	// top lists: execTopLists (v5.11), together with the internal destinations
	fromH := hourStart(p.From)
	// people and devices without the excluded users / sources
	if len(ex.Src) > 0 || len(ex.Users) > 0 {
		if u, dv, err := d.peopleCounts(ctx, fromH, p.To, ex); err == nil {
			out.Cur.Users, out.Cur.Devices = u, dv
		} else {
			return err
		}
		if out.Prev != nil {
			if u, dv, err := d.peopleCounts(ctx, hourStart(p.PFrom), p.PTo, ex); err == nil {
				out.Prev.Users, out.Prev.Devices = u, dv
			}
		}
	}
	return nil
}

// peopleCountsSQL: distinct users and source IPs in the hourly summary, without the excluded ones.
// The CASE keeps PostgreSQL from casting user names to inet.
var peopleCountsSQL = `SELECT
	count(DISTINCT name) FILTER (WHERE dim = 'user' AND NOT lower(name) = ANY($3::text[])),
	count(DISTINCT name) FILTER (WHERE CASE WHEN dim = 'src_ip' THEN NOT (name::inet <<= ANY($4::text[]::inet[])) AND name::inet <<= ANY(` + "{LOCAL}" + `) ELSE false END)
	FROM rollup_1h WHERE hour >= $1 AND hour < $2 AND dim IN ('user','src_ip')`

func (d *Database) peopleCounts(ctx context.Context, from, to time.Time, ex *execExcl) (int64, int64, error) {
	var u, dv int64
	users := append([]string{}, ex.Users...)
	err := d.pool.QueryRow(ctx, strings.Replace(peopleCountsSQL, "{LOCAL}", localNetsSQL(), 1), from, to, users, prefixStrings(ex.Src)).Scan(&u, &dv)
	return u, dv, err
}

func subTotals(x *execTotals, t exclAgg) {
	clamp := func(v int64) int64 {
		if v < 0 {
			return 0
		}
		return v
	}
	x.Events, x.Blocked = clamp(x.Events-t.cnt), clamp(x.Blocked-t.blk)
	x.Bytes, x.Sent, x.UserEvents = clamp(x.Bytes-t.byt), clamp(x.Sent-t.snt), clamp(x.UserEvents-t.usr)
}

func subInt(m map[string]any, k string, v int64) {
	cur, ok := m[k].(int64)
	if !ok {
		return
	}
	if cur -= v; cur < 0 {
		cur = 0
	}
	m[k] = cur
}
