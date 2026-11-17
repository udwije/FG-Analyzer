package main

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// v5.10: executive summary exclusions.
//
// Settings > Executive summary can exclude traffic from the management report: sources (IPs or subnets),
// destinations (IPs, subnets or host names such as *.windowsupdate.com), usernames (service accounts) and whole log
// subtypes (for example "local" traffic to the firewalls). A log is excluded when it matches ANY of them.
//
// The report is built from the summaries, which cannot be filtered after the fact. So the collector also keeps, per
// hour and firewall / log type / subtype, the totals of exactly the excluded logs (rollup_excl) and the report
// subtracts them. The figures stay exact, a 30-day report still builds in seconds, and a log matching several rules
// is only removed once. When the rules change, history is recomputed in the background (newest hours first, about
// 12 hours of logs per minute); until then the report says how much of the period is covered.

type execExcl struct {
	Src      []netip.Prefix
	Dst      []netip.Prefix
	Hosts    []string // lower-case patterns: plain text = contains, * = wildcard
	Users    []string // lower-case
	Subtypes []string
	hostRe   []*regexp.Regexp
	sig      string
}

var exclCur atomic.Pointer[execExcl]

func parsePrefix(s string) (netip.Prefix, bool) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked(), true
	}
	if a, err := netip.ParseAddr(s); err == nil {
		a = a.Unmap()
		return netip.PrefixFrom(a, a.BitLen()), true
	}
	return netip.Prefix{}, false
}

var hostPattern = regexp.MustCompile(`^[a-z0-9*._-]{1,200}$`)

// parseExcl validates the lists from the settings. Entries may be separated by commas or new lines.
func parseExcl(c ExecConfig) (*execExcl, error) {
	e := &execExcl{}
	split := func(l []string) []string {
		var out []string
		for _, x := range l {
			for _, y := range strings.FieldsFunc(x, func(r rune) bool { return r == ',' || r == '\n' || r == '\r' || r == ';' }) {
				if y = strings.TrimSpace(y); y != "" && !strings.HasPrefix(y, "#") {
					out = append(out, y)
				}
			}
		}
		return out
	}
	for _, s := range split(c.ExcludeSources) {
		p, ok := parsePrefix(s)
		if !ok {
			return nil, fmt.Errorf("executive summary: excluded source %q is not an IP address or subnet", s)
		}
		e.Src = append(e.Src, p)
	}
	for _, s := range split(c.ExcludeDestinations) {
		if p, ok := parsePrefix(s); ok {
			e.Dst = append(e.Dst, p)
			continue
		}
		h := strings.ToLower(s)
		if !hostPattern.MatchString(h) {
			return nil, fmt.Errorf("executive summary: excluded destination %q is not an IP, subnet or host name", s)
		}
		e.Hosts = append(e.Hosts, h)
		e.hostRe = append(e.hostRe, patternRegexp(h))
	}
	for _, s := range split(c.ExcludeUsers) {
		if len(s) > 100 {
			return nil, errors.New("executive summary: an excluded username is too long")
		}
		e.Users = append(e.Users, strings.ToLower(s))
	}
	for _, s := range split(c.ExcludeSubtypes) {
		s = strings.ToLower(s)
		if !safeWord.MatchString(s) {
			return nil, fmt.Errorf("executive summary: %q is not a log subtype", s)
		}
		e.Subtypes = append(e.Subtypes, s)
	}
	e.sig = e.signature()
	return e, nil
}

func (e *execExcl) active() bool {
	return e != nil && len(e.Src)+len(e.Dst)+len(e.Hosts)+len(e.Users)+len(e.Subtypes) > 0
}

func prefixStrings(l []netip.Prefix) []string {
	out := make([]string, len(l))
	for i, p := range l {
		out[i] = p.String()
	}
	return out
}

func (e *execExcl) signature() string {
	parts := [][]string{prefixStrings(e.Src), prefixStrings(e.Dst), append([]string{}, e.Hosts...), append([]string{}, e.Users...), append([]string{}, e.Subtypes...)}
	var b strings.Builder
	for _, p := range parts {
		sort.Strings(p)
		b.WriteString(strings.Join(p, ","))
		b.WriteByte('|')
	}
	h := sha1.Sum([]byte(b.String()))
	return hex.EncodeToString(h[:6])
}

// cond: SQL over fortigate_logs that is true for an excluded log.
func (e *execExcl) cond(args *[]any) string {
	var parts []string
	if len(e.Src) > 0 {
		parts = append(parts, "src_ip <<= ANY("+addArg(args, prefixStrings(e.Src))+"::text[]::inet[])")
	}
	if len(e.Dst) > 0 {
		parts = append(parts, "dst_ip <<= ANY("+addArg(args, prefixStrings(e.Dst))+"::text[]::inet[])")
	}
	if len(e.Hosts) > 0 {
		likes := make([]string, len(e.Hosts))
		for i, h := range e.Hosts {
			likes[i] = likePattern(h)
		}
		parts = append(parts, "lower(hostname) LIKE ANY("+addArg(args, likes)+"::text[])")
	}
	if len(e.Users) > 0 {
		parts = append(parts, "lower(user_name) = ANY("+addArg(args, e.Users)+"::text[])")
	}
	if len(e.Subtypes) > 0 {
		parts = append(parts, "subtype = ANY("+addArg(args, e.Subtypes)+"::text[])")
	}
	if len(parts) == 0 {
		return "false"
	}
	return "coalesce(" + strings.Join(parts, " OR ") + ", false)"
}

func (e *execExcl) matchSrc(name string) bool {
	a, err := netip.ParseAddr(strings.TrimSpace(name))
	if err != nil {
		return false
	}
	a = a.Unmap()
	for _, p := range e.Src {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// matchDest: a destination name is a host name, or an IP when the log had no host name.
func (e *execExcl) matchDest(name string) bool {
	if a, err := netip.ParseAddr(strings.TrimSpace(name)); err == nil {
		a = a.Unmap()
		for _, p := range e.Dst {
			if p.Contains(a) {
				return true
			}
		}
		return false
	}
	n := strings.ToLower(name)
	for _, re := range e.hostRe {
		if re.MatchString(n) {
			return true
		}
	}
	return false
}

func (e *execExcl) matchUser(name string) bool {
	n := strings.ToLower(name)
	for _, u := range e.Users {
		if u == n {
			return true
		}
	}
	return false
}

// describe lists the rules in plain language for the report.
func (e *execExcl) describe() []string {
	var out []string
	add := func(label string, l []string) {
		if len(l) > 0 {
			out = append(out, label+": "+strings.Join(l, ", "))
		}
	}
	add("Sources", prefixStrings(e.Src))
	dst := append(prefixStrings(e.Dst), e.Hosts...)
	add("Destinations", dst)
	add("Users", e.Users)
	add("Log subtypes", e.Subtypes)
	return out
}

// ---------------------------------------------------------------- the per-hour exclusion totals

func (d *Database) exclHour(ctx context.Context, h time.Time, e *execExcl) error {
	args := []any{h, h.Add(time.Hour), e.sig}
	cond := e.cond(&args)
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `DELETE FROM rollup_excl WHERE hour = $1`, h); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO rollup_excl (hour, sig, fw, log_type, subtype, zone, cnt, blk, byt, snt, usr)
		SELECT $1::timestamptz, $3::text, `+fwExpr+`, `+ltExpr+`, coalesce(nullif(subtype,''),'(none)'), z, count(*), count(*) FILTER (WHERE `+blockedExpr+`),
			coalesce(sum(fl_sent(log_id, fields, sent_bytes)+fl_rcvd(log_id, fields, received_bytes)),0)::bigint, coalesce(sum(`+epSentSQL("z")+`),0)::bigint, count(*) FILTER (WHERE coalesce(user_name,'') <> '')
		FROM (SELECT *, `+zoneSQL()+` AS z FROM fortigate_logs WHERE event_time >= $1 AND event_time < $2 AND `+cond+`) r GROUP BY 3, 4, 5, 6
		UNION ALL SELECT $1::timestamptz, $3::text, '', '', '', '', 0, 0, 0, 0, 0`, args...); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

var exclState struct {
	sync.Mutex
	fails     map[time.Time]int // v6.0.1: failed attempts per hour; skipped after exclMaxFails
	cleaned   string            // sig whose older rows were removed
	missing   int               // hours still to compute (last check)
	lastErr   string
	lastErrAt time.Time
}

// exclMissingSQL: hours in the window without a marker for this rule set, newest first.
const exclMissingSQL = `SELECT h FROM generate_series($1::timestamptz, $2::timestamptz, interval '1 hour') h
	WHERE NOT EXISTS (SELECT 1 FROM rollup_excl x WHERE x.hour = h AND x.sig = $3 AND x.fw = '') ORDER BY h DESC`

// exclBackfill computes up to n complete hours that the current rules have not been applied to yet.
func (d *Database) exclBackfill(ctx context.Context, n int) error {
	e := exclCur.Load()
	if !e.active() {
		return nil
	}
	exclState.Lock()
	clean := exclState.cleaned != e.sig
	exclState.Unlock()
	if clean {
		if _, err := d.pool.Exec(ctx, `DELETE FROM rollup_excl WHERE sig <> $1`, e.sig); err != nil {
			return err
		}
		exclState.Lock()
		exclState.cleaned = e.sig
		exclState.Unlock()
	}
	var oldest *time.Time
	if err := d.pool.QueryRow(ctx, `SELECT min(bucket) FROM rollup_5m`).Scan(&oldest); err != nil {
		return err
	}
	floor := hourStart(time.Now().AddDate(0, 0, -rollupBackfillDays))
	if oldest != nil && hourStart(*oldest).After(floor) {
		floor = hourStart(*oldest)
	}
	last := hourStart(time.Now()).Add(-time.Hour)
	if last.Before(floor) {
		return nil
	}
	rows, err := d.pool.Query(ctx, exclMissingSQL, floor, last, e.sig)
	if err != nil {
		return err
	}
	var hours []time.Time
	for rows.Next() {
		var h time.Time
		if err = rows.Scan(&h); err != nil {
			rows.Close()
			return err
		}
		hours = append(hours, h)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return err
	}
	exclState.Lock()
	exclState.missing = len(hours)
	exclState.Unlock()
	done := 0
	for _, h := range hours {
		if done >= n {
			break
		}
		exclState.Lock()
		if exclState.fails == nil {
			exclState.fails = map[time.Time]int{}
		}
		skip := exclState.fails[h] >= exclMaxFails
		exclState.Unlock()
		if skip {
			continue // v6.0.1: this hour failed too often: the others go on (it is retried after a restart)
		}
		hctx, cancel := context.WithTimeout(ctx, exclHourTimeout)
		err := d.exclHour(hctx, h, e)
		cancel()
		done++
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			exclState.Lock()
			exclState.fails[h]++
			n := exclState.fails[h]
			exclState.lastErr, exclState.lastErrAt = err.Error(), time.Now()
			exclState.Unlock()
			if n >= exclMaxFails {
				log.Printf("exclusions: skipping %s after %d failed attempts (%v); it is left out of the exclusions until the next restart",
					h.Format("2006-01-02 15:04"), n, err)
			} else {
				log.Printf("exclusions for %s: attempt %d failed: %v", h.Format("2006-01-02 15:04"), n, err)
			}
			continue
		}
		exclState.Lock()
		exclState.missing--
		delete(exclState.fails, h)
		exclState.Unlock()
	}
	return nil
}

// exclLive refreshes the current hour (and the previous one just after the hour), like the other summaries.
func (d *Database) exclLive(ctx context.Context, cur time.Time, prevToo bool) {
	e := exclCur.Load()
	if !e.active() {
		return
	}
	hs := []time.Time{cur}
	if prevToo {
		hs = append(hs, cur.Add(-time.Hour))
	}
	for _, h := range hs {
		if err := d.exclHour(ctx, h, e); err != nil {
			exclState.Lock()
			exclState.lastErr, exclState.lastErrAt = err.Error(), time.Now()
			exclState.Unlock()
			log.Printf("exclusions: %v", err)
		}
	}
}

func exclInfo() map[string]any {
	e := exclCur.Load()
	exclState.Lock()
	defer exclState.Unlock()
	out := map[string]any{"active": e.active(), "pending_hours": exclState.missing}
	var skipped []string
	for h, n := range exclState.fails {
		if n >= exclMaxFails {
			skipped = append(skipped, h.In(time.Local).Format("2 Jan 15:04"))
		}
	}
	sort.Strings(skipped)
	if len(skipped) > 0 {
		out["skipped_hours"] = skipped
	}
	if e.active() {
		out["rules"] = e.describe()
	}
	if exclState.lastErr != "" {
		out["last_error"], out["last_error_at"] = exclState.lastErr, exclState.lastErrAt.Unix()
	}
	return out
}

// ---------------------------------------------------------------- reading it (executive summary)

type exclAgg struct{ cnt, blk, byt, snt, usr int64 }

// timeKey matches the keys of exclGrouped for a time bucket: wall-clock time in the report zone.
func timeKey(t time.Time) string {
	loc, err := time.LoadLocation(reportTZ())
	if err != nil {
		loc = time.UTC
	}
	return t.In(loc).Format("2006-01-02 15")
}

// exclCoverage: share of the hours in [from, to) the current rules have been applied to.
func (d *Database) exclCoverage(ctx context.Context, sig string, from, to time.Time) (float64, error) {
	// only hours that can hold logs count: not before the oldest summarised data nor the 31-day back-fill limit
	start := hourStart(from)
	var oldest *time.Time
	if err := d.pool.QueryRow(ctx, `SELECT min(bucket) FROM rollup_5m`).Scan(&oldest); err != nil {
		return 0, err
	}
	if oldest != nil && hourStart(*oldest).After(start) {
		start = hourStart(*oldest)
	}
	if lim := hourStart(time.Now().AddDate(0, 0, -rollupBackfillDays)); lim.After(start) {
		start = lim
	}
	end := to // the current hour is refreshed every 5 minutes; it is not counted as missing
	if cur := hourStart(time.Now()); cur.Before(end) {
		end = cur
	}
	want := 0
	for h := start; h.Before(end); h = h.Add(time.Hour) {
		want++
	}
	if want == 0 {
		return 100, nil
	}
	var have int64
	err := d.pool.QueryRow(ctx, `SELECT count(*) FROM rollup_excl WHERE sig = $1 AND fw = '' AND hour >= $2 AND hour < $3`, sig, start, end).Scan(&have)
	if have > int64(want) {
		have = int64(want)
	}
	return 100 * float64(have) / float64(want), err
}

// exclTotals: what the rules remove from [from, to).
func (d *Database) exclTotals(ctx context.Context, sig string, from, to time.Time) (exclAgg, error) {
	var x exclAgg
	err := d.pool.QueryRow(ctx, `SELECT coalesce(sum(cnt),0)::bigint, coalesce(sum(blk),0)::bigint, coalesce(sum(byt),0)::bigint, coalesce(sum(snt),0)::bigint,
		coalesce(sum(usr),0)::bigint FROM rollup_excl WHERE sig = $1 AND hour >= $2 AND hour < $3 AND zone NOT IN `+deviceZones, sig, hourStart(from), to).Scan(&x.cnt, &x.blk, &x.byt, &x.snt, &x.usr)
	return x, err
}

// exclGrouped: removed totals by a key: "fw", "log_type", "subtype", or a time unit ("hour", "day") in the report zone.
func (d *Database) exclGrouped(ctx context.Context, sig string, from, to time.Time, by string) (map[string]exclAgg, error) {
	key := map[string]string{"fw": "fw", "log_type": "log_type", "subtype": "log_type || '/' || subtype", "zone": "zone"}[by]
	args := []any{sig, hourStart(from), to}
	if key == "" {
		unit, withZone := strings.CutSuffix(by, "|zone")
		u, tz := addArg(&args, unit), addArg(&args, reportTZ())
		key = "to_char(date_trunc(" + u + "::text, hour, " + tz + "::text) AT TIME ZONE " + tz + "::text, 'YYYY-MM-DD HH24')"
		if withZone {
			key += " || '|' || zone"
		}
	}
	rows, err := d.pool.Query(ctx, `SELECT `+key+`, coalesce(sum(cnt),0)::bigint, coalesce(sum(blk),0)::bigint, coalesce(sum(byt),0)::bigint,
		coalesce(sum(snt),0)::bigint, coalesce(sum(usr),0)::bigint FROM rollup_excl WHERE sig = $1 AND fw <> '' AND hour >= $2 AND hour < $3 GROUP BY 1`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]exclAgg{}
	for rows.Next() {
		var k string
		var x exclAgg
		if err = rows.Scan(&k, &x.cnt, &x.blk, &x.byt, &x.snt, &x.usr); err != nil {
			return nil, err
		}
		out[k] = x
	}
	return out, rows.Err()
}

// v6.0.1: an hour that keeps failing (usually a time-out on a compressed day) is tried at most exclMaxFails times,
// each with its own time limit, instead of being retried every minute for ever while the dashboards slow down.
const (
	exclMaxFails    = 3
	exclHourTimeout = 4 * time.Minute
)
