package main

import (
	"context"
	"encoding/csv"
	"fmt"
	"net/http"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// ---------------------------------------------------------------- filters
//
// Text filters accept: plain text  -> case-insensitive substring ("*" is a wildcard)
//                      =value      -> exact match (used by click-to-filter)
//                      !value      -> negation (works with both forms above)

type Filter struct {
	From, To                                     time.Time
	Subtype, Outcome, Action                     string
	User, Src, Dst, Category, App, Host, Risk, Q string
	Type, Scope                                  string // log_type; scope: "" all logs, "ai" AI security events, "aitraffic" AI traffic logs
	FW, Tool, Level, Service, Msg, Policy        string
	Extra                                        string // internal SQL fragment, never taken from the request
	Endpoint                                     bool   // v5.16: leave device traffic (firewalls, routing, tunnels arriving) out
}

var safeWord = regexp.MustCompile(`^[a-z0-9-]{1,40}$`)

// scope expressions: AI dashboards count security events (web filter / app control) like before;
// traffic logs to AI tools are used separately for data volumes.
var scopeExpr = map[string]string{
	"ai":        "ai_tool IS NOT NULL AND log_type = 'utm'",
	"aitraffic": "ai_tool IS NOT NULL AND log_type = 'traffic'",
	"aiall":     "ai_tool IS NOT NULL",
}

const blockedExpr = "action IN ('blocked','block','deny','dropped','reset','reset-client','reset-server','reject','blocked-url')"

func parseFilter(r *http.Request) Filter {
	q := r.URL.Query()
	now := time.Now()
	f := Filter{To: now.Add(time.Minute)}
	f.From = now.Add(-time.Duration(hours(r)) * time.Hour)
	if t, err := time.Parse(time.RFC3339, q.Get("from")); err == nil {
		f.From = t
		if t2, err := time.Parse(time.RFC3339, q.Get("to")); err == nil && t2.After(t) {
			f.To = t2
		}
	}
	if f.To.Sub(f.From) > 90*24*time.Hour {
		f.From = f.To.Add(-90 * 24 * time.Hour)
	}
	f.Subtype, f.Type, f.Scope = strings.ToLower(q.Get("subtype")), strings.ToLower(q.Get("type")), q.Get("scope")
	if !safeWord.MatchString(f.Subtype) {
		f.Subtype = ""
	}
	if !safeWord.MatchString(f.Type) {
		f.Type = ""
	}
	if _, ok := scopeExpr[f.Scope]; !ok {
		f.Scope = ""
	}
	f.FW, f.Tool, f.Level, f.Service, f.Msg, f.Policy = q.Get("fw"), q.Get("tool"), q.Get("level"), q.Get("service"), q.Get("msg"), q.Get("policy")
	f.Outcome, f.Action = q.Get("outcome"), strings.TrimSpace(q.Get("action"))
	f.User, f.Src, f.Dst = q.Get("user"), q.Get("src"), q.Get("dst")
	f.Category, f.App, f.Host, f.Risk, f.Q = q.Get("category"), q.Get("app"), q.Get("host"), q.Get("risk"), q.Get("q")
	return f
}

func likePattern(s string) string {
	s = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
	if strings.Contains(s, "*") {
		return strings.ReplaceAll(s, "*", "%")
	}
	return "%" + s + "%"
}

// ---------------------------------------------------------------- multi-value filters

// listItems splits a filter value into its items. IP filters may also be separated by spaces, ";" or new lines.
func listItems(val string, ipMode bool) []string {
	sep := func(r rune) bool {
		return r == ',' || (ipMode && (r == ' ' || r == ';' || r == '\n' || r == '\r' || r == '\t'))
	}
	var out []string
	for _, s := range strings.FieldsFunc(val, sep) {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

type filterItem struct {
	neg, exact bool
	v          string
}

func parseItem(s string) filterItem {
	var it filterItem
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "!") {
		it.neg, s = true, s[1:]
	}
	if strings.HasPrefix(s, "=") {
		it.exact, s = true, s[1:]
	}
	it.v = strings.TrimSpace(s)
	return it
}

func addArg(args *[]any, v any) string {
	*args = append(*args, v)
	return "$" + strconv.Itoa(len(*args))
}

// textCond: (any include matches) AND NOT (any exclude matches), over one or more columns.
// "=x" is an exact match (index friendly), plain text is a case-insensitive contains, "*" a wildcard.
func textCond(args *[]any, val string, split bool, cols ...string) string {
	val = strings.TrimSpace(val)
	if val == "" {
		return ""
	}
	items := []string{val}
	if split {
		items = listItems(val, false)
	}
	var incEq, incLike, excEq, excLike []string
	for _, s := range items {
		it := parseItem(s)
		if it.v == "" {
			continue
		}
		switch {
		case it.neg && it.exact:
			excEq = append(excEq, it.v)
		case it.neg:
			excLike = append(excLike, likePattern(it.v))
		case it.exact:
			incEq = append(incEq, it.v)
		default:
			incLike = append(incLike, likePattern(it.v))
		}
	}
	match := func(eq, like []string) string {
		var p []string
		if len(eq) > 0 {
			a := addArg(args, eq)
			for _, c := range cols {
				p = append(p, c+" = ANY("+a+"::text[])")
			}
		}
		if len(like) > 0 {
			a := addArg(args, like)
			for _, c := range cols {
				p = append(p, c+" ILIKE ANY("+a+"::text[])")
			}
		}
		return strings.Join(p, " OR ")
	}
	var conds []string
	if m := match(incEq, incLike); m != "" {
		conds = append(conds, "("+m+")")
	}
	if m := match(excEq, excLike); m != "" {
		conds = append(conds, "NOT coalesce(("+m+"), false)")
	}
	return strings.Join(conds, " AND ")
}

// ipCond: addresses use the btree index (= ANY), subnets use containment (<<= ANY), anything else
// (for example "10.1.") is a text match on the address.
func ipCond(args *[]any, val, col string) string {
	type set struct{ addr, nets, text []string }
	var inc, exc set
	for _, s := range listItems(val, true) {
		it := parseItem(s)
		if it.v == "" {
			continue
		}
		t := &inc
		if it.neg {
			t = &exc
		}
		if p, err := netip.ParsePrefix(it.v); err == nil {
			if p.IsSingleIP() {
				t.addr = append(t.addr, p.Addr().Unmap().String())
			} else {
				t.nets = append(t.nets, p.Masked().String())
			}
		} else if a, err := netip.ParseAddr(it.v); err == nil {
			t.addr = append(t.addr, a.Unmap().String())
		} else {
			t.text = append(t.text, likePattern(it.v))
		}
	}
	match := func(x set) string {
		var p []string
		if len(x.addr) > 0 {
			p = append(p, col+" = ANY("+addArg(args, x.addr)+"::text[]::inet[])")
		}
		if len(x.nets) > 0 && len(x.nets) <= maxRangeNets {
			// v6.0.1: one range per subnet ("col >= first AND col <= last") can use the index on the address column;
			// "col <<= ANY(array)" could not, so a site or zone filter (several subnets) scanned the whole period.
			for _, n := range x.nets {
				pp := netip.MustParsePrefix(n)
				p = append(p, "("+col+" >= "+addArg(args, pp.Addr().String())+"::inet AND "+col+" <= "+addArg(args, lastAddr(pp).String())+"::inet)")
			}
		} else if len(x.nets) > 0 {
			p = append(p, col+" <<= ANY("+addArg(args, x.nets)+"::text[]::inet[])")
		}
		if len(x.text) > 0 {
			p = append(p, "host("+col+") ILIKE ANY("+addArg(args, x.text)+"::text[])")
		}
		return strings.Join(p, " OR ")
	}
	var conds []string
	if m := match(inc); m != "" {
		conds = append(conds, "("+m+")")
	}
	if m := match(exc); m != "" {
		conds = append(conds, "NOT coalesce(("+m+"), false)")
	}
	return strings.Join(conds, " AND ")
}

func (f Filter) where() (string, []any) {
	args := []any{f.From, f.To}
	conds := []string{"event_time >= $1", "event_time < $2"}
	add := func(neg bool, sql string, v any) {
		args = append(args, v)
		c := strings.ReplaceAll(sql, "@", "$"+strconv.Itoa(len(args)))
		if neg {
			c = "NOT coalesce(" + c + ", false)"
		}
		conds = append(conds, c)
	}
	// Every text filter takes a list: "alice, bob, !=carol". Items are OR-ed, "!" items are excluded.
	text := func(val string, cols ...string) {
		if c := textCond(&args, val, true, cols...); c != "" {
			conds = append(conds, c)
		}
	}
	textOne := func(val string, cols ...string) { // free text that may itself contain commas (event messages)
		if c := textCond(&args, val, false, cols...); c != "" {
			conds = append(conds, c)
		}
	}
	// IP filters take addresses, subnets and partial text: "10.1.1.5, 10.2.0.0/16, !10.2.3.4"
	ip := func(val, col string) {
		if c := ipCond(&args, val, col); c != "" {
			conds = append(conds, c)
		}
	}
	if f.Scope != "" {
		conds = append(conds, "("+scopeExpr[f.Scope]+")")
	}
	if f.Type != "" {
		add(false, "log_type = @", f.Type)
	}
	if f.Subtype != "" {
		add(false, "subtype = @", f.Subtype)
	}
	text(f.FW, "device_name")
	text(f.Tool, "ai_tool")
	text(f.Level, "level")
	text(f.Service, "fields->>'service'")
	textOne(f.Msg, "fields->>'logdesc'")
	text(f.Policy, "policy_name", "policy_id::text")
	switch f.Outcome {
	case "blocked":
		conds = append(conds, blockedExpr)
	case "allowed":
		conds = append(conds, "NOT coalesce("+blockedExpr+", false)")
	}
	if f.Action != "" {
		neg := strings.HasPrefix(f.Action, "!")
		list := strings.Split(strings.TrimPrefix(f.Action, "!"), ",")
		for i := range list {
			list[i] = strings.TrimSpace(list[i])
		}
		add(neg, "action = ANY(@)", list)
	}
	text(f.User, "user_name")
	ip(f.Src, "src_ip")
	ip(f.Dst, "dst_ip")
	text(f.Category, "category")
	text(f.App, "application")
	text(f.Risk, "app_risk")
	text(f.Host, "hostname", "url")
	if strings.TrimSpace(f.Q) != "" {
		add(false, "raw_message ILIKE @", likePattern(strings.TrimSpace(f.Q)))
	}
	if f.Extra != "" {
		conds = append(conds, "("+f.Extra+")")
	}
	if f.Endpoint {
		conds = append(conds, zoneSQL()+" NOT IN "+deviceZones)
	}
	return strings.Join(conds, " AND "), args
}

// ---------------------------------------------------------------- queries

var dimExpr = map[string]string{
	"user":        "nullif(user_name,'')",
	"src_ip":      "host(src_ip)",
	"dst_ip":      "host(dst_ip)",
	"category":    "nullif(category,'')",
	"application": "nullif(application,'')",
	"hostname":    "nullif(hostname,'')",
	"action":      "nullif(action,'')",
	"risk":        "nullif(app_risk,'')",
	"dest":        "coalesce(nullif(hostname,''), host(dst_ip))",
	"country":     "nullif(fields->>'dstcountry','')",
	"type":        "nullif(log_type,'')",
	"subtype":     "nullif(subtype,'')",
	"fw":          "coalesce(nullif(device_name,''), host(source_ip))",
	"level":       "nullif(level,'')",
	"service":     "nullif(fields->>'service','')",
	"msg":         "nullif(fields->>'logdesc','')",
	"policy":      "coalesce(nullif(policy_name,''), nullif(policy_id,0)::text)",
	"tool":        "ai_tool",
}

func (d *Database) acquire(ctx context.Context) (func(), error) {
	select {
	case d.sem <- struct{}{}:
		dashActive.Add(1) // v6.0.1: background work waits while dashboards query
		dashLast.Store(time.Now().Unix())
		return func() { dashActive.Add(-1); dashLast.Store(time.Now().Unix()); <-d.sem }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

type Bucket struct {
	T       int64 `json:"t"`
	Total   int64 `json:"total"`
	Blocked int64 `json:"blocked"`
	Bytes   int64 `json:"bytes,omitempty"` // v5.10: data per bucket (download + upload)
	Sent    int64 `json:"sent,omitempty"`  // upload
}

func bucketSeconds(f Filter) int64 {
	switch span := f.To.Sub(f.From); {
	case span <= 2*time.Hour:
		return 60
	case span <= 12*time.Hour:
		return 300
	case span <= 48*time.Hour:
		return 900
	case span <= 7*24*time.Hour:
		return 3600
	default:
		return 14400
	}
}

// Overview answers the tiles, the timeline and the two low-cardinality lists (action, risk) in ONE pass
// using GROUPING SETS. Distinct counts for users / sources / hosts come for free from Top() (number of groups),
// which avoids three expensive count(DISTINCT ...) sorts over millions of rows.
func (d *Database) Overview(ctx context.Context, f Filter) (map[string]any, error) {
	rel, args := f.where()
	release, err := d.acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	step := bucketSeconds(f)
	rows, err := d.pool.Query(ctx, fmt.Sprintf(`SELECT GROUPING(b, a, r)::int, b, a, r, count(*), count(*) FILTER (WHERE blk), coalesce(sum(by),0)::bigint
		FROM (SELECT (floor(extract(epoch FROM event_time)/%d)*%d)::bigint AS b, nullif(action,'') AS a, nullif(app_risk,'') AS r,
		        coalesce(`+blockedExpr+`, false) AS blk, coalesce(fl_sent(log_id, fields, sent_bytes)+fl_rcvd(log_id, fields, received_bytes),0) AS by
		      FROM fortigate_logs WHERE `+rel+`) x
		GROUP BY GROUPING SETS ((b), (a), (r), ())`, step, step), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]any{"total": int64(0), "blocked": int64(0), "bytes": int64(0), "step": step, "from": f.From, "to": f.To}
	series, actions, risks := []Bucket{}, []map[string]any{}, []map[string]any{}
	for rows.Next() {
		var g int
		var b *int64
		var a, r *string
		var count, blocked, bytesN int64
		if err = rows.Scan(&g, &b, &a, &r, &count, &blocked, &bytesN); err != nil {
			return nil, err
		}
		switch g {
		case 3: // grouped by bucket
			if b == nil {
				continue
			}
			series = append(series, Bucket{T: *b, Total: count, Blocked: blocked})
		case 5: // grouped by action (NULL group = no action; skipped)
			if a == nil {
				continue
			}
			actions = append(actions, map[string]any{"name": *a, "count": count, "blocked": blocked, "bytes": bytesN})
		case 6: // grouped by risk (NULL group = logs without a risk, e.g. web filter)
			if r == nil {
				continue
			}
			risks = append(risks, map[string]any{"name": *r, "count": count, "blocked": blocked, "bytes": bytesN})
		case 7: // grand total
			out["total"], out["blocked"], out["bytes"] = count, blocked, bytesN
		}
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	sort.Slice(series, func(i, j int) bool { return series[i].T < series[j].T })
	byCount := func(l []map[string]any) []map[string]any {
		sort.Slice(l, func(i, j int) bool { return l[i]["count"].(int64) > l[j]["count"].(int64) })
		if len(l) > 10 {
			l = l[:10]
		}
		return l
	}
	out["series"], out["action"], out["risk"] = series, byCount(actions), byCount(risks)
	return out, nil
}

// Top returns the busiest values of one dimension plus the total number of distinct values (groups).
func (d *Database) Top(ctx context.Context, dim string, f Filter, limit int) ([]map[string]any, int64, error) {
	return d.TopBy(ctx, dim, f, limit, false)
}

func (d *Database) TopBy(ctx context.Context, dim string, f Filter, limit int, byBytes bool) ([]map[string]any, int64, error) {
	order := "cnt"
	if byBytes {
		order = "byt"
	}
	return d.TopOrder(ctx, dim, f, limit, order)
}

// TopOrder: order is cnt (events), byt (sent+received) or snt (sent only, i.e. uploads).
func (d *Database) TopOrder(ctx context.Context, dim string, f Filter, limit int, order string) ([]map[string]any, int64, error) {
	expr, ok := dimExpr[dim]
	if !ok {
		return nil, 0, fmt.Errorf("invalid dimension")
	}
	where, args := f.where()
	release, err := d.acquire(ctx)
	if err != nil {
		return nil, 0, err
	}
	defer release()
	args = append(args, limit)
	if order != "byt" && order != "snt" {
		order = "cnt"
	}
	rows, err := d.pool.Query(ctx, fmt.Sprintf(`SELECT name, cnt, blk, byt, snt, count(*) OVER (), rk FROM (
		SELECT %s AS name, count(*) AS cnt, count(*) FILTER (WHERE `+blockedExpr+`) AS blk,
		       coalesce(sum(fl_sent(log_id, fields, sent_bytes)+fl_rcvd(log_id, fields, received_bytes)),0)::bigint AS byt, coalesce(sum(fl_sent(log_id, fields, sent_bytes)),0)::bigint AS snt,
		       coalesce(max(`+riskRank+`),0)::bigint AS rk
		FROM fortigate_logs WHERE %s AND %s IS NOT NULL GROUP BY 1) t ORDER BY %s DESC LIMIT $%d`, expr, where, expr, order, len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []map[string]any{}
	var groups int64
	for rows.Next() {
		var name string
		var count, blocked, bytesN, sent, rk int64
		if err = rows.Scan(&name, &count, &blocked, &bytesN, &sent, &groups, &rk); err != nil {
			return nil, 0, err
		}
		out = append(out, map[string]any{"name": name, "count": count, "blocked": blocked, "bytes": bytesN, "sent": sent, "risk": rk})
	}
	return out, groups, rows.Err()
}

type LogRow struct {
	Time        time.Time `json:"time"`
	Subtype     string    `json:"subtype"`
	Action      string    `json:"action"`
	User        string    `json:"user"`
	SrcIP       string    `json:"src_ip"`
	DstIP       string    `json:"dst_ip"`
	Hostname    string    `json:"hostname"`
	URL         string    `json:"url"`
	Category    string    `json:"category"`
	Application string    `json:"application"`
	Risk        string    `json:"risk"`
	PolicyID    int       `json:"policy_id"`
	Bytes       int64     `json:"bytes"`
	Raw         string    `json:"raw"`
	Mapped      bool      `json:"mapped"`
	Type        string    `json:"type"`
	Device      string    `json:"fw"`
	AITool      string    `json:"tool"`
	UserSource  string    `json:"user_source"` // log, manual, nps
	Level       string    `json:"level"`
	Msg         string    `json:"msg"`
	Tags        []string  `json:"tags,omitempty"` // v6.0: site, zone, department, role
}

const logCols = `event_time, coalesce(subtype,''), coalesce(action,''), coalesce(user_name,''), coalesce(host(src_ip),''),
	coalesce(host(dst_ip),''), coalesce(hostname,''), coalesce(url,''), coalesce(category,''), coalesce(application,''),
	coalesce(app_risk,''), coalesce(policy_id,0), coalesce(sent_bytes+received_bytes,0), raw_message, map_id IS NOT NULL,
	coalesce(log_type,''), coalesce(nullif(device_name,''), host(source_ip)), coalesce(ai_tool,''),
	CASE WHEN map_id < 0 THEN 'assigned' WHEN map_id IS NOT NULL THEN 'manual' WHEN nps_id IS NOT NULL THEN 'nps' WHEN coalesce(user_name,'') <> '' THEN 'log' ELSE '' END,
	coalesce(level,''), coalesce(fields->>'logdesc', fields->>'msg', '')`

func (r *LogRow) scan(row interface{ Scan(...any) error }) error {
	return row.Scan(&r.Time, &r.Subtype, &r.Action, &r.User, &r.SrcIP, &r.DstIP, &r.Hostname, &r.URL, &r.Category,
		&r.Application, &r.Risk, &r.PolicyID, &r.Bytes, &r.Raw, &r.Mapped, &r.Type, &r.Device, &r.AITool, &r.UserSource, &r.Level, &r.Msg)
}

func (d *Database) Logs(ctx context.Context, f Filter, limit, offset int) ([]LogRow, bool, error) {
	where, args := f.where()
	release, err := d.acquire(ctx)
	if err != nil {
		return nil, false, err
	}
	defer release()
	args = append(args, limit+1, offset)
	rows, err := d.pool.Query(ctx, fmt.Sprintf(`SELECT %s FROM fortigate_logs WHERE %s ORDER BY event_time DESC, id DESC LIMIT $%d OFFSET $%d`,
		logCols, where, len(args)-1, len(args)), args...)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	out := []LogRow{}
	for rows.Next() {
		var r LogRow
		if err = r.scan(rows); err != nil {
			return nil, false, err
		}
		r.Tags = tagsFor(r.SrcIP, r.User, r.Device, r.Time)
		out = append(out, r)
	}
	more := len(out) > limit
	if more {
		out = out[:limit]
	}
	return out, more, rows.Err()
}

// csvSafe stops spreadsheet formula injection from URLs / user names in exported logs.
func csvSafe(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}

func (d *Database) ExportCSV(ctx context.Context, f Filter, w http.ResponseWriter, maxRows int) error {
	where, args := f.where()
	release, err := d.acquire(ctx)
	if err != nil {
		return err
	}
	defer release()
	args = append(args, maxRows)
	rows, err := d.pool.Query(ctx, fmt.Sprintf(`SELECT %s FROM fortigate_logs WHERE %s ORDER BY event_time DESC LIMIT $%d`, logCols, where, len(args)), args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="fortigate-logs-`+time.Now().Format("20060102-1504")+`.csv"`)
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"time", "firewall", "type", "subtype", "level", "action", "user", "user_source", "src_ip", "dst_ip", "hostname", "url", "category", "application", "ai_tool", "risk", "policy_id", "bytes", "message", "raw"})
	n := 0
	for rows.Next() {
		var r LogRow
		if err = r.scan(rows); err != nil {
			return err
		}
		_ = cw.Write([]string{r.Time.UTC().Format(time.RFC3339), csvSafe(r.Device), r.Type, r.Subtype, r.Level, r.Action, csvSafe(r.User), r.UserSource, r.SrcIP, r.DstIP,
			csvSafe(r.Hostname), csvSafe(r.URL), csvSafe(r.Category), csvSafe(r.Application), csvSafe(r.AITool), r.Risk, strconv.Itoa(r.PolicyID), strconv.FormatInt(r.Bytes, 10),
			csvSafe(r.Msg), csvSafe(r.Raw)})
		if n++; n%2000 == 0 {
			cw.Flush()
			if fl, ok := w.(http.Flusher); ok {
				fl.Flush()
			}
		}
	}
	cw.Flush()
	return rows.Err()
}

// ---------------------------------------------------------------- v6.0.1
const maxRangeNets = 64

// lastAddr: the last address of a (masked) prefix.
func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Masked().Addr().AsSlice()
	bits := p.Bits()
	for i := range b {
		lo := i * 8
		switch {
		case bits <= lo:
			b[i] = 0xff
		case bits < lo+8:
			b[i] |= byte(0xff >> uint(bits-lo))
		}
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}

// dashboards in use: queries running now, and when the last one finished
var dashActive atomic.Int64
var dashLast atomic.Int64

// dashboardsBusy: a dashboard query ran in the last 20 seconds (background history work waits).
func dashboardsBusy() bool {
	return dashActive.Load() > 0 || time.Now().Unix()-dashLast.Load() < 20
}
