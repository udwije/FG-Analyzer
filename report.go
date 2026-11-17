package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
)

// Custom reports: group the stored logs by up to three fields (and optionally by hour / day / week / month), pick the
// measures, filter with the same filter bar as the dashboards, sort, export to CSV, print, and save the definition.
//
// Where possible a report is answered from the summary tables (fast):
//   - rollup_5m: grouping by firewall / log type / subtype / severity only -> exact
//   - rollup_1h: firewall / log type + ONE of source IP, user, destination, application, service, policy, country,
//                action, AI tool, event message -> approximate for very long tails (per-hour top lists are kept)
// Everything else, distinct counts, first/last seen, and any filter other than firewall and log type scans the raw
// logs, with a 3-minute limit. "Exact" forces the raw scan.

type ReportSpec struct {
	Name    string   `json:"name"`
	Group   []string `json:"group"`   // up to 3 dimensions
	Bucket  string   `json:"bucket"`  // "", hour, day, week, month
	Metrics []string `json:"metrics"` // see reportMetrics
	Sort    string   `json:"sort"`    // a metric, a group field, or "bucket"
	Asc     bool     `json:"asc"`
	Limit   int      `json:"limit"`
	Exact   bool     `json:"exact"` // never use the summaries
}

type reportCol struct {
	Key   string `json:"key"`
	Label string `json:"label"`
	Kind  string `json:"kind"` // count, bytes, pct, time, text, seconds
}

var reportDims = map[string]reportCol{
	"fw":          {"fw", "Firewall", "text"},
	"type":        {"type", "Log type", "text"},
	"subtype":     {"subtype", "Subtype", "text"},
	"level":       {"level", "Severity", "text"},
	"action":      {"action", "Action", "text"},
	"user":        {"user", "User", "text"},
	"user_source": {"user_source", "Username from", "text"},
	"src_ip":      {"src_ip", "Source IP", "text"},
	"src_mac":     {"src_mac", "Source MAC", "text"},
	"dst_ip":      {"dst_ip", "Destination IP", "text"},
	"dst_port":    {"dst_port", "Destination port", "text"},
	"dest":        {"dest", "Destination (host or IP)", "text"},
	"hostname":    {"hostname", "Hostname", "text"},
	"category":    {"category", "Web category", "text"},
	"application": {"application", "Application", "text"},
	"risk":        {"risk", "App risk", "text"},
	"tool":        {"tool", "AI tool", "text"},
	"service":     {"service", "Service", "text"},
	"policy":      {"policy", "Firewall policy", "text"},
	"country":     {"country", "Destination country", "text"},
	"msg":         {"msg", "Event message", "text"},
	"vdom":        {"vdom", "VDOM", "text"},
	"zone":        {"zone", "Traffic direction", "text"},
}

var reportDimExpr = map[string]string{
	"user_source": `CASE WHEN map_id < 0 THEN 'assigned' WHEN map_id IS NOT NULL THEN 'manual' WHEN nps_id IS NOT NULL THEN 'nps' WHEN coalesce(user_name,'') <> '' THEN 'firewall' END`,
	"src_mac":     "nullif(src_mac,'')",
	"dst_port":    "nullif(dst_port,0)::text",
	"vdom":        "nullif(vdom,'')",
}

func init() { reportDimFuncs["zone"] = func() string { return "nullif(" + zoneSQL() + ",'')" } }

// reportDimFuncs: report fields whose SQL depends on the settings.
var reportDimFuncs = map[string]func() string{}

func dimSQL(k string) string {
	if fn, ok := reportDimFuncs[k]; ok {
		return fn()
	}
	if e, ok := reportDimExpr[k]; ok {
		return e
	}
	return dimExpr[k]
}

type metricDef struct {
	col reportCol
	sql string // over the raw table
	r   string // over a summary table ("" = not available there)
}

var reportMetrics = map[string]metricDef{
	"events":       {reportCol{"events", "Events", "count"}, "count(*)", "sum(cnt)"},
	"blocked":      {reportCol{"blocked", "Blocked", "count"}, "count(*) FILTER (WHERE " + blockedExpr + ")", "sum(blk)"},
	"allowed":      {reportCol{"allowed", "Allowed", "count"}, "count(*) FILTER (WHERE NOT coalesce(" + blockedExpr + ", false))", "sum(cnt) - sum(blk)"},
	"blocked_pct":  {reportCol{"blocked_pct", "Blocked %", "pct"}, "round(100.0 * count(*) FILTER (WHERE " + blockedExpr + ") / nullif(count(*),0), 1)", "round(100.0 * sum(blk) / nullif(sum(cnt),0), 1)"},
	"bytes":        {reportCol{"bytes", "Data (total)", "bytes"}, "coalesce(sum(fl_sent(log_id, fields, sent_bytes)+fl_rcvd(log_id, fields, received_bytes)),0)", "sum(byt)"},
	"sent":         {reportCol{"sent", "Upload", "bytes"}, "coalesce(sum(fl_sent(log_id, fields, sent_bytes)),0)", "sum(snt)"},
	"received":     {reportCol{"received", "Download", "bytes"}, "coalesce(sum(fl_rcvd(log_id, fields, received_bytes)),0)", "sum(byt) - sum(snt)"},
	"duration":     {reportCol{"duration", "Session time", "seconds"}, "coalesce(sum(duration_seconds),0)", ""},
	"users":        {reportCol{"users", "Distinct users", "count"}, "count(DISTINCT nullif(user_name,''))", ""},
	"sources":      {reportCol{"sources", "Distinct source IPs", "count"}, "count(DISTINCT src_ip)", ""},
	"destinations": {reportCol{"destinations", "Distinct destinations", "count"}, "count(DISTINCT coalesce(nullif(hostname,''), host(dst_ip)))", ""},
	"apps":         {reportCol{"apps", "Distinct applications", "count"}, "count(DISTINCT nullif(application,''))", ""},
	"first_seen":   {reportCol{"first_seen", "First seen", "time"}, "min(event_time)", ""},
	"last_seen":    {reportCol{"last_seen", "Last seen", "time"}, "max(event_time)", ""},
}

var r5mCols = map[string]string{"fw": "fw", "type": "log_type", "subtype": "subtype", "level": "nullif(level,'')", "zone": "nullif(zone,'')"}
var r1hCols = map[string]string{"fw": "fw", "type": "log_type"}
var r1hDims = map[string]bool{"src_ip": true, "user": true, "dest": true, "application": true, "service": true, "policy": true,
	"country": true, "action": true, "tool": true, "msg": true}

// specError: the report definition is wrong (HTTP 400), as opposed to a database problem.
type specError struct{ msg string }

func (e specError) Error() string { return e.msg }

func specErr(format string, a ...any) error { return specError{fmt.Sprintf(format, a...)} }

func (s *ReportSpec) validate() error {
	if len(s.Group) > 3 {
		return specErr("group by at most 3 fields")
	}
	seen := map[string]bool{}
	for _, g := range s.Group {
		if _, ok := reportDims[g]; !ok {
			return specErr("unknown field %q", g)
		}
		if seen[g] {
			return specErr("%q is listed twice", g)
		}
		seen[g] = true
	}
	switch s.Bucket {
	case "", "hour", "day", "week", "month":
	default:
		return specErr("unknown time grouping %q", s.Bucket)
	}
	if len(s.Metrics) == 0 {
		s.Metrics = []string{"events"}
	}
	ms := map[string]bool{}
	for _, m := range s.Metrics {
		if _, ok := reportMetrics[m]; !ok {
			return specErr("unknown measure %q", m)
		}
		if ms[m] {
			return specErr("%q is listed twice", m)
		}
		ms[m] = true
	}
	if s.Sort == "" {
		s.Sort = s.Metrics[0]
	}
	if !ms[s.Sort] && !seen[s.Sort] && !(s.Sort == "bucket" && s.Bucket != "") {
		return specErr("sort by %q: choose one of the shown columns", s.Sort)
	}
	if s.Limit < 1 {
		s.Limit = 100
	}
	if s.Limit > 5000 {
		s.Limit = 5000
	}
	if len(s.Name) > 120 {
		s.Name = s.Name[:120]
	}
	return nil
}

// reportTZ: day / week buckets follow the local calendar (systemd sets TZ=Asia/Colombo).
func reportTZ() string {
	if tz := os.Getenv("TZ"); tz != "" && !strings.ContainsAny(tz, "'\\") {
		return strings.TrimPrefix(tz, ":")
	}
	if n := time.Local.String(); n != "" && n != "Local" {
		return n
	}
	return "UTC"
}

// sessionTZ: the zone for database sessions, or "" to keep the server default (unknown local zone, e.g. Windows
// without TZ set). Unlike reportTZ it never falls back to UTC, which would shift a Windows install that relies on
// the PostgreSQL server's own (local) setting.
func sessionTZ() string {
	if tz := strings.TrimPrefix(os.Getenv("TZ"), ":"); tz != "" && !strings.ContainsAny(tz, "'\\") {
		if _, err := time.LoadLocation(tz); err == nil {
			return tz
		}
	}
	if n := time.Local.String(); n != "" && n != "Local" && n != "UTC" {
		return n
	}
	return ""
}

// filterIsSimple: only firewall and log type are filtered, so the summary tables can answer.
func filterIsSimple(f Filter) bool {
	if f.Q != "" || f.Scope != "" || f.Subtype != "" || f.Outcome != "" || f.Action != "" || f.Extra != "" {
		return false
	}
	for _, v := range []string{f.User, f.Src, f.Dst, f.Category, f.App, f.Host, f.Risk, f.Tool, f.Level, f.Service, f.Msg, f.Policy} {
		if strings.TrimSpace(v) != "" {
			return false
		}
	}
	return roll.covers(hourStart(f.From))
}

// reportSource picks "5m", "1h" or "raw".
func reportSource(s ReportSpec, f Filter) (src, dim1h string) {
	if s.Exact || !filterIsSimple(f) {
		return "raw", ""
	}
	for _, m := range s.Metrics {
		if reportMetrics[m].r == "" {
			return "raw", ""
		}
	}
	only5m := true
	for _, g := range s.Group {
		if _, ok := r5mCols[g]; !ok {
			only5m = false
		}
	}
	if only5m {
		return "5m", ""
	}
	for _, g := range s.Group {
		if _, ok := r1hCols[g]; ok {
			continue
		}
		if r1hDims[g] && dim1h == "" {
			dim1h = g
			continue
		}
		return "raw", ""
	}
	return "1h", dim1h
}

type ReportResult struct {
	Spec    ReportSpec     `json:"spec"`
	Columns []reportCol    `json:"columns"`
	Rows    [][]any        `json:"rows"`
	Totals  map[string]any `json:"totals"`
	Groups  int64          `json:"groups"` // rows before the limit
	Source  string         `json:"source"` // raw, summary, summary-approx
	From    time.Time      `json:"from"`
	To      time.Time      `json:"to"`
	TookMS  int64          `json:"took_ms"`
	Note    string         `json:"note,omitempty"`
}

func (d *Database) RunReport(ctx context.Context, s ReportSpec, f Filter) (*ReportResult, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	start := time.Now()
	src, dim1h := reportSource(s, f)
	res := &ReportResult{Spec: s, From: f.From, To: f.To}

	var from, where string
	var args []any
	keyExpr := map[string]string{}
	metricExpr := func(m string) string { return reportMetrics[m].sql }
	timeCol := "event_time"
	switch src {
	case "5m":
		where, args = rollWhere(f, "bucket", f.From.Truncate(5*time.Minute), f.To)
		from, timeCol = "rollup_5m", "bucket"
		for _, g := range s.Group {
			keyExpr[g] = r5mCols[g]
		}
		metricExpr = func(m string) string { return reportMetrics[m].r }
		res.Source = "summary"
		res.Note = "From the 5-minute summaries (exact counts)."
	case "1h":
		fromH := hourStart(f.From)
		args = []any{}
		d.loadDaysDone(ctx)
		from = rollSource(f, fromH, f.To, []string{dim1h}, &args, s.Bucket == "hour") // v5.13: finished days from rollup_1d
		where, timeCol = "true", "hour"
		for _, g := range s.Group {
			if c, ok := r1hCols[g]; ok {
				keyExpr[g] = c
			} else {
				keyExpr[g] = "name"
			}
		}
		metricExpr = func(m string) string { return reportMetrics[m].r }
		res.Source = "summary-approx"
		res.Note = "From the hourly summaries: totals start at " + fromH.Format("2006-01-02 15:04") +
			". Values outside each hour's busiest few thousand are not counted, so very small rows may be missing. Tick Exact for a full scan."
	default:
		where, args = f.where()
		from = "fortigate_logs"
		for _, g := range s.Group {
			keyExpr[g] = dimSQL(g)
		}
		res.Source = "raw"
	}

	// keys: the GROUP BY expressions (repeated verbatim in SELECT and GROUPING so PostgreSQL matches them)
	var keys, sel []string
	if s.Bucket != "" {
		tz := addArg(&args, reportTZ())
		unit := addArg(&args, s.Bucket)
		keys = append(keys, fmt.Sprintf("date_trunc(%s::text, %s, %s::text)", unit, timeCol, tz))
		res.Columns = append(res.Columns, reportCol{"bucket", map[string]string{"hour": "Hour", "day": "Day", "week": "Week starting", "month": "Month"}[s.Bucket], "time"})
	}
	for _, g := range s.Group {
		keys = append(keys, fmt.Sprintf("coalesce((%s)::text, '(none)')", keyExpr[g]))
		res.Columns = append(res.Columns, reportDims[g])
	}
	for i, k := range keys {
		sel = append(sel, fmt.Sprintf("%s AS c%d", k, i))
	}
	for i, m := range s.Metrics {
		sel = append(sel, fmt.Sprintf("%s AS c%d", metricExpr(m), len(keys)+i))
		res.Columns = append(res.Columns, reportMetrics[m].col)
	}
	sortCol := "c0"
	for i, c := range res.Columns {
		if c.Key == s.Sort {
			sortCol = fmt.Sprintf("c%d", i)
		}
	}
	dir := "DESC NULLS LAST"
	if s.Asc {
		dir = "ASC NULLS LAST"
	}
	gflag, grouping := "0", "()"
	if len(keys) > 0 {
		gflag = "GROUPING(" + strings.Join(keys, ", ") + ")"
		grouping = "(" + strings.Join(keys, ", ") + "), ()"
	}
	cols := make([]string, len(res.Columns))
	for i := range cols {
		cols[i] = fmt.Sprintf("c%d", i)
	}
	// GROUPING SETS gives the per-row figures and the true grand total (distinct counts included) in one scan.
	lim := addArg(&args, s.Limit)
	q := fmt.Sprintf(`WITH g AS (SELECT %s, %s AS is_total FROM %s WHERE %s GROUP BY GROUPING SETS (%s))
		SELECT * FROM (SELECT %s, true AS t, 1::bigint AS n, 0::bigint AS o FROM g WHERE is_total <> 0 OR %d = 0) tot
		UNION ALL
		SELECT * FROM (SELECT %s, false, count(*) OVER (), row_number() OVER (ORDER BY %s %s) FROM g WHERE is_total = 0 AND %d > 0
			ORDER BY %s %s LIMIT %s) r
		ORDER BY t DESC, o`,
		strings.Join(sel, ", "), gflag, from, where, grouping,
		strings.Join(cols, ", "), len(keys),
		strings.Join(cols, ", "), sortCol, dir, len(keys), sortCol, dir, lim)

	release, err := d.acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, "SET LOCAL statement_timeout = '180s'"); err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, q, args...)
	if err != nil {
		return nil, timeoutMsg(err)
	}
	defer rows.Close()
	res.Rows = [][]any{}
	n := len(res.Columns)
	for rows.Next() {
		vals, err := rows.Values()
		if err != nil {
			return nil, err
		}
		isTotal, _ := vals[n].(bool)
		cnt, _ := vals[n+1].(int64)
		out := make([]any, n)
		for i := 0; i < n; i++ {
			out[i] = normValue(vals[i])
		}
		if isTotal {
			res.Totals = map[string]any{}
			for i, c := range res.Columns {
				if _, ok := reportMetrics[c.Key]; ok {
					res.Totals[c.Key] = out[i]
				}
			}
			if len(keys) == 0 {
				res.Rows = append(res.Rows, out)
				res.Groups = 1
			}
			continue
		}
		res.Groups = cnt
		res.Rows = append(res.Rows, out)
	}
	if err = rows.Err(); err != nil {
		return nil, timeoutMsg(err)
	}
	res.TookMS = time.Since(start).Milliseconds()
	return res, nil
}

func timeoutMsg(err error) error {
	if err != nil && strings.Contains(err.Error(), "57014") && !strings.Contains(err.Error(), "unable to encode") {
		return errors.New("the report took longer than 3 minutes: shorten the period, add filters, or group by fewer fields")
	}
	return err
}

// normValue makes results JSON-friendly: sum() and round() return PostgreSQL numeric (pgtype.Numeric in pgx).
func normValue(v any) any {
	switch x := v.(type) {
	case pgtype.Numeric:
		if !x.Valid {
			return nil
		}
		if x.Exp >= 0 {
			if i, err := x.Int64Value(); err == nil && i.Valid {
				return i.Int64
			}
		}
		if f, err := x.Float64Value(); err == nil && f.Valid {
			return f.Float64
		}
		return nil
	case *pgtype.Numeric:
		if x == nil {
			return nil
		}
		return normValue(*x)
	case int32:
		return int64(x)
	case int16:
		return int64(x)
	default:
		return v
	}
}

// ---------------------------------------------------------------- saved reports

type SavedReport struct {
	ID      int64      `json:"id"`
	Name    string     `json:"name"`
	Owner   string     `json:"owner"`
	Shared  bool       `json:"shared"`
	Spec    ReportSpec `json:"spec"`
	Filters string     `json:"filters"` // the dashboard filter query string (period, firewall, IPs ...)
	Updated time.Time  `json:"updated"`
}

func (d *Database) ListReports(ctx context.Context, user string) ([]SavedReport, error) {
	rows, err := d.pool.Query(ctx, `SELECT id, name, owner, shared, spec, filters, updated FROM report_defs
		WHERE owner = $1 OR shared ORDER BY name`, user)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SavedReport{}
	for rows.Next() {
		var r SavedReport
		var spec []byte
		if err = rows.Scan(&r.ID, &r.Name, &r.Owner, &r.Shared, &spec, &r.Filters, &r.Updated); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(spec, &r.Spec)
		out = append(out, r)
	}
	return out, rows.Err()
}

func readSpec(w http.ResponseWriter, r *http.Request) (ReportSpec, bool) {
	var s ReportSpec
	if err := json.Unmarshal([]byte(r.URL.Query().Get("spec")), &s); err != nil {
		jsonError(w, http.StatusBadRequest, "bad report definition")
		return s, false
	}
	return s, true
}

func reportErr(w http.ResponseWriter, err error) {
	var se specError
	if errors.As(err, &se) {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	queryErr(w, err)
}

func (a *App) handleReport(w http.ResponseWriter, r *http.Request) {
	d := a.dbOrFail(w)
	if d == nil {
		return
	}
	s, ok := readSpec(w, r)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 200*time.Second)
	defer cancel()
	v, err := cached("report?"+r.URL.RawQuery, 60*time.Second, func() (any, error) { return d.RunReport(ctx, s, parseFilter(r)) })
	if err != nil {
		reportErr(w, err)
		return
	}
	jsonOut(w, v)
}

func (a *App) handleReportCSV(w http.ResponseWriter, r *http.Request) {
	d := a.dbOrFail(w)
	if d == nil {
		return
	}
	s, ok := readSpec(w, r)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 200*time.Second)
	defer cancel()
	f := parseFilter(r)
	res, err := d.RunReport(ctx, s, f)
	if err != nil {
		reportErr(w, err)
		return
	}
	a.audit(r, "report_export", s.Name)
	name := strings.Map(func(c rune) rune {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' {
			return c
		}
		return '-'
	}, firstNonEmpty(s.Name, "report"))
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`-`+time.Now().Format("20060102-1504")+`.csv"`)
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"# " + firstNonEmpty(s.Name, "Report"), "from " + f.From.Local().Format("2006-01-02 15:04"), "to " + f.To.Local().Format("2006-01-02 15:04"), "source " + res.Source})
	head := []string{}
	for _, c := range res.Columns {
		head = append(head, c.Label)
	}
	_ = cw.Write(head)
	for _, row := range res.Rows {
		rec := make([]string, len(row))
		for i, v := range row {
			switch x := v.(type) {
			case nil:
				rec[i] = ""
			case time.Time:
				rec[i] = x.Local().Format("2006-01-02 15:04")
			case string:
				rec[i] = csvSafe(x)
			default:
				rec[i] = fmt.Sprint(x)
			}
		}
		_ = cw.Write(rec)
	}
	cw.Flush()
}

// /api/reports: GET list (own + shared), POST save {id?, name, spec, filters, shared}, DELETE ?id=
func (a *App) handleReports(w http.ResponseWriter, r *http.Request) {
	d := a.dbOrFail(w)
	if d == nil {
		return
	}
	me := sessionFrom(r.Context())
	isAdmin := roleOf(me.Role) >= RoleAdmin
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	switch r.Method {
	case http.MethodGet:
		l, err := d.ListReports(ctx, me.User)
		if err != nil {
			queryErr(w, err)
			return
		}
		jsonOut(w, l)
	case http.MethodPost:
		var in SavedReport
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&in); err != nil {
			jsonError(w, http.StatusBadRequest, "bad request")
			return
		}
		in.Name = strings.TrimSpace(in.Name)
		if in.Name == "" || len(in.Name) > 120 {
			jsonError(w, http.StatusBadRequest, "give the report a name (up to 120 characters)")
			return
		}
		in.Spec.Name = in.Name
		if err := in.Spec.validate(); err != nil {
			jsonError(w, http.StatusBadRequest, err.Error())
			return
		}
		if len(in.Filters) > 4000 {
			jsonError(w, http.StatusBadRequest, "filters too long")
			return
		}
		spec, _ := json.Marshal(in.Spec)
		id := in.ID
		if in.ID > 0 {
			tag, err := d.pool.Exec(ctx, `UPDATE report_defs SET name=$2, spec=$3, filters=$4, shared=$5, updated=now()
				WHERE id=$1 AND (owner=$6 OR $7)`, in.ID, in.Name, spec, in.Filters, in.Shared, me.User, isAdmin)
			if err != nil {
				queryErr(w, err)
				return
			}
			if tag.RowsAffected() == 0 {
				jsonError(w, http.StatusForbidden, "only the owner (or an admin) can change this report; save it under a new name")
				return
			}
		} else if err := d.pool.QueryRow(ctx, `INSERT INTO report_defs(name, owner, shared, spec, filters) VALUES ($1,$2,$3,$4,$5) RETURNING id`,
			in.Name, me.User, in.Shared, spec, in.Filters).Scan(&id); err != nil {
			queryErr(w, err)
			return
		}
		a.audit(r, "report_saved", in.Name)
		jsonOut(w, map[string]any{"id": id})
	case http.MethodDelete:
		id, _ := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
		t, err := d.pool.Exec(ctx, `DELETE FROM report_defs WHERE id=$1 AND (owner=$2 OR $3)`, id, me.User, isAdmin)
		if err != nil {
			queryErr(w, err)
			return
		}
		if t.RowsAffected() == 0 {
			jsonError(w, http.StatusForbidden, "only the owner (or an admin) can delete this report")
			return
		}
		a.audit(r, "report_deleted", strconv.FormatInt(id, 10))
		jsonOut(w, map[string]bool{"ok": true})
	default:
		jsonError(w, http.StatusMethodNotAllowed, "method")
	}
}

// /api/report/fields: what the builder can offer.
func (a *App) handleReportFields(w http.ResponseWriter, r *http.Request) {
	dims := []reportCol{}
	for _, k := range []string{"fw", "type", "subtype", "level", "action", "user", "user_source", "src_ip", "src_mac", "dst_ip", "dst_port", "dest",
		"hostname", "category", "application", "risk", "tool", "service", "policy", "country", "msg", "vdom", "zone"} {
		dims = append(dims, reportDims[k])
	}
	ms := []map[string]any{}
	for _, k := range []string{"events", "blocked", "allowed", "blocked_pct", "bytes", "sent", "received", "duration", "users", "sources", "destinations", "apps", "first_seen", "last_seen"} {
		m := reportMetrics[k]
		ms = append(ms, map[string]any{"key": k, "label": m.col.Label, "kind": m.col.Kind, "fast": m.r != ""})
	}
	jsonOut(w, map[string]any{"dims": dims, "metrics": ms, "tz": reportTZ()})
}
