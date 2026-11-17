package main

import (
	"context"
	"fmt"
	"net/http"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// AI classification. Every log is tagged at ingest with ai_tool (NULL = not AI):
//  1. the first AI rule whose pattern matches the application or hostname names the tool;
//  2. otherwise, if the FortiGuard category is an AI category, the tool is the application
//     (when it is a real name) or the site's domain, so unknown AI services still show up by name.
// Patterns: plain text = contains (case-insensitive); with * = whole-value wildcard (e.g. *.x.ai).
// The same rules are turned into SQL for "Re-classify", so stored and live results always agree.

type aiMatcher struct {
	tool string
	res  []*regexp.Regexp
	pats []string
}

type aiRules struct {
	cats  map[string]bool
	rules []aiMatcher
	raw   []AIRule
	rcats []string
}

var aiCur atomic.Pointer[aiRules]

func patternRegexp(p string) *regexp.Regexp {
	p = strings.ToLower(strings.TrimSpace(p))
	if strings.Contains(p, "*") {
		parts := strings.Split(p, "*")
		for i := range parts { parts[i] = regexp.QuoteMeta(parts[i]) }
		return regexp.MustCompile("^" + strings.Join(parts, ".*") + "$")
	}
	// Domain-looking patterns use DNS label boundaries rather than substring matching.
	// This makes x.ai match x.ai and api.x.ai, but not notx.ai. Non-domain application
	// patterns retain the existing contains semantics.
	if strings.Contains(p, ".") && !strings.ContainsAny(p, " /:_") {
		return regexp.MustCompile(`(^|\.)` + regexp.QuoteMeta(strings.TrimSuffix(p, ".")) + `$`)
	}
	return regexp.MustCompile(regexp.QuoteMeta(p))
}

func setAIRules(cats []string, rules []AIRule) {
	r := &aiRules{cats: map[string]bool{}, raw: rules, rcats: cats}
	for _, c := range cats {
		if c = strings.ToLower(strings.TrimSpace(c)); c != "" {
			r.cats[c] = true
		}
	}
	for _, rule := range rules {
		m := aiMatcher{tool: strings.TrimSpace(rule.Tool)}
		for _, p := range rule.Patterns {
			if strings.TrimSpace(p) == "" {
				continue
			}
			m.res = append(m.res, patternRegexp(p))
			m.pats = append(m.pats, strings.TrimSpace(p))
		}
		if m.tool != "" && len(m.res) > 0 {
			r.rules = append(r.rules, m)
		}
	}
	aiCur.Store(r)
}

// rootDomain returns a registrable-style domain using a conservative embedded suffix set.
// It fixes known grouping collisions without introducing an online dependency; PSL-backed
// resolution can replace this table when the project adopts x/net/publicsuffix.
var multiLabelSuffix = map[string]bool{
	"co.uk":true,"org.uk":true,"ac.uk":true,"gov.uk":true,
	"com.lk":true,"org.lk":true,"edu.lk":true,"gov.lk":true,"net.lk":true,
	"com.au":true,"net.au":true,"org.au":true,"co.nz":true,"co.jp":true,"co.in":true,
}
func rootDomain(h string) string {
	h = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(h)), ".")
	if h == "" || net.ParseIP(h) != nil { return h }
	l := strings.Split(h, ".")
	if len(l) <= 2 { return h }
	suffix := strings.Join(l[len(l)-2:], ".")
	if multiLabelSuffix[suffix] && len(l) >= 3 { return strings.Join(l[len(l)-3:], ".") }
	return suffix
}

func classifyAI(app, host, category, catID string) string {
	r := aiCur.Load()
	if r == nil {
		return ""
	}
	a, h := strings.ToLower(app), strings.ToLower(host)
	for _, m := range r.rules {
		for _, re := range m.res {
			if (a != "" && re.MatchString(a)) || (h != "" && re.MatchString(h)) {
				return m.tool
			}
		}
	}
	if r.cats[strings.ToLower(category)] || (catID != "" && r.cats[catID]) {
		if app != "" && !aiGenericApp.MatchString(app) {
			return app
		}
		if host != "" {
			return rootDomain(host)
		}
		return "Other AI"
	}
	return ""
}

// ---------------------------------------------------------------- re-classify stored logs

// aiGenericApp: application names that do not name a tool. Must match the regular expression in aiCaseSQL.
var aiGenericApp = regexp.MustCompile(`(?i)^(ssl|tls|quic|unknown|https?)([_.+ -]|$)`)

func sqlLike(p string) string { return likePattern(strings.TrimSpace(p)) }

// aiCaseSQL renders the current rules as a SQL CASE expression; args are appended to args.
func aiCaseSQL(args *[]any) string {
	r := aiCur.Load()
	if r == nil {
		return "NULL"
	}
	arg := func(v any) string { *args = append(*args, v); return "$" + strconv.Itoa(len(*args)) }
	var b strings.Builder
	b.WriteString("CASE")
	for _, m := range r.rules {
		likes := make([]string, len(m.pats))
		for i, p := range m.pats {
			likes[i] = sqlLike(strings.ToLower(p))
		}
		pa := arg(likes)
		fmt.Fprintf(&b, " WHEN lower(coalesce(application,'')) LIKE ANY(%s::text[]) OR lower(coalesce(hostname,'')) LIKE ANY(%s::text[]) THEN %s", pa, pa, arg(m.tool))
	}
	cats := []string{}
	for c := range r.cats {
		cats = append(cats, c)
	}
	if len(cats) > 0 {
		pc := arg(cats)
		fmt.Fprintf(&b, ` WHEN lower(coalesce(category,'')) = ANY(%s::text[]) OR coalesce(fields->>'cat','') = ANY(%s::text[]) THEN coalesce(
			CASE WHEN application <> '' AND NOT (application ~* '^(ssl|tls|quic|unknown|https?)([_.+ -]|$)') THEN application END,
			nullif(substring(lower(hostname) from '([^.]+\.[^.]{2,3}\.[^.]{2}|[^.]+\.[^.]+)$'),''), 'Other AI')`, pc, pc)
	}
	b.WriteString(" END")
	return b.String()
}

type reclassState struct {
	mu      sync.Mutex
	running bool
	Done    int    `json:"days_done"`
	Total   int    `json:"days_total"`
	Hours   int    `json:"hours_done"`
	Rows    int64  `json:"rows_changed"`
	Err     string `json:"error,omitempty"`
	Note    string `json:"note,omitempty"`
	Started time.Time
}

var reclass reclassState

// isCompressedErr: older TimescaleDB versions refuse UPDATE on compressed chunks.
func isCompressedErr(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "compressed")
}

// Reclassify re-applies the AI rules to stored logs, one HOUR at a time, newest first (v5.10: was one day per
// statement, which held a long transaction over tens of millions of rows). The summaries of each hour are rebuilt
// as it goes, so the AI tabs update while it runs. If TimescaleDB refuses to change compressed chunks, it stops
// there and says so instead of failing.
func (d *Database) Reclassify(ctx context.Context, days int) {
	defer func() { reclass.mu.Lock(); reclass.running = false; reclass.mu.Unlock() }()
	end := hourStart(time.Now()).Add(time.Hour)
	for i := 0; i < days*24; i++ {
		to := end.Add(-time.Duration(i) * time.Hour)
		from := to.Add(-time.Hour)
		args := []any{from, to}
		expr := aiCaseSQL(&args)
		tag, err := d.pool.Exec(ctx, `UPDATE fortigate_logs SET ai_tool = x.t FROM (SELECT id, event_time, `+expr+` AS t FROM fortigate_logs
			WHERE event_time >= $1 AND event_time < $2) x WHERE fortigate_logs.id = x.id AND fortigate_logs.event_time = x.event_time
			AND fortigate_logs.event_time >= $1 AND fortigate_logs.event_time < $2 AND fortigate_logs.ai_tool IS DISTINCT FROM x.t`, args...)
		reclass.mu.Lock()
		if err != nil {
			if isCompressedErr(err) && i > 0 {
				reclass.Note = fmt.Sprintf("Stopped at %s: older logs are compressed and this TimescaleDB version cannot change them. "+
					"Newer logs were re-classified.", from.Format("2 Jan 15:04"))
			} else {
				reclass.Err = err.Error()
			}
			reclass.mu.Unlock()
			clearCache()
			return
		}
		reclass.Hours, reclass.Done, reclass.Rows = i+1, (i+1)/24, reclass.Rows+tag.RowsAffected()
		reclass.mu.Unlock()
		if tag.RowsAffected() > 0 {
			markRollupDirty(from, to)
		}
	}
	clearCache()
}

// /api/ai/defaults: the built-in AI rules, so Settings can add the ones an older config is missing.
func (a *App) handleAIDefaults(w http.ResponseWriter, r *http.Request) {
	jsonOut(w, map[string]any{"rules": defaultAIRules(), "categories": defaultConfig("").AICategories})
}

func (a *App) handleReclassify(w http.ResponseWriter, r *http.Request) {
	reclass.mu.Lock()
	defer reclass.mu.Unlock()
	if r.Method == http.MethodGet {
		jsonOut(w, map[string]any{"running": reclass.running, "days_done": reclass.Done, "days_total": reclass.Total, "hours_done": reclass.Hours,
			"rows_changed": reclass.Rows, "error": reclass.Err, "note": reclass.Note})
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	d := a.dbOrFail(w)
	if d == nil {
		return
	}
	if reclass.running {
		http.Error(w, "a re-classification is already running", http.StatusConflict)
		return
	}
	days, _ := strconv.Atoi(r.URL.Query().Get("days"))
	if days < 1 || days > 400 {
		days = 7
	}
	reclass.running, reclass.Done, reclass.Total, reclass.Hours, reclass.Rows, reclass.Err, reclass.Note, reclass.Started = true, 0, days, 0, 0, "", "", time.Now()
	go d.Reclassify(context.Background(), days)
	jsonOut(w, map[string]any{"started": true, "days": days})
}
