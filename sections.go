package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"
)

// v6.0: Settings are saved one section at a time.
//
// PUT /api/config/section {"values": {"alerts": {...}}} replaces only the named top-level settings. Everything else is
// taken from the stored configuration, so saving one section can never change (or blank) another one: the class of
// bugs where a Save in one card lost the WAN passphrases is closed by design. Every save is written to the audit log
// with the fields that changed, and GET /api/config/history?section=alerts lists those changes.

// sectionKeys: the top-level settings a section save may replace (blocklist and accounts have their own API).
var sectionKeys = map[string]bool{
	"listen_address": true, "web_listen_address": true, "tcp_enabled": true, "udp_enabled": true, "allowed_sources": true,
	"keep_subtypes": true, "batch_size": true, "retention_days": true, "spool_directory": true, "spool_max_mb": true,
	"compress_after_days": true, "query_concurrency": true, "session_hours": true, "web_tls": true, "tls_cert_file": true,
	"tls_key_file": true, "firewalls": true, "ai_categories": true, "ai_rules": true, "nps": true, "database": true,
	"exec": true, "internal_networks": true, "infra_networks": true, "tunnel_interfaces": true, "wan": true,
	"directory": true, "alerts": true, "sites": true,
}

// secretKey: never written to the audit log.
func secretKey(k string) bool {
	k = strings.ToLower(k)
	return strings.Contains(k, "pass") || strings.Contains(k, "token") || strings.Contains(k, "secret")
}

// mergeSection returns old with the given top-level settings replaced, decoded into a fresh value (no shared slices).
func mergeSection(old Config, values map[string]json.RawMessage) (Config, error) {
	var c Config
	b, err := json.Marshal(old)
	if err != nil {
		return c, err
	}
	m := map[string]json.RawMessage{}
	if err = json.Unmarshal(b, &m); err != nil {
		return c, err
	}
	for k, v := range values {
		if !sectionKeys[k] {
			return c, specErr("%q cannot be saved here", k)
		}
		m[k] = v
	}
	if b, err = json.Marshal(m); err != nil {
		return c, err
	}
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err = dec.Decode(&c); err != nil {
		return c, specErr("%v", err)
	}
	if _, ok := values["database"]; ok && c.Database.Password == "" {
		c.Database.Password = old.Database.Password
	}
	if _, ok := values["wan"]; ok {
		keepWANSecrets(&c.WAN, old.WAN)
	}
	c.AdminToken = old.AdminToken
	return c, nil
}

// flatten: "a.b.c" -> value, for the change list.
func flatten(prefix string, v any, out map[string]string) {
	switch x := v.(type) {
	case map[string]any:
		for k, y := range x {
			flatten(prefix+"."+k, y, out)
		}
	case []any:
		if len(x) == 0 {
			out[prefix] = "[]"
			return
		}
		for i, y := range x {
			flatten(fmt.Sprintf("%s[%d]", prefix, i), y, out)
		}
	default:
		out[prefix] = fmt.Sprint(x)
	}
}

// configDiff lists what changed between two configurations, for the given top-level keys (secrets left out).
func configDiff(old, cur Config, keys []string) []string {
	get := func(c Config) map[string]any {
		b, _ := json.Marshal(c)
		m := map[string]any{}
		_ = json.Unmarshal(b, &m)
		return m
	}
	om, nm := get(old), get(cur)
	var out []string
	for _, k := range keys {
		a, b := map[string]string{}, map[string]string{}
		flatten(k, om[k], a)
		flatten(k, nm[k], b)
		seen := map[string]bool{}
		for p := range a {
			seen[p] = true
		}
		for p := range b {
			seen[p] = true
		}
		var ps []string
		for p := range seen {
			ps = append(ps, p)
		}
		sort.Strings(ps)
		for _, p := range ps {
			last := p[strings.LastIndex(p, ".")+1:]
			if strings.HasSuffix(p, "_set") || a[p] == b[p] {
				continue
			}
			if secretKey(last) || secretKey(p) {
				// the value is never written; only the fact that it changed
				out = append(out, strings.TrimPrefix(p, k+".")+": secret changed")
				continue
			}
			out = append(out, fmt.Sprintf("%s: %s → %s", strings.TrimPrefix(p, k+"."), dash(a[p]), dash(b[p])))
		}
	}
	return out
}

func dash(s string) string {
	if s == "" || s == "<nil>" {
		return "–"
	}
	return s
}

// restartNeeded: settings that only take effect after a service restart.
func restartNeeded(c, old Config) bool {
	return c.ListenAddress != old.ListenAddress || c.WebListenAddress != old.WebListenAddress || c.TCPEnabled != old.TCPEnabled ||
		c.UDPEnabled != old.UDPEnabled || fmt.Sprint(c.AllowedSources, c.KeepSubtypes, c.Firewalls) != fmt.Sprint(old.AllowedSources, old.KeepSubtypes, old.Firewalls) ||
		c.Database != old.Database || c.QueueCapacity != old.QueueCapacity || c.BatchSize != old.BatchSize || c.WebTLS != old.WebTLS ||
		c.TLSCertFile != old.TLSCertFile || c.TLSKeyFile != old.TLSKeyFile || c.QueryConcurrency != old.QueryConcurrency
}

func (a *App) handleConfigSection(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		jsonError(w, http.StatusMethodNotAllowed, "PUT")
		return
	}
	var in struct {
		Section string                     `json:"section"`
		Values  map[string]json.RawMessage `json:"values"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil || len(in.Values) == 0 {
		jsonError(w, http.StatusBadRequest, "send {section, values}")
		return
	}
	keys := make([]string, 0, len(in.Values))
	for k := range in.Values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	// v6.0.13: merge and save as one step, refused (409) when the page's revision is out of date
	var mergeErr error
	old, saved, err := a.store.Update(ifMatch(r), func(old Config) (Config, error) {
		c, e := mergeSection(old, in.Values)
		mergeErr = e
		return c, e
	})
	switch {
	case err == errConfigConflict:
		jsonError(w, http.StatusConflict, err.Error())
		return
	case mergeErr != nil:
		reportErr(w, mergeErr)
		return
	case err != nil:
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	changes := configDiff(old, saved, keys)
	clearCache()
	sec := strings.TrimSpace(in.Section)
	if sec == "" {
		sec = strings.Join(keys, ",")
	}
	if len(sec) > 60 {
		sec = sec[:60]
	}
	detail := sec + ": " + ifStr(len(changes) == 0, "no change", strings.Join(changes, "; "))
	a.audit(r, "settings_section", detail)
	if d := a.getDB(); d != nil && d.ts && saved.CompressAfterDays != old.CompressAfterDays {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := d.timescalePolicies(ctx); err != nil {
				log.Printf("timescaledb compression policy: %v", err)
			}
		}()
	}
	setRevision(w, a.store)
	jsonOut(w, map[string]any{"saved": true, "restart_required": restartNeeded(saved, old), "changes": changes})
}

// /api/config/history?section=alerts: the recorded changes of one section (newest first).
func (a *App) handleConfigHistory(w http.ResponseWriter, r *http.Request) {
	d := a.dbOrFail(w)
	if d == nil {
		return
	}
	sec := strings.TrimSpace(r.URL.Query().Get("section"))
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	rows, err := d.pool.Query(ctx, `SELECT at, coalesce(username,''), coalesce(detail,'') FROM audit_log
		WHERE action IN ('settings_section','settings_saved') AND ($1 = '' OR detail LIKE $2) ORDER BY at DESC LIMIT 50`, sec, likePrefix(sec)+": %")
	if err != nil {
		queryErr(w, err)
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var at time.Time
		var u, det string
		if rows.Scan(&at, &u, &det) == nil {
			out = append(out, map[string]any{"at": at, "user": u, "detail": det})
		}
	}
	jsonOut(w, out)
}

func likePrefix(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}
