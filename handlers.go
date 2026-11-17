package main

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// ---- small response cache: dashboards re-ask the same question every refresh, and a
// 24 h aggregate over millions of rows is not free.
type cacheEntry struct {
	at time.Time
	v  any
}

var (
	cacheMu sync.Mutex
	cache   = map[string]cacheEntry{}
)

func cached(key string, ttl time.Duration, fn func() (any, error)) (any, error) {
	cacheMu.Lock()
	if e, ok := cache[key]; ok && time.Since(e.at) < ttl {
		cacheMu.Unlock()
		return e.v, nil
	}
	cacheMu.Unlock()
	v, err := fn()
	if err == nil {
		cacheMu.Lock()
		if len(cache) > 200 {
			cache = map[string]cacheEntry{}
		}
		cache[key] = cacheEntry{time.Now(), v}
		cacheMu.Unlock()
	}
	return v, err
}

// cachePut stores a value computed in the background (the dashboard warmer).
func cachePut(key string, v any) {
	cacheMu.Lock()
	if len(cache) > 200 {
		cache = map[string]cacheEntry{}
	}
	cache[key] = cacheEntry{time.Now(), v}
	cacheMu.Unlock()
}

func clearCache() {
	cacheMu.Lock()
	cache = map[string]cacheEntry{}
	cacheMu.Unlock()
}

func (a *App) dbOrFail(w http.ResponseWriter) *Database {
	d := a.getDB()
	if d == nil {
		http.Error(w, "database unavailable", http.StatusServiceUnavailable)
	}
	return d
}

func queryErr(w http.ResponseWriter, err error) {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		http.Error(w, "query timed out - narrow the time range or add filters", http.StatusGatewayTimeout)
		return
	}
	http.Error(w, err.Error(), http.StatusInternalServerError)
}

// /api/summary: tiles + timeline + top lists, all under one filter.
func (a *App) handleSummary(w http.ResponseWriter, r *http.Request) {
	d := a.dbOrFail(w)
	if d == nil {
		return
	}
	f := parseFilter(r)
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	v, err := cached("summary?"+r.URL.RawQuery, 30*time.Second, func() (any, error) {
		out, err := d.Overview(ctx, f)
		if err != nil {
			return nil, err
		}
		dims := []string{"user", "src_ip", "category", "application", "hostname"}
		res := make([][]map[string]any, len(dims))
		groups := make([]int64, len(dims))
		errs := make([]error, len(dims))
		var wg sync.WaitGroup
		for i, dim := range dims {
			wg.Add(1)
			go func(i int, dim string) {
				defer wg.Done()
				res[i], groups[i], errs[i] = d.Top(ctx, dim, f, 10)
			}(i, dim)
		}
		wg.Wait()
		for i, dim := range dims {
			if errs[i] != nil {
				return nil, errs[i]
			}
			out[dim] = res[i]
		}
		out["users"], out["sources"], out["hosts"] = groups[0], groups[1], groups[4]
		return out, nil
	})
	if err != nil {
		queryErr(w, err)
		return
	}
	jsonOut(w, v)
}

// /api/logs: filtered, paged event list.
func (a *App) handleLogs(w http.ResponseWriter, r *http.Request) {
	d := a.dbOrFail(w)
	if d == nil {
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit < 1 || limit > 500 {
		limit = 100
	}
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if offset < 0 || offset > 100000 {
		offset = 0
	}
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	rows, more, err := d.Logs(ctx, parseFilter(r), limit, offset)
	if err != nil {
		queryErr(w, err)
		return
	}
	jsonOut(w, map[string]any{"rows": rows, "more": more})
}

// /api/facets?field=user: suggestion values for the filter boxes (time range + source only).
func (a *App) handleFacets(w http.ResponseWriter, r *http.Request) {
	d := a.dbOrFail(w)
	if d == nil {
		return
	}
	f := parseFilter(r)
	f = Filter{From: f.From, To: f.To, Subtype: f.Subtype, Type: f.Type, Scope: f.Scope}
	field := r.URL.Query().Get("field")
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	v, err := cached("facets?"+r.URL.RawQuery, 5*time.Minute, func() (any, error) {
		if rows, ok, err := d.facetsRollup(ctx, field, f); ok { // v5.13: from the summaries
			return rows, err
		}
		rows, _, err := d.Top(ctx, field, f, 100)
		return rows, err
	})
	if err != nil {
		queryErr(w, err)
		return
	}
	jsonOut(w, v)
}

// /api/export.csv: same filters as the explorer, streamed, capped at 500k rows.
func (a *App) handleExport(w http.ResponseWriter, r *http.Request) {
	d := a.dbOrFail(w)
	if d == nil {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
	defer cancel()
	a.audit(r, "export", r.URL.RawQuery)
	if err := d.ExportCSV(ctx, parseFilter(r), w, 500000); err != nil {
		// headers may already be sent; the truncated CSV is the signal in that case
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
