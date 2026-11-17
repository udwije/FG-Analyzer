package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Manual IP -> user mappings for DHCP networks where FSSO misses some users.
//
// A mapping is stored in ip_user_map AND written into fortigate_logs.user_name (with map_id set) for matching rows
// that have no username. Everything else (filters, top users, investigation, exports) then works unchanged, FSSO
// names are never overwritten, and deleting a mapping reverts exactly the rows it filled. Newest mapping wins.

type Mapping struct {
	ID      int64     `json:"id"`
	IP      string    `json:"ip"`
	User    string    `json:"user"`
	From    time.Time `json:"from"`
	To      time.Time `json:"to"`
	Note    string    `json:"note"`
	Created time.Time `json:"created"`
	Rows    int64     `json:"rows"`
}

type mapState struct {
	mu      sync.RWMutex
	byIP    map[string][]Mapping
	lastRec atomic.Int64
}

var mstate = &mapState{byIP: map[string][]Mapping{}}

func normIP(s string) string {
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return ""
	}
	return a.Unmap().String()
}

// lookup returns the newest mapping covering ip at time t (used while ingesting new logs).
func lookupMapping(ip string, t time.Time) *Mapping {
	mstate.mu.RLock()
	defer mstate.mu.RUnlock()
	var best *Mapping
	l := mstate.byIP[normIP(ip)]
	for i := range l {
		if m := &l[i]; !t.Before(m.From) && t.Before(m.To) && (best == nil || m.ID > best.ID) {
			c := *m
			best = &c
		}
	}
	return best
}

type execer interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}

func applyMapping(ctx context.Context, e execer, m Mapping, override bool) (int64, error) {
	cond := `coalesce(user_name,'')=''`
	if override {
		cond += ` OR (map_id IS NOT NULL AND map_id <> $2) OR nps_id IS NOT NULL` // a manual mapping beats NPS
	}
	tag, err := e.Exec(ctx, `UPDATE fortigate_logs SET user_name=$1, map_id=$2, nps_id=NULL WHERE src_ip=$3::inet AND event_time >= $4 AND event_time < $5 AND (`+cond+`)`,
		m.User, m.ID, m.IP, m.From, m.To)
	return tag.RowsAffected(), err
}

func (d *Database) LoadMappings(ctx context.Context) error {
	rows, err := d.pool.Query(ctx, `SELECT id, host(ip), user_name, valid_from, valid_to FROM ip_user_map`)
	if err != nil {
		return err
	}
	defer rows.Close()
	by := map[string][]Mapping{}
	for rows.Next() {
		var m Mapping
		if err = rows.Scan(&m.ID, &m.IP, &m.User, &m.From, &m.To); err != nil {
			return err
		}
		by[m.IP] = append(by[m.IP], m)
	}
	mstate.mu.Lock()
	mstate.byIP = by
	mstate.mu.Unlock()
	return rows.Err()
}

// maybeReconcile runs at most once a minute from the ingest path: it reloads mappings (so edits made elsewhere are seen)
// and fills rows that arrived in the instant between a mapping being saved and the in-memory copy being refreshed.
func (d *Database) maybeReconcile() {
	now := time.Now().Unix()
	last := mstate.lastRec.Load()
	if now-last < 60 || !mstate.lastRec.CompareAndSwap(last, now) {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if d.LoadMappings(ctx) != nil {
			return
		}
		var recent []Mapping
		mstate.mu.RLock()
		for _, l := range mstate.byIP {
			for _, m := range l {
				if m.To.After(time.Now().Add(-time.Hour)) {
					recent = append(recent, m)
				}
			}
		}
		mstate.mu.RUnlock()
		sort.Slice(recent, func(i, j int) bool { return recent[i].ID > recent[j].ID }) // newest first, no override
		for _, m := range recent {
			_, _ = applyMapping(ctx, d.pool, m, false)
		}
	}()
}

func validateMapping(m *Mapping) error {
	if m.IP = normIP(m.IP); m.IP == "" {
		return errors.New("enter a valid IP address")
	}
	if m.User = strings.TrimSpace(m.User); m.User == "" || len(m.User) > 100 {
		return errors.New("enter a username (up to 100 characters)")
	}
	if m.Note = strings.TrimSpace(m.Note); len(m.Note) > 200 {
		return errors.New("note is too long")
	}
	if !m.To.After(m.From) {
		return errors.New("the end time must be after the start time")
	}
	if m.To.Sub(m.From) > 400*24*time.Hour {
		return errors.New("a mapping can cover at most 400 days")
	}
	return nil
}

func (d *Database) AddMapping(ctx context.Context, m Mapping) (Mapping, error) {
	if err := validateMapping(&m); err != nil {
		return m, err
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return m, err
	}
	defer tx.Rollback(ctx)
	if err = tx.QueryRow(ctx, `INSERT INTO ip_user_map(ip,user_name,valid_from,valid_to,note) VALUES ($1::inet,$2,$3,$4,$5) RETURNING id, created_at`,
		m.IP, m.User, m.From, m.To, m.Note).Scan(&m.ID, &m.Created); err != nil {
		return m, err
	}
	if m.Rows, err = applyMapping(ctx, tx, m, true); err != nil {
		return m, err
	}
	if _, err = tx.Exec(ctx, `UPDATE ip_user_map SET rows_applied = $2 WHERE id = $1`, m.ID, m.Rows); err != nil {
		return m, err
	}
	if err = tx.Commit(ctx); err != nil {
		return m, err
	}
	markRollupDirty(m.From, m.To)
	return m, d.LoadMappings(ctx)
}

func (d *Database) DeleteMapping(ctx context.Context, id int64) (int64, error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	var ip string
	var from, to time.Time
	if err = tx.QueryRow(ctx, `SELECT host(ip), valid_from, valid_to FROM ip_user_map WHERE id=$1`, id).Scan(&ip, &from, &to); err != nil {
		return 0, err
	}
	tag, err := tx.Exec(ctx, `UPDATE fortigate_logs SET user_name=NULL, map_id=NULL WHERE map_id=$1`, id)
	if err != nil {
		return 0, err
	}
	if _, err = tx.Exec(ctx, `DELETE FROM ip_user_map WHERE id=$1`, id); err != nil {
		return 0, err
	}
	// another mapping may also cover the rows we just released: newest first, never overriding
	rows, err := tx.Query(ctx, `SELECT id, host(ip), user_name, valid_from, valid_to FROM ip_user_map WHERE ip=$1::inet AND valid_from < $3 AND valid_to > $2 ORDER BY id DESC`, ip, from, to)
	if err != nil {
		return 0, err
	}
	var others []Mapping
	for rows.Next() {
		var m Mapping
		if err = rows.Scan(&m.ID, &m.IP, &m.User, &m.From, &m.To); err != nil {
			rows.Close()
			return 0, err
		}
		others = append(others, m)
	}
	rows.Close()
	for _, m := range others {
		if _, err = applyMapping(ctx, tx, m, false); err != nil {
			return 0, err
		}
	}
	// whatever is still empty goes back to the NPS session that held the IP, if any
	if _, err = tx.Exec(ctx, `UPDATE fortigate_logs l SET user_name=s.user_name, nps_id=s.id FROM nps_sessions s
		WHERE s.ip=$1::inet AND l.src_ip=$1::inet AND l.event_time >= $2 AND l.event_time < $3 AND coalesce(l.user_name,'')=''
		AND l.event_time >= s.started AND l.event_time < coalesce(s.ended, s.last_seen + make_interval(hours => $4))`,
		ip, from, to, int(npsEngine.idle/time.Hour)); err != nil {
		return 0, err
	}
	if err = tx.Commit(ctx); err != nil {
		return 0, err
	}
	markRollupDirty(from, to)
	return tag.RowsAffected(), d.LoadMappings(ctx)
}

func (d *Database) ListMappings(ctx context.Context) ([]Mapping, error) {
	rows, err := d.pool.Query(ctx, `SELECT m.id, host(m.ip), m.user_name, m.valid_from, m.valid_to, coalesce(m.note,''), m.created_at,
		m.rows_applied FROM ip_user_map m ORDER BY m.id DESC LIMIT 1000`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Mapping{}
	for rows.Next() {
		var m Mapping
		if err = rows.Scan(&m.ID, &m.IP, &m.User, &m.From, &m.To, &m.Note, &m.Created, &m.Rows); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// MappingOverview: coverage of usernames, the busiest IPs that still have no username, and which FSSO users
// were seen on those same IPs (so a lease can be extended in one click).
func (d *Database) MappingOverview(ctx context.Context, f Filter) (map[string]any, error) {
	f.User = ""
	rel, args := f.where()
	release, err := d.acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	rows, err := d.pool.Query(ctx, `SELECT host(src_ip), count(*), count(DISTINCT event_time::date), min(event_time), max(event_time)
		FROM fortigate_logs WHERE `+rel+` AND coalesce(user_name,'')='' AND src_ip IS NOT NULL GROUP BY 1 ORDER BY 2 DESC LIMIT 60`, args...)
	if err != nil {
		return nil, err
	}
	type un struct {
		IP          string    `json:"ip"`
		Events      int64     `json:"events"`
		Days        int64     `json:"days"`
		First, Last time.Time `json:"-"`
	}
	list := []map[string]any{}
	var ips []string
	for rows.Next() {
		var u un
		if err = rows.Scan(&u.IP, &u.Events, &u.Days, &u.First, &u.Last); err != nil {
			rows.Close()
			return nil, err
		}
		list = append(list, map[string]any{"ip": u.IP, "events": u.Events, "days": u.Days, "first": u.First, "last": u.Last, "observed": []map[string]any{}})
		ips = append(ips, u.IP)
	}
	rows.Close()
	if len(ips) > 0 {
		args2 := append(append([]any{}, args...), ips)
		obs, err := d.pool.Query(ctx, fmt.Sprintf(`SELECT host(src_ip), user_name, count(*), min(event_time), max(event_time) FROM fortigate_logs
			WHERE `+rel+` AND src_ip = ANY($%d::text[]::inet[]) AND coalesce(user_name,'')<>'' AND map_id IS NULL AND nps_id IS NULL GROUP BY 1,2 ORDER BY 3 DESC`, len(args2)), args2...)
		if err != nil {
			return nil, err
		}
		defer obs.Close()
		idx := map[string]int{}
		for i, ip := range ips {
			idx[ip] = i
		}
		for obs.Next() {
			var ip, user string
			var c int64
			var first, last time.Time
			if err = obs.Scan(&ip, &user, &c, &first, &last); err != nil {
				return nil, err
			}
			o := list[idx[ip]]["observed"].([]map[string]any)
			if len(o) < 4 {
				list[idx[ip]]["observed"] = append(o, map[string]any{"user": user, "events": c, "first": first, "last": last})
			}
		}
	}
	var total, known, manual, nps int64
	if err = d.pool.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE coalesce(user_name,'')<>''), count(*) FILTER (WHERE map_id IS NOT NULL),
		count(*) FILTER (WHERE nps_id IS NOT NULL) FROM fortigate_logs WHERE `+rel, args...).Scan(&total, &known, &manual, &nps); err != nil {
		return nil, err
	}
	return map[string]any{"unmapped": list, "total": total, "userKnown": known, "userMapped": manual, "userNPS": nps, "from": f.From, "to": f.To}, nil
}

// ---------------------------------------------------------------- HTTP

func (a *App) handleMappings(w http.ResponseWriter, r *http.Request) {
	d := a.dbOrFail(w)
	if d == nil {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	switch r.Method {
	case http.MethodGet:
		l, err := d.ListMappings(ctx)
		if err != nil {
			queryErr(w, err)
			return
		}
		jsonOut(w, l)
	case http.MethodPost:
		if !strings.Contains(r.Header.Get("Content-Type"), "application/json") {
			http.Error(w, "JSON body required", http.StatusUnsupportedMediaType)
			return
		}
		var m Mapping
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&m); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		m, err := d.AddMapping(ctx, m)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		cacheMu.Lock()
		cache = map[string]cacheEntry{}
		cacheMu.Unlock()
		jsonOut(w, m)
	case http.MethodDelete:
		id, _ := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
		n, err := d.DeleteMapping(ctx, id)
		if errors.Is(err, pgx.ErrNoRows) {
			http.Error(w, "mapping not found", http.StatusNotFound)
			return
		} else if err != nil {
			queryErr(w, err)
			return
		}
		cacheMu.Lock()
		cache = map[string]cacheEntry{}
		cacheMu.Unlock()
		jsonOut(w, map[string]any{"deleted": id, "reverted": n})
	default:
		http.Error(w, "method", http.StatusMethodNotAllowed)
	}
}

// parseWhen accepts "2026-10-12 08:30", "2026-10-12T08:30" or a bare date (end dates then include the whole day).
func parseWhen(s string, end bool) (time.Time, error) {
	s = strings.TrimSpace(s)
	for _, l := range []string{"2006-01-02 15:04", "2006-01-02T15:04", time.RFC3339} {
		if t, err := time.ParseInLocation(l, s, time.Local); err == nil {
			return t, nil
		}
	}
	t, err := time.ParseInLocation("2006-01-02", s, time.Local)
	if err != nil {
		return t, fmt.Errorf("cannot read time %q", s)
	}
	if end {
		t = t.AddDate(0, 0, 1)
	}
	return t, nil
}

// Import: one mapping per line, "ip,user,start,end[,note]".
func (a *App) handleMappingsImport(w http.ResponseWriter, r *http.Request) {
	d := a.dbOrFail(w)
	if d == nil {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	body := http.MaxBytesReader(w, r.Body, 1<<20)
	var in struct{ Text string }
	if err := json.NewDecoder(body).Decode(&in); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
	defer cancel()
	added, rows, errs := 0, int64(0), []string{}
	for i, line := range strings.Split(in.Text, "\n") {
		if line = strings.TrimSpace(line); line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		p := strings.SplitN(line, ",", 5)
		if len(p) < 4 {
			errs = append(errs, fmt.Sprintf("line %d: expected ip,user,start,end", i+1))
			continue
		}
		from, e1 := parseWhen(p[2], false)
		to, e2 := parseWhen(p[3], true)
		if e1 != nil || e2 != nil {
			errs = append(errs, fmt.Sprintf("line %d: cannot read the dates", i+1))
			continue
		}
		m := Mapping{IP: p[0], User: p[1], From: from, To: to}
		if len(p) == 5 {
			m.Note = p[4]
		}
		res, err := d.AddMapping(ctx, m)
		if err != nil {
			errs = append(errs, fmt.Sprintf("line %d: %v", i+1, err))
			continue
		}
		added++
		rows += res.Rows
	}
	cacheMu.Lock()
	cache = map[string]cacheEntry{}
	cacheMu.Unlock()
	jsonOut(w, map[string]any{"added": added, "rows": rows, "errors": errs})
}

func (a *App) handleMappingOverview(w http.ResponseWriter, r *http.Request) {
	d := a.dbOrFail(w)
	if d == nil {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	f := parseFilter(r)
	v, err := cached("mapov?"+r.URL.RawQuery, 30*time.Second, func() (any, error) {
		if mappingSimple(f) { // v5.13: from the summaries
			return d.mappingOverviewRollup(ctx, f)
		}
		return d.MappingOverview(ctx, f)
	})
	if err != nil {
		queryErr(w, err)
		return
	}
	jsonOut(w, v)
}
