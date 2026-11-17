package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// NPS (RADIUS) user mapping for wireless clients.
//
// The NPS accounting log is tailed. A record that carries a client IP (Framed-IP-Address, sent by most WLCs in
// accounting interim updates) opens or extends a session "this IP belongs to this user". When another user shows
// up on the same IP, the previous session ends at that moment. A session also ends on Accounting-Stop, or when
// nothing has been heard about it for idle_hours.
//
// When NPS has no IP for a client (common at Access-Accept time), the client MAC (Calling-Station-Id) is remembered.
// If learn_from_mac is on and the FortiGate logs carry srcmac (the FortiGate is the client's gateway), the first log
// from that MAC opens the session for its IP.
//
// Every log without a username is labelled with the session's user (nps_id records which session).
// Precedence: username in the FortiGate log (FSSO etc.) > manual mapping > NPS.

type npsRecord struct {
	Time    time.Time
	RawUser string
	User    string // best name: SAM-Account-Name > Fully-Qualified-User-Name > User-Name
	IP      string // Framed-IP-Address
	MAC     string // Calling-Station-Id, normalised
	NAS     string
	Packet  int // 1 Access-Request, 2 Access-Accept, 3 Access-Reject, 4 Accounting-Request
	Status  int // Acct-Status-Type: 1 Start, 2 Stop, 3 Interim-Update
}

var dtsTag = regexp.MustCompile(`<([A-Za-z0-9-]+) data_type="\d+">([^<]*)</`)

var npsTimeLayouts = []string{"01/02/2006 15:04:05.000", "01/02/2006 15:04:05", "1/2/2006 15:04:05.000", "1/2/2006 15:04:05", "2006-01-02 15:04:05.000", "2006-01-02 15:04:05"}

func parseNPSTime(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	for _, l := range npsTimeLayouts {
		if t, err := time.ParseInLocation(l, s, time.Local); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

func xmlUnescape(s string) string {
	return strings.NewReplacer("&amp;", "&", "&lt;", "<", "&gt;", ">", "&quot;", `"`, "&apos;", "'").Replace(s)
}

// parseNPSLine reads one line of an NPS log in DTS-compliant (XML) or IAS (legacy, comma separated) format.
func parseNPSLine(line string) (npsRecord, bool) {
	line = strings.TrimSpace(line)
	var r npsRecord
	if strings.HasPrefix(line, "<Event>") {
		v := map[string]string{}
		for _, m := range dtsTag.FindAllStringSubmatch(line, -1) {
			v[m[1]] = xmlUnescape(strings.TrimSpace(m[2]))
		}
		t, ok := parseNPSTime(v["Timestamp"])
		if !ok {
			return r, false
		}
		r.Time = t
		r.RawUser = v["User-Name"]
		r.User = firstNonEmpty(v["SAM-Account-Name"], v["Fully-Qualifed-User-Name"], v["Fully-Qualified-User-Name"], v["User-Name"])
		r.IP = v["Framed-IP-Address"]
		r.MAC = normMAC(v["Calling-Station-Id"])
		r.NAS = firstNonEmpty(v["Client-Friendly-Name"], v["NAS-IP-Address"], v["Client-IP-Address"])
		r.Packet, _ = strconv.Atoi(v["Packet-Type"])
		r.Status, _ = strconv.Atoi(v["Acct-Status-Type"])
		return r, true
	}
	// IAS: NAS-IP,User,Date,Time,Service,Computer, then attribute-id,value pairs
	p := strings.Split(line, ",")
	if len(p) < 8 {
		return r, false
	}
	t, ok := parseNPSTime(p[2] + " " + p[3])
	if !ok {
		return r, false
	}
	r.Time, r.RawUser, r.NAS = t, strings.Trim(p[1], `"`), p[0]
	attrs := map[string]string{}
	for i := 6; i+1 < len(p); i += 2 {
		attrs[strings.TrimSpace(p[i])] = strings.Trim(strings.TrimSpace(p[i+1]), `"`)
	}
	r.User = firstNonEmpty(attrs["4129"], r.RawUser)
	r.IP = attrs["8"]
	r.MAC = normMAC(attrs["31"])
	r.Packet, _ = strconv.Atoi(attrs["4136"])
	r.Status, _ = strconv.Atoi(attrs["40"])
	return r, true
}

// ---------------------------------------------------------------- session engine

type npsSession struct {
	ID         int64     `json:"id"`
	IP         string    `json:"ip"`
	User       string    `json:"user"`
	MAC        string    `json:"mac"`
	NAS        string    `json:"nas"`
	Origin     string    `json:"origin"`
	Start      time.Time `json:"start"`
	LastSeen   time.Time `json:"last_seen"`
	End        time.Time `json:"end"`
	Reason     string    `json:"reason"`
	applied    time.Time // logs up to here have been labelled
	dirty      bool
	endChanged bool
}

type macAuth struct {
	user string
	t    time.Time
}

type pendReq struct {
	mac string
	t   time.Time
}

type npsFile struct {
	Path   string    `json:"path"`
	Size   int64     `json:"size"`
	Offset int64     `json:"offset"`
	Mod    time.Time `json:"modified"`
}

type npsEng struct {
	mu        sync.Mutex
	cfg       NPSConfig
	idle      time.Duration
	byIP      map[string][]*npsSession
	macs      map[string]macAuth
	pending   map[string]pendReq
	offsets   map[string]int64
	loaded    bool
	files     []npsFile
	records   int64
	used      int64
	ignored   int64
	lastRec   time.Time
	lastPoll  time.Time
	lastErr   string
	lastErrAt time.Time
}

var npsEngine = newNPSEng()

func newNPSEng() *npsEng {
	return &npsEng{byIP: map[string][]*npsSession{}, macs: map[string]macAuth{}, pending: map[string]pendReq{}, offsets: map[string]int64{}, idle: 10 * time.Hour}
}

func (e *npsEng) configure(c NPSConfig) {
	e.mu.Lock()
	e.cfg = c
	if c.IdleHours > 0 {
		e.idle = time.Duration(c.IdleHours) * time.Hour
	}
	e.mu.Unlock()
}

func (e *npsEng) effEnd(s *npsSession) time.Time {
	if !s.End.IsZero() {
		return s.End
	}
	return s.LastSeen.Add(e.idle)
}

// normUser applies the name options; machine accounts (host/PC01, PC01$) are ignored.
func (e *npsEng) normUser(u string) string {
	u = strings.TrimSpace(u)
	lu := strings.ToLower(u)
	if u == "" || strings.HasPrefix(lu, "host/") || strings.HasSuffix(u, "$") {
		return ""
	}
	if e.cfg.StripDomain {
		if i := strings.LastIndex(u, `\`); i >= 0 {
			u = u[i+1:]
		}
		if i := strings.Index(u, "@"); i > 0 {
			u = u[:i]
		}
	}
	if e.cfg.Lowercase {
		u = strings.ToLower(u)
	}
	if len(u) > 100 {
		u = strings.ToValidUTF8(u[:100], "") // never cut a multi-byte character in half
	}
	return u
}

// insertSession is a variable so the session logic can be tested without a database.
var insertSession = func(ctx context.Context, d *Database, s *npsSession) error {
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return d.pool.QueryRow(cctx, `INSERT INTO nps_sessions(ip,user_name,mac,nas,origin,started,last_seen) VALUES ($1::inet,$2,$3,$4,$5,$6,$7) RETURNING id`,
		s.IP, s.User, nullIfEmpty(s.MAC), nullIfEmpty(s.NAS), s.Origin, s.Start, s.LastSeen).Scan(&s.ID)
}

// touchLocked records "user holds ip at t", ending whoever held the IP before.
func (e *npsEng) touchLocked(ctx context.Context, d *Database, ip, user, mac, nas, origin string, t time.Time) (*npsSession, error) {
	l := e.byIP[ip]
	var cur *npsSession
	if len(l) > 0 {
		cur = l[len(l)-1]
	}
	if cur != nil && t.Before(cur.Start) {
		return nil, nil // older than what we already know about this IP
	}
	if cur != nil && cur.End.IsZero() {
		expires := cur.LastSeen.Add(e.idle)
		if cur.User == user && t.Before(expires) {
			if t.After(cur.LastSeen) {
				cur.LastSeen, cur.dirty = t, true
			}
			if cur.MAC == "" && mac != "" {
				cur.MAC, cur.dirty = mac, true
			}
			return cur, nil
		}
		cur.End, cur.Reason = t, "replaced by "+user
		if expires.Before(t) {
			cur.End, cur.Reason = expires, "idle timeout"
		}
		cur.dirty, cur.endChanged = true, true
	}
	s := &npsSession{IP: ip, User: user, MAC: mac, NAS: nas, Origin: origin, Start: t, LastSeen: t, dirty: true}
	if err := insertSession(ctx, d, s); err != nil {
		return nil, err
	}
	l = append(l, s)
	if len(l) > 6 {
		l = l[len(l)-6:]
	}
	e.byIP[ip] = l
	return s, nil
}

func (e *npsEng) observe(ctx context.Context, d *Database, r npsRecord) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.records++
	if r.Time.After(e.lastRec) {
		e.lastRec = r.Time
	}
	switch r.Packet {
	case 1: // Access-Request: the MAC is here, the verdict comes in the Access-Accept
		if r.MAC != "" && r.RawUser != "" {
			e.pending[strings.ToLower(r.RawUser)] = pendReq{r.MAC, r.Time}
		}
		return nil
	case 3, 11: // reject / challenge
		e.ignored++
		return nil
	}
	user := e.normUser(r.User)
	if user == "" {
		e.ignored++
		return nil
	}
	mac := r.MAC
	if mac == "" {
		if p, ok := e.pending[strings.ToLower(r.RawUser)]; ok && r.Time.Sub(p.t) < 2*time.Minute && r.Time.Sub(p.t) > -time.Minute {
			mac = p.mac
		}
	}
	if mac != "" && r.Status != 2 {
		e.macs[mac] = macAuth{user, r.Time}
	}
	ip := normIP(r.IP)
	if ip == "" || ip == "0.0.0.0" || ip == "255.255.255.254" || ip == "255.255.255.255" {
		e.used++ // MAC remembered (if any); the IP comes later
		return nil
	}
	e.used++
	if r.Packet == 4 && r.Status == 2 {
		if l := e.byIP[ip]; len(l) > 0 {
			if cur := l[len(l)-1]; cur.User == user && cur.End.IsZero() && !r.Time.Before(cur.Start) {
				cur.End, cur.Reason, cur.dirty, cur.endChanged = r.Time, "accounting stop", true, true
			}
		}
		return nil
	}
	_, err := e.touchLocked(ctx, d, ip, user, mac, r.NAS, "nps", r.Time)
	return err
}

// userFor is called for each log without a username while it is being stored.
func (e *npsEng) userFor(ctx context.Context, d *Database, ip, mac string, t time.Time) *npsSession {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.cfg.Enabled || !e.loaded {
		return nil
	}
	ip = normIP(ip)
	l := e.byIP[ip]
	for i := len(l) - 1; i >= 0; i-- {
		s := l[i]
		if !t.Before(s.Start) && t.Before(e.effEnd(s)) {
			if mac != "" && s.MAC != "" && mac != s.MAC {
				continue // the log comes from a different device: the IP was handed on, this user no longer holds it
			}
			// the same device is still active on this IP: keep the session (and the MAC) alive
			if mac != "" && s.MAC == mac && s.End.IsZero() && t.After(s.LastSeen.Add(5*time.Minute)) {
				s.LastSeen, s.dirty = t, true
				if m, ok := e.macs[mac]; ok && m.user == s.User {
					e.macs[mac] = macAuth{m.user, t}
				}
			}
			c := *s
			return &c
		}
	}
	if !e.cfg.LearnFromMAC || mac == "" {
		return nil
	}
	m, ok := e.macs[mac]
	if !ok || t.Before(m.t.Add(-2*time.Minute)) || !t.Before(m.t.Add(e.idle)) {
		return nil
	}
	lctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	s, err := e.touchLocked(lctx, d, ip, m.user, mac, "", "mac", t)
	if err != nil || s == nil {
		return nil
	}
	c := *s
	return &c
}

// load restores recent sessions after a restart.
func (e *npsEng) load(ctx context.Context, d *Database) error {
	rows, err := d.pool.Query(ctx, `SELECT id, host(ip), user_name, coalesce(mac,''), coalesce(nas,''), origin, started, last_seen, ended, coalesce(end_reason,'')
		FROM nps_sessions WHERE coalesce(ended, last_seen + make_interval(hours => $1)) > now() - interval '2 days' ORDER BY started`, int(e.idle/time.Hour))
	if err != nil {
		return err
	}
	defer rows.Close()
	by := map[string][]*npsSession{}
	for rows.Next() {
		s := &npsSession{}
		var ended *time.Time
		if err = rows.Scan(&s.ID, &s.IP, &s.User, &s.MAC, &s.NAS, &s.Origin, &s.Start, &s.LastSeen, &ended, &s.Reason); err != nil {
			return err
		}
		if ended != nil {
			s.End = *ended
		}
		s.applied = time.Now()
		by[s.IP] = append(by[s.IP], s)
	}
	if err = rows.Err(); err != nil {
		return err
	}
	offs := map[string]int64{}
	orows, err := d.pool.Query(ctx, `SELECT path, file_offset FROM nps_offsets`)
	if err != nil {
		return err
	}
	defer orows.Close()
	for orows.Next() {
		var p string
		var o int64
		if err = orows.Scan(&p, &o); err != nil {
			return err
		}
		offs[p] = o
	}
	e.mu.Lock()
	e.byIP, e.offsets, e.loaded = by, offs, true
	for _, l := range by {
		for _, s := range l {
			if s.MAC != "" && s.End.IsZero() {
				e.macs[s.MAC] = macAuth{s.User, s.LastSeen}
			}
		}
	}
	e.mu.Unlock()
	return orows.Err()
}

// flush saves changed sessions and labels the stored logs they cover.
func (e *npsEng) flush(ctx context.Context, d *Database) error {
	e.mu.Lock()
	var work []npsSession
	now := time.Now()
	for ip, l := range e.byIP {
		keep := l[:0]
		for _, s := range l {
			if s.dirty {
				work = append(work, *s)
				s.dirty, s.endChanged = false, false
			}
			if e.effEnd(s).After(now.Add(-48*time.Hour)) || s == l[len(l)-1] {
				keep = append(keep, s)
			}
		}
		if len(keep) == 0 {
			delete(e.byIP, ip)
		} else {
			e.byIP[ip] = keep
		}
	}
	for k, p := range e.pending {
		if now.Sub(p.t) > 5*time.Minute {
			delete(e.pending, k)
		}
	}
	for k, m := range e.macs {
		if now.Sub(m.t) > e.idle+time.Hour {
			delete(e.macs, k)
		}
	}
	idle := e.idle
	e.mu.Unlock()
	if len(work) == 0 {
		return nil
	}
	redirty := func(from int) {
		e.mu.Lock()
		for _, w := range work[from:] {
			for _, s := range e.byIP[w.IP] {
				if s.ID == w.ID {
					s.dirty = true
					s.endChanged = s.endChanged || w.endChanged
				}
			}
		}
		e.mu.Unlock()
	}
	var changed int64
	for i, w := range work {
		var ended any
		if !w.End.IsZero() {
			ended = w.End
		}
		if _, err := d.pool.Exec(ctx, `UPDATE nps_sessions SET last_seen=$2, ended=$3, end_reason=$4, mac=coalesce(mac,$5) WHERE id=$1`, w.ID, w.LastSeen, ended, nullIfEmpty(w.Reason), nullIfEmpty(w.MAC)); err != nil {
			redirty(i)
			return err
		}
		if w.endChanged && !w.End.IsZero() {
			tag, err := d.pool.Exec(ctx, `UPDATE fortigate_logs SET user_name=NULL, nps_id=NULL WHERE nps_id=$1 AND event_time >= $2`, w.ID, w.End)
			if err != nil {
				redirty(i)
				return err
			}
			changed += tag.RowsAffected()
		}
	}
	for i, w := range work {
		from := w.Start
		if !w.applied.IsZero() && w.applied.Add(-10*time.Minute).After(from) {
			from = w.applied.Add(-10 * time.Minute)
		}
		to := w.End
		if to.IsZero() {
			to = w.LastSeen.Add(idle)
		}
		if lim := time.Now().Add(time.Minute); to.After(lim) {
			to = lim
		}
		if to.After(from) {
			tag, err := d.pool.Exec(ctx, `UPDATE fortigate_logs SET user_name=$1, nps_id=$2 WHERE src_ip=$3::inet AND event_time >= $4 AND event_time < $5 AND coalesce(user_name,'')=''`,
				w.User, w.ID, w.IP, from, to)
			if err != nil {
				redirty(i)
				return err
			}
			changed += tag.RowsAffected()
		}
		e.mu.Lock()
		for _, s := range e.byIP[w.IP] {
			if s.ID == w.ID {
				s.applied = to
			}
		}
		e.mu.Unlock()
	}
	_ = changed // dashboards pick this up on their next refresh; clearing the cache here made every view recompute every 5 s
	return nil
}

// ---------------------------------------------------------------- log file tailing

func expandNPSPaths(paths []string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(p string) {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	for _, p := range paths {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if st, err := os.Stat(p); err == nil && st.IsDir() {
			m, _ := filepath.Glob(filepath.Join(p, "IN*.log"))
			for _, f := range m {
				add(f)
			}
			continue
		}
		if strings.ContainsAny(p, "*?[") {
			m, _ := filepath.Glob(p)
			for _, f := range m {
				add(f)
			}
			continue
		}
		add(p)
	}
	return out
}

func (e *npsEng) setErr(err error) {
	e.mu.Lock()
	e.lastErr, e.lastErrAt = err.Error(), time.Now()
	e.mu.Unlock()
	log.Printf("nps: %v", err)
}

const npsChunk = 8 << 20

// poll reads new complete lines from every NPS log file, oldest file first.
func (e *npsEng) poll(ctx context.Context, d *Database, c NPSConfig) {
	files := expandNPSPaths(c.Paths)
	type fi struct {
		path string
		st   os.FileInfo
	}
	var list []fi
	for _, p := range files {
		st, err := os.Stat(p)
		if err != nil {
			e.setErr(err)
			continue
		}
		list = append(list, fi{p, st})
	}
	sort.Slice(list, func(i, j int) bool {
		if !list[i].st.ModTime().Equal(list[j].st.ModTime()) {
			return list[i].st.ModTime().Before(list[j].st.ModTime())
		}
		return list[i].path < list[j].path
	})
	cutoff := time.Now().Add(-time.Duration(c.BackfillHours) * time.Hour)
	status := []npsFile{}
	for _, f := range list {
		e.mu.Lock()
		off, known := e.offsets[f.path]
		e.mu.Unlock()
		size := f.st.Size()
		if !known && f.st.ModTime().Before(cutoff) {
			off = size // older than the backfill window: start at its end
		}
		if size < off {
			off = 0 // replaced or truncated
		}
		for off < size && ctx.Err() == nil {
			n, err := e.readChunk(ctx, d, f.path, off, size, cutoff)
			if err != nil {
				e.setErr(fmt.Errorf("%s: %w", f.path, err))
			}
			if n == 0 {
				break
			}
			off += n
			if err = e.saveOffset(ctx, d, f.path, off); err != nil {
				e.setErr(err)
				break
			}
		}
		if !known {
			_ = e.saveOffset(ctx, d, f.path, off)
		}
		status = append(status, npsFile{f.path, size, off, f.st.ModTime()})
	}
	e.mu.Lock()
	e.files, e.lastPoll = status, time.Now()
	e.mu.Unlock()
}

// readChunk processes complete lines from off; it returns how many bytes were consumed.
func (e *npsEng) readChunk(ctx context.Context, d *Database, path string, off, size int64, cutoff time.Time) (int64, error) {
	fh, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer fh.Close()
	want := size - off
	if want > npsChunk {
		want = npsChunk
	}
	buf := make([]byte, want)
	n, err := fh.ReadAt(buf, off)
	if err != nil && !errors.Is(err, io.EOF) {
		return 0, err
	}
	buf = buf[:n]
	last := bytes.LastIndexByte(buf, '\n')
	if last < 0 {
		if int64(n) == npsChunk {
			return int64(n), nil // a single absurdly long line: skip it
		}
		return 0, nil // the current line is still being written
	}
	var used int64
	for _, ln := range bytes.SplitAfter(buf[:last+1], []byte("\n")) {
		line := string(bytes.ReplaceAll(ln, []byte{0}, nil)) // tolerate UTF-16 written files
		if r, ok := parseNPSLine(line); ok && !r.Time.Before(cutoff) {
			if err := e.observe(ctx, d, r); err != nil {
				return used, err // retry from this line on the next poll
			}
		}
		used += int64(len(ln))
	}
	return used, nil
}

func (e *npsEng) saveOffset(ctx context.Context, d *Database, path string, off int64) error {
	if _, err := d.pool.Exec(ctx, `INSERT INTO nps_offsets(path,file_offset,updated) VALUES ($1,$2,now()) ON CONFLICT (path) DO UPDATE SET file_offset=EXCLUDED.file_offset, updated=now()`, path, off); err != nil {
		return err
	}
	e.mu.Lock()
	e.offsets[path] = off
	e.mu.Unlock()
	return nil
}

// npsLoop runs for the life of the service; enabling or changing NPS settings applies without a restart.
func (a *App) npsLoop(ctx context.Context) error {
	for {
		c := a.store.Get().NPS
		npsEngine.configure(c)
		wait := time.Duration(c.PollSeconds) * time.Second
		if wait <= 0 {
			wait = 5 * time.Second
		}
		if d := a.getDB(); c.Enabled && d != nil {
			npsEngine.mu.Lock()
			loaded := npsEngine.loaded
			npsEngine.mu.Unlock()
			if !loaded {
				if err := npsEngine.load(ctx, d); err != nil {
					npsEngine.setErr(fmt.Errorf("loading sessions: %w", err))
				}
			}
			npsEngine.mu.Lock()
			loaded = npsEngine.loaded
			npsEngine.mu.Unlock()
			if loaded {
				npsEngine.poll(ctx, d, c)
				if err := npsEngine.flush(ctx, d); err != nil {
					npsEngine.setErr(fmt.Errorf("saving sessions: %w", err))
				}
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(wait):
		}
	}
}

// ---------------------------------------------------------------- HTTP

func (a *App) handleNPSStatus(w http.ResponseWriter, r *http.Request) {
	e := npsEngine
	e.mu.Lock()
	open, total := 0, 0
	now := time.Now()
	for _, l := range e.byIP {
		for _, s := range l {
			total++
			if s.End.IsZero() && e.effEnd(s).After(now) {
				open++
			}
		}
	}
	out := map[string]any{"enabled": e.cfg.Enabled, "paths": e.cfg.Paths, "files": e.files, "records": e.records, "used": e.used, "ignored": e.ignored,
		"open_sessions": open, "known_sessions": total, "macs": len(e.macs), "last_record": e.lastRec, "last_poll": e.lastPoll,
		"last_error": e.lastErr, "last_error_at": e.lastErrAt}
	e.mu.Unlock()
	jsonOut(w, out)
}

// /api/nps/sessions: sessions overlapping the selected period, optionally for one IP or user.
func (a *App) handleNPSSessions(w http.ResponseWriter, r *http.Request) {
	d := a.dbOrFail(w)
	if d == nil {
		return
	}
	f := parseFilter(r)
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	rows, err := d.SessionsFor(ctx, f.From, f.To, strings.TrimSpace(r.URL.Query().Get("ip")), strings.TrimSpace(r.URL.Query().Get("user")), 500)
	if err != nil {
		queryErr(w, err)
		return
	}
	jsonOut(w, rows)
}

func (d *Database) SessionsFor(ctx context.Context, from, to time.Time, ip, user string, limit int) ([]map[string]any, error) {
	idleH := int(npsEngine.idle / time.Hour)
	args := []any{from, to, idleH}
	cond := ""
	ip = strings.TrimLeft(ip, "=!")
	user = strings.TrimLeft(user, "=!")
	if a := normIP(ip); a != "" {
		args = append(args, a)
		cond += fmt.Sprintf(" AND s.ip = $%d::inet", len(args))
	} else if ip != "" {
		args = append(args, likePattern(ip))
		cond += fmt.Sprintf(" AND host(s.ip) ILIKE $%d", len(args))
	}
	if user != "" {
		args = append(args, likePattern(user))
		cond += fmt.Sprintf(" AND s.user_name ILIKE $%d", len(args))
	}
	args = append(args, limit)
	release, err := d.acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	rows, err := d.pool.Query(ctx, fmt.Sprintf(`SELECT s.id, host(s.ip), s.user_name, coalesce(s.mac,''), coalesce(s.nas,''), s.origin, s.started, s.last_seen,
		coalesce(s.ended, s.last_seen + make_interval(hours => $3)), s.ended IS NULL AND s.last_seen + make_interval(hours => $3) > now(), coalesce(s.end_reason,''),
		CASE WHEN %s THEN (SELECT count(*) FROM fortigate_logs l WHERE l.nps_id = s.id) ELSE -1 END
		FROM nps_sessions s WHERE s.started < $2 AND coalesce(s.ended, s.last_seen + make_interval(hours => $3)) > $1 %s ORDER BY s.started DESC LIMIT $%d`,
		ifStr(cond != "", "true", "false"), cond, len(args)), args...) // v5.13: events counted only for a searched IP / user
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id, n int64
		var ipS, u, mac, nas, origin, reason string
		var st, ls, en time.Time
		var open bool
		if err = rows.Scan(&id, &ipS, &u, &mac, &nas, &origin, &st, &ls, &en, &open, &reason, &n); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{"id": id, "ip": ipS, "user": u, "mac": mac, "nas": nas, "origin": origin, "start": st, "last_seen": ls,
			"end": en, "open": open, "reason": reason, "events": n})
	}
	return out, rows.Err()
}
