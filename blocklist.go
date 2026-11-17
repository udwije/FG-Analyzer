package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// v5.20: blocklist for a FortiGate external threat feed.
//
// Attackers found by the alerts (password spraying, brute force) can be added to a blocklist with one click. LogSikka
// publishes the list as a plain text file, one address or subnet per line, at
//
//	https://<logsikka>:<port>/feed/<token>/blocklist.txt
//
// which a FortiGate reads as an External Connector / threat feed of type "IP address" (config system
// external-resource) and uses as an address in deny policies. The token in the address is the only protection of the
// feed (the FortiGate cannot sign in), so it is long and random and can be replaced in Settings > Blocklist.
//
// Safety: internal addresses (private ranges and Settings > Internal networks), the firewalls' own addresses, the
// addresses in "Never block", and subnets larger than /16 (IPv6 /48) are refused, so one click can never cut off the
// network itself. Entries can expire; expired entries leave the feed by themselves. A copy of the list is written to
// <data>/blocklist.txt.

type BlocklistConfig struct {
	Enabled     bool     `json:"enabled"`
	Token       string   `json:"token,omitempty"`
	NeverBlock  []string `json:"never_block,omitempty"` // addresses or subnets that may never be listed (partners, your public ranges)
	DefaultDays int      `json:"default_days"`          // 0 = no expiry
}

func (b *BlocklistConfig) validate() error {
	for _, s := range b.NeverBlock {
		if s = strings.TrimSpace(s); s != "" {
			if _, ok := parsePrefix(s); !ok {
				return fmt.Errorf("blocklist: never block %q is not an IP address or subnet", s)
			}
		}
	}
	if b.DefaultDays < 0 || b.DefaultDays > 3650 {
		b.DefaultDays = 30
	}
	if b.Token != "" && !validToken(b.Token) {
		b.Token = ""
	}
	return nil
}

func validToken(t string) bool {
	if len(t) < 32 || len(t) > 128 {
		return false
	}
	for _, c := range t {
		if !(c >= 'a' && c <= 'f' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

func newToken() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

type blEntry struct {
	ID      int64      `json:"id"`
	Entry   string     `json:"entry"`
	Note    string     `json:"note"`
	AlertID int64      `json:"alert_id,omitempty"`
	By      string     `json:"by"`
	Added   time.Time  `json:"added"`
	Expires *time.Time `json:"expires,omitempty"`
	Hits    int64      `json:"-"`
	prefix  netip.Prefix
}

func (e *blEntry) live(t time.Time) bool { return e.Expires == nil || t.Before(*e.Expires) }

type blIndex struct {
	list   []*blEntry
	loaded time.Time
}

var blCur atomic.Pointer[blIndex]
var blMu sync.Mutex // one change at a time

func init() { blCur.Store(&blIndex{}) }

// blListed: the live entry that covers p (an address or a subnet inside a listed subnet), or nil.
func blListed(p netip.Prefix, t time.Time) *blEntry {
	for _, e := range blCur.Load().list {
		if e.live(t) && e.prefix.Bits() <= p.Bits() && e.prefix.Contains(p.Addr()) {
			return e
		}
	}
	return nil
}

// blCheck says whether s may be put on the blocklist; it returns the normalised entry.
func blCheck(s string, c Config) (string, error) {
	s = strings.TrimSpace(s)
	p, ok := parsePrefix(s)
	if !ok {
		return "", fmt.Errorf("%q is not an IP address or subnet", s)
	}
	a := p.Addr()
	if a.IsLoopback() || a.IsMulticast() || a.IsUnspecified() || a.IsLinkLocalUnicast() || a.IsPrivate() {
		return "", fmt.Errorf("%s is a private or special address", p)
	}
	if (a.Is4() && p.Bits() < 16) || (a.Is6() && p.Bits() < 48) {
		return "", fmt.Errorf("%s is too large to block (at most a /16, IPv6 /48)", p)
	}
	for _, x := range localCur.Load().prefixes { // private ranges and Settings > Internal networks
		if x.Overlaps(p) {
			return "", fmt.Errorf("%s is inside your network (%s)", p, x)
		}
	}
	for _, f := range c.Firewalls {
		if fa, err := netip.ParseAddr(f.IP); err == nil && p.Contains(fa.Unmap()) {
			return "", fmt.Errorf("%s contains the firewall %s (%s)", p, f.Name, f.IP)
		}
	}
	for _, d := range c.WAN.Devices {
		if fa, err := netip.ParseAddr(d.Host); err == nil && p.Contains(fa.Unmap()) {
			return "", fmt.Errorf("%s contains the firewall %s (%s)", p, d.Name, d.Host)
		}
	}
	for _, n := range c.Blocklist.NeverBlock {
		if x, ok := parsePrefix(strings.TrimSpace(n)); ok && x.Overlaps(p) {
			return "", fmt.Errorf("%s is in Never block (%s)", p, x)
		}
	}
	return p.String(), nil
}

// blWhy: "" when s may be listed, otherwise the reason (for the alert dialog).
func blWhy(s string, c Config) string {
	if _, err := blCheck(s, c); err != nil {
		return err.Error()
	}
	return ""
}

func (d *Database) loadBlocklist(ctx context.Context) error {
	rows, err := d.pool.Query(ctx, `SELECT id, entry, coalesce(note,''), coalesce(alert_id,0), coalesce(added_by,''), added, expires FROM blocklist ORDER BY added DESC`)
	if err != nil {
		return err
	}
	defer rows.Close()
	x := &blIndex{loaded: time.Now()}
	for rows.Next() {
		e := &blEntry{}
		if err = rows.Scan(&e.ID, &e.Entry, &e.Note, &e.AlertID, &e.By, &e.Added, &e.Expires); err != nil {
			return err
		}
		if p, ok := parsePrefix(e.Entry); ok {
			e.prefix = p
			x.list = append(x.list, e)
		}
	}
	if err = rows.Err(); err != nil {
		return err
	}
	blCur.Store(x)
	return nil
}

// blFeed: the text of the feed (live entries, sorted, one per line).
func blFeed(t time.Time) string {
	var l []string
	for _, e := range blCur.Load().list {
		if e.live(t) {
			l = append(l, e.prefix.String())
		}
	}
	sort.Strings(l)
	if len(l) == 0 {
		return ""
	}
	return strings.Join(l, "\n") + "\n"
}

// blWriteFile keeps <data>/blocklist.txt in step with the feed.
func (a *App) blWriteFile() {
	p := filepath.Join(a.dataFolder(), "blocklist.txt")
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, []byte(blFeed(time.Now())), 0644); err == nil {
		_ = os.Rename(tmp, p)
	} else {
		log.Printf("blocklist file: %v", err)
	}
}

// blAdd adds entries (each checked); entries already listed get the later expiry.
func (a *App) blAdd(ctx context.Context, d *Database, entries []string, note string, alertID int64, days int, by string) (added []string, problems []string, err error) {
	blMu.Lock()
	defer blMu.Unlock()
	c := a.store.Get()
	var expires any
	if days > 0 {
		expires = time.Now().AddDate(0, 0, days)
	}
	if len(note) > 300 {
		note = strings.ToValidUTF8(note[:300], "")
	}
	for _, s := range entries {
		if strings.TrimSpace(s) == "" {
			continue
		}
		e, cerr := blCheck(s, c)
		if cerr != nil {
			problems = append(problems, cerr.Error())
			continue
		}
		var aid any
		if alertID > 0 {
			aid = alertID
		}
		if _, err = d.pool.Exec(ctx, `INSERT INTO blocklist(entry, note, alert_id, added_by, expires) VALUES ($1,$2,$3,$4,$5)
			ON CONFLICT (entry) DO UPDATE SET note = EXCLUDED.note, alert_id = coalesce(EXCLUDED.alert_id, blocklist.alert_id), added_by = EXCLUDED.added_by,
			added = now(), expires = CASE WHEN EXCLUDED.expires IS NULL OR blocklist.expires IS NULL THEN NULL ELSE greatest(EXCLUDED.expires, blocklist.expires) END`,
			e, note, aid, by, expires); err != nil {
			return added, problems, err
		}
		added = append(added, e)
	}
	if len(added) > 0 {
		if err = d.loadBlocklist(ctx); err != nil {
			return added, problems, err
		}
		a.blWriteFile()
	}
	return added, problems, nil
}

func (a *App) blRemove(ctx context.Context, d *Database, id int64) (string, error) {
	blMu.Lock()
	defer blMu.Unlock()
	var entry string
	if err := d.pool.QueryRow(ctx, `DELETE FROM blocklist WHERE id = $1 RETURNING entry`, id).Scan(&entry); err != nil {
		return "", errors.New("entry not found")
	}
	if err := d.loadBlocklist(ctx); err != nil {
		return entry, err
	}
	a.blWriteFile()
	return entry, nil
}

// blMaintain removes entries that expired more than 30 days ago and refreshes the file (expired entries leave it).
func (a *App) blMaintain(ctx context.Context, d *Database) {
	if _, err := d.pool.Exec(ctx, `DELETE FROM blocklist WHERE expires < now() - interval '30 days'`); err != nil {
		log.Printf("blocklist clean-up: %v", err)
		return
	}
	if err := d.loadBlocklist(ctx); err == nil {
		a.blWriteFile()
	}
}

// blockCandidates: what an alert offers for the blocklist (each source, and the /24 the alert groups them by).
func blockCandidates(kind, subject, sources string, c Config, now time.Time, repeat ...map[string]int) []map[string]any {
	switch kind {
	case "signin_attack", "success_after_fail", "bruteforce", "spray":
	default:
		return nil
	}
	seen := map[string]bool{}
	out := []map[string]any{}
	add := func(s string, group bool) {
		s = strings.TrimSpace(s)
		p, ok := parsePrefix(s)
		if !ok || seen[p.String()] {
			return
		}
		seen[p.String()] = true
		m := map[string]any{"entry": p.String(), "group": group}
		if len(repeat) > 0 {
			if n := repeat[0][p.String()]; n > 1 {
				m["repeat_days"] = n // v5.21: a repeat attacker
			}
		}
		if why := blWhy(p.String(), c); why != "" {
			m["why"] = why
		} else if e := blListed(p, now); e != nil {
			m["listed"] = e.prefix.String()
		}
		out = append(out, m)
	}
	for _, s := range strings.Split(sources, ",") {
		if i := strings.Index(s, " and "); i >= 0 { // "a, b and 12 more"
			s = s[:i]
		}
		add(s, false)
	}
	if strings.Contains(subject, "/") {
		add(subject, true)
	} else {
		add(subject, false)
	}
	return out
}

// ---------------------------------------------------------------- HTTP

// /feed/<token>/blocklist.txt: FortiGate-readable. v6.0.15 requires both the token and a configured firewall source IP.
var feedLimit = struct {
	sync.Mutex
	m map[string]*feedRate
}{m: map[string]*feedRate{}}

type feedRate struct { start time.Time; n int }

// feedSourceAllowed deliberately trusts only the socket peer. X-Forwarded-For is ignored because this endpoint is
// normally fetched directly by FortiGate and a client-controlled forwarding header must not bypass the allow-list.
func feedSourceAllowed(host string, c Config) bool {
	a, err := netip.ParseAddr(strings.TrimSpace(host))
	if err != nil { return false }
	a = a.Unmap()
	for _, f := range c.Firewalls {
		if x, e := netip.ParseAddr(strings.TrimSpace(f.IP)); e == nil && x.Unmap() == a { return true }
	}
	return false
}

// 30 fetches/minute/source is far above an external-resource polling interval while bounding accidental/tight loops.
func feedRateOK(host string, now time.Time) bool {
	feedLimit.Lock()
	defer feedLimit.Unlock()
	x := feedLimit.m[host]
	if x == nil || now.Sub(x.start) >= time.Minute {
		feedLimit.m[host] = &feedRate{start: now, n: 1}
		return true
	}
	x.n++
	return x.n <= 30
}

func (a *App) handleFeed(w http.ResponseWriter, r *http.Request) {
	cfg := a.store.Get()
	c := cfg.Blocklist
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if !c.Enabled || c.Token == "" || len(parts) != 3 || parts[0] != "feed" || parts[2] != "blocklist.txt" ||
		subtle.ConstantTimeCompare([]byte(parts[1]), []byte(c.Token)) != 1 {
		http.NotFound(w, r)
		return
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil { host = r.RemoteAddr }
	if !feedSourceAllowed(host, cfg) {
		http.NotFound(w, r) // do not reveal that a valid feed exists to an unapproved source
		return
	}
	now := time.Now()
	if !feedRateOK(host, now) {
		w.Header().Set("Retry-After", "60")
		http.Error(w, "feed request rate exceeded", http.StatusTooManyRequests)
		return
	}
	blFetch.Store(&feedFetch{At: now, From: host})
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(blFeed(time.Now())))
}

type feedFetch struct {
	At   time.Time `json:"at"`
	From string    `json:"from"`
}

var blFetch atomic.Pointer[feedFetch]

func (a *App) feedURL(r *http.Request) string {
	c := a.store.Get()
	if c.Blocklist.Token == "" {
		return ""
	}
	scheme := "http"
	if a.tlsOn.Load() {
		scheme = "https"
	}
	host := r.Host
	if h, p, err := net.SplitHostPort(c.WebListenAddress); err == nil && (h == "" || h == "0.0.0.0" || h == "::") {
		if rh, _, err := net.SplitHostPort(r.Host); err == nil {
			host = net.JoinHostPort(rh, p)
		}
	}
	return scheme + "://" + host + "/feed/" + c.Blocklist.Token + "/blocklist.txt"
}

// /api/blocklist: GET list and settings; POST {entries, note, alert_id, days}; DELETE ?id=
func (a *App) handleBlocklist(w http.ResponseWriter, r *http.Request) {
	d := a.dbOrFail(w)
	if d == nil {
		return
	}
	me := sessionFrom(r.Context())
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	switch r.Method {
	case http.MethodGet:
		c := a.store.Get()
		now := time.Now()
		hits, herr := d.blHits(ctx)
		list := []map[string]any{}
		for _, e := range blCur.Load().list {
			m := map[string]any{"id": e.ID, "entry": e.Entry, "note": e.Note, "alert_id": e.AlertID, "by": e.By, "added": e.Added,
				"expires": e.Expires, "live": e.live(now)}
			if h, ok := hits[e.ID]; ok {
				m["hits"], m["last_hit"] = h.n, h.last
			}
			list = append(list, m)
		}
		out := map[string]any{"entries": list, "enabled": c.Blocklist.Enabled, "never_block": c.Blocklist.NeverBlock,
			"default_days": c.Blocklist.DefaultDays, "url": a.feedURL(r), "can_edit": roleOf(me.Role) >= RoleAdmin,
			"live": strings.Count(blFeed(now), "\n")}
		if f := blFetch.Load(); f != nil {
			out["last_fetch"] = f
		}
		if herr != nil {
			out["hits_error"] = shortErr(herr)
		}
		jsonOut(w, out)
	case http.MethodPost:
		if roleOf(me.Role) < RoleAnalyst {
			jsonError(w, http.StatusForbidden, "viewers cannot change the blocklist")
			return
		}
		var in struct {
			Entries []string `json:"entries"`
			Note    string   `json:"note"`
			AlertID int64    `json:"alert_id"`
			Days    *int     `json:"days"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&in); err != nil || len(in.Entries) == 0 || len(in.Entries) > 500 {
			jsonError(w, http.StatusBadRequest, "give 1 to 500 addresses or subnets")
			return
		}
		days := a.store.Get().Blocklist.DefaultDays
		if in.Days != nil && *in.Days >= 0 && *in.Days <= 3650 {
			days = *in.Days
		}
		added, problems, err := a.blAdd(ctx, d, in.Entries, strings.TrimSpace(in.Note), in.AlertID, days, me.User)
		if err != nil {
			queryErr(w, err)
			return
		}
		if len(added) > 0 {
			a.audit(r, "blocklist_added", strings.Join(added, " ")+ifStr(in.AlertID > 0, " (alert "+strconv.FormatInt(in.AlertID, 10)+")", ""))
			if in.AlertID > 0 { // the alert is dealt with
				_, _ = d.pool.Exec(ctx, `UPDATE alerts SET status = 'ack', ack_by = $2, updated = now() WHERE id = $1 AND status = 'open'`, in.AlertID, me.User+" (blocklisted)")
			}
		}
		jsonOut(w, map[string]any{"added": added, "problems": problems, "enabled": a.store.Get().Blocklist.Enabled})
	case http.MethodDelete:
		if roleOf(me.Role) < RoleAnalyst {
			jsonError(w, http.StatusForbidden, "viewers cannot change the blocklist")
			return
		}
		id, _ := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
		entry, err := a.blRemove(ctx, d, id)
		if err != nil {
			jsonError(w, http.StatusBadRequest, err.Error())
			return
		}
		a.audit(r, "blocklist_removed", entry)
		jsonOut(w, map[string]any{"removed": entry})
	default:
		jsonError(w, http.StatusMethodNotAllowed, "method")
	}
}

// /api/blocklist/settings (admin): PUT {enabled, never_block, default_days, new_token}
func (a *App) handleBlocklistSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		jsonError(w, http.StatusMethodNotAllowed, "method")
		return
	}
	var in struct {
		Enabled     bool     `json:"enabled"`
		NeverBlock  []string `json:"never_block"`
		DefaultDays int      `json:"default_days"`
		NewToken    bool     `json:"new_token"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&in); err != nil {
		jsonError(w, http.StatusBadRequest, "bad request")
		return
	}
	c, err := cloneConfig(a.store.Get())
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	nb := []string{}
	for _, s := range in.NeverBlock {
		if s = strings.TrimSpace(s); s != "" {
			nb = append(nb, s)
		}
	}
	c.Blocklist.Enabled, c.Blocklist.NeverBlock, c.Blocklist.DefaultDays = in.Enabled, nb, in.DefaultDays
	if in.NewToken || c.Blocklist.Token == "" {
		c.Blocklist.Token = newToken()
	}
	if err = a.store.Save(c); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	a.audit(r, "blocklist_settings", fmt.Sprintf("enabled=%v new_token=%v", in.Enabled, in.NewToken))
	setRevision(w, a.store) // v6.0.13
	jsonOut(w, map[string]any{"ok": true, "url": a.feedURL(r)})
}

// blocklistLoop: once an hour, expired entries leave the file and old ones are deleted.
func (a *App) blocklistLoop(ctx context.Context) error {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
		if d := a.getDB(); d != nil {
			c, cancel := context.WithTimeout(ctx, time.Minute)
			a.blMaintain(c, d)
			cancel()
		}
	}
}

// ---------------------------------------------------------------- v5.21: is the feed working?

type blHit struct {
	n    int64
	last time.Time
}

// blHits: per entry, the connections from it that the firewalls blocked since it was added (from the hourly summary of
// blocked sources, so it counts what the FortiGates logged: a deny policy needs "Log violation traffic" on). Blocks by a
// local-in policy (traffic to the firewall itself) are in the Advanced sources (adv_src) and counted too.
func (d *Database) blHits(ctx context.Context) (map[int64]blHit, error) {
	v, err := cached("blhits", time.Minute, func() (any, error) {
		out := map[int64]blHit{}
		if len(blCur.Load().list) == 0 {
			return out, nil
		}
		rows, err := d.pool.Query(ctx, `SELECT b.id, coalesce(sum(r.blk),0)::bigint, max(r.hour) FROM blocklist b
			JOIN rollup_1h r ON r.dim IN ('src_ip','adv_src') AND r.blk > 0 AND r.hour >= date_trunc('hour', b.added) AND r.hour > now() - interval '31 days'
				AND r.name ~ '^[0-9a-fA-F:.]+$' AND r.name::inet <<= b.entry::inet
			GROUP BY b.id`)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		for rows.Next() {
			var id, n int64
			var last *time.Time
			if rows.Scan(&id, &n, &last) == nil {
				h := blHit{n: n}
				if last != nil {
					h.last = last.Add(time.Hour)
				}
				out[id] = h
			}
		}
		return out, rows.Err()
	})
	if err != nil {
		return map[int64]blHit{}, err
	}
	return v.(map[int64]blHit), nil
}

// repeatSources: sign-in attack sources (addresses and /24 groups) seen in alerts on more than one day in the last
// 30 days, with the number of days. They are offered (and pre-selected) for the blocklist.
func (d *Database) repeatSources(ctx context.Context) map[string]int {
	v, err := cached("blrepeat", 5*time.Minute, func() (any, error) {
		out := map[string]int{}
		rows, err := d.pool.Query(ctx, `SELECT x, count(DISTINCT first_seen::date) FROM alerts,
			unnest(array_append(string_to_array(sources, ', '), subject)) AS x
			WHERE kind IN ('signin_attack','bruteforce','spray','success_after_fail') AND last_seen > now() - interval '30 days' AND x <> ''
			GROUP BY 1 HAVING count(DISTINCT first_seen::date) > 1`)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		for rows.Next() {
			var s string
			var n int
			if rows.Scan(&s, &n) == nil {
				if f := strings.Fields(s); len(f) > 0 { // "a.b.c.d and 12 more" -> the address
					s = f[0]
				}
				if p, ok := parsePrefix(s); ok {
					out[p.String()] = n
				}
			}
		}
		return out, rows.Err()
	})
	if err != nil {
		return map[string]int{}
	}
	return v.(map[string]int)
}
