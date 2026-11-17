package main

import (
	"bytes"
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// v5.13: staff directory.
//
// A scheduled task on the NPS server (deploy/nps-server/logsikka-staff-export.ps1) writes staff.csv and computers.csv
// every night into a folder on the same share as the NPS logs. LogSikka reads them whenever they change:
//   - joiners appear after the next export; leavers (disabled or no longer in the file) become "former staff" -
//     their past activity keeps their name, but they are no longer counted as active people;
//   - every username is put into one form (CORP\Nimal, nimal@corp.lk and NIMAL are the same person);
//   - the people count only counts real staff, and a firewall "unauthenticated user" guess that is not a member of
//     staff is dropped instead of becoming a new "user";
//   - computers.csv gives the domain computer names, so devices can be labelled by host name.

type staffRec struct {
	User    string    `json:"user"` // canonical (sAMAccountName, lower case)
	UPN     string    `json:"upn"`
	Display string    `json:"display"`
	Dept    string    `json:"dept"`
	Title   string    `json:"title"`
	Email   string    `json:"email"`
	Active  bool      `json:"active"`
	OU      string    `json:"ou"`
	Left    time.Time `json:"left,omitempty"`
}

type directory struct {
	byUser   map[string]*staffRec
	alias    map[string]string // upn / email / lower name -> canonical user
	comps    map[string]bool   // computer names (lower, without domain)
	loaded   bool
	imported time.Time
	files    map[string]time.Time
	err      string
	errAt    time.Time
	active   int
	former   int
}

var dirCur atomic.Pointer[directory]
var dirMu sync.Mutex // one import at a time

func init() {
	dirCur.Store(&directory{byUser: map[string]*staffRec{}, alias: map[string]string{}, comps: map[string]bool{}})
}

var machineAcct = regexp.MustCompile(`(?i)(\$$|^host/|^nt authority|^anonymous)`)

// canonUser puts a username into one form: no domain, lower case, UPN / e-mail resolved to the account name.
func canonUser(u string) string {
	u = strings.TrimSpace(u)
	if u == "" || machineAcct.MatchString(u) {
		return ""
	}
	lu := strings.ToLower(u)
	dir := dirCur.Load()
	if c, ok := dir.alias[lu]; ok {
		return c
	}
	if i := strings.LastIndex(lu, `\`); i >= 0 {
		lu = lu[i+1:]
	}
	if c, ok := dir.alias[lu]; ok {
		return c
	}
	if i := strings.Index(lu, "@"); i > 0 {
		lu = lu[:i]
	}
	if c, ok := dir.alias[lu]; ok {
		return c
	}
	if len(lu) > 100 {
		lu = strings.ToValidUTF8(lu[:100], "")
	}
	return lu
}

func staffOf(u string) *staffRec {
	return dirCur.Load().byUser[canonUser(u)]
}

func directoryLoaded() bool { return dirCur.Load().loaded }

var servicePattern = regexp.MustCompile(`(?i)^(svc[-_.]|sql|admin[-_.]?$|administrator$|guest$|test|healthmailbox|krbtgt$|scan|backup|sa$)`)

// countPeople: distinct people among usernames. With a staff list: members of staff only (active or left during the
// period). Without one: plausible person names (no machine or service accounts).
func countPeople(names []string) int64 {
	seen := map[string]bool{}
	dir := dirCur.Load()
	for _, n := range names {
		c := canonUser(n)
		if c == "" {
			continue
		}
		if dir.loaded {
			if _, ok := dir.byUser[c]; !ok {
				continue
			}
		} else if servicePattern.MatchString(c) {
			continue
		}
		seen[c] = true
	}
	return int64(len(seen))
}

// ---------------------------------------------------------------- reading the files

func csvHeader(h []string) map[string]int {
	m := map[string]int{}
	for i, x := range h {
		x = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(x, "\ufeff")))
		m[x] = i
	}
	return m
}

func readCSVFile(path string) ([][]string, map[string]int, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	b = bytes.TrimPrefix(b, []byte("\xef\xbb\xbf"))
	if len(b) > 1 && b[0] == 0xff && b[1] == 0xfe { // UTF-16 LE from Export-Csv without -Encoding
		b = bytes.ReplaceAll(b[2:], []byte{0}, nil)
	}
	r := csv.NewReader(bytes.NewReader(b))
	r.FieldsPerRecord = -1
	r.LazyQuotes = true
	head, err := r.Read()
	if err != nil {
		return nil, nil, err
	}
	var rows [][]string
	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, err
		}
		rows = append(rows, rec)
	}
	return rows, csvHeader(head), nil
}

func col(rec []string, h map[string]int, names ...string) string {
	for _, n := range names {
		if i, ok := h[n]; ok && i < len(rec) {
			return strings.TrimSpace(rec[i])
		}
	}
	return ""
}

// parseStaff turns staff.csv into records.
func parseStaff(rows [][]string, h map[string]int) []staffRec {
	out := []staffRec{}
	for _, rec := range rows {
		u := strings.ToLower(col(rec, h, "username", "samaccountname", "sam", "user"))
		if i := strings.LastIndex(u, `\`); i >= 0 {
			u = u[i+1:]
		}
		if u == "" || machineAcct.MatchString(u) {
			continue
		}
		en := strings.ToLower(col(rec, h, "enabled", "active"))
		out = append(out, staffRec{User: u, UPN: strings.ToLower(col(rec, h, "upn", "userprincipalname")), Display: col(rec, h, "displayname", "name"),
			Dept: col(rec, h, "department", "dept"), Title: col(rec, h, "title"), Email: strings.ToLower(col(rec, h, "email", "mail")),
			Active: en == "" || en == "true" || en == "1" || en == "yes", OU: col(rec, h, "ou")})
	}
	return out
}

// importDirectory reads staff.csv / computers.csv from the folder when they changed, and updates the staff table.
func (a *App) importDirectory(ctx context.Context, d *Database, force bool) error {
	cfg := a.store.Get().Directory
	if !cfg.Enabled || strings.TrimSpace(cfg.Path) == "" {
		return nil
	}
	dirMu.Lock()
	defer dirMu.Unlock()
	old := dirCur.Load()
	sp, cp := filepath.Join(cfg.Path, "staff.csv"), filepath.Join(cfg.Path, "computers.csv")
	st, err := os.Stat(sp)
	if err != nil {
		return fmt.Errorf("staff list: %w", err)
	}
	var cmod time.Time
	if cs, err := os.Stat(cp); err == nil {
		cmod = cs.ModTime()
	}
	if !force && old.loaded && old.files[sp].Equal(st.ModTime()) && old.files[cp].Equal(cmod) {
		return nil
	}
	rows, h, err := readCSVFile(sp)
	if err != nil {
		return fmt.Errorf("staff.csv: %w", err)
	}
	if _, ok := h["username"]; !ok {
		if _, ok2 := h["samaccountname"]; !ok2 {
			return fmt.Errorf("staff.csv has no Username column")
		}
	}
	recs := parseStaff(rows, h)
	if old.loaded && old.active > 20 {
		act := 0
		for _, r := range recs {
			if r.Active {
				act++
			}
		}
		if act < old.active*7/10 {
			return fmt.Errorf("staff.csv lists %d active accounts, the previous one %d: kept the previous list (AD or export problem?)", act, old.active)
		}
	}
	comps := map[string]bool{}
	if !cmod.IsZero() {
		if crow, ch, err := readCSVFile(cp); err == nil {
			for _, rec := range crow {
				if n := strings.ToLower(col(rec, ch, "name")); n != "" {
					comps[n] = true
				}
			}
		}
	}
	// database: upsert, and mark accounts no longer in the file as former staff
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	names := make([]string, 0, len(recs))
	for _, r := range recs {
		names = append(names, r.User)
		if _, err = tx.Exec(ctx, `INSERT INTO staff(username, upn, display, dept, title, email, active, ou, first_import, last_import, left_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,now(),now(), CASE WHEN $7 THEN NULL ELSE now() END)
			ON CONFLICT (username) DO UPDATE SET upn=EXCLUDED.upn, display=EXCLUDED.display, dept=EXCLUDED.dept, title=EXCLUDED.title,
				email=EXCLUDED.email, ou=EXCLUDED.ou, last_import=now(), active=EXCLUDED.active,
				left_at = CASE WHEN EXCLUDED.active THEN NULL ELSE coalesce(staff.left_at, now()) END`,
			r.User, r.UPN, r.Display, r.Dept, r.Title, r.Email, r.Active, r.OU); err != nil {
			return err
		}
	}
	if _, err = tx.Exec(ctx, `UPDATE staff SET active = false, left_at = coalesce(left_at, now()) WHERE NOT (username = ANY($1::text[]))`, names); err != nil {
		return err
	}
	if err = tx.Commit(ctx); err != nil {
		return err
	}
	if err = loadDirectory(ctx, d, comps, map[string]time.Time{sp: st.ModTime(), cp: cmod}); err != nil {
		return err
	}
	log.Printf("staff list imported: %d accounts (%d active), %d computers", len(recs), dirCur.Load().active, len(comps))
	clearCache()
	return nil
}

// loadDirectory builds the in-memory index from the staff table (also at start-up, before the first import).
func loadDirectory(ctx context.Context, d *Database, comps map[string]bool, files map[string]time.Time) error {
	rows, err := d.pool.Query(ctx, `SELECT username, coalesce(upn,''), coalesce(display,''), coalesce(dept,''), coalesce(title,''), coalesce(email,''), active,
		coalesce(ou,''), left_at FROM staff`)
	if err != nil {
		return err
	}
	defer rows.Close()
	nd := &directory{byUser: map[string]*staffRec{}, alias: map[string]string{}, comps: comps, files: files, imported: time.Now()}
	if nd.comps == nil {
		nd.comps = dirCur.Load().comps
	}
	if nd.files == nil {
		nd.files = dirCur.Load().files
	}
	for rows.Next() {
		r := &staffRec{}
		var left *time.Time
		if err = rows.Scan(&r.User, &r.UPN, &r.Display, &r.Dept, &r.Title, &r.Email, &r.Active, &r.OU, &left); err != nil {
			return err
		}
		if left != nil {
			r.Left = *left
		}
		nd.byUser[r.User] = r
		nd.alias[r.User] = r.User
		for _, x := range []string{r.UPN, r.Email} {
			if x != "" {
				nd.alias[x] = r.User
			}
		}
		if r.Active {
			nd.active++
		} else {
			nd.former++
		}
	}
	if err = rows.Err(); err != nil {
		return err
	}
	nd.loaded = len(nd.byUser) > 0
	dirCur.Store(nd)
	return nil
}

func (a *App) directoryLoop(ctx context.Context) error {
	first := true
	for {
		wait := 5 * time.Minute
		if m := a.store.Get().Directory.PollMinutes; m > 0 {
			wait = time.Duration(m) * time.Minute
		}
		if first {
			wait = 20 * time.Second
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(wait):
		}
		d := a.getDB()
		if d == nil {
			continue
		}
		if first {
			c, cancel := context.WithTimeout(ctx, 30*time.Second)
			if err := loadDirectory(c, d, nil, nil); err != nil {
				log.Printf("staff list: %v", err)
			}
			cancel()
			first = false
		}
		c, cancel := context.WithTimeout(ctx, 2*time.Minute)
		err := a.importDirectory(c, d, false)
		cancel()
		dirMu.Lock()
		cur := dirCur.Load()
		if err != nil {
			if cur.err != err.Error() {
				log.Printf("staff list: %v", err)
			}
			cp := *cur
			cp.err, cp.errAt = err.Error(), time.Now()
			dirCur.Store(&cp)
		} else if cur.err != "" {
			cp := *cur
			cp.err = ""
			dirCur.Store(&cp)
		}
		dirMu.Unlock()
	}
}

// ---------------------------------------------------------------- HTTP

// /api/staff: the staff list with last activity and devices, plus usernames seen that are not staff.
func (a *App) handleStaff(w http.ResponseWriter, r *http.Request) {
	d := a.dbOrFail(w)
	if d == nil {
		return
	}
	if r.Method == http.MethodPost { // import now
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
		defer cancel()
		if err := a.importDirectory(ctx, d, true); err != nil {
			jsonError(w, http.StatusBadRequest, err.Error())
			return
		}
		a.audit(r, "staff_import", "")
		jsonOut(w, map[string]any{"ok": true})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	v, err := cached("staff", 60*time.Second, func() (any, error) {
		d.loadDaysDone(ctx)
		now := time.Now()
		args := []any{}
		src := rollSource(Filter{}, hourStart(now.AddDate(0, 0, -30)), now.Add(time.Hour), []string{"user"}, &args, false)
		rows, err := d.pool.Query(ctx, `SELECT name, sum(cnt)::bigint, max(hour) FROM `+src+` GROUP BY name`, args...)
		if err != nil {
			return nil, err
		}
		type seen struct {
			events int64
			last   time.Time
		}
		byUser := map[string]*seen{}
		raw := map[string]int64{}
		for rows.Next() {
			var n string
			var c int64
			var t time.Time
			if rows.Scan(&n, &c, &t) != nil {
				continue
			}
			cu := canonUser(n)
			if cu == "" {
				continue
			}
			s := byUser[cu]
			if s == nil {
				s = &seen{}
				byUser[cu] = s
			}
			s.events += c
			if t.After(s.last) {
				s.last = t
			}
			raw[cu] += c
		}
		rows.Close()
		dir := dirCur.Load()
		devs := assignCountByOwner()
		list := []map[string]any{}
		for _, s := range dir.byUser {
			m := map[string]any{"user": s.User, "display": s.Display, "dept": s.Dept, "title": s.Title, "email": s.Email, "active": s.Active,
				"left": s.Left, "devices": devs[s.User], "events": int64(0)}
			if x := byUser[s.User]; x != nil {
				m["events"], m["last_seen"] = x.events, x.last
			}
			list = append(list, m)
		}
		sort.Slice(list, func(i, j int) bool { return list[i]["user"].(string) < list[j]["user"].(string) })
		unverified := []map[string]any{}
		for u, c := range raw {
			if _, ok := dir.byUser[u]; !ok && dir.loaded {
				unverified = append(unverified, map[string]any{"user": u, "events": c, "last_seen": byUser[u].last})
			}
		}
		sort.Slice(unverified, func(i, j int) bool { return unverified[i]["events"].(int64) > unverified[j]["events"].(int64) })
		if len(unverified) > 100 {
			unverified = unverified[:100]
		}
		return map[string]any{"staff": list, "unverified": unverified, "status": directoryStatus(a)}, nil
	})
	if err != nil {
		queryErr(w, err)
		return
	}
	jsonOut(w, v)
}

func directoryStatus(a *App) map[string]any {
	c := a.store.Get().Directory
	dir := dirCur.Load()
	out := map[string]any{"enabled": c.Enabled, "path": c.Path, "loaded": dir.loaded, "active": dir.active, "former": dir.former, "computers": len(dir.comps)}
	if !dir.imported.IsZero() && dir.loaded {
		out["imported"] = dir.imported
	}
	files := []map[string]any{}
	for p, t := range dir.files {
		if !t.IsZero() {
			files = append(files, map[string]any{"path": p, "modified": t})
		}
	}
	out["files"] = files
	if dir.err != "" {
		out["error"], out["error_at"] = dir.err, dir.errAt
	}
	return out
}
