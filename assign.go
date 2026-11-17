package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// v5.13: permanent device assignments.
//
// Servers, printers, CCTV, shared PCs and the desktops that neither FSSO nor NPS covers are assigned once, by IP,
// subnet, MAC address or host name. Order for a log without a username:
//
//	username in the firewall log (FSSO, VPN, captive portal)
//	> time-bound manual mapping (User mapping tab)
//	> permanent assignment of type "person"
//	> NPS (wireless, follows the MAC)
//
// Assignments of other types (server, printer, shared, network device, ignore) never become a username: they label
// the device, so the dashboards can say how much traffic comes from people, servers, shared devices and unknown
// devices. A person assignment writes the owner into user_name with map_id = -id (negative = permanent).

type Assignment struct {
	ID      int64      `json:"id"`
	Kind    string     `json:"kind"` // ip, subnet, mac, host
	Value   string     `json:"value"`
	Type    string     `json:"type"`  // person, server, printer, shared, network, camera, ignore
	Owner   string     `json:"owner"` // username (person) or label
	Dept    string     `json:"dept"`
	Note    string     `json:"note"`
	MAC     string     `json:"mac"` // optional, for an ip assignment: the device expected on that address
	Until   *time.Time `json:"until,omitempty"`
	Created time.Time  `json:"created"`
	Updated time.Time  `json:"updated"`
	By      string     `json:"by"`
	prefix  netip.Prefix
}

var assignTypes = map[string]string{"person": "Person", "server": "Server", "printer": "Printer / scanner", "shared": "Shared device",
	"network": "Network device", "camera": "Camera / IoT", "ignore": "Ignore"}

type assignIndex struct {
	byIP   map[string]*Assignment
	nets   []*Assignment // longest prefix first
	byMAC  map[string]*Assignment
	byHost map[string]*Assignment
	all    []*Assignment
}

var asgCur atomic.Pointer[assignIndex]

func init() {
	asgCur.Store(&assignIndex{byIP: map[string]*Assignment{}, byMAC: map[string]*Assignment{}, byHost: map[string]*Assignment{}})
}

func (a *Assignment) live(t time.Time) bool { return a.Until == nil || t.Before(*a.Until) }

// lookupAssignment: MAC first (follows the device), then exact IP, the longest subnet, then the host name.
func lookupAssignment(ip, mac, host string, t time.Time) *Assignment {
	x := asgCur.Load()
	if mac != "" {
		if a := x.byMAC[mac]; a != nil && a.live(t) {
			return a
		}
	}
	if a := x.byIP[ip]; a != nil && a.live(t) {
		return a
	}
	if len(x.nets) > 0 {
		if addr, err := netip.ParseAddr(ip); err == nil {
			addr = addr.Unmap()
			for _, a := range x.nets {
				if a.prefix.Contains(addr) && a.live(t) {
					return a
				}
			}
		}
	}
	if host != "" {
		h := strings.ToLower(host)
		if i := strings.IndexByte(h, '.'); i > 0 {
			h = h[:i]
		}
		if a := x.byHost[h]; a != nil && a.live(t) {
			return a
		}
	}
	return nil
}

func assignCountByOwner() map[string]int {
	out := map[string]int{}
	for _, a := range asgCur.Load().all {
		if a.Type == "person" {
			out[canonUser(a.Owner)]++
		}
	}
	return out
}

func (d *Database) loadAssignments(ctx context.Context) error {
	rows, err := d.pool.Query(ctx, `SELECT id, kind, value, type, owner, coalesce(dept,''), coalesce(note,''), coalesce(mac,''), until, created, updated, coalesce(created_by,'')
		FROM assignments ORDER BY id`)
	if err != nil {
		return err
	}
	defer rows.Close()
	x := &assignIndex{byIP: map[string]*Assignment{}, byMAC: map[string]*Assignment{}, byHost: map[string]*Assignment{}}
	for rows.Next() {
		a := &Assignment{}
		if err = rows.Scan(&a.ID, &a.Kind, &a.Value, &a.Type, &a.Owner, &a.Dept, &a.Note, &a.MAC, &a.Until, &a.Created, &a.Updated, &a.By); err != nil {
			return err
		}
		switch a.Kind {
		case "ip":
			x.byIP[a.Value] = a
		case "subnet":
			if p, err := netip.ParsePrefix(a.Value); err == nil {
				a.prefix = p
				x.nets = append(x.nets, a)
			}
		case "mac":
			x.byMAC[a.Value] = a
		case "host":
			x.byHost[a.Value] = a
		}
		x.all = append(x.all, a)
	}
	sort.SliceStable(x.nets, func(i, j int) bool { return x.nets[i].prefix.Bits() > x.nets[j].prefix.Bits() })
	asgCur.Store(x)
	return rows.Err()
}

// normalizeAssignment validates and fills kind / value from what was typed.
func normalizeAssignment(a *Assignment) error {
	v := strings.TrimSpace(a.Value)
	if v == "" {
		return errors.New("enter an IP address, subnet, MAC address or host name")
	}
	switch {
	case normMAC(v) != "":
		a.Kind, a.Value = "mac", normMAC(v)
	case strings.Contains(v, "/"):
		p, err := netip.ParsePrefix(v)
		if err != nil {
			return fmt.Errorf("%q is not a valid subnet", v)
		}
		if p.IsSingleIP() {
			a.Kind, a.Value = "ip", p.Addr().Unmap().String()
		} else {
			a.Kind, a.Value = "subnet", p.Masked().String()
		}
	default:
		if ad, err := netip.ParseAddr(v); err == nil {
			a.Kind, a.Value = "ip", ad.Unmap().String()
		} else if hostPattern.MatchString(strings.ToLower(v)) && !strings.Contains(v, "*") {
			h := strings.ToLower(v)
			if i := strings.IndexByte(h, '.'); i > 0 {
				h = h[:i]
			}
			a.Kind, a.Value = "host", h
		} else {
			return fmt.Errorf("%q is not an IP address, subnet, MAC address or host name", v)
		}
	}
	a.Type = strings.ToLower(strings.TrimSpace(a.Type))
	if _, ok := assignTypes[a.Type]; !ok {
		return fmt.Errorf("type must be one of: person, server, printer, shared, network, camera, ignore")
	}
	a.Owner = strings.TrimSpace(a.Owner)
	if a.Type == "person" {
		a.Owner = canonUser(a.Owner)
		if a.Owner == "" {
			return errors.New("choose the person")
		}
		if s := staffOf(a.Owner); s != nil && a.Dept == "" {
			a.Dept = s.Dept
		}
	} else if a.Owner == "" {
		return errors.New("give the device a label (e.g. File server)")
	}
	if a.MAC = strings.TrimSpace(a.MAC); a.MAC != "" {
		if a.MAC = normMAC(a.MAC); a.MAC == "" {
			return errors.New("the expected MAC address is not valid")
		}
	}
	for _, s := range []*string{&a.Owner, &a.Dept, &a.Note} {
		if len(*s) > 200 {
			*s = strings.ToValidUTF8((*s)[:200], "")
		}
	}
	return nil
}

func (d *Database) assignLog(ctx context.Context, actor, action string, a *Assignment) {
	b, _ := json.Marshal(a)
	_, _ = d.pool.Exec(ctx, `INSERT INTO assign_log(actor, action, assignment_id, detail) VALUES ($1,$2,$3,$4)`, actor, action, a.ID, string(b))
}

// retroApply labels the recent logs (not yet compressed) of a person assignment, or releases them on delete.
func (d *Database) retroApply(ctx context.Context, a *Assignment, remove bool) (int64, error) {
	days := compressDays()
	from := time.Now().AddDate(0, 0, -days)
	var where string
	args := []any{from}
	switch a.Kind {
	case "ip":
		where = "src_ip = " + addArg(&args, a.Value) + "::inet"
	case "subnet":
		where = "src_ip <<= " + addArg(&args, a.Value) + "::inet"
	case "mac":
		where = "src_mac = " + addArg(&args, a.Value)
	default:
		return 0, nil // host names are only matched on new logs
	}
	var q string
	if remove {
		q = `UPDATE fortigate_logs SET user_name = NULL, map_id = NULL WHERE event_time >= $1 AND map_id = ` + addArg(&args, -a.ID)
	} else {
		if a.Type != "person" {
			return 0, nil
		}
		q = `UPDATE fortigate_logs SET user_name = ` + addArg(&args, a.Owner) + `, map_id = ` + addArg(&args, -a.ID) + `, nps_id = NULL
			WHERE event_time >= $1 AND ` + where + ` AND (coalesce(user_name,'') = '' OR nps_id IS NOT NULL OR map_id < 0)`
	}
	tag, err := d.pool.Exec(ctx, q, args...)
	if err != nil {
		return 0, err
	}
	if tag.RowsAffected() > 0 {
		markRollupDirty(from, time.Now().Add(time.Hour))
	}
	return tag.RowsAffected(), nil
}

func (d *Database) saveAssignment(ctx context.Context, a *Assignment, actor string) (int64, error) {
	if err := normalizeAssignment(a); err != nil {
		return 0, specErr("%s", err.Error())
	}
	// one assignment per IP / MAC / host / subnet: an existing one is replaced (edit)
	var oldID int64
	_ = d.pool.QueryRow(ctx, `SELECT id FROM assignments WHERE kind = $1 AND value = $2`, a.Kind, a.Value).Scan(&oldID)
	if a.ID == 0 && oldID != 0 {
		a.ID = oldID
	}
	if a.ID != 0 {
		if oldID != 0 && oldID != a.ID {
			return 0, specErr("%s is already assigned (edit that entry instead)", a.Value)
		}
		old := &Assignment{ID: a.ID}
		_ = d.pool.QueryRow(ctx, `SELECT kind, value FROM assignments WHERE id = $1`, a.ID).Scan(&old.Kind, &old.Value)
		if _, err := d.retroApply(ctx, old, true); err != nil {
			return 0, err
		}
		tag, err := d.pool.Exec(ctx, `UPDATE assignments SET kind=$2, value=$3, type=$4, owner=$5, dept=$6, note=$7, mac=$8, until=$9, updated=now() WHERE id=$1`,
			a.ID, a.Kind, a.Value, a.Type, a.Owner, a.Dept, a.Note, nullIfEmpty(a.MAC), a.Until)
		if err != nil {
			return 0, err
		}
		if tag.RowsAffected() == 0 {
			return 0, specErr("assignment not found")
		}
		d.assignLog(ctx, actor, "changed", a)
	} else {
		if err := d.pool.QueryRow(ctx, `INSERT INTO assignments(kind, value, type, owner, dept, note, mac, until, created_by) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id`,
			a.Kind, a.Value, a.Type, a.Owner, a.Dept, a.Note, nullIfEmpty(a.MAC), a.Until, actor).Scan(&a.ID); err != nil {
			return 0, err
		}
		d.assignLog(ctx, actor, "added", a)
	}
	if err := d.loadAssignments(ctx); err != nil {
		return 0, err
	}
	n, err := d.retroApply(ctx, a, false)
	clearCache()
	return n, err
}

func (d *Database) deleteAssignment(ctx context.Context, id int64, actor string) (int64, error) {
	a := &Assignment{ID: id}
	if err := d.pool.QueryRow(ctx, `SELECT kind, value, type, owner FROM assignments WHERE id = $1`, id).Scan(&a.Kind, &a.Value, &a.Type, &a.Owner); err != nil {
		return 0, specErr("assignment not found")
	}
	n, err := d.retroApply(ctx, a, true)
	if err != nil {
		return 0, err
	}
	if _, err = d.pool.Exec(ctx, `DELETE FROM assignments WHERE id = $1`, id); err != nil {
		return 0, err
	}
	d.assignLog(ctx, actor, "deleted", a)
	clearCache()
	return n, d.loadAssignments(ctx)
}

// ---------------------------------------------------------------- devices without a user, suggestions, warnings

type deviceRow struct {
	IP       string      `json:"ip"`
	Events   int64       `json:"events"`
	Bytes    int64       `json:"bytes"`
	Unknown  int64       `json:"unknown"` // events without a username
	MAC      string      `json:"mac"`
	Host     string      `json:"host"`
	DevType  string      `json:"devtype"`
	OS       string      `json:"os"`
	LastUser string      `json:"last_user"`
	Last     time.Time   `json:"last"`
	Domain   bool        `json:"domain"` // host name is a domain computer
	Assigned *Assignment `json:"assigned,omitempty"`
}

// unassignedDevices: internal devices with traffic but no username, busiest first, with what the firewall knows about them.
func (d *Database) unassignedDevices(ctx context.Context, from, to time.Time, limit int) ([]deviceRow, error) {
	d.loadDaysDone(ctx)
	args := []any{}
	src := rollSource(Filter{}, hourStart(from), to, []string{"nouser_src"}, &args, false)
	rows, err := d.pool.Query(ctx, `SELECT name, sum(cnt)::bigint, sum(byt)::bigint FROM `+src+` GROUP BY name ORDER BY 2 DESC LIMIT 400`, args...)
	if err != nil {
		return nil, err
	}
	list := []deviceRow{}
	for rows.Next() {
		var r deviceRow
		if err = rows.Scan(&r.IP, &r.Unknown, &r.Bytes); err != nil {
			rows.Close()
			return nil, err
		}
		if a := lookupAssignment(r.IP, "", "", time.Now()); a != nil {
			continue // already assigned (logs before the assignment still have no name)
		}
		list = append(list, r)
		if len(list) >= limit {
			break
		}
	}
	rows.Close()
	if len(list) == 0 {
		return list, nil
	}
	ips := make([]string, len(list))
	for i, r := range list {
		ips[i] = r.IP
	}
	// newest log per device: MAC, FortiGate device detection (srcname, devtype, osname), last username (index src_ip, event_time)
	c2, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	info, err := d.pool.Query(c2, `SELECT ip, l.src_mac, l.fields->>'srcname', l.fields->>'devtype', coalesce(l.fields->>'osname', l.fields->>'srcfamily'), l.event_time,
		(SELECT user_name FROM fortigate_logs u WHERE u.src_ip = ip::inet AND u.event_time >= $2 AND coalesce(u.user_name,'') <> '' ORDER BY u.event_time DESC LIMIT 1)
		FROM unnest($1::text[]) AS ip LEFT JOIN LATERAL (SELECT src_mac, fields, event_time FROM fortigate_logs WHERE src_ip = ip::inet AND event_time >= $2
			ORDER BY event_time DESC LIMIT 1) l ON true`, ips, to.AddDate(0, 0, -2))
	if err == nil {
		idx := map[string]int{}
		for i, r := range list {
			idx[r.IP] = i
		}
		dir := dirCur.Load()
		for info.Next() {
			var ip string
			var mac, host, dt, os, user *string
			var last *time.Time
			if info.Scan(&ip, &mac, &host, &dt, &os, &last, &user) != nil {
				continue
			}
			r := &list[idx[ip]]
			if mac != nil {
				r.MAC = *mac
			}
			if host != nil {
				r.Host = *host
				r.Domain = dir.comps[strings.ToLower(strings.SplitN(*host, ".", 2)[0])]
			}
			if dt != nil {
				r.DevType = *dt
			}
			if os != nil {
				r.OS = *os
			}
			if user != nil {
				r.LastUser = canonUser(*user)
			}
			if last != nil {
				r.Last = *last
			}
		}
		info.Close()
	} else {
		log.Printf("devices: %v", err)
	}
	return list, nil
}

// assignSuggestions: addresses where one person was seen on most days (NPS or the firewall), not assigned yet.
func (d *Database) assignSuggestions(ctx context.Context) ([]map[string]any, error) {
	now := time.Now()
	out := []map[string]any{}
	seenIP := map[string]bool{}
	// 1. NPS: the same user on the same IP on 4 or more of the last 7 days
	rows, err := d.pool.Query(ctx, `SELECT host(ip), user_name, count(DISTINCT started::date), max(coalesce(mac,'')), max(last_seen)
		FROM nps_sessions WHERE started > now() - interval '7 days' GROUP BY 1, 2 HAVING count(DISTINCT started::date) >= 4 ORDER BY 3 DESC LIMIT 200`)
	if err == nil {
		for rows.Next() {
			var ip, user, mac string
			var days int64
			var last time.Time
			if rows.Scan(&ip, &user, &days, &mac, &last) != nil {
				continue
			}
			if lookupAssignment(ip, mac, "", now) != nil || seenIP[ip] {
				continue
			}
			seenIP[ip] = true
			value, why := ip, fmt.Sprintf("NPS saw %s on this address on %d of the last 7 days", user, days)
			if mac != "" {
				value, why = mac, fmt.Sprintf("NPS saw %s on this device (%s) on %d of the last 7 days", user, ip, days)
			}
			out = append(out, map[string]any{"value": value, "ip": ip, "type": "person", "owner": canonUser(user), "why": why, "source": "nps", "days": days})
		}
		rows.Close()
	}
	// 2. firewall (FSSO): one user on 90% of an address's named events on 4 or more days
	d.loadDaysDone(ctx)
	args := []any{}
	src := rollSource(Filter{}, hourStart(now.AddDate(0, 0, -7)), now.Add(time.Hour), []string{"ipuser"}, &args, true)
	rows, err = d.pool.Query(ctx, `SELECT ip, usr, ev, days FROM (
		SELECT split_part(name,' ',1) AS ip, substr(name, strpos(name,' ')+1) AS usr, sum(cnt) AS ev, count(DISTINCT date_trunc('day', hour)) AS days,
			sum(sum(cnt)) OVER (PARTITION BY split_part(name,' ',1)) AS tot
		FROM `+src+` GROUP BY 1, 2) x WHERE ev >= 0.9 * tot AND days >= 4 ORDER BY ev DESC LIMIT 200`, args...)
	if err == nil {
		for rows.Next() {
			var ip, user string
			var ev float64
			var days int64
			if rows.Scan(&ip, &user, &ev, &days) != nil {
				continue
			}
			if !isLocalIP(ip) || lookupAssignment(ip, "", "", now) != nil || seenIP[ip] {
				continue
			}
			seenIP[ip] = true
			out = append(out, map[string]any{"value": ip, "ip": ip, "type": "person", "owner": canonUser(user), "source": "firewall", "days": days,
				"why": fmt.Sprintf("The firewall saw only %s on this address, on %d of the last 7 days", canonUser(user), days)})
		}
		rows.Close()
	}
	return out, err
}

// assignWarnings: things to fix in the assignments.
func (d *Database) assignWarnings(ctx context.Context) []map[string]any {
	out := []map[string]any{}
	add := func(a *Assignment, kind, msg string) {
		out = append(out, map[string]any{"id": a.ID, "value": a.Value, "owner": a.Owner, "kind": kind, "message": msg})
	}
	x := asgCur.Load()
	now := time.Now()
	dir := dirCur.Load()
	for _, a := range x.all {
		if a.Type == "person" && dir.loaded {
			s := dir.byUser[canonUser(a.Owner)]
			if s == nil {
				add(a, "unknown_person", a.Owner+" is not in the staff list")
			} else if !s.Active {
				add(a, "former", a.Owner+" has left (former staff): reassign this device")
			}
		}
		if a.Until != nil && a.Until.Before(now) {
			add(a, "expired", "expired on "+a.Until.Format("2 Jan 2006"))
		}
		if a.Kind == "ip" {
			for _, n := range x.nets {
				if n.prefix.Contains(netip.MustParseAddr(a.Value)) && (n.Owner != a.Owner || n.Type != a.Type) {
					add(a, "overlap", "inside "+n.Value+" ("+n.Owner+"); this more specific entry wins")
					break
				}
			}
		}
	}
	// no traffic in 30 days / a different device on a reserved address
	ips := []string{}
	for _, a := range x.all {
		if a.Kind == "ip" {
			ips = append(ips, a.Value)
		}
	}
	if len(ips) > 0 {
		d.loadDaysDone(ctx)
		args := []any{}
		src := rollSource(Filter{}, hourStart(now.AddDate(0, 0, -30)), now.Add(time.Hour), []string{"src_ip"}, &args, false)
		seen := map[string]bool{}
		if rows, err := d.pool.Query(ctx, `SELECT DISTINCT name FROM `+src+` WHERE name = ANY(`+addArg(&args, ips)+`::text[])`, args...); err == nil {
			for rows.Next() {
				var n string
				if rows.Scan(&n) == nil {
					seen[n] = true
				}
			}
			rows.Close()
			for _, a := range x.all {
				if a.Kind == "ip" && !seen[a.Value] && now.Sub(a.Created) > 30*24*time.Hour {
					add(a, "idle", "no traffic in the last 30 days")
				}
			}
		}
		withMAC := []string{}
		for _, a := range x.all {
			if a.Kind == "ip" && a.MAC != "" {
				withMAC = append(withMAC, a.Value)
			}
		}
		if len(withMAC) > 0 {
			c2, cancel := context.WithTimeout(ctx, 20*time.Second)
			if rows, err := d.pool.Query(c2, `SELECT ip, (SELECT src_mac FROM fortigate_logs WHERE src_ip = ip::inet AND event_time > now() - interval '1 day'
				AND src_mac IS NOT NULL ORDER BY event_time DESC LIMIT 1) FROM unnest($1::text[]) ip`, withMAC); err == nil {
				for rows.Next() {
					var ip string
					var mac *string
					if rows.Scan(&ip, &mac) == nil && mac != nil {
						if a := x.byIP[ip]; a != nil && a.MAC != *mac {
							add(a, "mac", "now used by another device ("+*mac+", expected "+a.MAC+")")
						}
					}
				}
				rows.Close()
			}
			cancel()
		}
	}
	return out
}

// ---------------------------------------------------------------- traffic attribution (dashboard)

// attribution: how much of the internal devices' activity can be traced to a person or a known device.
func (d *Database) attribution(ctx context.Context, f Filter) (map[string]any, error) {
	fromH := hourStart(f.From)
	if !mapCovers(fromH) {
		return nil, nil
	}
	d.loadDaysDone(ctx)
	args := []any{}
	src := rollSource(Filter{Type: f.Type, FW: f.FW}, fromH, f.To, []string{"src_ip", "nouser_src", "user"}, &args, false)
	rows, err := d.pool.Query(ctx, `SELECT dim, name, sum(cnt)::bigint FROM `+src+` GROUP BY 1, 2`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	tot, unk := map[string]int64{}, map[string]int64{}
	var users []string
	for rows.Next() {
		var dim, name string
		var c int64
		if rows.Scan(&dim, &name, &c) != nil {
			continue
		}
		switch dim {
		case "src_ip":
			if isLocalIP(name) {
				tot[name] += c
			}
		case "nouser_src":
			unk[name] += c
		case "user":
			users = append(users, name)
		}
	}
	buckets := map[string]int64{}
	var all int64
	now := time.Now()
	for ip, t := range tot {
		all += t
		u := unk[ip]
		if u > t {
			u = t
		}
		buckets["person"] += t - u
		if u == 0 {
			continue
		}
		if a := lookupAssignment(ip, "", "", now); a != nil && a.Type != "person" {
			buckets[a.Type] += u
		} else {
			buckets["unknown"] += u
		}
	}
	list := []map[string]any{}
	for _, k := range []string{"person", "server", "printer", "shared", "network", "camera", "ignore", "unknown"} {
		if buckets[k] > 0 {
			label := assignTypes[k]
			if k == "unknown" {
				label = "Unknown device"
			}
			list = append(list, map[string]any{"name": k, "label": label, "count": buckets[k]})
		}
	}
	return map[string]any{"total": all, "parts": list, "coverage": pct(all-buckets["unknown"], all), "people": countPeople(users), "staff_list": directoryLoaded()}, nil
}

// ---------------------------------------------------------------- HTTP

func (a *App) handleAssignments(w http.ResponseWriter, r *http.Request) {
	d := a.dbOrFail(w)
	if d == nil {
		return
	}
	me := sessionFrom(r.Context())
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	switch r.Method {
	case http.MethodGet:
		x := asgCur.Load()
		list := make([]*Assignment, len(x.all))
		copy(list, x.all)
		sort.Slice(list, func(i, j int) bool { return list[i].Updated.After(list[j].Updated) })
		dir := dirCur.Load()
		out := []map[string]any{}
		for _, as := range list {
			m := map[string]any{"id": as.ID, "kind": as.Kind, "value": as.Value, "type": as.Type, "owner": as.Owner, "dept": as.Dept, "note": as.Note,
				"mac": as.MAC, "until": as.Until, "created": as.Created, "updated": as.Updated, "by": as.By}
			if s := dir.byUser[canonUser(as.Owner)]; s != nil && as.Type == "person" {
				m["display"], m["former"] = s.Display, !s.Active
			}
			out = append(out, m)
		}
		jsonOut(w, map[string]any{"assignments": out, "types": assignTypes})
	case http.MethodPost:
		var in Assignment
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&in); err != nil {
			jsonError(w, http.StatusBadRequest, "bad request")
			return
		}
		n, err := d.saveAssignment(ctx, &in, me.User)
		if err != nil {
			reportErr(w, err)
			return
		}
		a.audit(r, "assignment_saved", in.Value+" "+in.Type+" "+in.Owner)
		jsonOut(w, map[string]any{"id": in.ID, "rows": n, "value": in.Value, "kind": in.Kind})
	case http.MethodDelete:
		id, _ := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
		n, err := d.deleteAssignment(ctx, id, me.User)
		if err != nil {
			reportErr(w, err)
			return
		}
		a.audit(r, "assignment_deleted", strconv.FormatInt(id, 10))
		jsonOut(w, map[string]any{"deleted": id, "rows": n})
	default:
		jsonError(w, http.StatusMethodNotAllowed, "method")
	}
}

// CSV: value,type,owner,dept,note,mac,until   (export with GET, import with POST {text})
func (a *App) handleAssignmentsCSV(w http.ResponseWriter, r *http.Request) {
	d := a.dbOrFail(w)
	if d == nil {
		return
	}
	if r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="logsikka-assignments-`+time.Now().Format("20060102")+`.csv"`)
		cw := csv.NewWriter(w)
		_ = cw.Write([]string{"value", "type", "owner", "dept", "note", "mac", "until"})
		for _, as := range asgCur.Load().all {
			until := ""
			if as.Until != nil {
				until = as.Until.Format("2006-01-02")
			}
			_ = cw.Write([]string{as.Value, as.Type, csvSafe(as.Owner), csvSafe(as.Dept), csvSafe(as.Note), as.MAC, until})
		}
		cw.Flush()
		return
	}
	var in struct{ Text string }
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2<<20)).Decode(&in); err != nil {
		jsonError(w, http.StatusBadRequest, "bad request")
		return
	}
	me := sessionFrom(r.Context())
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()
	cr := csv.NewReader(strings.NewReader(in.Text))
	cr.FieldsPerRecord, cr.TrimLeadingSpace = -1, true
	recs, err := cr.ReadAll()
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	added, errs := 0, []string{}
	for i, rec := range recs {
		if len(rec) == 0 || strings.HasPrefix(strings.TrimSpace(rec[0]), "#") || (i == 0 && strings.EqualFold(strings.TrimSpace(rec[0]), "value")) {
			continue
		}
		get := func(k int) string {
			if k < len(rec) {
				return strings.TrimSpace(rec[k])
			}
			return ""
		}
		as := Assignment{Value: get(0), Type: get(1), Owner: get(2), Dept: get(3), Note: get(4), MAC: get(5)}
		if u := get(6); u != "" {
			t, err := parseWhen(u, true)
			if err != nil {
				errs = append(errs, fmt.Sprintf("line %d: %v", i+1, err))
				continue
			}
			as.Until = &t
		}
		if _, err := d.saveAssignment(ctx, &as, me.User); err != nil {
			errs = append(errs, fmt.Sprintf("line %d: %v", i+1, err))
			continue
		}
		added++
	}
	a.audit(r, "assignments_imported", strconv.Itoa(added))
	jsonOut(w, map[string]any{"added": added, "errors": errs})
}

func (a *App) handleDevices(w http.ResponseWriter, r *http.Request) {
	d := a.dbOrFail(w)
	if d == nil {
		return
	}
	f := parseFilter(r)
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	v, err := cached("devices?"+r.URL.RawQuery, 60*time.Second, func() (any, error) {
		out := map[string]any{"staff_list": directoryLoaded(), "mapping_ready": mapCovers(hourStart(f.From))}
		var mu sync.Mutex
		var wg sync.WaitGroup
		var firstErr error
		run := func(k string, fn func() (any, error)) {
			wg.Add(1)
			go func() {
				defer wg.Done()
				v, err := fn()
				mu.Lock()
				defer mu.Unlock()
				if err != nil && firstErr == nil {
					firstErr = err
				}
				out[k] = v
			}()
		}
		run("unassigned", func() (any, error) { return d.unassignedDevices(ctx, f.From, f.To, 150) })
		run("suggestions", func() (any, error) { return d.assignSuggestions(ctx) })
		run("warnings", func() (any, error) { return d.assignWarnings(ctx), nil })
		run("attribution", func() (any, error) { return d.attribution(ctx, f) })
		wg.Wait()
		return out, firstErr
	})
	if err != nil {
		queryErr(w, err)
		return
	}
	jsonOut(w, v)
}

func (a *App) handleAssignHistory(w http.ResponseWriter, r *http.Request) {
	d := a.dbOrFail(w)
	if d == nil {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	rows, err := d.pool.Query(ctx, `SELECT at, coalesce(actor,''), action, coalesce(assignment_id,0), coalesce(detail,'') FROM assign_log ORDER BY at DESC LIMIT 300`)
	if err != nil {
		queryErr(w, err)
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var at time.Time
		var actor, action, detail string
		var id int64
		if rows.Scan(&at, &actor, &action, &id, &detail) != nil {
			continue
		}
		var as Assignment
		_ = json.Unmarshal([]byte(detail), &as)
		out = append(out, map[string]any{"at": at, "by": actor, "action": action, "id": id, "value": as.Value, "type": as.Type, "owner": as.Owner})
	}
	jsonOut(w, out)
}

// cleanLogUser: the username of a log in one form (when enabled), without machine accounts, and without a firewall
// "unauthenticated user" guess that is not a member of staff.
func cleanLogUser(r LogRecord) string {
	u := strings.TrimSpace(r.User)
	if u == "" {
		return ""
	}
	if machineAcct.MatchString(u) {
		return ""
	}
	fromGuess := r.Fields != nil && r.Fields["user"] == "" && r.Fields["srcuser"] == "" && r.Fields["unauthuser"] != ""
	if fromGuess && dropUnverified.Load() && directoryLoaded() && staffOf(u) == nil {
		return ""
	}
	if normalizeUsers.Load() {
		return canonUser(u)
	}
	return u
}

func (a *App) handleAttribution(w http.ResponseWriter, r *http.Request) {
	d := a.dbOrFail(w)
	if d == nil {
		return
	}
	f := parseFilter(r)
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	v, err := cached("attr?"+r.URL.RawQuery, 60*time.Second, func() (any, error) { return d.attribution(ctx, f) })
	if err != nil {
		queryErr(w, err)
		return
	}
	jsonOut(w, v)
}
