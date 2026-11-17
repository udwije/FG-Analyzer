package main

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"sync/atomic"
	"time"
)

// v6.0 (LogSikka, phase A): sites and the tag engine.
//
// Settings describe the network once: sites (head office, branches) with their firewalls, and the zones of each site
// (staff LAN, servers, guest Wi-Fi, CCTV ...) with their subnets and VLAN. Every internal address then has tags:
//
//	site:<name>   from the zone's subnet (most specific match), otherwise from the firewall that logged it
//	zone:<name>   the zone whose subnet holds the address
//	kind:<kind>   what the zone is for (staff, servers, guest, wifi, voice, cctv, iot, management, dmz, other)
//	dept:<name>   the person's department (staff list)
//	role:<type>   a permanent assignment (server, printer, shared, network, camera)
//	staff:former  the person has left
//
// Tags are worked out in memory (no new column in the log table), so they apply to history at once and change as
// soon as the sites are edited. The Sites page and the log detail use them; a site or zone tag filters the dashboards
// by its subnets.

type SiteConfig struct {
	Name      string       `json:"name"`
	Firewalls []string     `json:"firewalls"`
	Zones     []ZoneConfig `json:"zones"`
}

type ZoneConfig struct {
	Name    string   `json:"name"`
	Kind    string   `json:"kind"`
	VLAN    int      `json:"vlan,omitempty"`
	Subnets []string `json:"subnets"`
}

var zoneKinds = []string{"staff", "servers", "wifi", "guest", "voice", "cctv", "iot", "printers", "management", "dmz", "other"}

var tagName = regexp.MustCompile(`^[\p{L}\p{N} ._()&/+-]{1,48}$`)

func validSites(l []SiteConfig) error {
	sites := map[string]bool{}
	nets := map[string]string{}
	for i := range l {
		s := &l[i]
		s.Name = strings.TrimSpace(s.Name)
		if !tagName.MatchString(s.Name) {
			return fmt.Errorf("sites: %q is not a valid site name (letters, digits, spaces and . _ - ( ) & / +, up to 48)", s.Name)
		}
		if sites[strings.ToLower(s.Name)] {
			return fmt.Errorf("sites: the site %q is listed twice", s.Name)
		}
		sites[strings.ToLower(s.Name)] = true
		fws := []string{}
		for _, f := range s.Firewalls {
			if f = strings.TrimSpace(f); f != "" {
				fws = append(fws, f)
			}
		}
		s.Firewalls = fws
		zones := map[string]bool{}
		for j := range s.Zones {
			z := &s.Zones[j]
			z.Name, z.Kind = strings.TrimSpace(z.Name), strings.ToLower(strings.TrimSpace(z.Kind))
			if !tagName.MatchString(z.Name) {
				return fmt.Errorf("sites (%s): %q is not a valid zone name", s.Name, z.Name)
			}
			if zones[strings.ToLower(z.Name)] {
				return fmt.Errorf("sites (%s): the zone %q is listed twice", s.Name, z.Name)
			}
			zones[strings.ToLower(z.Name)] = true
			if z.Kind == "" {
				z.Kind = "other"
			}
			ok := false
			for _, k := range zoneKinds {
				ok = ok || k == z.Kind
			}
			if !ok {
				return fmt.Errorf("sites (%s, %s): unknown zone type %q", s.Name, z.Name, z.Kind)
			}
			if z.VLAN < 0 || z.VLAN > 4094 {
				return fmt.Errorf("sites (%s, %s): VLAN must be 1-4094", s.Name, z.Name)
			}
			subs := []string{}
			for _, n := range z.Subnets {
				if n = strings.TrimSpace(n); n == "" {
					continue
				}
				p, ok := parsePrefix(n)
				if !ok {
					return fmt.Errorf("sites (%s, %s): %q is not an IP address or subnet", s.Name, z.Name, n)
				}
				if other, dup := nets[p.String()]; dup {
					return fmt.Errorf("sites: %s is in both %s and %s", p, other, s.Name+" / "+z.Name)
				}
				nets[p.String()] = s.Name + " / " + z.Name
				subs = append(subs, p.String())
			}
			z.Subnets = subs
		}
	}
	return nil
}

// ---------------------------------------------------------------- the index

type zoneEntry struct {
	prefix     netip.Prefix
	site, zone string
	kind       string
	vlan       int
}

type siteIndex struct {
	zones  []zoneEntry       // most specific first
	fwSite map[string]string // lower-case firewall name -> site
	sites  []SiteConfig
}

var siteCur atomic.Pointer[siteIndex]

func init() { setSites(nil) }

func setSites(l []SiteConfig) {
	x := &siteIndex{fwSite: map[string]string{}, sites: l}
	for _, s := range l {
		for _, f := range s.Firewalls {
			x.fwSite[strings.ToLower(f)] = s.Name
		}
		for _, z := range s.Zones {
			for _, n := range z.Subnets {
				if p, ok := parsePrefix(n); ok {
					x.zones = append(x.zones, zoneEntry{p, s.Name, z.Name, z.Kind, z.VLAN})
				}
			}
		}
	}
	sort.SliceStable(x.zones, func(i, j int) bool { return x.zones[i].prefix.Bits() > x.zones[j].prefix.Bits() })
	siteCur.Store(x)
}

// zoneOf: the most specific zone holding the address (nil when none).
func zoneOf(ip string) *zoneEntry {
	a, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return nil
	}
	a = a.Unmap()
	x := siteCur.Load()
	for i := range x.zones {
		if x.zones[i].prefix.Contains(a) {
			return &x.zones[i]
		}
	}
	return nil
}

// siteOf: the site of an address (zone first), otherwise of the firewall that logged it ("" when unknown).
func siteOf(ip, fw string) string {
	if z := zoneOf(ip); z != nil {
		return z.site
	}
	return siteCur.Load().fwSite[strings.ToLower(strings.TrimSpace(fw))]
}

// tagsFor: the tags of a device / person seen in a log.
func tagsFor(ip, user, fw string, t time.Time) []string {
	out := []string{}
	if z := zoneOf(ip); z != nil {
		out = append(out, "site:"+z.site, "zone:"+z.zone, "kind:"+z.kind)
	} else if s := siteCur.Load().fwSite[strings.ToLower(fw)]; s != "" {
		out = append(out, "site:"+s)
	}
	if user != "" {
		if s := staffOf(user); s != nil {
			if s.Dept != "" {
				out = append(out, "dept:"+s.Dept)
			}
			if !s.Active {
				out = append(out, "staff:former")
			}
		}
	}
	if ip != "" {
		if a := lookupAssignment(ip, "", "", t); a != nil && a.Type != "person" {
			out = append(out, "role:"+a.Type)
		}
	}
	return out
}

// tagSubnets: the subnets behind a site:... or zone:... tag (for filtering the dashboards).
func tagSubnets(tag string) []string {
	k, v, ok := strings.Cut(tag, ":")
	if !ok {
		return nil
	}
	out := []string{}
	for _, s := range siteCur.Load().sites {
		for _, z := range s.Zones {
			if (k == "site" && strings.EqualFold(s.Name, v)) || (k == "zone" && strings.EqualFold(z.Name, v)) {
				out = append(out, z.Subnets...)
			}
		}
	}
	return out
}

// ---------------------------------------------------------------- Sites page

type zoneAggR struct {
	Site     string   `json:"site"`
	Zone     string   `json:"zone"`
	Kind     string   `json:"kind"`
	VLAN     int      `json:"vlan,omitempty"`
	Subnets  []string `json:"subnets,omitempty"`
	Events   int64    `json:"events"`
	Blocked  int64    `json:"blocked"`
	Bytes    int64    `json:"bytes"`
	InetDown int64    `json:"inet_down"`
	InetUp   int64    `json:"inet_up"`
	Devices  int      `json:"devices"`
	devs     map[string]bool
	Top      []map[string]any `json:"top"`
	topm     map[string]*[3]int64
}

func (z *zoneAggR) add(ip string, c, b, y int64) {
	z.Events += c
	z.Blocked += b
	z.Bytes += y
	if z.devs == nil {
		z.devs, z.topm = map[string]bool{}, map[string]*[3]int64{}
	}
	z.devs[ip] = true
	t := z.topm[ip]
	if t == nil {
		t = &[3]int64{}
		z.topm[ip] = t
	}
	t[0] += c
	t[1] += y
}

// sitesOverview: per site and zone, activity of the internal addresses in [from, to) from the summaries, plus the
// busiest internal /24 networks that no zone covers yet (suggestions for the Sites page).
func (d *Database) sitesOverview(ctx context.Context, from, to time.Time) (map[string]any, error) {
	d.loadDaysDone(ctx)
	fromH := hourStart(from)
	args := []any{}
	src := rollSource(Filter{}, fromH, to, []string{"src_ip", "inet_src"}, &args, false)
	rows, err := d.pool.Query(ctx, `SELECT dim, fw, name, sum(cnt)::bigint, sum(blk)::bigint, sum(byt)::bigint, sum(snt)::bigint FROM `+src+` GROUP BY 1, 2, 3`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	x := siteCur.Load()
	zones := map[string]*zoneAggR{}
	key := func(s, z string) string { return s + "\x00" + z }
	for _, s := range x.sites {
		for _, z := range s.Zones {
			zones[key(s.Name, z.Name)] = &zoneAggR{Site: s.Name, Zone: z.Name, Kind: z.Kind, VLAN: z.VLAN, Subnets: z.Subnets}
		}
	}
	type sug struct {
		events, bytes int64
		devs          map[string]bool
		fws           map[string]bool
	}
	sugs := map[string]*sug{}
	for rows.Next() {
		var dim, fw, ip string
		var c, b, y, s int64
		if err = rows.Scan(&dim, &fw, &ip, &c, &b, &y, &s); err != nil {
			return nil, err
		}
		if !isLocalIP(ip) {
			continue
		}
		var za *zoneAggR
		if z := zoneOf(ip); z != nil {
			za = zones[key(z.site, z.zone)]
		} else {
			site := x.fwSite[strings.ToLower(fw)]
			if site == "" {
				site = "(no site)"
			}
			k := key(site, "")
			if zones[k] == nil {
				zones[k] = &zoneAggR{Site: site, Zone: "", Kind: ""}
			}
			za = zones[k]
			if dim == "src_ip" {
				if a, err := netip.ParseAddr(ip); err == nil && a.Is4() {
					p, _ := a.Prefix(24)
					g := sugs[p.String()]
					if g == nil {
						g = &sug{devs: map[string]bool{}, fws: map[string]bool{}}
						sugs[p.String()] = g
					}
					g.events += c
					g.bytes += y
					g.devs[ip] = true
					g.fws[fw] = true
				}
			}
		}
		switch dim {
		case "src_ip":
			za.add(ip, c, b, y)
		case "inet_src":
			za.InetUp += s
			za.InetDown += y - s
		}
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	list := []*zoneAggR{}
	for _, z := range zones {
		z.Devices = len(z.devs)
		type kv struct {
			ip string
			v  [3]int64
		}
		var tl []kv
		for ip, v := range z.topm {
			tl = append(tl, kv{ip, *v})
		}
		sort.Slice(tl, func(i, j int) bool { return tl[i].v[0] > tl[j].v[0] })
		z.Top = []map[string]any{}
		for i, t := range tl {
			if i >= 5 {
				break
			}
			z.Top = append(z.Top, map[string]any{"ip": t.ip, "events": t.v[0], "bytes": t.v[1]})
		}
		list = append(list, z)
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].Site != list[j].Site {
			return list[i].Site < list[j].Site
		}
		if (list[i].Zone == "") != (list[j].Zone == "") {
			return list[j].Zone == ""
		}
		return list[i].Events > list[j].Events
	})
	sl := []map[string]any{}
	for p, g := range sugs {
		fws := []string{}
		for f := range g.fws {
			fws = append(fws, f)
		}
		sort.Strings(fws)
		sl = append(sl, map[string]any{"subnet": p, "events": g.events, "bytes": g.bytes, "devices": len(g.devs), "firewalls": fws})
	}
	sort.Slice(sl, func(i, j int) bool { return sl[i]["events"].(int64) > sl[j]["events"].(int64) })
	if len(sl) > 40 {
		sl = sl[:40]
	}
	sites := x.sites
	if sites == nil {
		sites = []SiteConfig{}
	}
	return map[string]any{"sites": sites, "zones": list, "suggestions": sl, "kinds": zoneKinds, "from": from, "to": to,
		"complete": roll.covers(fromH)}, nil
}

func (a *App) handleSites(w http.ResponseWriter, r *http.Request) {
	d := a.dbOrFail(w)
	if d == nil {
		return
	}
	f := parseFilter(r)
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	v, err := cached("sites?"+r.URL.RawQuery+"|"+sitesSig(), 60*time.Second, func() (any, error) { return d.sitesOverview(ctx, f.From, f.To) })
	if err != nil {
		queryErr(w, err)
		return
	}
	out := map[string]any{}
	for k, x := range v.(map[string]any) {
		out[k] = x
	}
	s := sessionFrom(r.Context())
	out["can_edit"] = s != nil && roleOf(s.Role) >= RoleAdmin
	fws := []string{}
	for _, fw := range a.store.Get().Firewalls {
		fws = append(fws, fw.Name)
	}
	out["known_firewalls"] = fws
	jsonOut(w, out)
}

// sitesSig changes whenever the sites are edited, so the cached page is rebuilt.
func sitesSig() string {
	x := siteCur.Load()
	return fmt.Sprintf("%d/%d", len(x.sites), len(x.zones)) + fmt.Sprint(x.sites)
}

// /api/tags?ip=&user=&fw=: the tags of one device; /api/tags?tag=zone:X: the subnets behind a site or zone tag.
func (a *App) handleTags(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if t := q.Get("tag"); t != "" {
		subs := tagSubnets(t)
		if len(subs) == 0 {
			jsonError(w, http.StatusNotFound, "no subnets behind "+t)
			return
		}
		jsonOut(w, map[string]any{"tag": t, "subnets": subs})
		return
	}
	jsonOut(w, map[string]any{"tags": tagsFor(q.Get("ip"), q.Get("user"), q.Get("fw"), time.Now())})
}
