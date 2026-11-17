package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"logsikka/snmp"
	"logsikka/snmp/ber"
)

// v5.16: WAN links measured on the firewall's own interface counters over SNMPv3 (the fgwan tool, built in).
//
// Log-based volumes depend on what the firewall logs (sessions without logging, the firewall's own traffic, IPsec
// overhead are missing); the interface counters are what the circuit really carried. Every poll_seconds the
// collector reads ifHCInOctets / ifHCOutOctets / ifOperStatus of the chosen interfaces, turns the counter deltas
// into bits per second and stores one row per interface (wan_samples). The WAN links tab, the executive report and
// Settings read from there. The SNMPv3 code (USM, AES, SHA-2) is the fgwan implementation, standard library only.

type WANConfig struct {
	Enabled     bool        `json:"enabled"`
	PollSeconds int         `json:"poll_seconds"`
	KeepDays    int         `json:"keep_days"`
	Devices     []WANDevice `json:"devices"`
}

type WANDevice struct {
	Name       string     `json:"name"`
	Host       string     `json:"host"`
	Port       int        `json:"port"`
	Username   string     `json:"username"`
	Level      string     `json:"security_level"`
	Auth       string     `json:"auth_protocol"`
	Priv       string     `json:"priv_protocol"`
	AuthPass   string     `json:"auth_pass,omitempty"`
	PrivPass   string     `json:"priv_pass,omitempty"`
	Interfaces []WANIface `json:"interfaces"`
	// v5.19: shown to the settings page only (the passphrases themselves never leave the server)
	AuthSet bool `json:"auth_set,omitempty"`
	PrivSet bool `json:"priv_set,omitempty"`
	// v5.20.1: "same SNMPv3 user as" another firewall: its passphrases are copied when this one's are left empty
	CredsFrom string `json:"creds_from,omitempty"`
}

type WANIface struct {
	Name     string `json:"name"` // ifName on the firewall (port1, wan2, agg1 ...)
	Label    string `json:"label"`
	DownMbps int    `json:"down_mbps"` // contracted capacity
	UpMbps   int    `json:"up_mbps"`
}

func (c *WANConfig) validate() error {
	// v5.20.1: samples are stored under the firewall's name, so two firewalls must never share a name or an address
	hosts, names := map[string]bool{}, map[string]bool{}
	for i := range c.Devices {
		d := &c.Devices[i]
		h := strings.ToLower(strings.TrimSpace(d.Host))
		if h != "" && hosts[h] {
			return fmt.Errorf("WAN links: the firewall address %s is listed twice", strings.TrimSpace(d.Host))
		}
		hosts[h] = true
		n := strings.TrimSpace(d.Name)
		if n == "" {
			n = strings.TrimSpace(d.Host)
		}
		if names[strings.ToLower(n)] {
			n += " (" + strings.TrimSpace(d.Host) + ")"
		}
		names[strings.ToLower(n)] = true
		d.Name = n
	}
	if c.PollSeconds < 10 || c.PollSeconds > 300 {
		c.PollSeconds = 30
	}
	if c.KeepDays < 7 || c.KeepDays > 730 {
		c.KeepDays = 180
	}
	for i := range c.Devices {
		d := &c.Devices[i]
		d.Host, d.Username, d.Name = strings.TrimSpace(d.Host), strings.TrimSpace(d.Username), strings.TrimSpace(d.Name)
		if d.Host == "" || d.Username == "" {
			return errors.New("WAN links: every firewall needs an address and an SNMPv3 username")
		}
		if d.Name == "" {
			d.Name = d.Host
		}
		if d.Port == 0 {
			d.Port = 161
		}
		if d.Level == "" {
			d.Level = "authPriv"
		}
		if _, _, _, err := d.protos(); err != nil {
			return fmt.Errorf("WAN links (%s): %v", d.Name, err)
		}
		// v5.19: a missing passphrase no longer refuses the whole configuration (that blocked every Save in
		// Settings). The firewall is kept, its tile and Diagnostics say "no passphrase saved", and it is not polled.
		d.AuthSet, d.PrivSet, d.CredsFrom = false, false, ""
		for j := range d.Interfaces {
			f := &d.Interfaces[j]
			f.Name, f.Label = strings.TrimSpace(f.Name), strings.TrimSpace(f.Label)
			if f.Name == "" {
				return fmt.Errorf("WAN links (%s): an interface has no name", d.Name)
			}
			if f.UpMbps == 0 {
				f.UpMbps = f.DownMbps
			}
		}
	}
	return nil
}

func (d WANDevice) protos() (snmp.SecurityLevel, snmp.AuthProto, snmp.PrivProto, error) {
	lv, err := snmp.ParseSecurityLevel(d.Level)
	if err != nil {
		return 0, 0, 0, err
	}
	au, err := snmp.ParseAuthProto(d.Auth)
	if err != nil {
		return 0, 0, 0, err
	}
	pr, err := snmp.ParsePrivProto(d.Priv)
	if err != nil {
		return 0, 0, 0, err
	}
	if lv == snmp.AuthPriv && pr == snmp.PrivAES256 && (au == snmp.AuthSHA1 || au == snmp.AuthMD5) {
		return 0, 0, 0, errors.New("AES256 needs SHA256 or longer for authentication")
	}
	return lv, au, pr, nil
}

// missingPass: what is missing for this firewall to be polled ("" = nothing).
func (d WANDevice) missingPass() string {
	lv, _, pr, err := d.protos()
	if err != nil {
		return ""
	}
	switch {
	case lv != snmp.NoAuthNoPriv && d.AuthPass == "" && lv == snmp.AuthPriv && pr != snmp.PrivNone && d.PrivPass == "":
		return "no passphrases saved: type the authentication and privacy passphrases in Settings > WAN links and Save"
	case lv != snmp.NoAuthNoPriv && d.AuthPass == "":
		return "no authentication passphrase saved: type it in Settings > WAN links and Save"
	case lv == snmp.AuthPriv && pr != snmp.PrivNone && d.PrivPass == "":
		return "no privacy passphrase saved: type it in Settings > WAN links and Save"
	}
	return ""
}

func (d WANDevice) client() (*snmp.Client, error) {
	lv, au, pr, err := d.protos()
	if err != nil {
		return nil, err
	}
	return snmp.New(snmp.Config{Host: d.Host, Port: d.Port, Timeout: 3 * time.Second, Retries: 1, Username: d.Username,
		Level: lv, Auth: au, Priv: pr, AuthPass: d.AuthPass, PrivPass: d.PrivPass})
}

// keepWANSecrets: the settings page never sees the passphrases; an empty field keeps the stored one.
func keepWANSecrets(newC *WANConfig, old WANConfig) {
	for i := range newC.Devices {
		n := &newC.Devices[i]
		var match *WANDevice
		for j := range old.Devices { // v5.19: by address; then by name (address changed)
			if strings.EqualFold(strings.TrimSpace(old.Devices[j].Host), strings.TrimSpace(n.Host)) {
				match = &old.Devices[j]
				break
			}
		}
		if match == nil {
			for j := range old.Devices {
				if n.Name != "" && strings.EqualFold(old.Devices[j].Name, strings.TrimSpace(n.Name)) {
					match = &old.Devices[j]
					break
				}
			}
		}
		if match != nil {
			if n.AuthPass == "" {
				n.AuthPass = match.AuthPass
			}
			if n.PrivPass == "" {
				n.PrivPass = match.PrivPass
			}
		}
	}
	// v5.20.1: "same SNMPv3 user as": empty passphrases are copied from the named firewall (typed in this form, or stored)
	for i := range newC.Devices {
		n := &newC.Devices[i]
		src := strings.TrimSpace(n.CredsFrom)
		if src == "" || (n.AuthPass != "" && n.PrivPass != "") {
			continue
		}
		same := func(d WANDevice) bool {
			return strings.EqualFold(strings.TrimSpace(d.Name), src) || strings.EqualFold(strings.TrimSpace(d.Host), src)
		}
		var from *WANDevice
		for j := range newC.Devices {
			if j != i && same(newC.Devices[j]) && newC.Devices[j].AuthPass != "" {
				from = &newC.Devices[j]
				break
			}
		}
		if from == nil {
			for j := range old.Devices {
				if same(old.Devices[j]) {
					from = &old.Devices[j]
					break
				}
			}
		}
		if from == nil {
			continue
		}
		if n.AuthPass == "" {
			n.AuthPass = from.AuthPass
		}
		if n.PrivPass == "" {
			n.PrivPass = from.PrivPass
		}
	}
}

func hideWANSecrets(c *WANConfig) {
	l := make([]WANDevice, len(c.Devices))
	copy(l, c.Devices)
	for i := range l {
		l[i].AuthSet, l[i].PrivSet = l[i].AuthPass != "", l[i].PrivPass != ""
		l[i].AuthPass, l[i].PrivPass = "", ""
	}
	c.Devices = l
}

// ---------------------------------------------------------------- poller

var (
	oidIfName    = ber.MustParseOIDString("1.3.6.1.2.1.31.1.1.1.1")
	oidIfHCIn    = ber.MustParseOIDString("1.3.6.1.2.1.31.1.1.1.6")
	oidIfHCOut   = ber.MustParseOIDString("1.3.6.1.2.1.31.1.1.1.10")
	oidIfSpeed   = ber.MustParseOIDString("1.3.6.1.2.1.31.1.1.1.15")
	oidIfAlias   = ber.MustParseOIDString("1.3.6.1.2.1.31.1.1.1.18")
	oidIfOper    = ber.MustParseOIDString("1.3.6.1.2.1.2.2.1.8")
	oidIfType    = ber.MustParseOIDString("1.3.6.1.2.1.2.2.1.3")
	oidSysName   = ber.MustParseOIDString("1.3.6.1.2.1.1.5.0")
	oidSysUptime = ber.MustParseOIDString("1.3.6.1.2.1.1.3.0")
)

type wanPrev struct {
	in, out uint64
	at      time.Time
}

type wanLive struct {
	Rx    float64   `json:"rx"`
	Tx    float64   `json:"tx"`
	Up    bool      `json:"up"`
	At    time.Time `json:"at"`
	Alias string    `json:"alias"`
	Speed int       `json:"speed_mbps"`
	Found bool      `json:"found"`
	EstDn int       `json:"est_down_kbps,omitempty"` // v5.19: estimated bandwidth set on the FortiGate interface
	EstUp int       `json:"est_up_kbps,omitempty"`
}

type wanDev struct {
	mu     sync.Mutex // v5.20.1: held while this firewall is polled (network I/O)
	smu    sync.Mutex // guards snap, read by the status page
	snap   wanSnap
	key    string
	cfg    WANDevice
	cl     *snmp.Client
	idx    map[string]int
	alias  map[int]string
	speed  map[int]int
	est    map[int][2]int // v5.19: FortiGate estimated bandwidth, kbps (down, up)
	extra  wanExtra       // v5.19: CPU / memory / sessions, SD-WAN health, IPsec tunnels
	discAt time.Time
	prev   map[string]wanPrev
	live   map[string]wanLive
	engine string // authoritative SNMP engine; HA failover changes this on a different member
	uptime uint64 // sysUpTime TimeTicks from the last successful poll
	err    string
	errAt  time.Time
	okAt   time.Time
}

// wanSnap: what the status page shows of a firewall, copied at the end of every poll.
type wanSnap struct {
	err         string
	errAt       time.Time
	okAt, tryAt time.Time
	stored      int64
	live        map[string]wanLive
	extra       wanExtra
}

var wanState = struct {
	sync.Mutex
	devs map[string]*wanDev
}{devs: map[string]*wanDev{}}

func (w *wanDev) discover() error {
	names, err := w.cl.Walk(oidIfName)
	if err != nil {
		return fmt.Errorf("reading the interface list: %w", err)
	}
	idx, alias, speed := map[string]int{}, map[int]string{}, map[int]int{}
	for _, vb := range names {
		idx[vb.Str()] = int(vb.OID[len(vb.OID)-1])
	}
	if l, err := w.cl.Walk(oidIfAlias); err == nil {
		for _, vb := range l {
			alias[int(vb.OID[len(vb.OID)-1])] = vb.Str()
		}
	}
	if l, err := w.cl.Walk(oidIfSpeed); err == nil {
		for _, vb := range l {
			speed[int(vb.OID[len(vb.OID)-1])] = int(vb.Uint())
		}
	}
	est := map[int][2]int{}
	if l, err := w.cl.Walk(oidFgEstUp); err == nil {
		for _, vb := range l {
			i := int(vb.OID[len(vb.OID)-1])
			x := est[i]
			x[1] = int(vb.Uint())
			est[i] = x
		}
	}
	if l, err := w.cl.Walk(oidFgEstDown); err == nil {
		for _, vb := range l {
			i := int(vb.OID[len(vb.OID)-1])
			x := est[i]
			x[0] = int(vb.Uint())
			est[i] = x
		}
	}
	w.idx, w.alias, w.speed, w.est, w.discAt = idx, alias, speed, est, time.Now()
	return nil
}

type wanSample struct {
	dev, iface string
	rx, tx     float64
	up         bool
	bytesIn, bytesOut uint64
	interval float64
	at time.Time
}

// poll reads the counters of the chosen interfaces in one request and returns the rates since the previous poll.
func (w *wanDev) poll() ([]wanSample, error) {
	if w.idx == nil || time.Since(w.discAt) > 5*time.Minute {
		if err := w.discover(); err != nil {
			return nil, err
		}
	}
	type slot struct {
		name string
		idx  int
	}
	var oids [][]uint32
	var slots []slot
	// Read sysUpTime with the interface counters. Engine ID + uptime protects the rate baseline across
	// HA member changes and firewall reboots, where otherwise a valid-looking counter delta can spike.
	oids = append(oids, oidSysUptime)
	for _, f := range w.cfg.Interfaces {
		i, ok := w.idx[f.Name]
		if !ok {
			w.live[f.Name] = wanLive{Found: false, At: time.Now()}
			continue
		}
		slots = append(slots, slot{f.Name, i})
		oids = append(oids, ber.Concat(oidIfHCIn, uint32(i)), ber.Concat(oidIfHCOut, uint32(i)), ber.Concat(oidIfOper, uint32(i)))
	}
	if len(slots) == 0 {
		return nil, errors.New("none of the chosen interfaces exists on the firewall (check the names)")
	}
	vbs, err := w.cl.Get(oids)
	if err != nil {
		return nil, err
	}
	if len(vbs) != len(oids) {
		return nil, fmt.Errorf("asked for %d values, got %d", len(oids), len(vbs))
	}
	engine := fmt.Sprintf("%x", w.cl.EngineID())
	upTicks := vbs[0].Uint()
	if (w.engine != "" && engine != "" && engine != w.engine) || (w.uptime > 0 && upTicks < w.uptime) {
		w.prev = map[string]wanPrev{}
	}
	if engine != "" { w.engine = engine }
	w.uptime = upTicks
	now := time.Now()
	var out []wanSample
	for k, s := range slots {
		in, ou, st := vbs[1+3*k], vbs[1+3*k+1], vbs[1+3*k+2]
		up := st.Exists() && st.Int() == 1
		l := wanLive{Up: up, At: now, Alias: w.alias[s.idx], Speed: w.speed[s.idx], Found: true, EstDn: w.est[s.idx][0], EstUp: w.est[s.idx][1]}
		if !in.Exists() || !ou.Exists() {
			w.live[s.name] = l
			delete(w.prev, s.name)
			continue
		}
		ci, co := in.Uint(), ou.Uint()
		p, had := w.prev[s.name]
		w.prev[s.name] = wanPrev{ci, co, now}
		if had {
			dt := now.Sub(p.at).Seconds()
			if dt > 0 && ci >= p.in && co >= p.out { // a 64-bit counter going back is a reset: skip this sample
				rx, tx := float64(ci-p.in)*8/dt, float64(co-p.out)*8/dt
				if sp := float64(w.speed[s.idx]); sp <= 0 || (rx <= sp*1e6*10 && tx <= sp*1e6*10) {
					l.Rx, l.Tx = rx, tx
					out = append(out, wanSample{dev: w.cfg.Name, iface: s.name, rx: rx, tx: tx, up: up, bytesIn: ci-p.in, bytesOut: co-p.out, interval: dt, at: now})
				}
			}
		}
		w.live[s.name] = l
	}
	return out, nil
}

func (a *App) wanLoop(ctx context.Context) error {
	wanStarted = time.Now()
	for {
		c := a.store.Get().WAN
		wait := time.Duration(c.PollSeconds) * time.Second
		if wait <= 0 {
			wait = 30 * time.Second
		}
		if c.Enabled {
			a.wanTick(ctx, c)
		} else {
			wanCloseAll()
		}
		select {
		case <-ctx.Done():
			wanCloseAll()
			return nil
		case <-time.After(wait):
		}
	}
}

func wanCloseAll() {
	wanState.Lock()
	for k, w := range wanState.devs {
		if w.cl != nil {
			_ = w.cl.Close()
		}
		delete(wanState.devs, k)
	}
	wanState.Unlock()
}

func (a *App) wanTick(ctx context.Context, c WANConfig) {
	wanState.Lock()
	keep := map[string]bool{}
	var list []*wanDev
	for _, dc := range c.Devices {
		b, _ := json.Marshal(dc)
		key := dc.Host + "|" + dc.Username
		keep[key] = true
		w := wanState.devs[key]
		if w != nil && string(b) != w.key {
			if w.cl != nil {
				_ = w.cl.Close()
			}
			w = nil
		}
		if w == nil {
			w = &wanDev{key: string(b), cfg: dc, prev: map[string]wanPrev{}, live: map[string]wanLive{}}
			wanState.devs[key] = w
		}
		list = append(list, w)
	}
	for k, w := range wanState.devs {
		if !keep[k] {
			if w.cl != nil {
				_ = w.cl.Close()
			}
			delete(wanState.devs, k)
		}
	}
	wanState.Unlock()
	// v5.20.1: every firewall is polled at the same time and on its own lock. Before, the firewalls were polled one
	// after another while holding the lock the status page needs, so one firewall that did not answer (6 s per try)
	// delayed every other firewall and froze the WAN links page.
	var mu sync.Mutex
	var wg sync.WaitGroup
	var all []wanSample
	var health []wanHealth
	for _, w := range list {
		wg.Add(1)
		go func(w *wanDev) {
			defer wg.Done()
			s, h := w.pollOnce()
			mu.Lock()
			all = append(all, s...)
			if h != nil {
				health = append(health, *h)
			}
			mu.Unlock()
		}(w)
	}
	wg.Wait()
	d := a.getDB()
	if d != nil && len(health) > 0 { // v5.21
		c3, cancel3 := context.WithTimeout(ctx, 10*time.Second)
		logWANHealthErr(d.storeHealth(c3, health))
		cancel3()
	}
	if d == nil || len(all) == 0 {
		return
	}
	devs, ifs, ups := make([]string, len(all)), make([]string, len(all)), make([]bool, len(all))
	rx, tx := make([]float64, len(all)), make([]float64, len(all))
	bin, bout := make([]int64, len(all)), make([]int64, len(all))
	intervals := make([]float64, len(all))
	times := make([]time.Time, len(all))
	for i, s := range all {
		devs[i], ifs[i], rx[i], tx[i], ups[i] = s.dev, s.iface, s.rx, s.tx, s.up
		bin[i], bout[i], intervals[i], times[i] = int64(s.bytesIn), int64(s.bytesOut), s.interval, s.at
	}
	c2, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if _, err := d.pool.Exec(c2, `INSERT INTO wan_samples(ts, dev, iface, rx, tx, up, bytes_in, bytes_out, interval_seconds) SELECT * FROM unnest($1::timestamptz[], $2::text[], $3::text[], $4::float8[], $5::float8[], $6::bool[], $7::bigint[], $8::bigint[], $9::float8[])`,
		times, devs, ifs, rx, tx, ups, bin, bout, intervals); err != nil {
		log.Printf("WAN links: storing samples: %v", err)
		wanStoreErr.Store(err.Error())
		return
	}
	wanStoreErr.Store("")
	n := map[string]int64{}
	for _, s := range all {
		n[s.dev]++
	}
	for _, w := range list {
		if k := n[w.cfg.Name]; k > 0 {
			w.smu.Lock()
			if w.snap.stored == 0 {
				log.Printf("WAN links %s: first samples stored", w.cfg.Name)
			}
			w.snap.stored += k
			w.smu.Unlock()
		}
	}
}

// ---------------------------------------------------------------- reading it

type wanLink struct {
	Dev, Iface, Label string
	Down, Up          int
}

func wanLinks(c WANConfig) []wanLink {
	var out []wanLink
	for _, d := range c.Devices {
		for _, f := range d.Interfaces {
			out = append(out, wanLink{d.Name, f.Name, firstNonEmpty(f.Label, f.Name), f.DownMbps, f.UpMbps})
		}
	}
	return out
}

// wanStats: per link, average / 95th percentile / peak in both directions, time above 80% of capacity, and the
// average by hour of day (local time).
func (d *Database) wanStats(ctx context.Context, c WANConfig, from, to time.Time) ([]map[string]any, error) {
	links := wanLinks(c)
	if len(links) == 0 {
		return []map[string]any{}, nil
	}
	devs, ifs := make([]string, len(links)), make([]string, len(links))
	downs, ups := make([]float64, len(links)), make([]float64, len(links))
	for i, l := range links {
		devs[i], ifs[i], downs[i], ups[i] = l.Dev, l.Iface, float64(l.Down)*1e6, float64(l.Up)*1e6
	}
	rows, err := d.pool.Query(ctx, `SELECT s.dev, s.iface, avg(rx), avg(tx), percentile_cont(0.95) WITHIN GROUP (ORDER BY rx),
		percentile_cont(0.95) WITHIN GROUP (ORDER BY tx), max(rx), max(tx), count(*),
		count(*) FILTER (WHERE c.down > 0 AND rx >= 0.8 * c.down), count(*) FILTER (WHERE c.up > 0 AND tx >= 0.8 * c.up),
		count(*) FILTER (WHERE NOT s.up), min(ts), max(ts)
		FROM wan_samples s JOIN unnest($3::text[], $4::text[], $5::float8[], $6::float8[]) AS c(dev, iface, down, up) ON c.dev = s.dev AND c.iface = s.iface
		WHERE ts >= $1 AND ts < $2 GROUP BY 1, 2`, from, to, devs, ifs, downs, ups)
	if err != nil {
		return nil, err
	}
	got := map[string]map[string]any{}
	for rows.Next() {
		var dv, f string
		var arx, atx, prx, ptx, mrx, mtx float64
		var n, brx, btx, down int64
		var first, last time.Time
		if err = rows.Scan(&dv, &f, &arx, &atx, &prx, &ptx, &mrx, &mtx, &n, &brx, &btx, &down, &first, &last); err != nil {
			rows.Close()
			return nil, err
		}
		got[dv+"|"+f] = map[string]any{"avg_down": arx, "avg_up": atx, "p95_down": prx, "p95_up": ptx, "peak_down": mrx, "peak_up": mtx,
			"samples": n, "busy_down": brx, "busy_up": btx, "down_samples": down, "first": first, "last": last}
	}
	rows.Close()
	hours := map[string][]float64{}
	if hr, err := d.pool.Query(ctx, `SELECT dev, iface, extract(hour FROM ts)::int, avg(rx), avg(tx) FROM wan_samples WHERE ts >= $1 AND ts < $2 GROUP BY 1, 2, 3`, from, to); err == nil {
		for hr.Next() {
			var dv, f string
			var h int
			var r, t float64
			if hr.Scan(&dv, &f, &h, &r, &t) == nil && h >= 0 && h < 24 {
				k := dv + "|" + f
				if hours[k] == nil {
					hours[k] = make([]float64, 48)
				}
				hours[k][h], hours[k][24+h] = r, t
			}
		}
		hr.Close()
	}
	out := []map[string]any{}
	for _, l := range links {
		m := map[string]any{"dev": l.Dev, "iface": l.Iface, "label": l.Label, "down_mbps": l.Down, "up_mbps": l.Up}
		if s, ok := got[l.Dev+"|"+l.Iface]; ok {
			for k, v := range s {
				m[k] = v
			}
		}
		if h, ok := hours[l.Dev+"|"+l.Iface]; ok {
			m["by_hour_down"], m["by_hour_up"] = h[:24], h[24:]
		}
		out = append(out, m)
	}
	return out, nil
}

func wanStep(span time.Duration, poll int) int64 {
	step := int64(span.Seconds() / 400)
	for _, s := range []int64{60, 120, 300, 600, 900, 1800, 3600, 7200, 14400, 21600, 43200, 86400} {
		if step <= s {
			step = s
			break
		}
	}
	if step < int64(poll) {
		step = int64(poll)
	}
	return step
}

func (a *App) handleWAN(w http.ResponseWriter, r *http.Request) {
	c := a.store.Get().WAN
	f := parseFilter(r)
	out := map[string]any{"enabled": c.Enabled, "poll_seconds": c.PollSeconds, "from": f.From, "to": f.To, "status": wanStatus(c)}
	if r.URL.Query().Get("diag") == "1" { // v5.18
		jsonOut(w, a.wanDiag(r.Context(), c))
		return
	}
	if r.URL.Query().Get("health") == "1" { // v5.21: CPU, memory, SD-WAN health and tunnels over the period
		d := a.dbOrFail(w)
		if d == nil {
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		v, err := cached("wanhealth?"+r.URL.RawQuery, 30*time.Second, func() (any, error) { return d.wanHealthData(ctx, f.From, f.To, c.PollSeconds) })
		if err != nil {
			queryErr(w, err)
			return
		}
		jsonOut(w, v)
		return
	}
	d := a.getDB()
	if d == nil || len(wanLinks(c)) == 0 {
		out["links"] = []any{}
		jsonOut(w, out)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	if r.URL.Query().Get("live") == "1" { // v5.17: the live charts (every poll), last 30 minutes at full resolution
		l, err := d.wanLive(ctx, c, 30*time.Minute)
		if err != nil {
			queryErr(w, err)
			return
		}
		out["live"] = l
		jsonOut(w, out)
		return
	}
	v, err := cached("wan?"+r.URL.RawQuery, 30*time.Second, func() (any, error) {
		stats, err := d.wanStats(ctx, c, f.From, f.To)
		if err != nil {
			return nil, err
		}
		usage, err := d.wanUsage(ctx, c, f.From, f.To)
		if err != nil {
			return nil, err
		}
		step := wanStep(f.To.Sub(f.From), c.PollSeconds)
		rows, err := d.pool.Query(ctx, `SELECT dev, iface, (floor(extract(epoch FROM ts)/$3)*$3)::bigint, avg(rx), avg(tx), max(rx), max(tx)
			FROM wan_samples WHERE ts >= $1 AND ts < $2 GROUP BY 1, 2, 3 ORDER BY 3`, f.From, f.To, step)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		series := map[string][][5]float64{}
		for rows.Next() {
			var dv, fn string
			var b int64
			var ar, at, mr, mt float64
			if rows.Scan(&dv, &fn, &b, &ar, &at, &mr, &mt) == nil {
				series[dv+"|"+fn] = append(series[dv+"|"+fn], [5]float64{float64(b), ar, at, mr, mt})
			}
		}
		for _, s := range stats {
			s["series"] = series[fmt.Sprint(s["dev"])+"|"+fmt.Sprint(s["iface"])]
		}
		return map[string]any{"links": stats, "step": step, "usage": usage}, nil
	})
	if err != nil {
		queryErr(w, err)
		return
	}
	for k, x := range v.(map[string]any) {
		out[k] = x
	}
	jsonOut(w, out)
}

func wanStatus(c WANConfig) []map[string]any {
	wanState.Lock()
	defer wanState.Unlock()
	out := []map[string]any{}
	for _, dc := range c.Devices {
		m := map[string]any{"name": dc.Name, "host": dc.Host}
		if wd := wanState.devs[dc.Host+"|"+dc.Username]; wd != nil {
			wd.smu.Lock() // v5.20.1: a snapshot; never waits for a firewall that is being polled
			sn := wd.snap
			wd.smu.Unlock()
			if sn.err != "" {
				m["error"], m["error_at"] = sn.err, sn.errAt
			}
			if !sn.okAt.IsZero() {
				m["last_ok"] = sn.okAt
			}
			if !sn.tryAt.IsZero() {
				m["last_try"] = sn.tryAt
			}
			m["stored"] = sn.stored
			m["extra"] = sn.extra
			live := map[string]wanLive{}
			for k, v := range sn.live {
				live[k] = v
			}
			m["live"] = live
		}
		out = append(out, m)
	}
	return out
}

// /api/wan/discover (admin): walk a firewall's interfaces so they can be picked in Settings.
func (a *App) handleWANDiscover(w http.ResponseWriter, r *http.Request) {
	var dv WANDevice
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&dv); err != nil {
		jsonError(w, http.StatusBadRequest, "bad request")
		return
	}
	tmp := WANConfig{Devices: []WANDevice{dv}}
	keepWANSecrets(&tmp, a.store.Get().WAN)
	if err := tmp.validate(); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	dv = tmp.Devices[0]
	if m := dv.missingPass(); m != "" {
		jsonError(w, http.StatusBadRequest, strings.Replace(m, " in Settings > WAN links and Save", " above", 1))
		return
	}
	cl, err := dv.client()
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	defer cl.Close()
	id, err := cl.Get([][]uint32{oidSysName, oidSysUptime})
	if err != nil {
		jsonError(w, http.StatusBadGateway, err.Error()+snmpHint(err))
		return
	}
	names, err := cl.Walk(oidIfName)
	if err != nil {
		jsonError(w, http.StatusBadGateway, err.Error())
		return
	}
	type row struct {
		Index int    `json:"index"`
		Name  string `json:"name"`
		Alias string `json:"alias"`
		Speed int    `json:"speed_mbps"`
		Up    bool   `json:"up"`
		Type  int    `json:"type"`
		EstDn int    `json:"est_down_kbps"`
		EstUp int    `json:"est_up_kbps"`
	}
	by := map[int]*row{}
	var l []*row
	for _, vb := range names {
		i := int(vb.OID[len(vb.OID)-1])
		x := &row{Index: i, Name: vb.Str()}
		by[i] = x
		l = append(l, x)
	}
	fill := func(oid []uint32, fn func(*row, snmp.VarBind)) {
		if vs, err := cl.Walk(oid); err == nil {
			for _, vb := range vs {
				if x := by[int(vb.OID[len(vb.OID)-1])]; x != nil && vb.Exists() {
					fn(x, vb)
				}
			}
		}
	}
	fill(oidIfAlias, func(x *row, vb snmp.VarBind) { x.Alias = vb.Str() })
	fill(oidIfSpeed, func(x *row, vb snmp.VarBind) { x.Speed = int(vb.Uint()) })
	fill(oidIfOper, func(x *row, vb snmp.VarBind) { x.Up = vb.Int() == 1 })
	fill(oidIfType, func(x *row, vb snmp.VarBind) { x.Type = int(vb.Int()) })
	fill(oidFgEstDown, func(x *row, vb snmp.VarBind) { x.EstDn = int(vb.Uint()) })
	fill(oidFgEstUp, func(x *row, vb snmp.VarBind) { x.EstUp = int(vb.Uint()) })
	sort.Slice(l, func(i, j int) bool { return l[i].Index < l[j].Index })
	sys := ""
	if len(id) > 0 {
		sys = id[0].Str()
	}
	jsonOut(w, map[string]any{"sys_name": sys, "interfaces": l})
}

func snmpHint(err error) string {
	m := strings.ToLower(err.Error())
	switch {
	case strings.Contains(m, "timeout"):
		return ". No answer: add this server to the SNMP user's trusted hosts on the FortiGate, allow SNMP on the interface it reaches, and UDP/161."
	case strings.Contains(m, "digest"):
		return ". The authentication passphrase or protocol does not match the FortiGate user."
	case strings.Contains(m, "decrypt"), strings.Contains(m, "scoped"):
		return ". The privacy passphrase or protocol (AES128 / AES256) does not match."
	case strings.Contains(m, "report"):
		return ". Usually an unknown username or a security level the user is not set up for."
	}
	return ""
}

func round1(f float64) float64 { return math.Round(f*10) / 10 }

var wanKeep atomic.Int32

func wanKeepDays() int {
	if n := int(wanKeep.Load()); n > 0 {
		return n
	}
	return 180
}

// ---------------------------------------------------------------- v5.17: data volume and the live view

// wanVolSQL: v6.0.6 stores exact counter deltas. Older rows fall back to the historical
// rate x bounded-gap calculation so upgrades preserve existing WAN history.
const wanVolSQL = `SELECT dev, iface, ts,
 CASE WHEN bytes_in IS NOT NULL THEN bytes_in::float8 ELSE rx * dt / 8 END AS din,
 CASE WHEN bytes_out IS NOT NULL THEN bytes_out::float8 ELSE tx * dt / 8 END AS dout
 FROM (SELECT *, CASE WHEN dt0 IS NULL THEN NULL ELSE least(dt0, $3::float8) END AS dt FROM (
 SELECT dev, iface, ts, rx, tx, bytes_in, bytes_out, interval_seconds,
 extract(epoch FROM ts - lag(ts) OVER (PARTITION BY dev, iface ORDER BY ts))::float8 AS dt0
 FROM wan_samples WHERE ts >= $1::timestamptz - interval '15 minutes' AND ts < $2) x0) x
 WHERE (bytes_in IS NOT NULL OR dt IS NOT NULL) AND ts >= $1`

// wanUsage: per link, the data downloaded and uploaded per day (local calendar), in the period and month to date.
func (d *Database) wanUsage(ctx context.Context, c WANConfig, from, to time.Time) (map[string]any, error) {
	poll := float64(max(c.PollSeconds, 10)) * 3
	rows, err := d.pool.Query(ctx, `SELECT dev, iface, date_trunc('day', ts, $4::text), coalesce(sum(din),0)::float8, coalesce(sum(dout),0)::float8
		FROM (`+wanVolSQL+`) v GROUP BY 1, 2, 3 ORDER BY 3`, from, to, poll, reportTZ())
	if err != nil {
		return nil, err
	}
	days := map[string][]map[string]any{}
	tot := map[string][2]float64{}
	for rows.Next() {
		var dv, f string
		var t time.Time
		var a, b float64
		if rows.Scan(&dv, &f, &t, &a, &b) == nil {
			k := dv + "|" + f
			days[k] = append(days[k], map[string]any{"day": t, "down": int64(a), "up": int64(b)})
			x := tot[k]
			tot[k] = [2]float64{x[0] + a, x[1] + b}
		}
	}
	rows.Close()
	now := time.Now().In(time.Local)
	m0 := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.Local)
	month := map[string][2]float64{}
	if mr, err := d.pool.Query(ctx, `SELECT dev, iface, coalesce(sum(din),0)::float8, coalesce(sum(dout),0)::float8 FROM (`+wanVolSQL+`) v GROUP BY 1, 2`,
		m0, now.Add(time.Minute), poll); err == nil {
		for mr.Next() {
			var dv, f string
			var a, b float64
			if mr.Scan(&dv, &f, &a, &b) == nil {
				month[dv+"|"+f] = [2]float64{a, b}
			}
		}
		mr.Close()
	}
	out := map[string]any{}
	for _, l := range wanLinks(c) {
		k := l.Dev + "|" + l.Iface
		dl := days[k]
		if dl == nil {
			dl = []map[string]any{}
		}
		out[k] = map[string]any{"days": dl, "down": int64(tot[k][0]), "up": int64(tot[k][1]), "month_down": int64(month[k][0]),
			"month_up": int64(month[k][1]), "month_from": m0}
	}
	return out, nil
}

// wanLive: the last minutes of samples per link at full resolution, for the live charts.
func (d *Database) wanLive(ctx context.Context, c WANConfig, span time.Duration) (map[string][][3]float64, error) {
	rows, err := d.pool.Query(ctx, `SELECT dev, iface, extract(epoch FROM ts)::float8, rx, tx FROM wan_samples WHERE ts > now() - $1 * interval '1 second' ORDER BY ts`,
		int(span.Seconds()))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][][3]float64{}
	for rows.Next() {
		var dv, f string
		var t, rx, tx float64
		if rows.Scan(&dv, &f, &t, &rx, &tx) == nil {
			out[dv+"|"+f] = append(out[dv+"|"+f], [3]float64{t, rx, tx})
		}
	}
	return out, rows.Err()
}

var wanStoreErr atomic.Value

// wanDiag (v5.18): everything needed to see why the WAN tab is empty, in one answer. Each step is checked on its own
// and reports its own error, so one failing query cannot hide the others.
func (a *App) wanDiag(rctx context.Context, c WANConfig) map[string]any {
	ctx, cancel := context.WithTimeout(rctx, 20*time.Second)
	defer cancel()
	out := map[string]any{"enabled": c.Enabled, "poll_seconds": c.PollSeconds, "now": time.Now()}
	devs := []map[string]any{}
	for _, d := range c.Devices {
		ifs := []string{}
		for _, f := range d.Interfaces {
			ifs = append(ifs, f.Name)
		}
		devs = append(devs, map[string]any{"name": d.Name, "host": d.Host, "user": d.Username, "level": d.Level, "auth": d.Auth, "priv": d.Priv,
			"auth_pass_set": d.AuthPass != "", "priv_pass_set": d.PrivPass != "", "interfaces": ifs})
	}
	out["config"] = devs
	out["poller"] = wanStatus(c)
	if s, _ := wanStoreErr.Load().(string); s != "" {
		out["store_error"] = s
	}
	db := a.getDB()
	if db == nil {
		out["database"] = "not connected"
		return out
	}
	checks := map[string]string{}
	rows, err := db.pool.Query(ctx, `SELECT dev, iface, count(*), max(ts) FROM wan_samples WHERE ts > now() - interval '1 hour' GROUP BY 1, 2 ORDER BY 1, 2`)
	if err != nil {
		checks["samples"] = err.Error()
	} else {
		l := []map[string]any{}
		for rows.Next() {
			var dv, f string
			var n int64
			var t time.Time
			if rows.Scan(&dv, &f, &n, &t) == nil {
				l = append(l, map[string]any{"dev": dv, "iface": f, "last_hour": n, "last": t})
			}
		}
		rows.Close()
		out["samples"] = l
		checks["samples"] = "ok"
	}
	now := time.Now()
	run := func(name string, fn func() error) {
		if err := fn(); err != nil {
			checks[name] = err.Error()
		} else {
			checks[name] = "ok"
		}
	}
	run("stats", func() error { _, err := db.wanStats(ctx, c, now.Add(-6*time.Hour), now); return err })
	run("usage", func() error { _, err := db.wanUsage(ctx, c, now.Add(-6*time.Hour), now); return err })
	run("live", func() error { _, err := db.wanLive(ctx, c, 30*time.Minute); return err })
	run("series", func() error {
		r, err := db.pool.Query(ctx, `SELECT dev, iface, (floor(extract(epoch FROM ts)/$3)*$3)::bigint, avg(rx) FROM wan_samples WHERE ts >= $1 AND ts < $2 GROUP BY 1, 2, 3`,
			now.Add(-6*time.Hour), now, int64(60))
		if err == nil {
			r.Close()
		}
		return err
	})
	out["checks"] = checks
	return out
}

// ---------------------------------------------------------------- v5.19: FortiGate MIB (FORTINET-FORTIGATE-MIB)

var (
	oidFgEstUp     = ber.MustParseOIDString("1.3.6.1.4.1.12356.101.7.2.1.1.2") // fgIntfEntEstUpBandwidth (kbps), augments ifEntry
	oidFgEstDown   = ber.MustParseOIDString("1.3.6.1.4.1.12356.101.7.2.1.1.3") // fgIntfEntEstDownBandwidth (kbps)
	oidFgCPU       = ber.MustParseOIDString("1.3.6.1.4.1.12356.101.4.1.3.0")   // fgSysCpuUsage (%)
	oidFgMem       = ber.MustParseOIDString("1.3.6.1.4.1.12356.101.4.1.4.0")   // fgSysMemUsage (%)
	oidFgSessions  = ber.MustParseOIDString("1.3.6.1.4.1.12356.101.4.1.8.0")   // fgSysSesCount
	oidFgSLAEntry  = ber.MustParseOIDString("1.3.6.1.4.1.12356.101.4.9.2.1")   // fgVWLHealthCheckLinkEntry
	oidFgVPN2Entry = ber.MustParseOIDString("1.3.6.1.4.1.12356.101.12.4.2.1")  // fgVpn2TunEntry
)

type wanSLA struct {
	Name    string  `json:"name"`  // health check
	Iface   string  `json:"iface"` // member interface
	Alive   bool    `json:"alive"`
	Latency float64 `json:"latency_ms"`
	Jitter  float64 `json:"jitter_ms"`
	Loss    float64 `json:"loss_pct"`
	UsedIn  int64   `json:"used_in_kbps"`
	UsedOut int64   `json:"used_out_kbps"`
}

type wanVPN struct {
	Name   string  `json:"name"` // phase 1 (phase 2)
	Remote string  `json:"remote"`
	Up     bool    `json:"up"`
	In     uint64  `json:"in_bytes"`
	Out    uint64  `json:"out_bytes"`
	RxBps  float64 `json:"rx_bps"`
	TxBps  float64 `json:"tx_bps"`
}

type wanExtra struct {
	At       time.Time `json:"at"`
	CPU      *int64    `json:"cpu,omitempty"`
	Mem      *int64    `json:"mem,omitempty"`
	Sessions *int64    `json:"sessions,omitempty"`
	SLA      []wanSLA  `json:"sla"`
	VPN      []wanVPN  `json:"vpn"`
	VPNUp    int       `json:"vpn_up"`
	VPNDown  int       `json:"vpn_down"`
	Err      string    `json:"error,omitempty"` // the FortiGate MIB did not answer (only the interface counters are used)
	prevVPN  map[string]wanPrev
}

func parseF(s string) float64 {
	var f float64
	_, _ = fmt.Sscanf(strings.TrimSpace(s), "%g", &f)
	return f
}

func inetStr(b []byte) string {
	switch len(b) {
	case 4:
		return fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3])
	case 16:
		return net.IP(b).String()
	}
	return string(b)
}

// table walks one MIB table entry and groups the values by row index: rows[index][column].
func (w *wanDev) table(root []uint32) (map[string]map[uint32]snmp.VarBind, []string, error) {
	vbs, err := w.cl.Walk(root)
	if err != nil {
		return nil, nil, err
	}
	rows, order := map[string]map[uint32]snmp.VarBind{}, []string{}
	for _, vb := range vbs {
		if len(vb.OID) <= len(root)+1 || !vb.Exists() {
			continue
		}
		col := vb.OID[len(root)]
		k := ber.String(vb.OID[len(root)+1:])
		if rows[k] == nil {
			rows[k] = map[uint32]snmp.VarBind{}
			order = append(order, k)
		}
		rows[k][col] = vb
	}
	return rows, order, nil
}

// pollExtras reads the FortiGate-specific values. They are optional: an older FortiOS, another VDOM or a missing
// MIB view only leaves them empty. The SD-WAN and VPN tables are read every other poll.
func (w *wanDev) pollExtras() (fresh bool) {
	x := &w.extra
	now := time.Now()
	if vbs, err := w.cl.Get([][]uint32{oidFgCPU, oidFgMem, oidFgSessions}); err == nil && len(vbs) == 3 {
		get := func(vb snmp.VarBind) *int64 {
			if !vb.Exists() {
				return nil
			}
			v := int64(vb.Uint())
			return &v
		}
		x.CPU, x.Mem, x.Sessions, x.Err = get(vbs[0]), get(vbs[1]), get(vbs[2]), ""
	} else if err != nil {
		x.Err = err.Error()
	}
	if !x.At.IsZero() && now.Sub(x.At) < 50*time.Second {
		return false
	}
	x.At, fresh = now, true
	if rows, order, err := w.table(oidFgSLAEntry); err == nil {
		l := []wanSLA{}
		for _, k := range order {
			r := rows[k]
			l = append(l, wanSLA{Name: r[2].Str(), Iface: r[14].Str(), Alive: r[4].Int() == 0, Latency: parseF(r[5].Str()), Jitter: parseF(r[6].Str()),
				Loss: parseF(r[9].Str()), UsedIn: int64(r[15].Uint()), UsedOut: int64(r[16].Uint())})
		}
		x.SLA = l
	}
	if rows, order, err := w.table(oidFgVPN2Entry); err == nil {
		if x.prevVPN == nil {
			x.prevVPN = map[string]wanPrev{}
		}
		l, up, down := []wanVPN{}, 0, 0
		seen := map[string]bool{}
		for _, k := range order {
			r := rows[k]
			v := wanVPN{Name: r[2].Str(), Remote: inetStr(r[5].Raw), Up: r[26].Int() == 2, In: r[24].Uint(), Out: r[25].Uint()}
			if p2 := r[3].Str(); p2 != "" && p2 != v.Name {
				v.Name += " (" + p2 + ")"
			}
			if p, ok := x.prevVPN[k]; ok {
				if dt := now.Sub(p.at).Seconds(); dt > 0 && v.In >= p.in && v.Out >= p.out {
					v.RxBps, v.TxBps = float64(v.In-p.in)*8/dt, float64(v.Out-p.out)*8/dt
				}
			}
			x.prevVPN[k] = wanPrev{v.In, v.Out, now}
			seen[k] = true
			if v.Up {
				up++
			} else {
				down++
			}
			l = append(l, v)
		}
		for k := range x.prevVPN {
			if !seen[k] {
				delete(x.prevVPN, k)
			}
		}
		sort.SliceStable(l, func(i, j int) bool {
			if l[i].Up != l[j].Up {
				return !l[i].Up // tunnels that are down first
			}
			return l[i].RxBps+l[i].TxBps > l[j].RxBps+l[j].TxBps
		})
		x.VPN, x.VPNUp, x.VPNDown = l, up, down
	}
	return fresh
}

// pollOnce polls one firewall (its own lock only) and publishes the result for the status page.
func (w *wanDev) pollOnce() ([]wanSample, *wanHealth) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.smu.Lock()
	w.snap.tryAt = time.Now()
	w.smu.Unlock()
	var err error
	if m := w.cfg.missingPass(); m != "" {
		err = errors.New(m)
	} else if len(w.cfg.Interfaces) == 0 {
		err = errors.New("no interfaces chosen: Settings > WAN links > Find interfaces, pick the internet circuits and Save")
	} else if w.cl == nil {
		w.cl, err = w.cfg.client()
	}
	var s []wanSample
	var hl *wanHealth
	if err == nil {
		s, err = w.poll()
	}
	if err == nil {
		fresh := w.pollExtras() // v5.19: FortiGate MIB (CPU, memory, sessions, SD-WAN health, IPsec tunnels)
		h := w.health(fresh)    // v5.21: stored
		hl = &h
	}
	if err != nil {
		if w.err != err.Error() {
			log.Printf("WAN links %s: %v", w.cfg.Name, err)
		}
		w.err, w.errAt = err.Error(), time.Now()
		if w.cl != nil && (strings.Contains(err.Error(), "timeout") || strings.Contains(err.Error(), "digest")) {
			w.idx = nil // rediscover once it answers again
		}
	} else {
		w.err, w.okAt = "", time.Now()
	}
	live := make(map[string]wanLive, len(w.live))
	for k, v := range w.live {
		live[k] = v
	}
	w.smu.Lock()
	w.snap.err, w.snap.errAt, w.snap.okAt, w.snap.live, w.snap.extra = w.err, w.errAt, w.okAt, live, w.extra
	w.smu.Unlock()
	return s, hl
}
