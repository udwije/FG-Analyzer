package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func testSites() []SiteConfig {
	return []SiteConfig{
		{Name: "HO", Firewalls: []string{"HO-FW"}, Zones: []ZoneConfig{
			{Name: "HO staff", Kind: "staff", VLAN: 10, Subnets: []string{"10.10.0.0/16"}},
			{Name: "HO servers", Kind: "servers", VLAN: 20, Subnets: []string{"10.10.20.0/24"}},
		}},
		{Name: "Kandy", Firewalls: []string{"KDY-FW"}, Zones: []ZoneConfig{{Name: "KDY LAN", Subnets: []string{"10.30.1.7/24"}}}},
	}
}

func TestSitesValidateAndLookup(t *testing.T) {
	l := testSites()
	if err := validSites(l); err != nil {
		t.Fatal(err)
	}
	if l[1].Zones[0].Kind != "other" || l[1].Zones[0].Subnets[0] != "10.30.1.0/24" {
		t.Fatalf("defaults / masking: %+v", l[1].Zones[0])
	}
	setSites(l)
	defer setSites(nil)
	if z := zoneOf("10.10.20.5"); z == nil || z.zone != "HO servers" {
		t.Fatalf("most specific zone: %+v", z)
	}
	if z := zoneOf("10.10.5.5"); z == nil || z.zone != "HO staff" || z.kind != "staff" {
		t.Fatalf("staff zone: %+v", z)
	}
	if siteOf("192.168.99.1", "kdy-fw") != "Kandy" || siteOf("192.168.99.1", "other") != "" {
		t.Error("firewall fallback")
	}
	if s := tagSubnets("site:HO"); len(s) != 2 {
		t.Errorf("site subnets %v", s)
	}
	if s := tagSubnets("zone:KDY LAN"); len(s) != 1 || s[0] != "10.30.1.0/24" {
		t.Errorf("zone subnets %v", s)
	}
	for _, bad := range [][]SiteConfig{
		{{Name: "A"}, {Name: "a"}},
		{{Name: "A", Zones: []ZoneConfig{{Name: "z", Subnets: []string{"nope"}}}}},
		{{Name: "A", Zones: []ZoneConfig{{Name: "z", Kind: "toaster"}}}},
		{{Name: "A", Zones: []ZoneConfig{{Name: "z", Subnets: []string{"10.0.0.0/8"}}, {Name: "y", Subnets: []string{"10.0.0.0/8"}}}}},
		{{Name: "bad\"name"}},
	} {
		if validSites(bad) == nil {
			t.Errorf("%+v accepted", bad)
		}
	}
}

func TestTagsFor(t *testing.T) {
	setSites(testSites())
	defer setSites(nil)
	_ = validSites(siteCur.Load().sites)
	setSites(siteCur.Load().sites)
	old := dirCur.Load()
	defer dirCur.Store(old)
	dirCur.Store(&directory{byUser: map[string]*staffRec{"nimal": {User: "nimal", Dept: "Finance", Active: false}},
		alias: map[string]string{"nimal": "nimal"}, comps: map[string]bool{}, loaded: true})
	tags := strings.Join(tagsFor("10.10.20.9", "CORP\\nimal", "HO-FW", time.Now()), " ")
	for _, want := range []string{"site:HO", "zone:HO servers", "kind:servers", "dept:Finance", "staff:former"} {
		if !strings.Contains(tags, want) {
			t.Errorf("missing %s in %s", want, tags)
		}
	}
	if tags := tagsFor("172.16.1.1", "", "KDY-FW", time.Now()); len(tags) != 1 || tags[0] != "site:Kandy" {
		t.Errorf("firewall site only: %v", tags)
	}
}

func TestSectionSaveTouchesOnlyItsSection(t *testing.T) {
	dir := t.TempDir()
	store, err := LoadConfig(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	c := store.Get()
	c.Database.Password = "db-secret"
	c.WAN = WANConfig{Enabled: true, Devices: []WANDevice{{Name: "HO-FW", Host: "10.0.0.1", Username: "fgt", Auth: "SHA256", Priv: "AES128",
		AuthPass: "auth-1", PrivPass: "priv-1", Interfaces: []WANIface{{Name: "wan1"}}}}}
	c.Alerts.BruteForce = 10
	if err = store.Save(c); err != nil {
		t.Fatal(err)
	}
	a := &App{store: store}
	put := func(body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		a.handleConfigSection(w, httptest.NewRequest("PUT", "/api/config/section", strings.NewReader(body)))
		return w
	}
	al := store.Get().Alerts
	al.BruteForce = 25
	ab, _ := json.Marshal(al)
	w := put(`{"section":"Alerts","values":{"alerts":` + string(ab) + `}}`)
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	var res struct{ Changes []string }
	_ = json.Unmarshal(w.Body.Bytes(), &res)
	if len(res.Changes) != 1 || !strings.Contains(res.Changes[0], "brute_force: 10 → 25") {
		t.Errorf("changes %v", res.Changes)
	}
	got := store.Get()
	if got.Alerts.BruteForce != 25 || got.WAN.Devices[0].AuthPass != "auth-1" || got.Database.Password != "db-secret" {
		t.Fatalf("other sections changed: %+v %+v", got.Alerts, got.WAN.Devices[0])
	}
	// the WAN card sends its devices without passphrases: they are kept
	wan := got.WAN
	hideWANSecrets(&wan)
	wb, _ := json.Marshal(wan)
	if w = put(`{"section":"WAN links","values":{"wan":` + string(wb) + `}}`); w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if d := store.Get().WAN.Devices[0]; d.AuthPass != "auth-1" || d.PrivPass != "priv-1" {
		t.Fatalf("passphrases lost: %+v", d)
	}
	if strings.Contains(w.Body.String(), "auth-1") {
		t.Error("a secret reached the change list")
	}
	// the database card with an empty password keeps the stored one
	db := store.Get().Database
	db.Password, db.Host = "", "10.9.9.9"
	dbb, _ := json.Marshal(db)
	if w = put(`{"values":{"database":` + string(dbb) + `}}`); w.Code != 200 || store.Get().Database.Password != "db-secret" {
		t.Fatalf("database: %d %s", w.Code, w.Body)
	}
	if !strings.Contains(w.Body.String(), `"restart_required":true`) {
		t.Error("a database change needs a restart")
	}
	for _, bad := range []string{`{"values":{"admin_token":"x"}}`, `{"values":{"blocklist":{}}}`, `{"values":{"retention_days":0}}`, `{}`} {
		before := store.Get().RetentionDays
		if w = put(bad); w.Code == 200 || store.Get().RetentionDays != before {
			t.Errorf("%s: %d", bad, w.Code)
		}
	}
	// sites are saved like any section and applied at once
	sb, _ := json.Marshal(testSites())
	if w = put(`{"section":"Sites","values":{"sites":` + string(sb) + `}}`); w.Code != 200 {
		t.Fatalf("sites: %d %s", w.Code, w.Body)
	}
	defer setSites(nil)
	if z := zoneOf("10.10.20.1"); z == nil || z.site != "HO" {
		t.Fatal("sites not applied after save")
	}
}

func TestOldCookieStillSignsIn(t *testing.T) {
	dir := t.TempDir()
	users, err := openUsers(dir)
	if err != nil {
		t.Fatal(err)
	}
	_ = users.add("wall", "viewer", "wallboard-pass-1")
	_ = users.update("wall", func(x *User) error { x.MustChange = false; return nil }) // v6.0.2 must-change gate
	a := &App{store: &ConfigStore{cfg: Config{}}, users: users, sessions: newSessionStore("")}
	u, _ := users.verify("wall", "wallboard-pass-1")
	tok := a.sessions.create(u, "10.0.0.1", time.Hour)
	for _, name := range []string{cookiePlain, cookieSecure, "fortilog_session", "__Host-fortilog"} {
		r := httptest.NewRequest("GET", "/api/x", nil)
		r.AddCookie(&http.Cookie{Name: name, Value: tok})
		w := httptest.NewRecorder()
		a.auth(RoleViewer, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })(w, r)
		if w.Code != 200 {
			t.Errorf("cookie %s: %d", name, w.Code)
		}
	}
	r := httptest.NewRequest("POST", "/api/x", bytes.NewReader(nil))
	r.Header.Set("X-LogSikka", "1")
	if !csrfOK(r) {
		t.Error("X-LogSikka header")
	}
}

func TestHostReaders(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux only")
	}
	if _, _, _, ok := readCPU(); !ok {
		t.Error("cpu")
	}
	if m, _, ok := readMem(); !ok || m <= 0 || m > 100 {
		t.Errorf("mem %v %v", m, ok)
	}
	if readLoad() < 0 {
		t.Error("load")
	}
	a := &App{store: &ConfigStore{cfg: Config{}}, queue: make(chan Envelope, 10), spool: Spool{dir: t.TempDir()}}
	a.sampleHealth(context.Background())
	time.Sleep(20 * time.Millisecond)
	a.sampleHealth(context.Background())
	if p := healthSeries(); len(p) == 0 || p[len(p)-1].Cores == 0 {
		t.Errorf("series %v", p)
	}
}

func TestFirstExisting(t *testing.T) {
	d := t.TempDir()
	newD, oldD := filepath.Join(d, "logsikka"), filepath.Join(d, "fortilog")
	if firstExisting(newD, oldD) != newD {
		t.Error("fresh install uses the new folder")
	}
	_ = mkdir(oldD)
	if firstExisting(newD, oldD) != oldD {
		t.Error("an existing FortiLog folder is kept")
	}
	_ = mkdir(newD)
	if firstExisting(newD, oldD) != newD {
		t.Error("the new folder wins once it exists")
	}
}

func mkdir(p string) error { return osMkdirAll(p) }

func TestSubnetRanges(t *testing.T) {
	for in, want := range map[string]string{"10.10.0.0/16": "10.10.255.255", "10.20.5.0/24": "10.20.5.255", "192.168.1.128/25": "192.168.1.255",
		"10.0.0.0/8": "10.255.255.255", "2001:db8::/32": "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff"} {
		if got := lastAddr(netipMust(in)).String(); got != want {
			t.Errorf("%s -> %s, want %s", in, got, want)
		}
	}
	args := []any{}
	c := ipCond(&args, "10.10.0.0/16, 10.20.5.0/24", "src_ip")
	if !strings.Contains(c, "src_ip >= $1::inet AND src_ip <= $2::inet") || len(args) != 4 || args[1] != "10.10.255.255" {
		t.Fatalf("%s %v", c, args)
	}
}

func TestDashboardsBusy(t *testing.T) {
	dashLast.Store(0)
	if dashboardsBusy() {
		t.Fatal("idle")
	}
	d := &Database{sem: make(chan struct{}, 2)}
	rel, _ := d.acquire(context.Background())
	if !dashboardsBusy() {
		t.Fatal("a running query is busy")
	}
	rel()
	if !dashboardsBusy() {
		t.Fatal("busy for 20 s after the last query")
	}
	dashLast.Store(time.Now().Unix() - 30)
	if dashboardsBusy() {
		t.Fatal("idle again after 20 s")
	}
}
