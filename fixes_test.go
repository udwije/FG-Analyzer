package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestSanitizeLogMakesTextSafeForPostgres(t *testing.T) {
	in := []byte("date=2026-10-15 time=03:00:00 srcip=10.0.0.1 url=\"/bad\xff\xfe\" user=\"na\x00me\"")
	r := ParseLog(in, "10.0.0.9")
	for name, v := range map[string]string{"raw": r.Raw, "url": r.URL, "user": r.User} {
		if !utf8.ValidString(v) || strings.ContainsRune(v, 0) {
			t.Errorf("%s still unsafe: %q", name, v)
		}
	}
	if r.SrcIP != "10.0.0.1" {
		t.Errorf("good fields must survive, srcip=%q", r.SrcIP)
	}
	if got := ParseLog([]byte("date=2026-10-15 url=\"/caf\xc3\xa9\""), "x").URL; got != "/café" {
		t.Errorf("valid UTF-8 must be kept, got %q", got)
	}
}

func TestIsDataError(t *testing.T) {
	if !isDataError(errors.Join(errors.New("x"), &pgconn.PgError{Code: "22021"})) || !isDataError(&pgconn.PgError{Code: "23505"}) {
		t.Error("class 22 and 23 are data errors")
	}
	if isDataError(&pgconn.PgError{Code: "08006"}) || isDataError(errors.New("connection refused")) {
		t.Error("connection failures are not data errors")
	}
}

func TestNPSDifferentMACIsNotAttributed(t *testing.T) {
	var next int64
	insertSession = func(_ context.Context, _ *Database, s *npsSession) error { next++; s.ID = next; return nil }
	e := newNPSEng()
	e.configure(NPSConfig{Enabled: true, IdleHours: 8, StripDomain: true, Lowercase: true})
	e.loaded = true
	t0 := time.Date(2026, 10, 14, 8, 0, 0, 0, time.Local)
	_ = e.observe(context.Background(), nil, npsRecord{Time: t0, RawUser: "alice", User: "alice", IP: "10.1.1.10", MAC: "aa:aa:aa:aa:aa:aa", Packet: 4, Status: 3})
	if s := e.userFor(context.Background(), nil, "10.1.1.10", "aa:aa:aa:aa:aa:aa", t0.Add(time.Hour)); s == nil || s.User != "alice" {
		t.Fatal("alice's own device must still match")
	}
	if s := e.userFor(context.Background(), nil, "10.1.1.10", "dd:dd:dd:dd:dd:dd", t0.Add(time.Hour)); s != nil {
		t.Fatalf("a different device on the same IP must not inherit alice, got %q", s.User)
	}
	if s := e.userFor(context.Background(), nil, "10.1.1.10", "", t0.Add(time.Hour)); s == nil {
		t.Fatal("logs without a MAC keep the old behaviour")
	}
}

func TestNormUserNeverSplitsACharacter(t *testing.T) {
	long := strings.Repeat("a", 99) + "é" // 'é' straddles the 100-byte cut
	e := newNPSEng()
	if u := e.normUser(long); !utf8.ValidString(u) || u == "" {
		t.Fatalf("truncated name is invalid UTF-8: %q", u)
	}
}

func TestCrossSiteWritesAreRejected(t *testing.T) {
	req := func(method, ct, hdr string) *http.Request {
		r := httptest.NewRequest(method, "/api/x", nil)
		if ct != "" {
			r.Header.Set("Content-Type", ct)
		}
		if hdr != "" {
			r.Header.Set("X-LogSikka", hdr)
		}
		return r
	}
	if csrfOK(req("POST", "text/plain", "")) {
		t.Error("simple cross-site POST must be refused")
	}
	if !csrfOK(req("POST", "application/json", "")) || !csrfOK(req("POST", "", "1")) || !csrfOK(req("GET", "", "")) {
		t.Error("JSON, custom-header and GET requests are allowed")
	}
}

func TestAPIRequiresSignInAndRole(t *testing.T) {
	dir := t.TempDir()
	users, err := openUsers(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err = users.add("wall", "viewer", "wallboard-pass-1"); err == nil {
		// v6.0.2: a new account must change its password first; this test covers an account that already has
		err = users.update("wall", func(x *User) error { x.MustChange = false; return nil })
	}
	if err != nil {
		t.Fatal(err)
	}
	a := &App{store: &ConfigStore{cfg: Config{}}, users: users, sessions: newSessionStore("")}
	ok := func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }
	call := func(min Role, token string) int {
		r := httptest.NewRequest("GET", "/api/x", nil)
		if token != "" {
			r.AddCookie(&http.Cookie{Name: cookiePlain, Value: token})
		}
		w := httptest.NewRecorder()
		a.auth(min, ok)(w, r)
		return w.Code
	}
	if c := call(RoleViewer, ""); c != 401 {
		t.Errorf("no session: got %d, want 401", c)
	}
	if c := call(RoleViewer, "made-up-token"); c != 401 {
		t.Errorf("unknown token: got %d, want 401", c)
	}
	u, err := users.verify("wall", "wallboard-pass-1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = users.verify("wall", "wrong-password"); err == nil {
		t.Error("a wrong password must fail")
	}
	tok := a.sessions.create(u, "10.0.0.1", time.Hour)
	if c := call(RoleViewer, tok); c != 200 {
		t.Errorf("viewer on a viewer page: got %d", c)
	}
	if c := call(RoleAdmin, tok); c != 403 {
		t.Errorf("viewer on an admin page: got %d, want 403", c)
	}
	_ = users.update("wall", func(x *User) error { x.Disabled = true; return nil })
	users.checked = time.Time{}
	if c := call(RoleViewer, tok); c != 401 {
		t.Errorf("disabled account must be signed out, got %d", c)
	}
}

func TestMultiValueFilters(t *testing.T) {
	f := Filter{From: time.Now().Add(-time.Hour), To: time.Now(), Src: "10.1.1.5, 10.2.0.0/16 !10.2.3.4", User: "alice,=bob, !=carol"}
	sql, args := f.where()
	for _, want := range []string{"src_ip = ANY(", "(src_ip >= $", "NOT coalesce((src_ip = ANY(", "user_name ILIKE ANY(", "user_name = ANY("} {
		if !strings.Contains(sql, want) {
			t.Errorf("missing %q in %s", want, sql)
		}
	}
	if len(args) != 2+4+3 {
		t.Errorf("want 9 args, got %d: %v", len(args), args)
	}
	if got := listItems("a, b,,c", false); len(got) != 3 {
		t.Errorf("listItems: %v", got)
	}
}

func TestHostGuardBlocksRebinding(t *testing.T) {
	h := hostGuard("127.0.0.1:8080", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	for host, want := range map[string]int{"127.0.0.1:8080": 200, "localhost:8080": 200, "evil.example:8080": 421} {
		r := httptest.NewRequest("GET", "/", nil)
		r.Host = host
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != want {
			t.Errorf("Host %q: got %d want %d", host, w.Code, want)
		}
	}
	if hostGuard("0.0.0.0:8080", nil) != nil {
		t.Error("network-facing binds are not restricted by hostGuard")
	}
}

func TestInvalidIPIsNotStored(t *testing.T) {
	r := ParseLog([]byte(`date=2026-10-20 time=09:35:00 type="traffic" srcip=10.1.1.5 dstip="dstip=192.168.2.1"`), "10.0.0.9")
	// v5.9: the address inside the doubled key is recovered instead of being thrown away
	if r.DstIP != "192.168.2.1" || r.SrcIP != "10.1.1.5" || r.ParseStatus != "parsed" {
		t.Fatalf("got dst=%q src=%q status=%q", r.DstIP, r.SrcIP, r.ParseStatus)
	}
	// a value that holds no address at all is still emptied and the log marked partial
	if j := ParseLog([]byte(`date=2026-10-20 time=09:35:00 type="traffic" srcip=10.1.1.5 dstip="dstip=not-an-ip"`), "10.0.0.9"); j.DstIP != "" || j.ParseStatus != "partial" {
		t.Fatalf("junk: dst=%q status=%q", j.DstIP, j.ParseStatus)
	}
	if r2 := ParseLog([]byte(`date=2026-10-20 time=09:35:00 srcip=::ffff:10.1.1.6`), "x"); r2.SrcIP != "10.1.1.6" || r2.ParseStatus != "parsed" {
		t.Fatalf("mapped IPv6 must be unmapped and valid, got %q %q", r2.SrcIP, r2.ParseStatus)
	}
}

func TestSpooledRecordIsCleanedBeforeInsert(t *testing.T) {
	// a record parsed by v5.5 and kept in the spool still carries the bad value
	r := LogRecord{SrcIP: "10.1.1.5", DstIP: "dstip=192.168.2.1", SourceIP: "10.0.0.9", ParseStatus: "parsed"}
	cleanRecord(&r)
	if r.DstIP != "192.168.2.1" || r.SrcIP != "10.1.1.5" {
		t.Fatalf("not repaired: %+v", r)
	}
	bad := LogRecord{SrcIP: "10.1.1.5", DstIP: "dstip=not-an-ip", ParseStatus: "parsed"}
	if !cleanRecord(&bad) || bad.DstIP != "" || bad.ParseStatus != "partial" {
		t.Fatalf("junk not cleaned: %+v", bad)
	}
	ok := LogRecord{SrcIP: "10.1.1.5", DstIP: "8.8.8.8"}
	if cleanRecord(&ok) {
		t.Error("a valid record must not be changed")
	}
}

func TestEncodeErrorIsDataError(t *testing.T) {
	err := errors.New(`ERROR: COPY from stdin failed: unable to encode "dstip=192.168.2.1" into binary format for inet (OID 869): cannot find encode plan (SQLSTATE 57014)`)
	if !isDataError(err) {
		t.Error("an encode failure must be quarantined, not treated as a lost connection")
	}
	if isDataError(nil) {
		t.Error("nil is not a data error")
	}
}

func TestReportSpecValidation(t *testing.T) {
	ok := ReportSpec{Group: []string{"fw", "user"}, Bucket: "day", Metrics: []string{"events", "bytes"}, Sort: "bytes"}
	if err := ok.validate(); err != nil {
		t.Fatal(err)
	}
	if ok.Limit != 100 {
		t.Errorf("default limit, got %d", ok.Limit)
	}
	for _, bad := range []ReportSpec{
		{Group: []string{"fw", "user", "src_ip", "dst_ip"}},
		{Group: []string{"nope"}},
		{Group: []string{"fw", "fw"}},
		{Metrics: []string{"drop table"}},
		{Bucket: "minute"},
		{Metrics: []string{"events"}, Sort: "bytes"},
	} {
		err := bad.validate()
		var se specError
		if err == nil || !errors.As(err, &se) {
			t.Errorf("%+v should be rejected with a specError, got %v", bad, err)
		}
	}
	if src, _ := reportSource(ReportSpec{Group: []string{"user"}, Metrics: []string{"users"}}, Filter{}); src != "raw" {
		t.Errorf("distinct counts need raw, got %s", src)
	}
	if src, _ := reportSource(ReportSpec{Group: []string{"fw"}, Metrics: []string{"events"}, Exact: true}, Filter{}); src != "raw" {
		t.Errorf("exact must force raw, got %s", src)
	}
}

func TestExecPeriods(t *testing.T) {
	for _, k := range []string{"7d", "30d", "lastweek", "lastmonth", "thismonth"} {
		r := httptest.NewRequest("GET", "/api/exec?period="+k, nil)
		p, err := execPeriodFor(r)
		if err != nil {
			t.Fatalf("%s: %v", k, err)
		}
		if !p.To.After(p.From) || !p.PTo.Equal(p.From) || p.PTo.Sub(p.PFrom) != p.To.Sub(p.From) {
			t.Errorf("%s: bad bounds %+v", k, p)
		}
	}
	if p, _ := execPeriodFor(httptest.NewRequest("GET", "/api/exec?period=lastweek", nil)); p.From.Weekday() != time.Monday {
		t.Errorf("last week must start on a Monday: %v", p.From)
	}
	if _, err := execPeriodFor(httptest.NewRequest("GET", "/api/exec?period=forever", nil)); err == nil {
		t.Error("unknown period must be rejected")
	}
}

func TestExecAssessment(t *testing.T) {
	th := ExecConfig{}
	th.defaults()
	o := &ExecSummary{Cur: execTotals{Events: 1000000, Blocked: 300000, Bytes: 5 << 30, Sent: 1 << 30, UserEvents: 700000, Users: 50, Devices: 80, AISent: 10 << 20, AdminFail: 60},
		Prev:      &execTotals{Events: 900000, Blocked: 100000, AISent: 10 << 20},
		Firewalls: []map[string]any{{"name": "HO-FW", "longest_gap": int64(120), "quiet": int64(0)}, {"name": "KH-FW", "longest_gap": int64(2 * 3600), "quiet": int64(0)}},
		Signins:   map[string]any{"from_internet": int64(3)}, Top: map[string]any{}, Story: []string{}, Findings: []execFinding{}, Checks: []execCheck{}}
	(&App{}).execAssess(o, th, execPeriod{}, 7)
	if o.Status != "red" {
		t.Errorf("blocked +200%% and 60 failed sign-ins must be red, got %s", o.Status)
	}
	st := map[string]string{}
	for _, c := range o.Checks {
		st[c.Key] = c.Status
	}
	if st["blocked"] != "red" || st["signins"] != "red" || st["firewalls"] != "amber" || st["ai"] != "ok" || st["visibility"] != "ok" {
		t.Errorf("checks: %v", st)
	}
	if len(o.Story) < 3 || len(o.Findings) < 3 {
		t.Errorf("story %d findings %d", len(o.Story), len(o.Findings))
	}
}
