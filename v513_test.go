package main

import (
	"testing"
	"time"
)

func TestBackslashKeptInQuotedValues(t *testing.T) {
	r := ParseLog([]byte(`date=2026-10-27 time=09:00:00 srcip=10.1.1.5 user="CORP\nimal" msg="say \"hi\" \\ ok"`), "10.0.0.1")
	if r.User != `CORP\nimal` {
		t.Fatalf("user %q", r.User)
	}
	if r.Fields["msg"] != `say "hi" \ ok` {
		t.Fatalf("msg %q", r.Fields["msg"])
	}
}

func TestCanonUserAndPeople(t *testing.T) {
	old := dirCur.Load()
	defer dirCur.Store(old)
	dirCur.Store(&directory{byUser: map[string]*staffRec{"nimal": {User: "nimal", Active: true}, "kamal": {User: "kamal", Active: false}},
		alias: map[string]string{"nimal": "nimal", "nimal.perera@corp.lk": "nimal", "kamal": "kamal"}, comps: map[string]bool{}, loaded: true})
	for in, want := range map[string]string{`CORP\Nimal`: "nimal", "NIMAL.PERERA@corp.lk": "nimal", "nimal@corp.lk": "nimal", "PC01$": "", "host/pc01": "", "guest77": "guest77"} {
		if got := canonUser(in); got != want {
			t.Errorf("%q -> %q, want %q", in, got, want)
		}
	}
	if n := countPeople([]string{`CORP\nimal`, "nimal", "kamal", "svc-backup", "printer01"}); n != 2 {
		t.Errorf("people %d, want 2 (staff only)", n)
	}
}

func TestNormalizeAssignment(t *testing.T) {
	for _, c := range []struct{ in, kind, val string }{
		{"10.10.5.20", "ip", "10.10.5.20"}, {"10.10.5.0/24", "subnet", "10.10.5.0/24"}, {"10.10.5.7/24", "subnet", "10.10.5.0/24"},
		{"10.10.5.20/32", "ip", "10.10.5.20"}, {"AA-BB-CC-DD-EE-FF", "mac", "aa:bb:cc:dd:ee:ff"}, {"HO-PC-031.corp.lk", "host", "ho-pc-031"},
	} {
		a := &Assignment{Value: c.in, Type: "server", Owner: "x"}
		if err := normalizeAssignment(a); err != nil || a.Kind != c.kind || a.Value != c.val {
			t.Errorf("%q -> %s %s (%v)", c.in, a.Kind, a.Value, err)
		}
	}
	for _, bad := range []Assignment{{Value: "", Type: "server", Owner: "x"}, {Value: "10.1.1.1", Type: "toaster", Owner: "x"},
		{Value: "10.1.1.1", Type: "server"}, {Value: "bad host!", Type: "server", Owner: "x"}} {
		b := bad
		if normalizeAssignment(&b) == nil {
			t.Errorf("%+v accepted", bad)
		}
	}
}

func TestAssignmentLookupOrder(t *testing.T) {
	old := asgCur.Load()
	defer asgCur.Store(old)
	x := &assignIndex{byIP: map[string]*Assignment{}, byMAC: map[string]*Assignment{}, byHost: map[string]*Assignment{}}
	n16 := &Assignment{Kind: "subnet", Value: "10.9.0.0/16", Type: "shared", Owner: "Branch"}
	n24 := &Assignment{Kind: "subnet", Value: "10.9.1.0/24", Type: "server", Owner: "Servers"}
	for _, a := range []*Assignment{n16, n24} {
		a.prefix, _ = parsePrefix(a.Value)
		x.nets = append(x.nets, a)
	}
	x.nets[0], x.nets[1] = n24, n16 // longest first
	x.byIP["10.9.1.5"] = &Assignment{Kind: "ip", Value: "10.9.1.5", Type: "person", Owner: "nimal"}
	x.byMAC["aa:aa:aa:aa:aa:aa"] = &Assignment{Kind: "mac", Type: "person", Owner: "kamal"}
	asgCur.Store(x)
	now := time.Now()
	if a := lookupAssignment("10.9.1.5", "aa:aa:aa:aa:aa:aa", "", now); a.Owner != "kamal" {
		t.Error("MAC must win")
	}
	if a := lookupAssignment("10.9.1.5", "", "", now); a.Owner != "nimal" {
		t.Error("IP before subnet")
	}
	if a := lookupAssignment("10.9.1.6", "", "", now); a.Owner != "Servers" {
		t.Error("smallest subnet wins")
	}
	if a := lookupAssignment("10.9.2.6", "", "", now); a.Owner != "Branch" {
		t.Error("larger subnet")
	}
	if lookupAssignment("10.8.0.1", "", "", now) != nil {
		t.Error("no match expected")
	}
}

func TestRollSourceSplitsDays(t *testing.T) {
	daysDone.Lock()
	saved := daysDone.m
	day := dayStart(time.Now()).AddDate(0, 0, -2)
	daysDone.m = map[int64]bool{day.Unix(): true}
	daysDone.Unlock()
	defer func() { daysDone.Lock(); daysDone.m = saved; daysDone.Unlock() }()
	args := []any{}
	src := rollSource(Filter{}, day.Add(-3*time.Hour), day.AddDate(0, 0, 1).Add(5*time.Hour), []string{"user"}, &args, false)
	if !contains(src, "rollup_1d") || !contains(src, "rollup_1h") {
		t.Fatalf("expected both tables: %s", src)
	}
	args = []any{}
	if src = rollSource(Filter{}, day.Add(-3*time.Hour), day.AddDate(0, 0, 1).Add(5*time.Hour), []string{"user"}, &args, true); contains(src, "rollup_1d") {
		t.Fatal("hourly buckets must not use days")
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
