package main

import (
	"strings"
	"testing"
	"time"
)

func TestExclusionsParseAndMatch(t *testing.T) {
	e, err := parseExcl(ExecConfig{ExcludeSources: []string{"10.9.0.0/16, 192.168.1.5"}, ExcludeDestinations: []string{"*.backup.local\n198.51.100.0/24"},
		ExcludeUsers: []string{"SVC-Backup"}, ExcludeSubtypes: []string{"local"}})
	if err != nil || !e.active() {
		t.Fatal(err)
	}
	if !e.matchSrc("10.9.3.4") || !e.matchSrc("192.168.1.5") || e.matchSrc("10.1.1.1") {
		t.Error("source match")
	}
	if !e.matchDest("files.backup.local") || !e.matchDest("198.51.100.7") || e.matchDest("chatgpt.com") {
		t.Error("destination match")
	}
	if !e.matchUser("svc-backup") || e.matchUser("alice") {
		t.Error("user match")
	}
	args := []any{}
	if c := e.cond(&args); !strings.Contains(c, "src_ip <<= ANY") || len(args) != 5 {
		t.Errorf("cond %s %v", c, args)
	}
	e2, _ := parseExcl(ExecConfig{ExcludeSubtypes: []string{"local"}, ExcludeUsers: []string{"svc-backup"}, ExcludeSources: []string{"192.168.1.5", "10.9.0.0/16"},
		ExcludeDestinations: []string{"198.51.100.0/24", "*.backup.local"}})
	if e.sig != e2.sig {
		t.Error("signature must not depend on order")
	}
	for _, bad := range []ExecConfig{{ExcludeSources: []string{"nope"}}, {ExcludeDestinations: []string{"bad host!"}}, {ExcludeSubtypes: []string{"x y"}}} {
		if _, err := parseExcl(bad); err == nil {
			t.Errorf("%+v accepted", bad)
		}
	}
	if (&execExcl{}).active() {
		t.Error("empty rules are not active")
	}
}

func TestAIRollupWhere(t *testing.T) {
	now := time.Now()
	f := Filter{From: now.Add(-24 * time.Hour), To: now, Scope: "ai", User: "alice", Src: "10.1.0.0/16", Outcome: "blocked"}
	w, args, why := aiRollWhere(f, f.From, f.To)
	if why != "" || !strings.Contains(w, "log_type = 'utm'") || !strings.Contains(w, "blk > 0") || len(args) < 4 {
		t.Fatalf("%q %v %q", w, args, why)
	}
	for _, g := range []Filter{{Scope: "ai", Q: "x"}, {Scope: "ai", Dst: "1.1.1.1"}, {Scope: ""}} {
		if _, _, why := aiRollWhere(g, now, now); why == "" {
			t.Errorf("%+v must fall back to raw", g)
		}
	}
}

func TestGenericNamesAgree(t *testing.T) {
	for n, want := range map[string]bool{"SSL": true, "SSL_TLSv1.3": true, "QUIC": true, "unknown": true, "Sslvpn-Portal": false, "TLScontact": false, "Telegram": false} {
		if genericName(n) != want {
			t.Errorf("%s: %v", n, !want)
		}
	}
	setAIRules([]string{"GenAI"}, defaultAIRules())
	if got := classifyAI("HTTPS.BROWSER", "new-ai.io", "GenAI", ""); got != "new-ai.io" {
		t.Errorf("generic app must not name the tool: %q", got)
	}
}
