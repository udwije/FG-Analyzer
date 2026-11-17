package main

import (
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestBlocklistSafety(t *testing.T) {
	setLocalNets([]string{"203.0.113.0/24"})
	defer setLocalNets(nil)
	c := Config{Firewalls: []Firewall{{Name: "HO-FW", IP: "198.51.100.1"}}, Blocklist: BlocklistConfig{NeverBlock: []string{"192.0.2.0/24"}}}
	for in, want := range map[string]string{"87.251.64.17": "87.251.64.17/32", "87.251.64.0/24": "87.251.64.0/24", " 2001:db8:1::5 ": "2001:db8:1::5/128"} {
		got, err := blCheck(in, c)
		if err != nil || got != want {
			t.Errorf("%q -> %q %v, want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"10.1.1.5", "192.168.0.0/16", "203.0.113.9", "198.51.100.0/24", "192.0.2.10", "8.0.0.0/8", "0.0.0.0/0",
		"127.0.0.1", "224.0.0.1", "not-an-ip", "100.64.1.1", "2001:db8::/32"} {
		if _, err := blCheck(bad, c); err == nil {
			t.Errorf("%q must be refused", bad)
		}
	}
}

func TestBlocklistFeedAndCandidates(t *testing.T) {
	old := blCur.Load()
	defer blCur.Store(old)
	past, future := time.Now().Add(-time.Hour), time.Now().Add(time.Hour)
	mk := func(s string, exp *time.Time) *blEntry {
		p, _ := parsePrefix(s)
		return &blEntry{Entry: p.String(), prefix: p, Expires: exp}
	}
	blCur.Store(&blIndex{list: []*blEntry{mk("87.251.64.0/24", nil), mk("193.8.186.7", &future), mk("45.1.1.1", &past)}})
	f := blFeed(time.Now())
	if f != "193.8.186.7/32\n87.251.64.0/24\n" {
		t.Fatalf("feed %q", f)
	}
	if blListed(netip.MustParsePrefix("87.251.64.17/32"), time.Now()) == nil || blListed(netip.MustParsePrefix("45.1.1.1/32"), time.Now()) != nil {
		t.Error("listed")
	}
	c := Config{}
	l := blockCandidates("signin_attack", "87.251.64.0/24", "87.251.64.17, 87.251.64.179, 10.1.1.5 and 3 more", c, time.Now())
	if len(l) != 4 {
		t.Fatalf("candidates %v", l)
	}
	if l[0]["listed"] == nil || l[2]["why"] == nil || l[3]["group"] != true {
		t.Errorf("candidates %v", l)
	}
	if blockCandidates("large_upload", "10.1.1.5", "", c, time.Now()) != nil {
		t.Error("only sign-in attacks offer the blocklist")
	}
}

func TestFeedNeedsToken(t *testing.T) {
	dir := t.TempDir()
	store, err := LoadConfig(dir + "/config.json")
	if err != nil {
		t.Fatal(err)
	}
	c := store.Get()
	// v6.0.15 requires the feed token and the socket peer to be a configured firewall.
	c.Firewalls = []Firewall{{Name: "HO-FW", IP: "192.0.2.10"}}
	c.Blocklist = BlocklistConfig{Enabled: true, Token: strings.Repeat("ab", 24), DefaultDays: 30}
	if err = store.Save(c); err != nil {
		t.Fatal(err)
	}
	a := &App{store: store}
	callFrom := func(path, remote string) int {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", path, nil)
		r.RemoteAddr = remote
		a.handleFeed(w, r)
		return w.Code
	}
	call := func(path string) int { return callFrom(path, "192.0.2.10:514") }
	if call("/feed/"+c.Blocklist.Token+"/blocklist.txt") != 200 {
		t.Error("right token refused")
	}
	if callFrom("/feed/"+c.Blocklist.Token+"/blocklist.txt", "192.0.2.99:514") != 404 {
		t.Error("valid token from an unapproved source must be refused")
	}
	for _, p := range []string{"/feed/" + strings.Repeat("cd", 24) + "/blocklist.txt", "/feed//blocklist.txt", "/feed/" + c.Blocklist.Token + "/other.txt"} {
		if call(p) != 404 {
			t.Errorf("%s must be refused", p)
		}
	}
	c.Blocklist.Enabled = false
	_ = store.Save(c)
	if call("/feed/"+c.Blocklist.Token+"/blocklist.txt") != 404 {
		t.Error("a disabled feed must not answer")
	}
}
