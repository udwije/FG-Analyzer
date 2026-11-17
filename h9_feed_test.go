package main

import (
    "net/http/httptest"
    "testing"
    "time"
)

func TestH9FeedRestrictedToConfiguredFirewallSource(t *testing.T) {
    token := newToken()
    c := defaultConfig(t.TempDir())
    c.Firewalls = []Firewall{{Name:"HO-FW", IP:"192.0.2.10"}}
    c.Blocklist.Enabled, c.Blocklist.Token = true, token
    a := &App{store:&ConfigStore{cfg:c}}
    path := "/feed/"+token+"/blocklist.txt"
    allowed := httptest.NewRequest("GET", path, nil); allowed.RemoteAddr="192.0.2.10:12345"
    w := httptest.NewRecorder(); a.handleFeed(w,allowed)
    if w.Code != 200 { t.Fatalf("configured firewall feed=%d %s",w.Code,w.Body.String()) }
    refused := httptest.NewRequest("GET", path, nil); refused.RemoteAddr="192.0.2.99:12345"
    refused.Header.Set("X-Forwarded-For","192.0.2.10")
    w=httptest.NewRecorder(); a.handleFeed(w,refused)
    if w.Code != 404 { t.Fatalf("unconfigured source feed=%d, want 404",w.Code) }
}

func TestH9FeedRateLimit(t *testing.T) {
    feedLimit.Lock(); feedLimit.m=map[string]*feedRate{}; feedLimit.Unlock()
    now:=time.Now(); host:="192.0.2.10"
    for i:=0;i<30;i++ { if !feedRateOK(host,now) { t.Fatalf("request %d rejected",i+1) } }
    if feedRateOK(host,now) { t.Fatal("31st request in one minute accepted") }
    if !feedRateOK(host,now.Add(time.Minute)) { t.Fatal("new rate window did not open") }
}

func TestH9FeedSourceIPv4Mapped(t *testing.T) {
    c:=defaultConfig(t.TempDir()); c.Firewalls=[]Firewall{{IP:"192.0.2.10"}}
    if !feedSourceAllowed("::ffff:192.0.2.10",c) { t.Fatal("IPv4-mapped configured firewall refused") }
}
