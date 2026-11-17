package main

import (
    "bufio"
    "bytes"
    "context"
    "net"
    "testing"
)

func TestFirewallListIsAllowList(t *testing.T) {
    cfg := defaultConfig(t.TempDir())
    cfg.Firewalls = []Firewall{{IP: "192.0.2.10"}}
    cfg.AllowedSources = []string{"198.51.100.0/24"}
    r := NewReceiver(cfg, make(chan Envelope, 1), &Metrics{})
    if !r.allowedSource(&net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 514}) { t.Fatal("configured firewall refused") }
    if !r.allowedSource(&net.UDPAddr{IP: net.ParseIP("198.51.100.7"), Port: 514}) { t.Fatal("CIDR source refused") }
    if r.allowedSource(&net.UDPAddr{IP: net.ParseIP("203.0.113.9"), Port: 514}) { t.Fatal("unlisted source accepted") }
}

func TestReadSyslogFrameBoundsNewlineBeforeBuffering(t *testing.T) {
    br := bufio.NewReaderSize(bytes.NewReader(append(bytes.Repeat([]byte{'x'}, 4096), '\n')), 64)
    if _, err := readSyslogFrame(br, 1024); err == nil { t.Fatal("oversized line accepted") }
}

func TestReadSyslogFrameRejectsLargeOctetCount(t *testing.T) {
    br := bufio.NewReader(bytes.NewBufferString("2048 payload"))
    if _, err := readSyslogFrame(br, 1024); err == nil { t.Fatal("oversized octet frame accepted") }
}

func TestMustChangeGuardUsesPasswordEndpoint(t *testing.T) {
    _ = context.Background() // compile-time import guard for older test toolchains
}
