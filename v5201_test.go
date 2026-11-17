package main

import (
	"strings"
	"testing"
	"time"

	"logsikka/snmp"
	"logsikka/snmp/ber"
)

func TestWANSameUserCopiesPassphrases(t *testing.T) {
	old := WANConfig{Devices: []WANDevice{{Name: "HO-FW", Host: "10.0.0.1", Username: "fgt", AuthPass: "a1", PrivPass: "p1"}}}
	// a new firewall, passphrases left empty, "same SNMPv3 user as HO-FW"
	n := WANConfig{Devices: []WANDevice{{Name: "HO-FW", Host: "10.0.0.1", Username: "fgt"},
		{Name: "KH-FW", Host: "10.0.0.2", Username: "fgt", CredsFrom: "HO-FW"}}}
	keepWANSecrets(&n, old)
	if n.Devices[1].AuthPass != "a1" || n.Devices[1].PrivPass != "p1" {
		t.Fatalf("not copied: %+v", n.Devices[1])
	}
	// from a firewall typed in the same form (not saved yet)
	n2 := WANConfig{Devices: []WANDevice{{Name: "A", Host: "10.0.0.5", Username: "u", AuthPass: "x", PrivPass: "y"},
		{Name: "B", Host: "10.0.0.6", Username: "u", CredsFrom: "a"}}}
	keepWANSecrets(&n2, WANConfig{})
	if n2.Devices[1].AuthPass != "x" {
		t.Fatal("copy from the form")
	}
	// typed passphrases win
	n3 := WANConfig{Devices: []WANDevice{{Name: "KH-FW", Host: "10.0.0.2", Username: "fgt", AuthPass: "own", PrivPass: "own2", CredsFrom: "HO-FW"}}}
	keepWANSecrets(&n3, old)
	if n3.Devices[0].AuthPass != "own" {
		t.Fatal("typed passphrase overwritten")
	}
	if err := n.validate(); err != nil || n.Devices[1].CredsFrom != "" {
		t.Fatalf("creds_from must not be stored: %v %q", err, n.Devices[1].CredsFrom)
	}
}

func TestWANDuplicates(t *testing.T) {
	c := WANConfig{Devices: []WANDevice{{Name: "FW", Host: "10.0.0.1", Username: "u"}, {Name: "fw", Host: "10.0.0.2", Username: "u"}, {Host: "10.0.0.3", Username: "u"}}}
	if err := c.validate(); err != nil {
		t.Fatal(err)
	}
	if c.Devices[1].Name != "fw (10.0.0.2)" || c.Devices[2].Name != "10.0.0.3" {
		t.Fatalf("names %q %q", c.Devices[1].Name, c.Devices[2].Name)
	}
	d := WANConfig{Devices: []WANDevice{{Name: "A", Host: "10.0.0.1", Username: "u"}, {Name: "B", Host: " 10.0.0.1", Username: "u"}}}
	if d.validate() == nil {
		t.Fatal("the same address twice must be refused")
	}
}

func TestReportText(t *testing.T) {
	if m := snmp.ReportText(ber.MustParseOIDString("1.3.6.1.6.3.15.1.1.3.0"), "fgt"); !strings.Contains(m, `unknown SNMPv3 user "fgt"`) {
		t.Error(m)
	}
	if m := snmp.ReportText(ber.MustParseOIDString("1.3.6.1.6.3.15.1.1.5.0"), ""); !strings.Contains(m, "digest") {
		t.Error(m)
	}
}

// the status page reads a snapshot and never waits for a firewall that is being polled
func TestWANStatusDoesNotWaitForPoll(t *testing.T) {
	c := WANConfig{Devices: []WANDevice{{Name: "KL-FW", Host: "10.9.9.9", Username: "u"}}}
	w := &wanDev{cfg: c.Devices[0], prev: map[string]wanPrev{}, live: map[string]wanLive{}}
	w.snap.err = "timeout"
	wanState.Lock()
	wanState.devs["10.9.9.9|u"] = w
	wanState.Unlock()
	defer func() { wanState.Lock(); delete(wanState.devs, "10.9.9.9|u"); wanState.Unlock() }()
	w.mu.Lock() // a poll in progress
	defer w.mu.Unlock()
	done := make(chan []map[string]any, 1)
	go func() { done <- wanStatus(c) }()
	select {
	case st := <-done:
		if st[0]["error"] != "timeout" {
			t.Errorf("status %v", st)
		}
	case <-time.After(time.Second):
		t.Fatal("wanStatus waited for the poll")
	}
}

func TestPollOnceNeedsInterfaces(t *testing.T) {
	w := &wanDev{cfg: WANDevice{Name: "X", Host: "10.0.0.1", Username: "u", Level: "authPriv", Auth: "SHA256", Priv: "AES128", AuthPass: "a", PrivPass: "p"},
		prev: map[string]wanPrev{}, live: map[string]wanLive{}}
	_, _ = w.pollOnce()
	if !strings.Contains(w.snap.err, "no interfaces chosen") || w.snap.tryAt.IsZero() {
		t.Fatalf("snap %+v", w.snap)
	}
}
