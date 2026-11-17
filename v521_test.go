package main

import (
	"math"
	"testing"
	"time"
)

func TestWANAlertDefaults(t *testing.T) {
	var c AlertConfig
	c.defaults()
	if c.WANBusyPct != 80 || c.WANBusyMin != 15 || c.WANLossPct != 2 || c.TunnelDownMin != 5 || c.FWLoadPct != 85 {
		t.Fatalf("defaults %+v", c)
	}
	c = AlertConfig{WANBusyPct: 150, WANBusyMin: 30, WANLossPct: 0.5}
	c.defaults()
	if c.WANBusyPct != 80 || c.WANBusyMin != 30 || c.WANLossPct != 0.5 {
		t.Fatalf("limits %+v", c)
	}
}

func TestHealthSnapshot(t *testing.T) {
	cpu := int64(42)
	w := &wanDev{cfg: WANDevice{Name: "HO-FW"}}
	w.extra = wanExtra{CPU: &cpu, SLA: []wanSLA{{Name: "dns", Iface: "wan1", Alive: true}}, VPN: []wanVPN{{Name: "t1", Up: true}}}
	h := w.health(false)
	if h.sys == nil || h.sys[0] != 42 || !math.IsNaN(h.sys[1]) || h.tabl || h.sla != nil {
		t.Fatalf("not fresh: %+v", h)
	}
	h = w.health(true)
	if len(h.sla) != 1 || len(h.vpn) != 1 || !h.tabl {
		t.Fatalf("fresh: %+v", h)
	}
	w.extra.SLA[0].Alive = false // the snapshot is a copy
	if !h.sla[0].Alive {
		t.Error("health must copy the tables")
	}
	f := toFloats([]any{1.5, nil, nanNull(math.NaN())})
	if f[0] == nil || *f[0] != 1.5 || f[1] != nil || f[2] != nil {
		t.Errorf("toFloats %v", f)
	}
	if jsonNum(math.NaN()) != -1 || jsonNum(3) != 3 {
		t.Error("jsonNum")
	}
}

func TestRepeatAttackerFlag(t *testing.T) {
	l := blockCandidates("signin_attack", "87.251.64.0/24", "87.251.64.17, 87.251.64.5", Config{}, time.Now(),
		map[string]int{"87.251.64.17/32": 3, "87.251.64.0/24": 2})
	got := map[string]any{}
	for _, m := range l {
		got[m["entry"].(string)] = m["repeat_days"]
	}
	if got["87.251.64.17/32"] != 3 || got["87.251.64.0/24"] != 2 || got["87.251.64.5/32"] != nil {
		t.Fatalf("repeat flags %v", got)
	}
}

// the SNMP "not answering" alert: raised for a timeout after 15 minutes, never for a missing passphrase
func TestWANPollHits(t *testing.T) {
	cfg := WANConfig{Devices: []WANDevice{{Name: "A", Host: "10.0.0.1"}, {Name: "B", Host: "10.0.0.2"}, {Name: "C", Host: "10.0.0.3"}}}
	now := time.Now()
	st := map[string]map[string]any{
		"A": {"error": "snmp: engine discovery: snmp: timeout after 3s", "last_ok": now.Add(-20 * time.Minute), "last_try": now},
		"B": {"error": "no passphrases saved: type them", "last_try": now},
		"C": {"error": "snmp: timeout", "last_ok": now.Add(-5 * time.Minute), "last_try": now},
	}
	wanStarted = now.Add(-time.Hour)
	h := wanPollHits(cfg, st, now)
	if len(h) != 1 || h[0].fw != "A" || h[0].kind != "wan_poll" {
		t.Fatalf("hits %+v", h)
	}
}
