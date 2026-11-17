package main

import "testing"

func TestSessionByteIncrements(t *testing.T) {
	sessTrack.m = map[string]sessCum{}
	mk := func(logid string, sent, rcvd int64, extra map[string]string) LogRecord {
		f := map[string]string{"sessionid": "77"}
		for k, v := range extra {
			f[k] = v
		}
		return LogRecord{Type: "traffic", LogID: logid, DeviceName: "HO-FW", SrcIP: "10.1.1.5", SentBytes: sent, ReceivedBytes: rcvd, Fields: f}
	}
	// FortiOS without delta fields: increments are worked out from the running totals
	r1 := mk("0000000020", 100, 1000, nil)
	adjustSessionBytes(&r1)
	r2 := mk("0000000020", 300, 5000, nil)
	adjustSessionBytes(&r2)
	r3 := mk("0000000013", 350, 6000, nil)
	adjustSessionBytes(&r3)
	if r1.SentBytes+r2.SentBytes+r3.SentBytes != 350 || r1.ReceivedBytes+r2.ReceivedBytes+r3.ReceivedBytes != 6000 {
		t.Fatalf("sum %d/%d, want 350/6000", r1.SentBytes+r2.SentBytes+r3.SentBytes, r1.ReceivedBytes+r2.ReceivedBytes+r3.ReceivedBytes)
	}
	// the FortiGate's own delta wins
	r4 := mk("0000000020", 900, 9000, map[string]string{"sentdelta": "40", "rcvddelta": "400"})
	adjustSessionBytes(&r4)
	if r4.SentBytes != 40 || r4.ReceivedBytes != 400 {
		t.Fatalf("delta not used: %d/%d", r4.SentBytes, r4.ReceivedBytes)
	}
	// short sessions are untouched
	r5 := LogRecord{Type: "traffic", LogID: "0000000013", SentBytes: 5, ReceivedBytes: 6, Fields: map[string]string{"sessionid": "9"}}
	adjustSessionBytes(&r5)
	if r5.SentBytes != 5 || r5.ReceivedBytes != 6 {
		t.Fatal("short session changed")
	}
}

func TestLocalNets(t *testing.T) {
	setLocalNets([]string{"203.0.113.0/24"})
	defer setLocalNets(nil)
	for ip, want := range map[string]bool{"10.1.1.1": true, "192.168.2.13": true, "203.0.113.9": true, "8.8.8.8": false, "100.64.1.1": true} {
		if isLocalIP(ip) != want {
			t.Errorf("%s: %v", ip, !want)
		}
	}
	if validNets([]string{"10.0.0.0/8", "nope"}) == nil {
		t.Error("bad network accepted")
	}
	if !internalDest("CKI-HO-MOBILE", nil) || !internalDest("intranet.corp.example", []string{"corp.example"}) || internalDest("teams.microsoft.com", nil) {
		t.Error("internalDest")
	}
}
