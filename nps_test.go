package main

import (
	"context"
	"testing"
	"time"
)

func TestParseNPSDTS(t *testing.T) {
	line := `<Event><Timestamp data_type="4">10/14/2026 09:12:33.123</Timestamp><Computer-Name data_type="1">NPS01</Computer-Name><Event-Source data_type="1">IAS</Event-Source><User-Name data_type="1">CORP\jdoe</User-Name><Framed-IP-Address data_type="3">10.20.5.44</Framed-IP-Address><Calling-Station-Id data_type="1">AA-BB-CC-DD-EE-FF</Calling-Station-Id><Client-Friendly-Name data_type="1">WLC-1</Client-Friendly-Name><Acct-Status-Type data_type="0">3</Acct-Status-Type><Packet-Type data_type="0">4</Packet-Type><SAM-Account-Name data_type="1">CORP\jdoe</SAM-Account-Name></Event>`
	r, ok := parseNPSLine(line)
	if !ok {
		t.Fatal("not parsed")
	}
	want := time.Date(2026, 10, 14, 9, 12, 33, 123e6, time.Local)
	if !r.Time.Equal(want) || r.User != `CORP\jdoe` || r.IP != "10.20.5.44" || r.MAC != "aa:bb:cc:dd:ee:ff" || r.Packet != 4 || r.Status != 3 || r.NAS != "WLC-1" {
		t.Fatalf("bad record %+v", r)
	}
}

func TestParseNPSIAS(t *testing.T) {
	line := `10.0.0.5,CORP\jdoe,10/14/2026,09:12:33,IAS,NPS01,44,0000001A,8,10.20.5.44,31,aa:bb:cc:dd:ee:ff,40,1,4136,4,4129,CORP\jdoe`
	r, ok := parseNPSLine(line)
	if !ok || r.IP != "10.20.5.44" || r.Packet != 4 || r.Status != 1 || r.MAC != "aa:bb:cc:dd:ee:ff" || r.User != `CORP\jdoe` {
		t.Fatalf("bad record %+v ok=%v", r, ok)
	}
}

func TestNormUser(t *testing.T) {
	e := &npsEng{cfg: NPSConfig{StripDomain: true, Lowercase: true}}
	for in, want := range map[string]string{`CORP\JDoe`: "jdoe", "jdoe@corp.local": "jdoe", "host/PC01.corp.local": "", "PC01$": "", "": ""} {
		if got := e.normUser(in); got != want {
			t.Errorf("%q -> %q, want %q", in, got, want)
		}
	}
}

func TestNormMAC(t *testing.T) {
	for in, want := range map[string]string{"AA-BB-CC-DD-EE-FF": "aa:bb:cc:dd:ee:ff", "aabb.ccdd.eeff": "aa:bb:cc:dd:ee:ff", "AABBCCDDEEFF": "aa:bb:cc:dd:ee:ff", "nope": "", "AA-BB-CC-DD-EE-FF:ssid": ""} {
		if got := normMAC(in); got != want {
			t.Errorf("%q -> %q, want %q", in, got, want)
		}
	}
}

func TestClassifyAI(t *testing.T) {
	setAIRules([]string{"Artificial Intelligence Technology", "GenAI"}, defaultAIRules())
	cases := []struct{ app, host, cat, id, want string }{
		{"ChatGPT", "", "GenAI", "", "ChatGPT"},
		{"", "chatgpt.com", "Artificial Intelligence Technology", "100", "ChatGPT"},
		{"", "api.githubcopilot.com", "", "", "GitHub Copilot"},
		{"", "copilot.microsoft.com", "", "", "Microsoft Copilot"},
		{"", "api.x.ai", "", "", "Grok"},
		{"", "box.aiservice.com", "", "", ""},
		{"", "chat.some-new-ai.co.uk", "Artificial Intelligence Technology", "100", "some-new-ai.co.uk"},
		{"HTTPS", "unknown-ai.io", "Artificial Intelligence Technology", "100", "unknown-ai.io"},
		{"Facebook", "facebook.com", "Social Networking", "37", ""},
	}
	for _, c := range cases {
		if got := classifyAI(c.app, c.host, c.cat, c.id); got != c.want {
			t.Errorf("%v -> %q, want %q", c, got, c.want)
		}
	}
}

func TestAICaseSQL(t *testing.T) {
	setAIRules([]string{"GenAI"}, []AIRule{{Tool: "Grok", Patterns: []string{"*.x.ai", "grok"}}})
	args := []any{}
	sql := aiCaseSQL(&args)
	if len(args) != 3 || sql == "" {
		t.Fatalf("args=%v sql=%s", args, sql)
	}
	if p := args[0].([]string); p[0] != "%.x.ai" || p[1] != "%grok%" {
		t.Fatalf("patterns %v", p)
	}
}

func TestParseFortiGateDevice(t *testing.T) {
	setFirewalls([]Firewall{{Name: "HQ", IP: "10.0.0.1"}})
	setAIRules([]string{"GenAI"}, defaultAIRules())
	r := ParseLog([]byte(`date=2026-10-14 time=09:00:00 devname="FGT-BR1" devid="FG100F" eventtime=1791950400000000000 type="traffic" subtype="forward" srcip=10.20.5.44 srcmac="aa:bb:cc:dd:ee:ff" dstip=1.2.3.4 hostname="chatgpt.com" app="HTTPS" action="accept"`), "10.0.0.2")
	if r.DeviceName != "FGT-BR1" || r.SrcMAC != "aa:bb:cc:dd:ee:ff" || r.AITool != "ChatGPT" {
		t.Fatalf("%+v", r)
	}
	if r2 := ParseLog([]byte(`devname="X" type="event"`), "10.0.0.1"); r2.DeviceName != "HQ" {
		t.Fatalf("configured name not used: %q", r2.DeviceName)
	}
}

func TestNPSSessions(t *testing.T) {
	var next int64
	insertSession = func(_ context.Context, _ *Database, s *npsSession) error { next++; s.ID = next; return nil }
	e := newNPSEng()
	e.configure(NPSConfig{Enabled: true, IdleHours: 2, StripDomain: true, Lowercase: true, LearnFromMAC: true})
	e.loaded = true
	ctx := context.Background()
	t0 := time.Date(2026, 10, 14, 8, 0, 0, 0, time.Local)
	rec := func(min int, user, ip, mac string, pkt, st int) {
		if err := e.observe(ctx, nil, npsRecord{Time: t0.Add(time.Duration(min) * time.Minute), RawUser: user, User: user, IP: ip, MAC: mac, Packet: pkt, Status: st}); err != nil {
			t.Fatal(err)
		}
	}
	at := func(min int, ip, mac string) string {
		if s := e.userFor(ctx, nil, ip, mac, t0.Add(time.Duration(min)*time.Minute)); s != nil {
			return s.User
		}
		return ""
	}
	rec(0, `CORP\alice`, "10.1.1.10", "aa:aa:aa:aa:aa:aa", 4, 3) // alice interim update with IP
	if u := at(5, "10.1.1.10", ""); u != "alice" {
		t.Fatalf("want alice, got %q", u)
	}
	rec(30, `CORP\bob`, "10.1.1.10", "bb:bb:bb:bb:bb:bb", 4, 1) // bob takes the IP: alice ends at 08:30
	if u := at(29, "10.1.1.10", ""); u != "alice" {
		t.Fatalf("before handover want alice, got %q", u)
	}
	if u := at(31, "10.1.1.10", ""); u != "bob" {
		t.Fatalf("after handover want bob, got %q", u)
	}
	rec(60, `CORP\bob`, "10.1.1.10", "", 4, 2) // accounting stop
	if u := at(61, "10.1.1.10", ""); u != "" {
		t.Fatalf("after stop want nobody, got %q", u)
	}
	// carol authenticates without an IP; the FortiGate log with her MAC reveals the IP
	rec(70, `CORP\carol`, "", "cc:cc:cc:cc:cc:cc", 2, 0)
	if u := at(72, "10.1.1.77", "cc:cc:cc:cc:cc:cc"); u != "carol" {
		t.Fatalf("mac learning want carol, got %q", u)
	}
	if u := at(73, "10.1.1.77", ""); u != "carol" {
		t.Fatalf("learned session want carol, got %q", u)
	}
	// idle timeout (2 h) with no further records
	if u := at(72+125, "10.1.1.77", ""); u != "" {
		t.Fatalf("after idle want nobody, got %q", u)
	}
	// machine accounts are ignored
	rec(200, "host/PC01.corp.local", "10.1.1.90", "", 4, 3)
	if u := at(201, "10.1.1.90", ""); u != "" {
		t.Fatalf("machine account mapped: %q", u)
	}
}
