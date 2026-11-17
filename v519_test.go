package main

import "testing"

func TestFortiGateMIBHelpers(t *testing.T) {
	if inetStr([]byte{203, 0, 113, 9}) != "203.0.113.9" {
		t.Error("IPv4 gateway")
	}
	for in, want := range map[string]float64{"12.345": 12.345, " 0.000": 0, "": 0, "3": 3} {
		if parseF(in) != want {
			t.Errorf("%q -> %v", in, parseF(in))
		}
	}
	d := WANDevice{Host: "h", Username: "u", Level: "authPriv", Auth: "SHA256", Priv: "AES128"}
	if d.missingPass() == "" {
		t.Error("both passphrases missing must be reported")
	}
	d.AuthPass, d.PrivPass = "a", "p"
	if d.missingPass() != "" {
		t.Error("nothing missing")
	}
	d.Level, d.PrivPass = "authNoPriv", ""
	if d.missingPass() != "" {
		t.Error("authNoPriv needs no privacy passphrase")
	}
}
