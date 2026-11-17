package main

import "testing"

func TestSigGroup(t *testing.T) {
	for in, want := range map[string]string{"87.251.64.17": "87.251.64.0/24", "87.251.64.179": "87.251.64.0/24", "193.8.186.7": "193.8.186.0/24",
		"10.1.2.3": "10.1.2.3", "192.168.10.40": "192.168.10.40", "2001:db8::1": "2001:db8::/64", "https(1.2.3.4)": "https(1.2.3.4)", "?": "?"} {
		if got := sigGroup(in); got != want {
			t.Errorf("%s -> %s, want %s", in, got, want)
		}
	}
}

func TestViaCode(t *testing.T) {
	for _, c := range []struct {
		in   string
		vpn  bool
		want string
	}{{"https", false, "https"}, {"SSH", false, "ssh"}, {"ssl-web", true, "sslvpn"}, {"ssl-tunnel", true, "sslvpn"}, {"ipsec-dialup", true, "ipsec"},
		{"", true, "vpn"}, {"", false, "admin"}, {"vpn", true, "vpn"}} {
		if got := viaCode(c.in, c.vpn); got != c.want {
			t.Errorf("%q %v -> %q, want %q", c.in, c.vpn, got, c.want)
		}
	}
	if viaLabel("https", true) != "the HTTPS admin page" || viaLabel("sslvpn", false) != "SSL VPN" {
		t.Error("labels")
	}
	if joinAnd([]string{"a", "b", "c"}) != "a, b and c" || joinList([]string{"a", "b", "c"}, 2) != "a, b and 1 more" {
		t.Error("join")
	}
	if l := sortedKeys(map[string]bool{"10.0.0.10": true, "10.0.0.9": true}); l[0] != "10.0.0.9" {
		t.Errorf("numeric sort: %v", l)
	}
}
