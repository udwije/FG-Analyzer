package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestZoneSQLHasDeviceZones(t *testing.T) {
	setInfra([]string{"10.10.99.0/24", "bad", "10.20.1.2"}, []string{"HO-to-KDY", `bad"name`})
	defer setInfra(nil, nil)
	z := zoneSQL()
	for _, want := range []string{"'infra'", "'transit'", "10.10.99.0/24", "10.20.1.2/32", `"HO-to-KDY"`} {
		if !strings.Contains(z, want) {
			t.Errorf("zone SQL lacks %s", want)
		}
	}
	if strings.Contains(z, "bad") {
		t.Error("an invalid entry reached the SQL")
	}
	if validTunnels([]string{"ok-name", "x'y"}) == nil {
		t.Error("a quote in a tunnel name must be refused")
	}
}

func TestSessionTrackSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	sessTrack.Lock()
	sessTrack.m = map[string]sessCum{"FW||7|10.1.1.5": {100, 2000, time.Now().Unix()}, "old": {1, 1, time.Now().Unix() - 7200}}
	sessTrack.Unlock()
	saveSessionTrack(dir)
	sessTrack.Lock()
	sessTrack.m = map[string]sessCum{}
	sessTrack.Unlock()
	loadSessionTrack(dir)
	sessTrack.Lock()
	defer sessTrack.Unlock()
	if v, ok := sessTrack.m["FW||7|10.1.1.5"]; !ok || v.sent != 100 || v.rcvd != 2000 {
		t.Fatalf("not restored: %+v", sessTrack.m)
	}
	if _, ok := sessTrack.m["old"]; ok {
		t.Error("a session silent for 2 hours must not be restored")
	}
}

func TestCertificateRequestAndInstall(t *testing.T) {
	dir := t.TempDir()
	csrPEM, err := makeCSR(dir, "fortilog.corp.lk", "CEAT", []string{"fortilog", "192.168.2.20"})
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode([]byte(csrPEM))
	csr, err := x509.ParseCertificateRequest(blk.Bytes)
	if err != nil || csr.CheckSignature() != nil {
		t.Fatalf("csr: %v", err)
	}
	if len(csr.DNSNames) != 2 || len(csr.IPAddresses) != 1 {
		t.Fatalf("names %v ips %v", csr.DNSNames, csr.IPAddresses)
	}
	// a CA signs it
	caKey, _ := ecdsa.GenerateKey(csr.PublicKey.(*ecdsa.PublicKey).Curve, rand.Reader)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Corp CA"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().AddDate(1, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, _ := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: csr.Subject, DNSNames: csr.DNSNames, IPAddresses: csr.IPAddresses,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(1, 0, 0), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, csr.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	chain := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})) + string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))
	// a certificate for another key is refused
	if _, _, err := installCert(dir, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))); err == nil {
		t.Fatal("a certificate for a different key must be refused")
	}
	cf, kf, err := installCert(dir, chain)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "tls-request.key")); err == nil {
		t.Error("the pending key should be moved")
	}
	if b, _ := os.ReadFile(cf); strings.Count(string(b), "BEGIN CERTIFICATE") != 2 {
		t.Error("chain not kept")
	}
	if st, _ := os.Stat(kf); runtime.GOOS != "windows" && st.Mode().Perm() != 0600 { // Windows has no Unix permissions
		t.Error("key file must be 0600")
	}
}

func TestWANConfig(t *testing.T) {
	c := WANConfig{Devices: []WANDevice{{Host: " 10.0.0.1 ", Username: "fgt-monitor", Auth: "SHA256", Priv: "AES128", AuthPass: "a", PrivPass: "p",
		Interfaces: []WANIface{{Name: "wan1", DownMbps: 100}}}}}
	if err := c.validate(); err != nil {
		t.Fatal(err)
	}
	d := c.Devices[0]
	if d.Name != "10.0.0.1" || d.Port != 161 || d.Level != "authPriv" || d.Interfaces[0].UpMbps != 100 || c.PollSeconds != 30 {
		t.Fatalf("defaults: %+v %+v", c, d)
	}
	bad := WANConfig{Devices: []WANDevice{{Host: "h", Username: "u", Auth: "SHA1", Priv: "AES256", AuthPass: "a", PrivPass: "p"}}}
	if bad.validate() == nil {
		t.Error("SHA1 with AES256 must be refused")
	}
	// v5.19: a missing passphrase must NOT block saving the configuration; the poller reports it instead
	np := WANConfig{Devices: []WANDevice{{Host: "h", Username: "u", Auth: "SHA256", Priv: "AES128", AuthPass: "a"}}}
	if err := np.validate(); err != nil {
		t.Errorf("missing passphrase blocked the save: %v", err)
	}
	if np.Devices[0].missingPass() == "" {
		t.Error("the missing privacy passphrase must be reported")
	}
	// stored passphrases are found by address even when the username changed
	moved := WANConfig{Devices: []WANDevice{{Host: "10.0.0.1", Username: "other-user"}}}
	keepWANSecrets(&moved, c)
	if moved.Devices[0].AuthPass != "a" || moved.Devices[0].missingPass() != "" {
		t.Error("passphrases must follow the firewall address")
	}
	n := WANConfig{Devices: []WANDevice{{Host: "10.0.0.1", Username: "fgt-monitor"}}}
	keepWANSecrets(&n, c)
	if n.Devices[0].AuthPass != "a" || n.Devices[0].PrivPass != "p" {
		t.Error("empty passphrases must keep the stored ones")
	}
	h := c
	hideWANSecrets(&h)
	if h.Devices[0].AuthPass != "" || c.Devices[0].AuthPass != "a" || !h.Devices[0].AuthSet || !h.Devices[0].PrivSet {
		t.Error("hiding must not touch the stored copy")
	}
	if s := wanStep(24*time.Hour, 30); s != 300 {
		t.Errorf("24 h step %d", s)
	}
}

func TestMigrationIncludesWAN(t *testing.T) {
	n := 0
	for _, s := range migrationSteps(schemaSQL) {
		if strings.Contains(s.sql, "wan_samples") && s.check != "" {
			n++
		}
	}
	if n != 6 { // table, 2 indexes, and the 3 v6.0.6 counter-delta columns
		t.Errorf("wan steps %d", n)
	}
}
