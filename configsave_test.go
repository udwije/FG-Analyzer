package main

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

// v5.20: saving Settings (whose passphrase fields are always empty) must keep the stored WAN passphrases, and must not
// change the live configuration before it is validated and saved.
func TestSaveSettingsKeepsWANPassphrases(t *testing.T) {
	dir := t.TempDir()
	store, err := LoadConfig(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	c := store.Get()
	c.WAN = WANConfig{Enabled: true, Devices: []WANDevice{
		{Name: "HO-FW", Host: "10.0.0.1", Username: "fgt", Auth: "SHA256", Priv: "AES128", AuthPass: "auth-1", PrivPass: "priv-1", Interfaces: []WANIface{{Name: "wan1"}}},
		{Name: "KH-FW", Host: "10.0.0.2", Username: "fgt", Auth: "SHA256", Priv: "AES128", AuthPass: "auth-2", PrivPass: "priv-2", Interfaces: []WANIface{{Name: "wan1"}}}}}
	if err = store.Save(c); err != nil {
		t.Fatal(err)
	}
	a := &App{store: store}
	// what the settings page sends: GET /api/config with the secrets hidden, then PUT it back unchanged
	shown := store.Get()
	hideWANSecrets(&shown.WAN)
	shown.Database.Password = ""
	body := formBody(t, shown)
	for round := 0; round < 3; round++ {
		w := httptest.NewRecorder()
		a.handleConfig(w, httptest.NewRequest("PUT", "/api/config", bytes.NewReader(body)))
		if w.Code != 200 {
			t.Fatalf("save %d: %d %s", round, w.Code, w.Body.String())
		}
		got := store.Get().WAN.Devices
		if len(got) != 2 || got[0].AuthPass != "auth-1" || got[0].PrivPass != "priv-1" || got[1].AuthPass != "auth-2" || got[1].PrivPass != "priv-2" {
			t.Fatalf("save %d lost the passphrases: %+v", round, got)
		}
	}
	// a failed save must leave the live configuration untouched
	bad := shown
	bad.RetentionDays = 0
	body = formBody(t, bad)
	w := httptest.NewRecorder()
	a.handleConfig(w, httptest.NewRequest("PUT", "/api/config", bytes.NewReader(body)))
	if w.Code == 200 || store.Get().WAN.Devices[0].AuthPass != "auth-1" {
		t.Fatalf("invalid save: code %d, passphrase %q", w.Code, store.Get().WAN.Devices[0].AuthPass)
	}
}

// formBody: the configuration as the settings page sends it: every WAN passphrase field present and empty.
func formBody(t *testing.T, c Config) []byte {
	b, _ := json.Marshal(c)
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	for _, d := range m["wan"].(map[string]any)["devices"].([]any) {
		d.(map[string]any)["auth_pass"], d.(map[string]any)["priv_pass"] = "", ""
	}
	b, _ = json.Marshal(m)
	return b
}
