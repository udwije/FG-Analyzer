package main

import (
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// v6.0.13 (H7): a save carrying an out-of-date revision is refused and changes nothing; a current one is saved.
func TestSettingsCompareAndSwap(t *testing.T) {
	store, err := LoadConfig(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	a := &App{store: store}
	get := func() string {
		w := httptest.NewRecorder()
		a.handleConfig(w, httptest.NewRequest("GET", "/api/config", nil))
		if w.Code != 200 {
			t.Fatalf("GET %d %s", w.Code, w.Body)
		}
		rev := w.Header().Get("X-Config-Revision")
		if rev == "" {
			t.Fatal("GET /api/config sent no X-Config-Revision")
		}
		return rev
	}
	put := func(rev string, brute int) *httptest.ResponseRecorder {
		al := store.Get().Alerts
		al.BruteForce = brute
		ab, _ := json.Marshal(al)
		r := httptest.NewRequest("PUT", "/api/config/section", strings.NewReader(`{"section":"Alerts","values":{"alerts":`+string(ab)+`}}`))
		if rev != "" {
			r.Header.Set("If-Match", rev)
		}
		w := httptest.NewRecorder()
		a.handleConfigSection(w, r)
		return w
	}

	tabA := get()
	tabB := get()
	if tabA != tabB {
		t.Fatal("the same settings gave two revisions")
	}
	// tab A saves first
	w := put(tabA, 21)
	if w.Code != 200 || store.Get().Alerts.BruteForce != 21 {
		t.Fatalf("current revision refused: %d %s", w.Code, w.Body)
	}
	newRev := w.Header().Get("X-Config-Revision")
	if newRev == "" || newRev == tabA {
		t.Fatalf("save did not return a new revision: %q", newRev)
	}
	// tab B still has the old revision: refused, nothing changed
	if w = put(tabB, 99); w.Code != 409 {
		t.Fatalf("stale revision: want 409, got %d %s", w.Code, w.Body)
	}
	if store.Get().Alerts.BruteForce != 21 {
		t.Fatal("a refused save changed the settings")
	}
	// with the revision returned by its own save, tab A can save again
	if w = put(newRev, 22); w.Code != 200 || store.Get().Alerts.BruteForce != 22 {
		t.Fatalf("revision from the previous save refused: %d %s", w.Code, w.Body)
	}
	// clients that send no revision (scripts, older pages) are saved as before
	if w = put("", 23); w.Code != 200 || store.Get().Alerts.BruteForce != 23 {
		t.Fatalf("save without If-Match: %d %s", w.Code, w.Body)
	}
}

// the whole-form save (PUT /api/config) is protected the same way
func TestFullSettingsSaveStaleRevision(t *testing.T) {
	store, err := LoadConfig(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	a := &App{store: store}
	stale := store.Revision()
	c := store.Get()
	c.RetentionDays = 45
	if err = store.Save(c); err != nil {
		t.Fatal(err)
	}
	shown := store.Get()
	shown.RetentionDays = 10
	b, _ := json.Marshal(shown)
	r := httptest.NewRequest("PUT", "/api/config", strings.NewReader(string(b)))
	r.Header.Set("If-Match", stale)
	w := httptest.NewRecorder()
	a.handleConfig(w, r)
	if w.Code != 409 || store.Get().RetentionDays != 45 {
		t.Fatalf("stale full save: %d, retention %d", w.Code, store.Get().RetentionDays)
	}
}

// the revision must not change when nothing changed, and must not be derivable without the start-up key
func TestConfigRevisionStable(t *testing.T) {
	c := defaultConfig(t.TempDir())
	if configRevision(c) != configRevision(c) {
		t.Fatal("revision not stable")
	}
	d := c
	d.Database.Password = "other"
	if configRevision(c) == configRevision(d) {
		t.Fatal("a password change must change the revision")
	}
}
