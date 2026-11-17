package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

// v6.0.13 (roadmap H7): settings compare-and-swap.
//
// GET /api/config returns the revision of the stored settings in the X-Config-Revision header. The Settings page
// sends it back in If-Match when it saves. When the settings were changed in between (another admin, another tab,
// WAN "Find interfaces", blocklist or summary settings), the save is refused with 409 instead of silently
// overwriting the newer change. Requests without If-Match (scripts, older pages) are saved as before.
//
// The revision is an HMAC of the stored configuration with a key created at start-up, so it never reveals
// anything about the passwords in it. After a restart every revision changes: an open page then gets a 409 and
// must be reloaded once.

var errConfigConflict = errors.New("these settings were changed by someone else after this page was loaded. Reload the page and make your change again")

var revisionKey = func() []byte {
	k := make([]byte, 32)
	_, _ = rand.Read(k)
	return k
}()

func configRevision(c Config) string {
	b, _ := json.Marshal(c)
	m := hmac.New(sha256.New, revisionKey)
	m.Write(b)
	return hex.EncodeToString(m.Sum(nil)[:12])
}

// Revision of the stored settings.
func (s *ConfigStore) Revision() string { return configRevision(s.Get()) }

// Save stores c unconditionally (start-up, upgrades, scripts). Saves are serialised.
func (s *ConfigStore) Save(c Config) error {
	s.saveMu.Lock()
	defer s.saveMu.Unlock()
	return s.saveLocked(c)
}

// Update reads, changes and stores the settings as one step: no other save can run in between. When rev is not
// empty and the stored settings no longer have that revision, nothing is saved and errConfigConflict is returned.
// It returns the settings before and after the save.
func (s *ConfigStore) Update(rev string, fn func(old Config) (Config, error)) (Config, Config, error) {
	s.saveMu.Lock()
	defer s.saveMu.Unlock()
	old := s.Get()
	if rev != "" && rev != configRevision(old) {
		return old, old, errConfigConflict
	}
	c, err := fn(old)
	if err != nil {
		return old, old, err
	}
	if err = s.saveLocked(c); err != nil {
		return old, old, err
	}
	return old, s.Get(), nil
}

// ifMatch: the revision the page loaded (empty when the client did not send one).
func ifMatch(r *http.Request) string {
	return strings.Trim(strings.TrimSpace(r.Header.Get("If-Match")), `"`)
}

func setRevision(w http.ResponseWriter, s *ConfigStore) {
	w.Header().Set("X-Config-Revision", s.Revision())
}
