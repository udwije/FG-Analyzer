package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"
)

// Sign-in for the dashboard.
//
// Accounts live in <data>/users.json (bcrypt hashes, mode 0600), not in the database, so you can still sign in and
// fix the database settings when PostgreSQL is down. Sessions are random 256-bit tokens in an HttpOnly cookie; only
// their SHA-256 is kept (in memory and in <data>/sessions.json, so a service restart does not sign everyone out).
//
// Roles: viewer   dashboards only (good for a wall screen)
//        analyst  + log explorer, CSV export, investigation, user mapping and NPS sessions
//        admin    + settings, accounts and the audit log
//
// The first start creates "admin" with a random password in <data>/initial-admin-password.txt.
// From the shell:  logsikka --data <dir> user list|add|passwd|role|disable|enable|delete ...

type Role int

const (
	RoleViewer  Role = 1
	RoleAnalyst Role = 2
	RoleAdmin   Role = 3
)

func roleOf(s string) Role {
	switch strings.ToLower(s) {
	case "admin":
		return RoleAdmin
	case "analyst":
		return RoleAnalyst
	case "viewer":
		return RoleViewer
	}
	return 0
}

type User struct {
	Username   string    `json:"username"`
	Role       string    `json:"role"`
	Hash       string    `json:"hash,omitempty"`
	Disabled   bool      `json:"disabled,omitempty"`
	MustChange bool      `json:"must_change,omitempty"`
	Created    time.Time `json:"created"`
	LastLogin  time.Time `json:"last_login,omitempty"`
}

var validUsername = regexp.MustCompile(`^[A-Za-z0-9._@-]{2,64}$`)

func checkPassword(p string) error {
	if len(p) < 10 {
		return errors.New("use at least 10 characters for the password")
	}
	if len(p) > 72 {
		return errors.New("use at most 72 characters for the password")
	}
	return nil
}

// ---------------------------------------------------------------- user store (users.json)

type userStore struct {
	mu      sync.Mutex
	path    string
	mod     time.Time
	checked time.Time
	users   map[string]*User // key: lower-case username
}

func openUsers(dir string) (*userStore, error) {
	s := &userStore{path: filepath.Join(dir, "users.json"), users: map[string]*User{}}
	if err := s.load(); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if len(s.users) == 0 {
		pw := randomPassword(16)
		h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
		if err != nil {
			return nil, err
		}
		s.users["admin"] = &User{Username: "admin", Role: "admin", Hash: string(h), MustChange: true, Created: time.Now()}
		if err = s.save(); err != nil {
			return nil, err
		}
		f := filepath.Join(dir, "initial-admin-password.txt")
		msg := fmt.Sprintf("LogSikka first sign-in\n\nusername: admin\npassword: %s\n\nYou will be asked to change it. Delete this file afterwards.\n", pw)
		if err = os.WriteFile(f, []byte(msg), 0600); err != nil {
			return nil, err
		}
		log.Printf("no accounts yet: created 'admin'; its one-time password is in %s", f)
	}
	return s, nil
}

func (s *userStore) load() error {
	st, err := os.Stat(s.path)
	if err != nil {
		return err
	}
	b, err := os.ReadFile(s.path)
	if err != nil {
		return err
	}
	var list []*User
	if err = json.Unmarshal(b, &list); err != nil {
		return fmt.Errorf("%s: %w", s.path, err)
	}
	m := map[string]*User{}
	for _, u := range list {
		if u != nil && u.Username != "" {
			m[strings.ToLower(u.Username)] = u
		}
	}
	s.users, s.mod = m, st.ModTime()
	return nil
}

// refresh picks up changes made from the command line while the service runs (checked every 5 s at most).
func (s *userStore) refresh() {
	if time.Since(s.checked) < 5*time.Second {
		return
	}
	s.checked = time.Now()
	if st, err := os.Stat(s.path); err == nil && !st.ModTime().Equal(s.mod) {
		if err = s.load(); err != nil {
			log.Printf("users: %v", err)
		}
	}
}

func (s *userStore) save() error {
	list := make([]*User, 0, len(s.users))
	for _, u := range s.users {
		list = append(list, u)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Username < list[j].Username })
	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(s.path), 0750); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err = os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	if err = os.Rename(tmp, s.path); err != nil {
		return err
	}
	if st, err := os.Stat(s.path); err == nil {
		s.mod = st.ModTime()
	}
	return nil
}

func (s *userStore) get(name string) (User, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refresh()
	u, ok := s.users[strings.ToLower(name)]
	if !ok {
		return User{}, false
	}
	return *u, true
}

// compared against when the user does not exist, so timing does not reveal valid names
var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("not-a-real-password"), bcrypt.MinCost)

func (s *userStore) verify(name, pw string) (User, error) {
	u, ok := s.get(name)
	if !ok || u.Disabled {
		_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(pw))
		return User{}, errors.New("wrong username or password")
	}
	if bcrypt.CompareHashAndPassword([]byte(u.Hash), []byte(pw)) != nil {
		return User{}, errors.New("wrong username or password")
	}
	return u, nil
}

func (s *userStore) update(name string, fn func(u *User) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refresh()
	u, ok := s.users[strings.ToLower(name)]
	if !ok {
		return fmt.Errorf("no account named %q", name)
	}
	c := *u
	if err := fn(&c); err != nil {
		return err
	}
	*u = c
	return s.save()
}

func (s *userStore) setPassword(name, pw string, mustChange bool) error {
	if err := checkPassword(pw); err != nil {
		return err
	}
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	return s.update(name, func(u *User) error { u.Hash, u.MustChange = string(h), mustChange; return nil })
}

// completePasswordChange stores the user's chosen password. When this completes the one-time
// bootstrap admin's forced first change, the plaintext bootstrap credential is removed. A failure
// to remove an already-obsolete file is logged but never rolls back the new password.
func (s *userStore) completePasswordChange(name, pw string) error {
	u, ok := s.get(name)
	if !ok {
		return fmt.Errorf("no account named %q", name)
	}
	bootstrap := strings.EqualFold(u.Username, "admin") && u.MustChange
	if err := s.setPassword(name, pw, false); err != nil {
		return err
	}
	if bootstrap {
		f := filepath.Join(filepath.Dir(s.path), "initial-admin-password.txt")
		if err := os.Remove(f); err != nil && !errors.Is(err, os.ErrNotExist) {
			log.Printf("password changed, but could not remove obsolete bootstrap password %s: %v", f, err)
		} else if err == nil {
			log.Printf("removed obsolete one-time administrator password %s", f)
		}
	}
	return nil
}

func (s *userStore) add(name, role, pw string) error {
	if !validUsername.MatchString(name) {
		return errors.New("a username is 2-64 letters, digits or . _ @ -")
	}
	if roleOf(role) == 0 {
		return errors.New("role must be viewer, analyst or admin")
	}
	if err := checkPassword(pw); err != nil {
		return err
	}
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refresh()
	if _, ok := s.users[strings.ToLower(name)]; ok {
		return fmt.Errorf("an account named %q already exists", name)
	}
	s.users[strings.ToLower(name)] = &User{Username: name, Role: strings.ToLower(role), Hash: string(h), MustChange: true, Created: time.Now()}
	return s.save()
}

func (s *userStore) remove(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refresh()
	if _, ok := s.users[strings.ToLower(name)]; !ok {
		return fmt.Errorf("no account named %q", name)
	}
	delete(s.users, strings.ToLower(name))
	return s.save()
}

func (s *userStore) list() []User {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refresh()
	out := make([]User, 0, len(s.users))
	for _, u := range s.users {
		c := *u
		c.Hash = ""
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Username < out[j].Username })
	return out
}

// activeAdmins counts enabled admins other than skip (so the last admin cannot be removed or demoted).
func (s *userStore) activeAdmins(skip string) int {
	n := 0
	for _, u := range s.list() {
		if u.Role == "admin" && !u.Disabled && !strings.EqualFold(u.Username, skip) {
			n++
		}
	}
	return n
}

func randomPassword(n int) string {
	const alphabet = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b := make([]byte, n)
	for i := range b {
		k, _ := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		b[i] = alphabet[k.Int64()]
	}
	return string(b)
}

// ---------------------------------------------------------------- sessions

type session struct {
	User     string    `json:"user"`
	Role     string    `json:"role"`
	Created  time.Time `json:"created"`
	Expires  time.Time `json:"expires"`
	LastSeen time.Time `json:"last_seen"`
	IP       string    `json:"ip"`
}

type sessionStore struct {
	mu    sync.Mutex
	path  string // "" = memory only (tests)
	m     map[string]*session
	saved time.Time
}

func newSessionStore(path string) *sessionStore {
	s := &sessionStore{path: path, m: map[string]*session{}}
	if path != "" {
		if b, err := os.ReadFile(path); err == nil {
			_ = json.Unmarshal(b, &s.m)
		}
	}
	return s
}

func tokenKey(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

func (s *sessionStore) saveLocked() {
	if s.path == "" {
		return
	}
	now := time.Now()
	for k, v := range s.m {
		if now.After(v.Expires) {
			delete(s.m, k)
		}
	}
	b, err := json.Marshal(s.m)
	if err != nil {
		return
	}
	tmp := s.path + ".tmp"
	if os.WriteFile(tmp, b, 0600) == nil {
		_ = os.Rename(tmp, s.path)
	}
	s.saved = now
}

func (s *sessionStore) create(u User, ip string, d time.Duration) string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	token := base64.RawURLEncoding.EncodeToString(b)
	now := time.Now()
	s.mu.Lock()
	s.m[tokenKey(token)] = &session{User: u.Username, Role: u.Role, Created: now, Expires: now.Add(d), LastSeen: now, IP: ip}
	s.saveLocked()
	s.mu.Unlock()
	return token
}

func (s *sessionStore) get(token string) *session {
	if token == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.m[tokenKey(token)]
	if !ok {
		return nil
	}
	if time.Now().After(v.Expires) {
		delete(s.m, tokenKey(token))
		return nil
	}
	v.LastSeen = time.Now()
	if time.Since(s.saved) > 5*time.Minute {
		s.saveLocked()
	}
	c := *v
	return &c
}

func (s *sessionStore) drop(token string) {
	s.mu.Lock()
	delete(s.m, tokenKey(token))
	s.saveLocked()
	s.mu.Unlock()
}

// dropUser signs a user out everywhere (password reset, account disabled or deleted), except keepToken.
func (s *sessionStore) dropUser(name, keepToken string) {
	keep := ""
	if keepToken != "" {
		keep = tokenKey(keepToken)
	}
	s.mu.Lock()
	for k, v := range s.m {
		if strings.EqualFold(v.User, name) && k != keep {
			delete(s.m, k)
		}
	}
	s.saveLocked()
	s.mu.Unlock()
}

// ---------------------------------------------------------------- failed sign-in throttle

type failInfo struct {
	n           int
	first, lock time.Time
}

var (
	failMu sync.Mutex
	fails  = map[string]*failInfo{}
)

// loginLocked: after 5 failures within 15 minutes, an address must wait 15 minutes.
func loginLocked(ip string) time.Duration {
	failMu.Lock()
	defer failMu.Unlock()
	if f, ok := fails[ip]; ok && time.Now().Before(f.lock) {
		return time.Until(f.lock)
	}
	return 0
}

func loginFailed(ip string) {
	failMu.Lock()
	defer failMu.Unlock()
	f, ok := fails[ip]
	if !ok || time.Since(f.first) > 15*time.Minute {
		if len(fails) > 10000 {
			fails = map[string]*failInfo{}
		}
		f = &failInfo{first: time.Now()}
		fails[ip] = f
	}
	f.n++
	if f.n >= 5 {
		f.lock = time.Now().Add(15 * time.Minute)
		f.n, f.first = 0, time.Now()
	}
}

func loginOK(ip string) {
	failMu.Lock()
	delete(fails, ip)
	failMu.Unlock()
}

// ---------------------------------------------------------------- HTTP

type ctxKey int

const sessionKey ctxKey = 1

const cookiePlain, cookieSecure = "logsikka_session", "__Host-logsikka"

// v6.0: the cookies of LogSikka (before the rename) are still accepted, so nobody is signed out by the upgrade.
var oldCookies = []string{"__Host-fortilog", "fortilog_session"}

func clientIP(r *http.Request) string {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}

func sessionToken(r *http.Request) string {
	for _, n := range append([]string{cookieSecure, cookiePlain}, oldCookies...) {
		if c, err := r.Cookie(n); err == nil && c.Value != "" {
			return c.Value
		}
	}
	return ""
}

// currentSession returns the signed-in session, re-checking the account (deleted, disabled, role changed).
func (a *App) currentSession(r *http.Request) *session {
	if a.sessions == nil || a.users == nil {
		return nil
	}
	s := a.sessions.get(sessionToken(r))
	if s == nil {
		return nil
	}
	u, ok := a.users.get(s.User)
	if !ok || u.Disabled {
		a.sessions.drop(sessionToken(r))
		return nil
	}
	s.Role = u.Role
	return s
}

func sessionFrom(ctx context.Context) *session {
	s, _ := ctx.Value(sessionKey).(*session)
	return s
}

// csrfOK: state-changing requests must carry JSON or the X-LogSikka header. A page on another site cannot send
// either without a CORS preflight, which this server never approves.
func csrfOK(r *http.Request) bool {
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		return true
	}
	return r.Header.Get("X-LogSikka") != "" || r.Header.Get("X-FortiLog") != "" || strings.Contains(r.Header.Get("Content-Type"), "application/json")
}

func jsonError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// auth wraps an API handler: a signed-in session with at least role min, plus the cross-site guard.
func (a *App) auth(min Role, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s := a.currentSession(r)
		if s == nil {
			jsonError(w, http.StatusUnauthorized, "sign in required")
			return
		}
		u, ok := a.users.get(s.User)
		if !ok { jsonError(w, http.StatusUnauthorized, "sign in required"); return }
		if u.MustChange && r.URL.Path != "/api/password" && r.URL.Path != "/api/logout" && r.URL.Path != "/api/me" {
			jsonError(w, http.StatusForbidden, "password change required")
			return
		}
		if roleOf(s.Role) < min {
			jsonError(w, http.StatusForbidden, "your account ("+s.Role+") cannot do this")
			return
		}
		if !csrfOK(r) {
			http.Error(w, "forbidden: send Content-Type: application/json or X-LogSikka", http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		next(w, r.WithContext(context.WithValue(r.Context(), sessionKey, s)))
	}
}

func (a *App) setSessionCookie(w http.ResponseWriter, token string, maxAge int) {
	name := cookiePlain
	if a.tlsOn.Load() {
		name = cookieSecure
	}
	http.SetCookie(w, &http.Cookie{Name: name, Value: token, Path: "/", MaxAge: maxAge, HttpOnly: true, Secure: a.tlsOn.Load(), SameSite: http.SameSiteLaxMode})
}

func (a *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || !csrfOK(r) {
		jsonError(w, http.StatusMethodNotAllowed, "POST JSON")
		return
	}
	ip := clientIP(r)
	if wait := loginLocked(ip); wait > 0 {
		jsonError(w, http.StatusTooManyRequests, fmt.Sprintf("Too many failed sign-ins. Try again in %d minutes.", int(wait.Minutes())+1))
		return
	}
	var in struct{ Username, Password string }
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&in); err != nil {
		jsonError(w, http.StatusBadRequest, "bad request")
		return
	}
	usernameKey := "user:" + strings.ToLower(strings.TrimSpace(in.Username))
	if wait := loginLocked(usernameKey); wait > 0 { jsonError(w, http.StatusTooManyRequests, "Too many failed sign-ins for this account."); return }
	u, err := a.users.verify(strings.TrimSpace(in.Username), in.Password)
	if err != nil {
		loginFailed(ip)
		loginFailed(usernameKey)
		a.auditAs(in.Username, ip, "login_failed", "")
		jsonError(w, http.StatusUnauthorized, "Wrong username or password.")
		return
	}
	loginOK(ip)
	loginOK(usernameKey)
	hrs := int(sessionHours.Load())
	if hrs < 1 {
		hrs = 12
	}
	token := a.sessions.create(u, ip, time.Duration(hrs)*time.Hour)
	a.setSessionCookie(w, token, hrs*3600)
	_ = a.users.update(u.Username, func(x *User) error { x.LastLogin = time.Now(); return nil })
	a.auditAs(u.Username, ip, "login", "")
	jsonOut(w, map[string]any{"username": u.Username, "role": u.Role, "must_change": u.MustChange})
}

func (a *App) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || !csrfOK(r) {
		jsonError(w, http.StatusMethodNotAllowed, "POST")
		return
	}
	if s := a.currentSession(r); s != nil {
		a.auditAs(s.User, clientIP(r), "logout", "")
	}
	a.sessions.drop(sessionToken(r))
	a.setSessionCookie(w, "", -1)
	jsonOut(w, map[string]bool{"ok": true})
}

func (a *App) handleMe(w http.ResponseWriter, r *http.Request) {
	s := sessionFrom(r.Context())
	u, _ := a.users.get(s.User)
	jsonOut(w, map[string]any{"username": s.User, "role": s.Role, "must_change": u.MustChange, "expires": s.Expires.Unix(), "version": version})
}

func (a *App) handlePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, http.StatusMethodNotAllowed, "POST")
		return
	}
	s := sessionFrom(r.Context())
	var in struct{ Old, New string }
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&in); err != nil {
		jsonError(w, http.StatusBadRequest, "bad request")
		return
	}
	if _, err := a.users.verify(s.User, in.Old); err != nil {
		jsonError(w, http.StatusBadRequest, "The current password is wrong.")
		return
	}
	if in.New == in.Old {
		jsonError(w, http.StatusBadRequest, "Choose a new password that differs from the current one.")
		return
	}
	if err := a.users.completePasswordChange(s.User, in.New); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	a.sessions.dropUser(s.User, sessionToken(r)) // sign out other browsers
	a.audit(r, "password_changed", "")
	jsonOut(w, map[string]bool{"ok": true})
}

// /api/users (admin): GET list, POST create or change {username, role, password, disabled}, DELETE ?username=
func (a *App) handleUsers(w http.ResponseWriter, r *http.Request) {
	me := sessionFrom(r.Context())
	switch r.Method {
	case http.MethodGet:
		jsonOut(w, a.users.list())
	case http.MethodPost:
		var in struct {
			Username, Role, Password string
			Disabled                 *bool
			Create                   bool
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&in); err != nil {
			jsonError(w, http.StatusBadRequest, "bad request")
			return
		}
		in.Username, in.Role = strings.TrimSpace(in.Username), strings.ToLower(strings.TrimSpace(in.Role))
		if in.Create {
			if err := a.users.add(in.Username, in.Role, in.Password); err != nil {
				jsonError(w, http.StatusBadRequest, err.Error())
				return
			}
			a.audit(r, "user_added", in.Username+" ("+in.Role+")")
			jsonOut(w, map[string]bool{"ok": true})
			return
		}
		cur, ok := a.users.get(in.Username)
		if !ok {
			jsonError(w, http.StatusNotFound, "no such account")
			return
		}
		self := strings.EqualFold(in.Username, me.User)
		demote := in.Role != "" && in.Role != "admin" && cur.Role == "admin"
		disable := in.Disabled != nil && *in.Disabled
		if (demote || disable) && (self || a.users.activeAdmins(in.Username) == 0) {
			jsonError(w, http.StatusBadRequest, "Keep at least one enabled admin, and do not lock yourself out.")
			return
		}
		if in.Role != "" && roleOf(in.Role) == 0 {
			jsonError(w, http.StatusBadRequest, "role must be viewer, analyst or admin")
			return
		}
		if in.Password != "" {
			if err := a.users.setPassword(in.Username, in.Password, !self); err != nil {
				jsonError(w, http.StatusBadRequest, err.Error())
				return
			}
			a.sessions.dropUser(in.Username, sessionToken(r))
			a.audit(r, "user_password_reset", in.Username)
		}
		if err := a.users.update(in.Username, func(u *User) error {
			if in.Role != "" {
				u.Role = in.Role
			}
			if in.Disabled != nil {
				u.Disabled = *in.Disabled
			}
			return nil
		}); err != nil {
			jsonError(w, http.StatusBadRequest, err.Error())
			return
		}
		if disable {
			a.sessions.dropUser(in.Username, "")
		}
		a.audit(r, "user_changed", fmt.Sprintf("%s role=%s disabled=%v", in.Username, in.Role, disable))
		jsonOut(w, map[string]bool{"ok": true})
	case http.MethodDelete:
		name := r.URL.Query().Get("username")
		cur, ok := a.users.get(name)
		if !ok {
			jsonError(w, http.StatusNotFound, "no such account")
			return
		}
		if strings.EqualFold(name, me.User) || (cur.Role == "admin" && a.users.activeAdmins(name) == 0) {
			jsonError(w, http.StatusBadRequest, "You cannot delete your own account or the last admin.")
			return
		}
		if err := a.users.remove(name); err != nil {
			jsonError(w, http.StatusBadRequest, err.Error())
			return
		}
		a.sessions.dropUser(name, "")
		a.audit(r, "user_deleted", name)
		jsonOut(w, map[string]bool{"ok": true})
	default:
		jsonError(w, http.StatusMethodNotAllowed, "method")
	}
}

// ---------------------------------------------------------------- audit log

func (a *App) audit(r *http.Request, action, detail string) {
	user := ""
	if s := sessionFrom(r.Context()); s != nil {
		user = s.User
	}
	a.auditAs(user, clientIP(r), action, detail)
}

func (a *App) auditAs(user, ip, action, detail string) {
	if len(detail) > 500 {
		detail = strings.ToValidUTF8(detail[:500], "")
	}
	if len(user) > 64 {
		user = strings.ToValidUTF8(user[:64], "")
	}
	log.Printf("audit: user=%q ip=%s action=%s %s", user, ip, action, detail)
	d := a.getDB()
	if d == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = d.pool.Exec(ctx, `INSERT INTO audit_log(username, ip, action, detail) VALUES ($1,$2,$3,$4)`, user, ip, action, detail)
	}()
}

func (a *App) handleAudit(w http.ResponseWriter, r *http.Request) {
	d := a.dbOrFail(w)
	if d == nil {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	args := []any{}
	cond := ""
	if q != "" {
		cond = " WHERE username ILIKE $1 OR action ILIKE $1 OR ip ILIKE $1 OR detail ILIKE $1"
		args = append(args, likePattern(q))
	}
	rows, err := d.pool.Query(ctx, `SELECT at, coalesce(username,''), coalesce(ip,''), action, coalesce(detail,'') FROM audit_log`+cond+` ORDER BY at DESC LIMIT 300`, args...)
	if err != nil {
		queryErr(w, err)
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var at time.Time
		var u, ip, act, det string
		if err = rows.Scan(&at, &u, &ip, &act, &det); err != nil {
			queryErr(w, err)
			return
		}
		out = append(out, map[string]any{"at": at, "user": u, "ip": ip, "action": act, "detail": det})
	}
	jsonOut(w, out)
}

// ---------------------------------------------------------------- command line: logsikka user ...

const userUsage = `Manage dashboard accounts (run as the service user, e.g. sudo -u logsikka):
  logsikka --data DIR user list
  logsikka --data DIR user add NAME ROLE        ROLE: viewer, analyst or admin (asks for a password)
  logsikka --data DIR user passwd NAME          (asks for a new password)
  logsikka --data DIR user role NAME ROLE
  logsikka --data DIR user disable|enable|delete NAME
The running service picks up the change within a few seconds.`

func readPassword(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	if term.IsTerminal(int(os.Stdin.Fd())) {
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		return string(b), err
	}
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func askNewPassword() (string, error) {
	p1, err := readPassword("New password: ")
	if err != nil {
		return "", err
	}
	if term.IsTerminal(int(os.Stdin.Fd())) {
		p2, err := readPassword("Repeat it:    ")
		if err != nil {
			return "", err
		}
		if p1 != p2 {
			return "", errors.New("the passwords do not match")
		}
	}
	return p1, checkPassword(p1)
}

func runUserCLI(dir string, args []string) error {
	s, err := openUsers(dir)
	if err != nil {
		return err
	}
	if len(args) == 0 {
		return errors.New(userUsage)
	}
	need := func(n int) error {
		if len(args) < n {
			return errors.New(userUsage)
		}
		return nil
	}
	switch args[0] {
	case "list":
		fmt.Printf("%-24s %-8s %-9s %s\n", "USERNAME", "ROLE", "STATE", "LAST SIGN-IN")
		for _, u := range s.list() {
			state, last := "enabled", "never"
			if u.Disabled {
				state = "disabled"
			}
			if !u.LastLogin.IsZero() {
				last = u.LastLogin.Format("2006-01-02 15:04")
			}
			fmt.Printf("%-24s %-8s %-9s %s\n", u.Username, u.Role, state, last)
		}
		return nil
	case "add":
		if err = need(3); err != nil {
			return err
		}
		pw, err := askNewPassword()
		if err != nil {
			return err
		}
		if err = s.add(args[1], args[2], pw); err != nil {
			return err
		}
		fmt.Printf("Added %s (%s). They will be asked to choose their own password at first sign-in.\n", args[1], args[2])
	case "passwd":
		if err = need(2); err != nil {
			return err
		}
		if _, ok := s.get(args[1]); !ok {
			return fmt.Errorf("no account named %q", args[1])
		}
		pw, err := askNewPassword()
		if err != nil {
			return err
		}
		if err = s.setPassword(args[1], pw, false); err != nil {
			return err
		}
		_ = s.update(args[1], func(u *User) error { u.Disabled = false; return nil })
		fmt.Printf("Password changed for %s.\n", args[1])
	case "role":
		if err = need(3); err != nil {
			return err
		}
		if roleOf(args[2]) == 0 {
			return errors.New("role must be viewer, analyst or admin")
		}
		if err = s.update(args[1], func(u *User) error { u.Role = strings.ToLower(args[2]); return nil }); err != nil {
			return err
		}
		fmt.Printf("%s is now %s.\n", args[1], strings.ToLower(args[2]))
	case "disable", "enable":
		if err = need(2); err != nil {
			return err
		}
		off := args[0] == "disable"
		if err = s.update(args[1], func(u *User) error { u.Disabled = off; return nil }); err != nil {
			return err
		}
		fmt.Printf("%s is %sd.\n", args[1], args[0])
	case "delete":
		if err = need(2); err != nil {
			return err
		}
		if err = s.remove(args[1]); err != nil {
			return err
		}
		fmt.Printf("Deleted %s.\n", args[1])
	default:
		return errors.New(userUsage)
	}
	return nil
}
