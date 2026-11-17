package main

import (
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"embed"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/fs"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

//go:embed web/*
var webFS embed.FS

func (a *App) serveWeb(ctx context.Context) error {
	c := a.store.Get()
	mux := http.NewServeMux()
	mux.Handle("/", a.staticHandler())

	// sign-in (public) and account
	mux.HandleFunc("/api/login", a.handleLogin)
	mux.HandleFunc("/api/logout", a.handleLogout)
	mux.HandleFunc("/api/me", a.auth(RoleViewer, a.handleMe))
	mux.HandleFunc("/api/password", a.auth(RoleViewer, a.handlePassword))

	// viewer: dashboards
	mux.HandleFunc("/api/status", a.auth(RoleViewer, a.handleStatus))
	mux.HandleFunc("/api/summary", a.auth(RoleViewer, a.handleSummary))
	mux.HandleFunc("/api/facets", a.auth(RoleViewer, a.handleFacets))
	mux.HandleFunc("/api/insights", a.auth(RoleViewer, a.handleInsights))
	mux.HandleFunc("/api/global", a.auth(RoleViewer, a.handleGlobal))

	// analyst: raw logs, people and mappings
	mux.HandleFunc("/api/logs", a.auth(RoleAnalyst, a.handleLogs))
	mux.HandleFunc("/api/export.csv", a.auth(RoleAnalyst, a.handleExport))
	mux.HandleFunc("/api/investigate", a.auth(RoleAnalyst, a.handleInvestigate))
	mux.HandleFunc("/api/mapping/overview", a.auth(RoleAnalyst, a.handleMappingOverview))
	mux.HandleFunc("/api/mappings", a.auth(RoleAnalyst, a.handleMappings))
	mux.HandleFunc("/api/mappings/import", a.auth(RoleAnalyst, a.handleMappingsImport))
	mux.HandleFunc("/api/nps/status", a.auth(RoleAnalyst, a.handleNPSStatus))
	mux.HandleFunc("/api/nps/sessions", a.auth(RoleAnalyst, a.handleNPSSessions))
	mux.HandleFunc("/api/report", a.auth(RoleAnalyst, a.handleReport))
	mux.HandleFunc("/api/report.csv", a.auth(RoleAnalyst, a.handleReportCSV))
	mux.HandleFunc("/api/report/fields", a.auth(RoleAnalyst, a.handleReportFields))
	mux.HandleFunc("/api/reports", a.auth(RoleAnalyst, a.handleReports))
	mux.HandleFunc("/api/exec", a.auth(RoleViewer, a.handleExec))
	mux.HandleFunc("/api/exec/settings", a.auth(RoleViewer, a.handleExecSettings)) // v5.15
	// v5.16
	mux.HandleFunc("/api/aireport", a.auth(RoleViewer, a.handleAIReport))
	mux.HandleFunc("/api/wan", a.auth(RoleViewer, a.handleWAN))
	mux.HandleFunc("/api/wan/discover", a.auth(RoleAdmin, a.handleWANDiscover))
	mux.HandleFunc("/api/health", a.auth(RoleAdmin, a.handleHealth))
	mux.HandleFunc("/api/tls", a.auth(RoleAdmin, a.handleTLS))
	// v5.13: devices and people, detections
	mux.HandleFunc("/api/devices", a.auth(RoleAnalyst, a.handleDevices))
	mux.HandleFunc("/api/assignments", a.auth(RoleAnalyst, a.handleAssignments))
	mux.HandleFunc("/api/assignments.csv", a.auth(RoleAnalyst, a.handleAssignmentsCSV))
	mux.HandleFunc("/api/assignments/history", a.auth(RoleAnalyst, a.handleAssignHistory))
	mux.HandleFunc("/api/staff", a.auth(RoleAnalyst, a.handleStaff))
	mux.HandleFunc("/api/alerts", a.auth(RoleViewer, a.handleAlerts))
	// v5.20: blocklist (threat feed for the FortiGates)
	mux.HandleFunc("/api/blocklist", a.auth(RoleViewer, a.handleBlocklist))
	mux.HandleFunc("/api/blocklist/settings", a.auth(RoleAdmin, a.handleBlocklistSettings))
	mux.HandleFunc("/feed/", a.handleFeed)
	mux.HandleFunc("/api/attribution", a.auth(RoleViewer, a.handleAttribution))
	// v6.0: sites and tags, settings saved one section at a time, server health over 24 hours
	mux.HandleFunc("/api/sites", a.auth(RoleViewer, a.handleSites))
	mux.HandleFunc("/api/tags", a.auth(RoleViewer, a.handleTags))
	mux.HandleFunc("/api/config/section", a.auth(RoleAdmin, a.handleConfigSection))
	mux.HandleFunc("/api/config/history", a.auth(RoleAdmin, a.handleConfigHistory))
	mux.HandleFunc("/api/health/series", a.auth(RoleAdmin, a.handleHealthSeries))

	// admin: settings, accounts, audit
	mux.HandleFunc("/api/ai/reclassify", a.auth(RoleAdmin, a.handleReclassify))
	mux.HandleFunc("/api/ai/defaults", a.auth(RoleAdmin, a.handleAIDefaults))
	mux.HandleFunc("/api/config", a.auth(RoleAdmin, a.handleConfig))
	mux.HandleFunc("/api/database/test", a.auth(RoleAdmin, a.handleDBTest))
	mux.HandleFunc("/api/users", a.auth(RoleAdmin, a.handleUsers))
	mux.HandleFunc("/api/audit", a.auth(RoleAdmin, a.handleAudit))

	a.tlsOn.Store(c.WebTLS)
	srv := &http.Server{Addr: c.WebListenAddress, Handler: securityHeaders(c.WebTLS, hostGuard(c.WebListenAddress, gzipAPI(mux))),
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 60 * time.Second, IdleTimeout: 120 * time.Second}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()
	var err error
	if c.WebTLS {
		cert, key := c.TLSCertFile, c.TLSKeyFile
		if cert == "" || key == "" {
			if cert, key, err = ensureSelfSigned(a.dataFolder()); err != nil {
				return fmt.Errorf("https certificate: %w", err)
			}
		}
		srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		log.Printf("dashboard: https://%s (certificate %s)", c.WebListenAddress, cert)
		err = srv.ListenAndServeTLS(cert, key)
	} else {
		log.Printf("dashboard: http://%s (web_tls is off: passwords cross the network unencrypted)", c.WebListenAddress)
		err = srv.ListenAndServe()
	}
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

// staticHandler serves the page; everything except the sign-in page needs a session.
func (a *App) staticHandler() http.Handler {
	sub, _ := fs.Sub(webFS, "web")
	files := http.FileServer(http.FS(sub))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if p == "/login.html" || p == "/favicon.svg" || p == "/logo.svg" || p == "/favicon.ico" { // v6.0: the sign-in page shows the logo
			w.Header().Set("Cache-Control", "no-store")
			files.ServeHTTP(w, r)
			return
		}
		if a.currentSession(r) == nil {
			if p == "/" || strings.HasSuffix(p, ".html") {
				http.Redirect(w, r, "/login.html", http.StatusFound)
				return
			}
			http.Error(w, "sign in required", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Cache-Control", "no-cache")
		files.ServeHTTP(w, r)
	})
}

func securityHeaders(https bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "same-origin")
		if https {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		next.ServeHTTP(w, r)
	})
}

// ---------------------------------------------------------------- gzip for API responses (JSON and CSV)

type gzipWriter struct {
	http.ResponseWriter
	zw      *gzip.Writer
	status  int
	started bool
}

func (g *gzipWriter) WriteHeader(code int) {
	if g.status == 0 {
		g.status = code
	}
}

func (g *gzipWriter) start() {
	if g.started {
		return
	}
	g.started = true
	h := g.ResponseWriter.Header()
	h.Del("Content-Length")
	h.Set("Content-Encoding", "gzip")
	h.Add("Vary", "Accept-Encoding")
	if g.status == 0 {
		g.status = http.StatusOK
	}
	g.ResponseWriter.WriteHeader(g.status)
	g.zw, _ = gzip.NewWriterLevel(g.ResponseWriter, gzip.BestSpeed)
}

func (g *gzipWriter) Write(b []byte) (int, error) {
	g.start()
	return g.zw.Write(b)
}

func (g *gzipWriter) Flush() {
	if g.zw != nil {
		_ = g.zw.Flush()
	}
	if f, ok := g.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (g *gzipWriter) finish() {
	if g.zw != nil {
		_ = g.zw.Close()
		return
	}
	if g.status != 0 {
		g.ResponseWriter.WriteHeader(g.status)
	}
}

func gzipAPI(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/") || !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			next.ServeHTTP(w, r)
			return
		}
		g := &gzipWriter{ResponseWriter: w}
		defer g.finish()
		next.ServeHTTP(g, r)
	})
}

// ---------------------------------------------------------------- self-signed certificate

// ensureSelfSigned creates <data>/tls.crt and tls.key once (valid 3 years, for this host name and its addresses).
// Replace them with a certificate from your internal CA, or set tls_cert_file / tls_key_file, to avoid the warning.
func ensureSelfSigned(dir string) (string, string, error) {
	cert, key := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	if _, e1 := os.Stat(cert); e1 == nil {
		if _, e2 := os.Stat(key); e2 == nil {
			return cert, key, nil
		}
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		return "", "", err
	}
	host, _ := os.Hostname()
	tmpl := x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "LogSikka " + host, Organization: []string{"LogSikka"}},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(3, 0, 0),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true, DNSNames: []string{"localhost"},
	}
	if host != "" {
		tmpl.DNSNames = append(tmpl.DNSNames, host)
	}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, ad := range addrs {
			if ipn, ok := ad.(*net.IPNet); ok {
				tmpl.IPAddresses = append(tmpl.IPAddresses, ipn.IP)
			}
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return "", "", err
	}
	kb, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return "", "", err
	}
	if err = os.WriteFile(key, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0600); err != nil {
		return "", "", err
	}
	if err = os.WriteFile(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644); err != nil {
		return "", "", err
	}
	log.Printf("created a self-signed dashboard certificate: %s", cert)
	return cert, key, nil
}

func jsonOut(w http.ResponseWriter, v any) { _ = json.NewEncoder(w).Encode(v) }
func hours(r *http.Request) int {
	h, _ := strconv.Atoi(r.URL.Query().Get("hours"))
	if h < 1 || h > 24*90 {
		h = 24
	}
	return h
}

// handleStatus also asks the database what it really holds, so "stored" is proven, not assumed.
func (a *App) handleStatus(w http.ResponseWriter, r *http.Request) {
	s := a.status()
	s["exclusions"] = exclInfo()
	s["directory"] = directoryStatus(a)
	if d := a.getDB(); d != nil {
		// v5.10: shared by every open browser for 10 s, and limited to the newest chunk. It used to look for max(id) over
		// the whole table every 10 s per browser, which on compressed TimescaleDB chunks is not an index lookup.
		v, err := cached("status-db", 10*time.Second, func() (any, error) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			var last *time.Time
			var n int64
			err := d.pool.QueryRow(ctx, `SELECT (SELECT max(event_time) FROM fortigate_logs WHERE event_time > now() - interval '2 days'),
				(SELECT count(*) FROM fortigate_logs WHERE event_time > now() - interval '15 minutes' AND received_at > now() - interval '5 minutes')`).Scan(&last, &n)
			m := map[string]any{"db_rows_5min": n}
			if last != nil {
				m["db_latest_event"] = last.Unix()
			}
			return m, err
		})
		if err == nil {
			for k, x := range v.(map[string]any) {
				s[k] = x
			}
		} else {
			s["db_check_error"] = err.Error()
		}
	}
	jsonOut(w, s)
}
func (a *App) handleConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		c := a.store.Get()
		c.Database.Password = ""
		c.AdminToken = ""
		hideWANSecrets(&c.WAN)
		setRevision(w, a.store)
		jsonOut(w, c)
		return
	}
	if r.Method != http.MethodPut {
		http.Error(w, "method", 405)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	// v6.0.13: decode, merge and save as one step; refused (409) when the page's revision is out of date
	old, c, err := a.store.Update(ifMatch(r), func(old Config) (Config, error) { return fullConfigMerge(old, body) })
	if err == errConfigConflict {
		jsonError(w, http.StatusConflict, err.Error())
		return
	}
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	clearCache()
	a.audit(r, "settings_saved", "")
	if d := a.getDB(); d != nil && d.ts && c.CompressAfterDays != old.CompressAfterDays {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := d.timescalePolicies(ctx); err != nil {
				log.Printf("timescaledb compression policy: %v", err)
			}
		}()
	}
	restart := c.ListenAddress != old.ListenAddress || c.WebListenAddress != old.WebListenAddress || c.TCPEnabled != old.TCPEnabled || c.UDPEnabled != old.UDPEnabled || fmt.Sprint(c.AllowedSources, c.KeepSubtypes, c.Firewalls) != fmt.Sprint(old.AllowedSources, old.KeepSubtypes, old.Firewalls) || c.Database != old.Database || c.QueueCapacity != old.QueueCapacity || c.BatchSize != old.BatchSize ||
		c.WebTLS != old.WebTLS || c.TLSCertFile != old.TLSCertFile || c.TLSKeyFile != old.TLSKeyFile || c.QueryConcurrency != old.QueryConcurrency
	setRevision(w, a.store)
	jsonOut(w, map[string]any{"saved": true, "restart_required": restart})
}

// fullConfigMerge applies a whole-form save (PUT /api/config) to the stored settings old.
func fullConfigMerge(old Config, body []byte) (Config, error) {
	// v5.20: work on a deep copy. "c := old" shared the WAN device list (a slice) with the live configuration, so
	// decoding the form (whose passphrase fields are always empty) blanked the stored passphrases before
	// keepWANSecrets could copy them back: every Save in Settings lost them.
	c, err := cloneConfig(old)
	if err != nil {
		return old, err
	}
	c.Firewalls, c.AIRules, c.AICategories, c.AllowedSources, c.KeepSubtypes, c.NPS.Paths = nil, nil, nil, nil, nil, nil
	c.WAN.Devices = nil // decoded fresh: a list element must never inherit another firewall's fields
	if err := json.Unmarshal(body, &c); err != nil {
		return old, err
	}
	if c.Firewalls == nil {
		c.Firewalls = old.Firewalls
	}
	if c.AIRules == nil {
		c.AIRules = old.AIRules
	}
	if c.AICategories == nil {
		c.AICategories = old.AICategories
	}
	if c.NPS.Paths == nil {
		c.NPS.Paths = old.NPS.Paths
	}
	if c.WAN.Devices == nil {
		c.WAN.Devices = old.WAN.Devices
	}
	if c.Database.Password == "" {
		c.Database.Password = old.Database.Password
	}
	if c.AdminToken == "" {
		c.AdminToken = old.AdminToken
	}
	keepWANSecrets(&c.WAN, old.WAN)
	return c, nil
}

func (a *App) handleDBTest(w http.ResponseWriter, r *http.Request) {
	c := a.store.Get()
	var input DatabaseConfig
	if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		_ = json.NewDecoder(r.Body).Decode(&input)
		stored := c.Database
		if input.Host != "" {
			c.Database = input
		}
		// the saved password is only reused for the SAME server, port and user, never sent to a host typed into the form
		if c.Database.Password == "" && c.Database.Host == stored.Host && c.Database.Port == stored.Port && c.Database.User == stored.User {
			c.Database.Password = stored.Password
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	d, err := OpenDatabase(ctx, c.Database)
	if err != nil {
		http.Error(w, err.Error(), 503)
		return
	}
	d.Close()
	jsonOut(w, map[string]bool{"ok": true})
}

// hostGuard stops DNS-rebinding attacks against a dashboard bound to the loopback address: a page on another site
// can make its own hostname resolve to 127.0.0.1, but the browser still sends that hostname in the Host header.
func hostGuard(listen string, next http.Handler) http.Handler {
	host, _, err := net.SplitHostPort(listen)
	if err != nil || (host != "127.0.0.1" && host != "localhost" && host != "::1") {
		return next // reachable from the network: protected by sign-in
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := r.Host
		if hh, _, e := net.SplitHostPort(h); e == nil {
			h = hh
		}
		switch strings.Trim(h, "[]") {
		case "localhost", "127.0.0.1", "::1":
			next.ServeHTTP(w, r)
		default:
			http.Error(w, "unexpected Host header", http.StatusMisdirectedRequest)
		}
	})
}

// cloneConfig returns a copy of c that shares no slices or maps with it.
func cloneConfig(c Config) (Config, error) {
	var out Config
	b, err := json.Marshal(c)
	if err != nil {
		return out, err
	}
	err = json.Unmarshal(b, &out)
	return out, err
}

func jsonBytes(v any) ([]byte, error) { return json.Marshal(v) }
