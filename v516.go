package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"time"
)

// v5.16: endpoint point of view, network-device traffic, site-to-site duplicates, session tracking across restarts,
// system health and certificate requests.

// ---------------------------------------------------------------- infrastructure and tunnels

type infraSet struct {
	nets    string // literal inet[]
	tunnels string // literal text[]
}

var infraCur atomic.Pointer[infraSet]

var tunnelName = regexp.MustCompile(`^[A-Za-z0-9._:@ -]{1,64}$`)

func validTunnels(l []string) error {
	for _, s := range l {
		if s = strings.TrimSpace(s); s != "" && !tunnelName.MatchString(s) {
			return fmt.Errorf("tunnel interfaces: %q is not an interface name", s)
		}
	}
	return nil
}

func setInfra(nets, tunnels []string) {
	n := []string{}
	for _, s := range nets {
		if p, ok := parsePrefix(strings.TrimSpace(s)); ok {
			n = append(n, p.String())
		}
	}
	t := []string{}
	for _, s := range tunnels {
		if s = strings.TrimSpace(s); s != "" && tunnelName.MatchString(s) {
			t = append(t, `"`+s+`"`) // validated: no quotes or backslashes
		}
	}
	infraCur.Store(&infraSet{nets: "'{" + strings.Join(n, ",") + "}'::inet[]", tunnels: "'{" + strings.Join(t, ",") + "}'::text[]"})
}

func init() { setInfra(nil, nil) }

func infraNetsSQL() string { return infraCur.Load().nets }
func tunnelsSQL() string   { return infraCur.Load().tunnels }

// ---------------------------------------------------------------- session byte tracking survives a restart

// Without this, the first statistics log of every long session after a restart had no previous total to subtract
// (when the firewall sends no sentdelta) and was counted at its full running total.

type savedSess struct {
	K  string `json:"k"`
	S  int64  `json:"s"`
	R  int64  `json:"r"`
	At int64  `json:"at"`
}

func sessTrackPath(dir string) string { return filepath.Join(dir, "session-bytes.json") }

func saveSessionTrack(dir string) {
	sessTrack.Lock()
	l := make([]savedSess, 0, len(sessTrack.m))
	for k, v := range sessTrack.m {
		l = append(l, savedSess{k, v.sent, v.rcvd, v.at})
	}
	sessTrack.Unlock()
	b, err := json.Marshal(l)
	if err != nil {
		return
	}
	tmp := sessTrackPath(dir) + ".tmp"
	if err = os.WriteFile(tmp, b, 0600); err == nil {
		err = os.Rename(tmp, sessTrackPath(dir))
	}
	if err != nil {
		log.Printf("saving session totals: %v", err)
		return
	}
	log.Printf("saved the running totals of %d open sessions", len(l))
}

func loadSessionTrack(dir string) {
	b, err := os.ReadFile(sessTrackPath(dir))
	if err != nil {
		return
	}
	var l []savedSess
	if json.Unmarshal(b, &l) != nil {
		return
	}
	now := time.Now().Unix()
	n := 0
	sessTrack.Lock()
	for _, s := range l {
		if now-s.At < 1800 { // the same rule as the sweeper: 30 minutes without a log = gone
			sessTrack.m[s.K] = sessCum{s.S, s.R, s.At}
			n++
		}
	}
	sessTrack.Unlock()
	_ = os.Remove(sessTrackPath(dir))
	if n > 0 {
		log.Printf("restored the running totals of %d open sessions", n)
	}
}

// ---------------------------------------------------------------- system health (Settings > System health)

type jobInfo struct {
	Name    string     `json:"name"`
	Label   string     `json:"label"`
	Done    bool       `json:"done"`
	Upto    *time.Time `json:"upto,omitempty"`
	Percent float64    `json:"percent"`
}

func (a *App) handleHealth(w http.ResponseWriter, r *http.Request) {
	d := a.getDB()
	out := map[string]any{"now": time.Now(), "status": a.status(), "directory": directoryStatus(a)}
	files, _ := a.spool.Files()
	out["spool"] = map[string]any{"files": len(files), "bytes": a.spool.scan(), "max_mb": a.store.Get().SpoolMaxMB}
	out["tls"] = a.tlsInfo()
	out["disk"] = diskInfo(map[string]string{"LogSikka data": a.dataFolder()})
	if d == nil {
		out["database"] = map[string]any{"connected": false}
		jsonOut(w, out)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	v, err := cached("health-db", time.Minute, func() (any, error) { return a.healthDB(ctx, d) })
	if err != nil {
		out["database"] = map[string]any{"connected": true, "error": err.Error()}
	} else {
		for k, x := range v.(map[string]any) {
			out[k] = x
		}
	}
	jsonOut(w, out)
}

func (a *App) healthDB(ctx context.Context, d *Database) (map[string]any, error) {
	out := map[string]any{}
	var size int64
	var dataDir string
	if err := d.pool.QueryRow(ctx, `SELECT pg_database_size(current_database())`).Scan(&size); err != nil {
		return nil, err
	}
	if d.pool.QueryRow(ctx, `SELECT coalesce(current_setting('data_directory', true), '')`).Scan(&dataDir) != nil || dataDir == "" {
		dataDir = "/var/lib/postgresql" // the setting is only readable by superusers; the usual place on Ubuntu
	}
	db := map[string]any{"connected": true, "size": size, "timescale": d.ts}
	// table sizes (hypertables count their chunks)
	rows, err := d.pool.Query(ctx, `SELECT c.relname, CASE WHEN $1 AND c.relname = 'fortigate_logs' THEN
			(SELECT coalesce(sum(total_bytes),0)::bigint FROM chunks_detailed_size('fortigate_logs')) + pg_total_relation_size(c.oid)
		ELSE pg_total_relation_size(c.oid) END
		FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = current_schema() AND c.relkind IN ('r','p')
		ORDER BY 2 DESC LIMIT 12`, d.ts)
	if err == nil {
		tables := []map[string]any{}
		for rows.Next() {
			var n string
			var s int64
			if rows.Scan(&n, &s) == nil {
				tables = append(tables, map[string]any{"name": n, "size": s})
			}
		}
		rows.Close()
		db["tables"] = tables
	}
	// logs per day (last 8 days) and growth
	days := []map[string]any{}
	if rows, err := d.pool.Query(ctx, `SELECT date_trunc('day', bucket), sum(cnt)::bigint FROM rollup_5m WHERE bucket > now() - interval '8 days' GROUP BY 1 ORDER BY 1`); err == nil {
		for rows.Next() {
			var t time.Time
			var n int64
			if rows.Scan(&t, &n) == nil {
				days = append(days, map[string]any{"day": t, "logs": n})
			}
		}
		rows.Close()
	}
	db["days"] = days
	var stored int64
	_ = d.pool.QueryRow(ctx, `SELECT coalesce(sum(cnt),0)::bigint FROM rollup_5m`).Scan(&stored)
	var perDay float64
	full := 0
	for i, x := range days {
		if i > 0 && i < len(days)-1 { // whole days only
			perDay += float64(x["logs"].(int64))
			full++
		}
	}
	if full > 0 {
		perDay /= float64(full)
	}
	db["logs_per_day"] = int64(perDay)
	if stored > 0 && perDay > 0 {
		perLog := float64(size) / float64(stored)
		growth := perDay * perLog
		db["bytes_per_day"] = int64(growth)
		db["retention_days"] = a.store.Get().RetentionDays
		// steady state: retention days of logs (compression makes older days smaller; this is an upper bound)
		db["steady_size"] = int64(growth * float64(a.store.Get().RetentionDays))
	}
	out["database"] = db
	if dataDir != "" {
		out["disk"] = diskInfo(map[string]string{"LogSikka data": a.dataFolder(), "PostgreSQL data": dataDir})
	}
	// background jobs
	floor, _ := d.backfillFloor(ctx)
	now := hourStart(time.Now())
	roll.mu.Lock()
	jobs := []jobInfo{
		{"backfill", "Summaries of older logs", roll.complete, nil, 0},
		{"r516", "Traffic directions, endpoint up/down and device traffic (v5.16 rebuild)", roll.rbOK, nil, 0},
		{"ai", "AI summary", roll.aiOK, nil, 0},
		{"evt", "Sign-ins and changes", roll.evtOK, nil, 0},
		{"map", "User-mapping summary", roll.mpOK, nil, 0},
		{"extra", "Web categories and risky apps", roll.extraOK, nil, 0},
	}
	cur := map[string]time.Time{"backfill": roll.covered, "r516": roll.rb, "ai": roll.ai, "evt": roll.evt, "map": roll.mp, "extra": roll.extra}
	pending := len(roll.dirty)
	roll.mu.Unlock()
	span := now.Sub(floor).Hours()
	for i := range jobs {
		t := cur[jobs[i].Name]
		if !t.IsZero() {
			tt := t
			jobs[i].Upto = &tt
		}
		switch {
		case jobs[i].Done || span <= 0:
			jobs[i].Percent = 100
		case !t.IsZero():
			jobs[i].Percent = clampPct(100 * now.Sub(t).Hours() / span)
		}
	}
	var daysBuilt int64
	_ = d.pool.QueryRow(ctx, `SELECT count(*) FROM rollup_1d_done`).Scan(&daysBuilt)
	ex := exclInfo()
	out["jobs"] = map[string]any{"list": jobs, "dirty_hours": pending, "days_built": daysBuilt, "exclusions": ex, "from": floor}
	return out, nil
}

func clampPct(p float64) float64 {
	if p < 0 {
		return 0
	}
	if p > 100 {
		return 100
	}
	return float64(int(p*10)) / 10
}

// diskInfo: free space of the file systems holding the given folders (walking up when a folder is not readable).
func diskInfo(paths map[string]string) []map[string]any {
	out := []map[string]any{}
	seen := map[string]bool{}
	for label, p := range paths {
		for q := p; q != "" && q != "."; q = filepath.Dir(q) {
			total, free, ok := diskFree(q)
			if ok {
				key := fmt.Sprint(total, free)
				if !seen[key] {
					seen[key] = true
					out = append(out, map[string]any{"label": label, "path": q, "total": total, "free": free})
				}
				break
			}
			if q == filepath.Dir(q) {
				break
			}
		}
	}
	return out
}

// ---------------------------------------------------------------- certificate: request (CSR) and install

func (a *App) tlsInfo() map[string]any {
	c := a.store.Get()
	out := map[string]any{"enabled": c.WebTLS}
	path := c.TLSCertFile
	if path == "" {
		path = filepath.Join(a.dataFolder(), "tls.crt")
	}
	out["file"] = path
	if b, err := os.ReadFile(path); err == nil {
		if blk, _ := pem.Decode(b); blk != nil {
			if cert, err := x509.ParseCertificate(blk.Bytes); err == nil {
				out["subject"], out["issuer"] = cert.Subject.String(), cert.Issuer.String()
				out["not_after"], out["dns"] = cert.NotAfter, cert.DNSNames
				out["self_signed"] = cert.Subject.String() == cert.Issuer.String()
				ips := []string{}
				for _, ip := range cert.IPAddresses {
					ips = append(ips, ip.String())
				}
				out["ips"] = ips
			}
		}
	}
	if _, err := os.Stat(filepath.Join(a.dataFolder(), "tls-request.key")); err == nil {
		out["pending_request"] = true
		if b, err := os.ReadFile(filepath.Join(a.dataFolder(), "tls-request.csr")); err == nil {
			out["csr"] = string(b)
		}
	}
	return out
}

func (a *App) handleTLS(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		jsonOut(w, a.tlsInfo())
		return
	}
	var in struct {
		Action string   `json:"action"`
		CN     string   `json:"cn"`
		Names  []string `json:"names"`
		Org    string   `json:"org"`
		Cert   string   `json:"cert"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<17)).Decode(&in); err != nil {
		jsonError(w, http.StatusBadRequest, "bad request")
		return
	}
	dir := a.dataFolder()
	switch in.Action {
	case "csr":
		csr, err := makeCSR(dir, in.CN, in.Org, in.Names)
		if err != nil {
			jsonError(w, http.StatusBadRequest, err.Error())
			return
		}
		a.audit(r, "tls_request", in.CN)
		jsonOut(w, map[string]any{"csr": csr})
	case "install":
		file, key, err := installCert(dir, in.Cert)
		if err != nil {
			jsonError(w, http.StatusBadRequest, err.Error())
			return
		}
		c := a.store.Get()
		c.TLSCertFile, c.TLSKeyFile, c.WebTLS = file, key, true
		if err := a.store.Save(c); err != nil {
			jsonError(w, http.StatusBadRequest, err.Error())
			return
		}
		a.audit(r, "tls_installed", file)
		setRevision(w, a.store) // v6.0.13: the Settings page keeps saving without a false "changed by someone else"
		jsonOut(w, map[string]any{"installed": true, "restart_required": true, "tls": a.tlsInfo()})
	default:
		jsonError(w, http.StatusBadRequest, "unknown action")
	}
}

var dnsName = regexp.MustCompile(`^(\*\.)?[A-Za-z0-9]([A-Za-z0-9-]{0,62})(\.[A-Za-z0-9]([A-Za-z0-9-]{0,62}))*$`)

// makeCSR creates a new key (kept in the data folder until the signed certificate is installed) and a request for it.
func makeCSR(dir, cn, org string, names []string) (string, error) {
	cn = strings.TrimSpace(cn)
	if cn == "" {
		return "", errors.New("enter the server name people will use (e.g. logsikka.corp.lk)")
	}
	tmpl := x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}
	if org = strings.TrimSpace(org); org != "" {
		tmpl.Subject.Organization = []string{org}
	}
	all := append([]string{cn}, names...)
	seen := map[string]bool{}
	for _, n := range all {
		n = strings.TrimSpace(n)
		if n == "" || seen[strings.ToLower(n)] {
			continue
		}
		seen[strings.ToLower(n)] = true
		if ip := net.ParseIP(n); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else if dnsName.MatchString(n) {
			tmpl.DNSNames = append(tmpl.DNSNames, n)
		} else {
			return "", fmt.Errorf("%q is not a host name or IP address", n)
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", err
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &tmpl, key)
	if err != nil {
		return "", err
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", err
	}
	if err = os.WriteFile(filepath.Join(dir, "tls-request.key"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0600); err != nil {
		return "", err
	}
	csr := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
	if err = os.WriteFile(filepath.Join(dir, "tls-request.csr"), []byte(csr), 0644); err != nil {
		return "", err
	}
	return csr, nil
}

// installCert checks that the signed certificate belongs to the pending request's key and installs both.
func installCert(dir, certPEM string) (string, string, error) {
	kb, err := os.ReadFile(filepath.Join(dir, "tls-request.key"))
	if err != nil {
		return "", "", errors.New("there is no pending certificate request: create one first")
	}
	kblk, _ := pem.Decode(kb)
	if kblk == nil {
		return "", "", errors.New("the pending key is unreadable: create a new request")
	}
	key, err := x509.ParseECPrivateKey(kblk.Bytes)
	if err != nil {
		return "", "", err
	}
	rest := []byte(strings.TrimSpace(certPEM))
	var leaf *x509.Certificate
	var chain []byte
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return "", "", fmt.Errorf("certificate: %w", err)
		}
		if leaf == nil {
			leaf = c
		}
		chain = append(chain, pem.EncodeToMemory(blk)...)
	}
	if leaf == nil {
		return "", "", errors.New("paste the certificate in PEM form (-----BEGIN CERTIFICATE-----)")
	}
	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(&key.PublicKey) {
		return "", "", errors.New("this certificate was not issued for the pending request (the keys do not match)")
	}
	if time.Now().After(leaf.NotAfter) {
		return "", "", errors.New("this certificate has already expired")
	}
	certFile, keyFile := filepath.Join(dir, "tls-ca.crt"), filepath.Join(dir, "tls-ca.key")
	if err = os.WriteFile(certFile, chain, 0644); err != nil {
		return "", "", err
	}
	if err = os.WriteFile(keyFile, kb, 0600); err != nil {
		return "", "", err
	}
	_ = os.Remove(filepath.Join(dir, "tls-request.key"))
	_ = os.Remove(filepath.Join(dir, "tls-request.csr"))
	return certFile, keyFile, nil
}
