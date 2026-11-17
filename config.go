package main

import (
	"encoding/json"
	"errors"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
)

type Config struct {
	ListenAddress    string         `json:"listen_address"`
	TCPEnabled       bool           `json:"tcp_enabled"`
	UDPEnabled       bool           `json:"udp_enabled"`
	AllowedSources   []string       `json:"allowed_sources"`
	KeepSubtypes     []string       `json:"keep_subtypes"`
	MaxMessageBytes  int            `json:"max_message_bytes"`
	QueueCapacity    int            `json:"queue_capacity"`
	BatchSize        int            `json:"batch_size"`
	BatchIntervalMS  int            `json:"batch_interval_ms"`
	Database         DatabaseConfig `json:"database"`
	RetentionDays    int            `json:"retention_days"`
	SpoolDirectory   string         `json:"spool_directory"`
	SpoolMaxMB       int64          `json:"spool_max_mb"`
	WebListenAddress string         `json:"web_listen_address"`
	AdminToken       string         `json:"admin_token,omitempty"`

	// v5
	Firewalls    []Firewall `json:"firewalls"`     // named FortiGate sources; their IPs are also allowed senders
	AICategories []string   `json:"ai_categories"` // FortiGuard web filter / app control categories that mean "AI"
	AIRules      []AIRule   `json:"ai_rules"`      // first match wins; patterns are checked against application and hostname
	NPS          NPSConfig  `json:"nps"`

	// v5.5
	WebTLS            bool   `json:"web_tls"`                 // HTTPS for the dashboard; a self-signed certificate is created when no files are given
	TLSCertFile       string `json:"tls_cert_file,omitempty"` // optional: your own certificate (PEM)
	TLSKeyFile        string `json:"tls_key_file,omitempty"`
	SessionHours      int    `json:"session_hours"`       // a sign-in lasts this long (wall screens: viewer account, long value)
	QueryConcurrency  int    `json:"query_concurrency"`   // dashboard queries running at once
	CompressAfterDays int    `json:"compress_after_days"` // TimescaleDB: compress day chunks older than this

	// v5.7
	Exec ExecConfig `json:"exec"`
	// v5.12: address ranges inside your network besides the private ranges (traffic direction: internal / internet)
	InternalNetworks []string `json:"internal_networks,omitempty"`
	// v5.16: network devices (switches, APs, controllers, management VLANs) and site-to-site tunnel interfaces
	InfraNetworks    []string  `json:"infra_networks,omitempty"`
	TunnelInterfaces []string  `json:"tunnel_interfaces,omitempty"`
	WAN              WANConfig `json:"wan"`
	// v5.13
	Directory DirectoryConfig `json:"directory"`
	Alerts    AlertConfig     `json:"alerts"`
	// v5.20: blocklist published as a FortiGate external threat feed
	Blocklist BlocklistConfig `json:"blocklist"`
	// v6.0: sites, their firewalls and zones (see sites.go)
	Sites []SiteConfig `json:"sites,omitempty"`
}

// DirectoryConfig: the staff list exported every night on the NPS server (staff.csv, computers.csv).
type DirectoryConfig struct {
	Enabled        bool   `json:"enabled"`
	Path           string `json:"path"`            // folder holding staff.csv (e.g. /mnt/nps/nps01/logsikka)
	PollMinutes    int    `json:"poll_minutes"`    // how often the files are checked for changes
	NormalizeUsers bool   `json:"normalize_users"` // store CORP\Nimal and nimal@corp.lk as nimal
	DropUnverified bool   `json:"drop_unverified"` // a firewall "unauthenticated user" guess that is not staff is not used
}

// ExecConfig: the organisation name on the executive summary and the thresholds behind its green / amber / red status.
type ExecConfig struct {
	OrgName         string `json:"org_name"`
	BlockedUpAmber  int    `json:"blocked_up_amber"` // % rise in blocked activity vs the previous period
	BlockedUpRed    int    `json:"blocked_up_red"`
	AdminFailAmber  int    `json:"admin_fail_amber"` // failed admin / VPN sign-ins in the period
	AdminFailRed    int    `json:"admin_fail_red"`
	RiskAppsAmber   int    `json:"risk_apps_amber"` // high or critical risk applications that were allowed
	RiskAppsRed     int    `json:"risk_apps_red"`
	AIUploadUpAmber int    `json:"ai_upload_up_amber"` // % rise in data uploaded to AI tools
	QuietAmberMin   int    `json:"quiet_amber_min"`    // a firewall silent this long is amber
	QuietRedHours   int    `json:"quiet_red_hours"`    // ... and this long is red
	DeviceBlocksDay int    `json:"device_blocks_day"`  // a device with more blocked connections per day than this is "unusual"
	// v5.10: traffic left out of the executive summary (a log matching ANY list is excluded). See exclude.go.
	ExcludeSources      []string `json:"exclude_sources,omitempty"`      // IPs or subnets
	ExcludeDestinations []string `json:"exclude_destinations,omitempty"` // IPs, subnets or host names (*.example.com)
	ExcludeUsers        []string `json:"exclude_users,omitempty"`        // usernames, e.g. service accounts
	ExcludeSubtypes     []string `json:"exclude_subtypes,omitempty"`     // log subtypes, e.g. local
	// v5.11
	IgnoreFirewalls   []string `json:"ignore_firewalls,omitempty"`    // renamed / retired devices: left out of availability checks and the firewall share
	InternalDomains   []string `json:"internal_domains,omitempty"`    // your own domains: left out of "Most used destinations"
	ShowInternalDests bool     `json:"show_internal_dests,omitempty"` // keep internal addresses and short names in "Most used destinations"
}

func (e *ExecConfig) defaults() {
	set := func(v *int, d int) {
		if *v <= 0 {
			*v = d
		}
	}
	set(&e.BlockedUpAmber, 25)
	set(&e.BlockedUpRed, 100)
	set(&e.AdminFailAmber, 6)
	set(&e.AdminFailRed, 50)
	set(&e.RiskAppsAmber, 1)
	set(&e.RiskAppsRed, 4)
	set(&e.AIUploadUpAmber, 50)
	set(&e.QuietAmberMin, 60)
	set(&e.QuietRedHours, 24)
	set(&e.DeviceBlocksDay, 10000)
	if e.BlockedUpRed < e.BlockedUpAmber {
		e.BlockedUpRed = e.BlockedUpAmber
	}
	if e.AdminFailRed < e.AdminFailAmber {
		e.AdminFailRed = e.AdminFailAmber
	}
	if e.RiskAppsRed < e.RiskAppsAmber {
		e.RiskAppsRed = e.RiskAppsAmber
	}
	clean := func(l []string) []string {
		out := []string{}
		for _, x := range l {
			if x = strings.TrimSpace(x); x != "" && len(x) <= 200 {
				out = append(out, x)
			}
		}
		return out
	}
	e.IgnoreFirewalls, e.InternalDomains = clean(e.IgnoreFirewalls), clean(e.InternalDomains)
	e.OrgName = strings.TrimSpace(e.OrgName)
	if len(e.OrgName) > 120 {
		e.OrgName = e.OrgName[:120]
	}
}

type Firewall struct {
	Name string `json:"name"`
	IP   string `json:"ip"`
}

type AIRule struct {
	Tool     string   `json:"tool"`
	Patterns []string `json:"patterns"`
}

type NPSConfig struct {
	Enabled       bool     `json:"enabled"`
	Paths         []string `json:"paths"`          // folders (IN*.log is read), files or globs; UNC paths work if the service account can read them
	PollSeconds   int      `json:"poll_seconds"`   // how often the files are checked
	IdleHours     int      `json:"idle_hours"`     // a session with no new NPS record ends this long after it was last seen
	BackfillHours int      `json:"backfill_hours"` // on first start, records older than this are skipped
	StripDomain   bool     `json:"strip_domain"`   // CORP\alice -> alice, alice@corp.local -> alice
	Lowercase     bool     `json:"lowercase"`
	LearnFromMAC  bool     `json:"learn_from_mac"` // when NPS has no Framed-IP, use FortiGate srcmac to find the IP
}

type DatabaseConfig struct {
	Host           string `json:"host"`
	Port           int    `json:"port"`
	Name           string `json:"name"`
	User           string `json:"user"`
	Password       string `json:"password,omitempty"`
	SSLMode        string `json:"ssl_mode"`
	MaxConnections int32  `json:"max_connections"`
}

func defaultAIRules() []AIRule {
	r := func(tool string, p ...string) AIRule { return AIRule{Tool: tool, Patterns: p} }
	return []AIRule{
		r("ChatGPT", "chatgpt", "openai", "oaiusercontent.com", "oaistatic.com", "sora.com"),
		r("Claude", "claude", "anthropic"),
		r("Gemini", "gemini", "bard.google.com", "aistudio.google.com", "notebooklm"),
		r("GitHub Copilot", "githubcopilot", "copilot-proxy", "github.copilot"),
		r("Microsoft Copilot", "copilot", "sydney.bing.com"),
		r("Perplexity", "perplexity"),
		r("DeepSeek", "deepseek"),
		r("Grok", "grok", "*.x.ai"),
		r("Meta AI", "meta.ai"),
		r("Mistral", "mistral.ai", "mistral"),
		r("Poe", "poe.com"),
		r("Character.AI", "character.ai"),
		r("Hugging Face", "huggingface"),
		r("Midjourney", "midjourney"),
		r("QuillBot", "quillbot"),
		// v5.10 additions (Settings > AI detection > "Add missing built-in tools" adds them to an existing setup)
		r("Qwen", "qwen", "tongyi.aliyun", "chat.qwen.ai"),
		r("Kimi", "kimi.moonshot", "kimi.com", "moonshot.cn"),
		r("Manus", "manus.im"),
		r("Groq", "groq.com"),
		r("Phind", "phind"),
		r("Cursor", "cursor.sh", "cursor.com", "cursor-cdn"),
		r("Codeium / Windsurf", "codeium", "windsurf.com"),
		r("Replit AI", "replit"),
		r("Lovable", "lovable.dev"),
		r("Jasper", "jasper.ai"),
		r("Writesonic", "writesonic"),
		r("ElevenLabs", "elevenlabs"),
		r("Suno", "suno.com", "suno.ai"),
		r("Runway", "runwayml"),
		r("Leonardo.ai", "leonardo.ai"),
		r("Ideogram", "ideogram"),
		r("Stability AI", "stability.ai", "dreamstudio"),
		r("OpenRouter", "openrouter"),
	}
}

func defaultConfig(base string) Config {
	return Config{ListenAddress: ":6514", TCPEnabled: true, UDPEnabled: false, MaxMessageBytes: 1 << 20,
		QueueCapacity: 200000, BatchSize: 1000, BatchIntervalMS: 1000, RetentionDays: 30,
		SpoolDirectory: filepath.Join(base, "spool"), SpoolMaxMB: 10240, WebListenAddress: "127.0.0.1:8080",
		Database:     DatabaseConfig{Host: "127.0.0.1", Port: 5432, Name: "logsikka", User: "logsikka", SSLMode: "disable", MaxConnections: 10},
		AICategories: []string{"Artificial Intelligence Technology", "GenAI"},
		AIRules:      defaultAIRules(),
		NPS: NPSConfig{Enabled: false, Paths: []string{`C:\Windows\System32\LogFiles`}, PollSeconds: 5, IdleHours: 10,
			BackfillHours: 24, StripDomain: true, Lowercase: true, LearnFromMAC: true},
		WebTLS: true, SessionHours: 12, QueryConcurrency: 6, CompressAfterDays: 2,
		Directory: DirectoryConfig{PollMinutes: 5, NormalizeUsers: true, DropUnverified: true},
		Alerts:    AlertConfig{Enabled: true},
		Blocklist: BlocklistConfig{DefaultDays: 30},
	}
}

type ConfigStore struct {
	mu     sync.RWMutex
	saveMu sync.Mutex // v6.0.13: one save at a time (see configrev.go)
	path   string
	cfg    Config
}

func LoadConfig(path string) (*ConfigStore, error) {
	base := filepath.Dir(path)
	c := defaultConfig(base)
	b, err := os.ReadFile(path)
	if err == nil {
		if err = json.Unmarshal(b, &c); err != nil {
			return nil, err
		}
		_ = c.validate() // fills in settings added by newer versions
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	s := &ConfigStore{path: path, cfg: c}
	if errors.Is(err, os.ErrNotExist) {
		if err = s.Save(c); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func (s *ConfigStore) Get() Config { s.mu.RLock(); defer s.mu.RUnlock(); return s.cfg }

func (c *Config) validate() error {
	if c.ListenAddress == "" || c.WebListenAddress == "" || c.QueueCapacity < 100 || c.BatchSize < 1 || c.RetentionDays < 1 {
		return errors.New("invalid configuration")
	}
	seen := map[string]bool{}
	for i := range c.Firewalls {
		f := &c.Firewalls[i]
		f.Name, f.IP = strings.TrimSpace(f.Name), strings.TrimSpace(f.IP)
		a, err := netip.ParseAddr(f.IP)
		if err != nil {
			return errors.New("firewall " + f.Name + ": enter the IP address the logs come from")
		}
		f.IP = a.Unmap().String()
		if f.Name == "" {
			f.Name = f.IP
		}
		if seen[f.IP] {
			return errors.New("firewall IP " + f.IP + " is listed twice")
		}
		seen[f.IP] = true
	}
	for _, r := range c.AIRules {
		if strings.TrimSpace(r.Tool) == "" || len(r.Patterns) == 0 {
			return errors.New("every AI rule needs a tool name and at least one pattern")
		}
	}
	if c.NPS.PollSeconds < 1 {
		c.NPS.PollSeconds = 5
	}
	if c.NPS.IdleHours < 1 {
		c.NPS.IdleHours = 10
	}
	if c.NPS.BackfillHours < 0 {
		c.NPS.BackfillHours = 0
	}
	if c.SessionHours < 1 {
		c.SessionHours = 12
	}
	if c.SessionHours > 24*90 {
		c.SessionHours = 24 * 90
	}
	if c.QueryConcurrency < 1 || c.QueryConcurrency > 32 {
		c.QueryConcurrency = 6
	}
	c.Exec.defaults()
	if _, err := parseExcl(c.Exec); err != nil {
		return err
	}
	if err := validNets(c.InternalNetworks); err != nil {
		return err
	}
	if err := validNets(c.InfraNetworks); err != nil {
		return errors.New("infrastructure " + err.Error())
	}
	if err := validTunnels(c.TunnelInterfaces); err != nil {
		return err
	}
	if err := c.WAN.validate(); err != nil {
		return err
	}
	if err := c.Blocklist.validate(); err != nil {
		return err
	}
	if err := validSites(c.Sites); err != nil {
		return err
	}
	c.Alerts.defaults()
	if c.Directory.PollMinutes < 1 || c.Directory.PollMinutes > 1440 {
		c.Directory.PollMinutes = 5
	}
	c.Directory.Path = strings.TrimSpace(c.Directory.Path)
	if c.CompressAfterDays < 1 || c.CompressAfterDays > 365 {
		c.CompressAfterDays = 2
	}
	if c.Database.MaxConnections < int32(c.QueryConcurrency)+4 {
		c.Database.MaxConnections = int32(c.QueryConcurrency) + 4 // writer, NPS, rollups and status need their own
	}
	return nil
}

// saveLocked writes and publishes c. The caller holds saveMu (Save / Update in configrev.go).
func (s *ConfigStore) saveLocked(c Config) error {
	if err := c.validate(); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0750); err != nil {
		return err
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err = os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	if err = os.Rename(tmp, s.path); err != nil {
		return err
	}
	s.mu.Lock()
	s.cfg = c
	s.mu.Unlock()
	onConfigChanged(c)
	return nil
}

// onConfigChanged pushes the settings that apply live (firewall names, AI rules, NPS name handling).
func onConfigChanged(c Config) {
	setFirewalls(c.Firewalls)
	normalizeUsers.Store(c.Directory.NormalizeUsers)
	dropUnverified.Store(c.Directory.DropUnverified && c.Directory.Enabled)
	setLocalNets(c.InternalNetworks)
	setInfra(c.InfraNetworks, c.TunnelInterfaces)
	setSites(c.Sites)
	wanKeep.Store(int32(c.WAN.KeepDays))
	if e, err := parseExcl(c.Exec); err == nil {
		exclCur.Store(e)
	} else {
		log.Printf("executive summary exclusions ignored: %v", err)
		exclCur.Store(&execExcl{})
	}
	setAIRules(c.AICategories, c.AIRules)
	if c.QueryConcurrency > 0 {
		queryConcurrency.Store(int32(c.QueryConcurrency))
	}
	if c.CompressAfterDays > 0 {
		compressAfterDays.Store(int32(c.CompressAfterDays))
	}
	if c.SessionHours > 0 {
		sessionHours.Store(int32(c.SessionHours))
	}
}

// settings read by code that has no Config at hand (database open, session creation)
var queryConcurrency, compressAfterDays, sessionHours atomic.Int32
var normalizeUsers, dropUnverified atomic.Bool
