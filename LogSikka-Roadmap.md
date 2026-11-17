# LogSikka Roadmap

| | |
|---|---|
| Document version | 2.0 |
| Date | 29 Oct 2026 |
| Current release | v6.0.1 |
| Next release | v6.0.2 (hardening, section 10) |
| Next major line | v6.x (phases A–E) and v7.0 (phase F) |
| Owner | IT Security (Network & Information Security) |

LogSikka is the new name of FortiLog (since v6.0). Keep this file in the repository root next to `CHANGES.md`. Update
the **status** column of the phase tables and the **decision log** with every release. Completed items are removed from
the plan and recorded in the release history (section 14).

**Changes in this version:** items finished in v6.0 / v6.0.1 removed; hardening release and review findings added
(section 10); phases renumbered by one version (hardening takes v6.0.2); risks, inputs and decisions updated.

---

## 1. Goal

LogSikka becomes a **self-hosted network and security log tool for FortiGate-based organisations** (roughly 100–5,000
staff, several sites). It collects FortiGate syslog and SNMP, uses NPS / AD for user identity, and later Cisco syslog.
It must stay simple to run, work offline, and be usable by other organisations with similar environments without code
changes.

### Principles

1. **No organisation-specific code.** Sites, VLANs, firewalls and naming are configuration, set through a setup wizard.
2. **Tags, not typing.** Everything is labelled once, mostly automatically. Dashboards, filters, reports and settings
   work by clicking.
3. **Pre-computed figures.** Dashboards read summaries, never raw logs.
4. **Rule-based and explainable.** Every classification can say which rule or log field decided it. No AI/ML models in
   the processing path (see decision D-03).
5. **Never block the pipeline.** Log intake keeps running whatever else is slow or failing (spool, non-blocking upgrades).
6. **One package per platform**, offline-capable (.deb / .rpm / Docker).
7. **Trust nothing on the wire.** Syslog senders and SNMP responses are authenticated, input sizes are bounded, and
   every configuration change is recorded. (New, from the v6.0.1 review.)

---

## 2. Where we are (v6.0.1)

| Area | State |
|---|---|
| Collection | FortiGate syslog (UDP/TCP), spool on disk, PostgreSQL / TimescaleDB, compression and retention |
| Identity | Firewall users (FSSO), NPS (wireless), manual and permanent assignments, staff list from AD export |
| Network model | Sites with firewalls and zones (subnet, VLAN, type); tags for site, zone, zone type, department, role, former staff; site / zone filters on dashboards |
| Dashboards | All logs, AI overview / policy / investigation, Devices & people, User mapping, Alerts, WAN links, Sites, Reports, Log explorer, Advanced |
| Reports | Executive summary (incl. Internet circuits), AI usage report, report builder |
| Alerts | Sign-in attacks, out-of-hours changes, silent firewalls, blocked bursts, large uploads, unknown devices, WAN (capacity, SD-WAN, tunnels, firewall load, SNMP) |
| WAN | SNMPv3 polling of interface counters, FortiGate MIB (CPU, memory, sessions, SD-WAN health, IPsec), history, data used |
| Blocklist | Threat feed for FortiGates from alerts, safety rules, hit counts, repeat attackers |
| Settings | Each section saved on its own, with a per-section change history |
| System health | Host and pipeline figures per minute for 24 hours (in memory, Linux host figures) |
| Tests | 70 test functions; coverage 21.5% (main), 16.4% (`snmp`), 79.8% (`ber`) |

### Known limits that drive this roadmap

- **Security gaps found in the v6.0.1 review** (section 10, hardening): the syslog allow-list does not restrict by
  default, SNMPv3 accepts unauthenticated responses, the TCP syslog read is unbounded, WAN polling ignores HA failover.
- Filtering and settings still need typed IPs, names and subnets (tags exist for sites and zones only).
- Application detection relies mostly on application control and the FortiGuard AI category; web filter, DNS filter and
  traffic logs are hard to classify.
- Dashboard highlights are counts, not statements you can act on.
- The web front-end is plain JavaScript in 13 incremental files (v516.js … v600.js).
- Everything is tested on plain PostgreSQL only, not on TimescaleDB.
- Server health is limited to 24 hours in memory, with no disk, table size or forecast figures.

---

## 3. Architecture

### Components and languages

| Component | Language | Notes |
|---|---|---|
| Web API, auth, rules, alerts, reports, SNMP, NPS / AD | **Go** (keep) | Fast, single binary; a rewrite gives nothing measurable. Raise `go.mod` from 1.22 to a supported release |
| Ingestion: receive → parse → enrich / tag → batch | **Go**, isolated module | Only CPU-bound hot path. Fixed interface; benchmarked. Ported to Rust **only** if Go misses the target (D-04) |
| Edge forwarder for branches / other organisations | **Rust** (phase E) | Small agent: buffer when the link is down, compress, encrypt, forward |
| Storage | PostgreSQL + TimescaleDB | Continuous aggregates for the sums and counts; see the aggregate prototype in phase A |
| Very large sites | ClickHouse back-end (optional, later) | Only above ~50 M logs/day; same query interface |
| Front-end | **TypeScript + Svelte**, compiled and embedded in the Go binary | Typed components, one chart library, tag chips, pickers, skeleton loaders. Node.js needed on the build PC only. Pin npm versions, audit in CI |
| Rules | **CEL** (`cel-go`) | Tag rules, evidence weights and alert conditions. Compile at config time; common shapes (CIDR, domain, user) go to the radix / label indexes, CEL only for the rest |

### Performance targets

| Metric | Target |
|---|---|
| Sustained intake | 5–10× current peak (current ≈ 460 logs/s) on the existing Ubuntu server |
| Intake lag (log time → stored) | < 10 s at 1× peak |
| Dashboard query, 30 days, any tag filter | < 1 s from summaries |
| Database upgrade on start | Never blocks intake (in place since v5.14.1) |
| Rule evaluation | Compiled once; no per-log allocations in the hot path |
| Background history work | Always makes progress (guaranteed budget), without slowing dashboards |

Benchmark first: `accept()` currently parses a message twice when subtype filtering is on, and allocates a copy per
message. Fix these before any language decision.

---

## 4. Tag engine (core of v6): what is left

Delivered in v6.0: site, zone, zone type, department, role and former-staff tags, worked out in memory; site / zone
filters; Sites page. What remains:

### Still to tag

Destinations, applications, firewalls, circuits, alerts and every log (as a compact list of tag IDs).

| Group | Filled from | Examples |
|---|---|---|
| Destination | Application engine (section 5), country | `app:ChatGPT`, `cat:AI`, `cat:cloud-storage`, `geo:foreign` |
| Security | Risk, IPS, blocklist, alerts | `risk:high`, `blocked`, `attacker`, `repeat-attacker` |
| Custom | Admin rules (CEL): subnet, host, user, app, destination | `project:SAP`, `vendor-access` |
| Device role (more) | FortiGate device detection | `role:laptop`, `role:unknown` |
| VIP | Staff list | `vip` |

### Design decisions still open

- **Where tags live.** v6.0 computes tags in memory at query time (D-08). That makes site / zone edits apply to history
  at once, but it also means past reports change when a zone changes, and tag filters cannot yet use the database
  summaries. Decide per tag type:
  - stable dimensions (site, zone) as small integer columns in the summaries;
  - slowly changing tags (department, role) in dimension tables with validity intervals, joined when summaries are built
    (history stays accurate, no UPDATE on compressed chunks);
  - avoid a GIN-indexed tag array on the raw log table at current volumes.
- **Overlapping private ranges.** Sites reject the same subnet at two sites, and NPS sessions / assignments are keyed by
  IP alone. Key identity by site (firewall or NAS) so two branches using the same range do not collide.
- **Re-tagging.** Changing a rule re-tags summaries in the background; raw logs are not rewritten once compressed.
- **Tag filters on every chart**, with tag summaries in the database.

---

## 5. Application identification (rule-based)

One engine for all applications; AI is one category. Every session gets an **app**, a **category**, a **confidence**,
the **evidence** that decided it, and an **activity level**.

### Evidence and confidence (default weights; editable as CEL rules)

| Evidence | Confidence |
|---|---|
| Application control `appid` | 0.95 |
| Traffic log `app` field | 0.90 |
| Exact hostname / SNI in the catalogue | 0.90 |
| Hostname learned from application control | 0.85 |
| Wildcard domain in the catalogue | 0.80 |
| Destination IP linked to a domain by a recent DNS answer | 0.60 |
| Vendor IP range (Microsoft 365, Google, Zoom, AWS, Cloudflare) | 0.40 (vendor only) |
| DNS lookup with no traffic | 0.30 ("looked up", not "used") |
| Port / service only | 0.20 (generic) |

Logs of the same session are merged by **`devid` + `vdom` + `sessionid`** inside a time window (`sessionid` repeats and is
only unique per device; after an HA failover each member has its own counters). The strongest evidence wins.

### Matching rules (fixes the current AI false positives)

- Hostnames match as **exact or domain suffix** (`host == d` or ends with `.d`), never "contains". Application names may
  still use contains.
- Registrable domains come from the **Public Suffix List**, not a length heuristic (today `api.x.ai` is not grouped
  under `x.ai`).
- Known collisions to test: `gemini` (the crypto exchange), `copilot`, `poe.com`, `kimi`, `cursor.com`, `mistral`,
  `grok`, `replit`, `phind`.

### Activity level

- **Used:** sessions with real data (default in dashboards).
- **Background:** periodic, small, telemetry / update-like.
- **Looked up:** DNS only.

### Learning from application control

When an application control log names the app and the same session has a hostname or SNI, LogSikka records
"hostname → app". After enough consistent observations it becomes a **learned mapping**, applied to web filter, DNS and
traffic logs from policies without application control. Learned mappings are a separate, reviewable layer. Guard
against poisoning: require a minimum number of distinct clients and a consistency ratio, and never learn infrastructure
domains.

### DNS → traffic linking

- DNS filter answers fill a bounded, TTL-based table of IP → domain; traffic logs with only `dstip` get the domain.
- IPs shared by unrelated domains (CDNs) are marked ambiguous and never decide an app alone.
- In this environment DNS filter logs show the domain controllers as the source, so the table is shared, not
  per client. Optional: read the Windows DNS server analytical log from the DCs (like NPS) for per-client lookups.

### App catalogue

- Entry: app, vendor, category, risk, data-handling note, exact / suffix domains, SNI patterns, FortiGuard `appid`s,
  vendor IP ranges.
- Seeded from free sources (check licences before any outside release):

| Source | Use | Licence |
|---|---|---|
| nDPI host lists (ntop) | Hostname → application seed list | LGPL (credit required) |
| Public Suffix List | Registrable-domain grouping | MPL 2.0 |
| Vendor endpoint lists (Microsoft 365, Google, Zoom, AWS, Cloudflare) | Vendor domains and IP ranges | Published by vendors |
| Tranco top-sites list | Ranking unknown domains in the review queue | Free, research use; check terms |

- Shared infrastructure domains (`cloudfront.net`, `akamaiedge.net`, `azureedge.net`, `googleusercontent.com`,
  `amazonaws.com` …) are flagged **infrastructure** and never identify an app by domain alone.
- One category tree maps FortiGuard app and web categories: AI, Collaboration & meetings, File storage & transfer,
  Social, Streaming, Remote access, Developer, Business SaaS, Updates & telemetry, Infrastructure, Other.
- Versioned pack, updated from a URL or an offline file; local additions live in a separate layer that updates never
  overwrite.

### Discovery and review

- Unidentified registrable domains ranked by people, data and days seen, with the FortiGuard category as a hint.
- Grouping suggestions for domains reached together by the same clients.
- One click: new app, add to an existing app, or mark infrastructure / background. Approval re-labels past data.

### Coverage page

Share of data and sessions identified, by firewall, policy and log type, with the setting that would help most
(e.g. "Policy 12 has no application control profile: 38% of unidentified data"). Also state what the firewall can and
cannot see (QUIC, ECH, no SSL inspection fall back to the FortiGuard category).

### Recommended FortiGate settings (no blocking needed)

1. Application control profile (monitor) on every internet policy.
2. Certificate inspection for SNI on HTTPS.
3. DNS filter (monitor) on the DC → internet DNS path.
4. Log all sessions on internet policies.

---

## 6. User experience: what is left

Delivered in v6.0: thin loading bar at the top; page title shows its menu group.

### Navigation

- Five grouped menus: **Monitor** (Overview, All logs, Alerts, WAN links, Sites), **AI & Apps**, **People**,
  **Analyse** (Reports, Log explorer, Advanced), **System** (Settings, Server health); breadcrumb on every page.
- Command palette (Ctrl+K): jump to a firewall, tunnel, IP, user, app or setting.
- Remembered state per user: last page, period, folded sections.

### Overview (new start page)

- Per-site health strip: circuit load, link quality, tunnels, alerts, blocked attacks (green / amber / red).
- "What changed" statements, e.g. "Finance uploads to AI tools +240% vs last week (3 people)".
- Top 3 items to act on, each with an action button (assign device, add to blocklist, open logs).
- Status cards (collection, firewalls, WAN, alerts, applications, blocklist) linking to the detail pages.
- Wall-screen mode: full screen, large numbers, cycles Overview → WAN → Alerts. Must not starve background work (see
  section 10, H10).

### Click-based filtering

- Tag chips: click to include, Shift+click to exclude; chart items add chips.
- Pickers with counts from your own data; free text only as a fallback.
- Saved views: pin to the Overview, or turn into a report.

### Cards and states

- Every card: title, one-line explanation, ⓘ "how this is calculated", ⋯ menu (full screen, CSV / PNG, open in Log explorer).
- Empty / error states say what is missing and link to the setting that fixes it.

### Loading feedback

- Skeleton placeholders, spinners on the clicked button.
- Charts dim and keep their place while a new period loads.
- Job tray with progress and time left for long tasks; toasts with Undo after deletions.

### Visual system

- One bundled sans-serif font with tabular figures; serif only in printed reports.
- Type scale 12 / 13 / 14 / 16 / 20 / 28 px; spacing in multiples of 4; one radius and shadow style.
- Colours by meaning (ok, warning, critical, info, neutral) across all themes; contrast checked in dark mode and print.
- Add a Content-Security-Policy header once inline handlers are gone (Svelte shell).

---

## 7. Settings (refactor): what is left

Delivered in v6.0: separate save API per section; change history per section (fix in H7).

| Group | Sections |
|---|---|
| Sources | Syslog, firewalls, NPS, staff list, WAN / SNMP |
| Network model | Sites, internal networks, network devices, tunnels |
| Detection | Application rules and catalogue, alerts, blocklist, exclusions |
| Reports | Executive and AI report settings, logo |
| System | Database, storage and retention, dashboard access and certificate, accounts, appearance, server health |

- Row editors instead of text boxes (one row per subnet / entry, with name, tag, colour, validation); done for sites
  and zones only.
- Pickers from data: firewalls in the logs, interfaces found over SNMP, staff, apps and categories seen.
- Toggles and sliders for limits, with defaults shown and Reset to default per section.
- Test buttons next to every external dependency (database, NPS share, staff file, SNMP per firewall, feed URL).
- Config export / import as JSON without secrets.
- Validate listener, TLS-path and database settings before saving, with apply-and-confirm so an admin cannot lock
  themselves out after a restart.

---

## 8. Server health (System › Server health): what is left

Delivered in v6.0: CPU, I/O wait, load, memory, swap, logs received and written per second, queue, spool, write time per
batch, newest log age, cache hit ratio, connections; 24 hours, in memory, Linux only.

| Group | Still to add |
|---|---|
| Ingestion | 1 h / 24 h peak, dropped / rejected, parse errors, refused senders |
| Database | Write latency p50 / p95, slowest queries, table / index sizes, compression ratio, growth per day |
| Host | Disk use and I/O wait (data and PostgreSQL disks), network on the syslog port; Windows equivalents |
| Service | Go goroutines, last restart, background jobs and their waiting / failed hours, WAN poll timing per firewall |
| History | Persist the series (7-day charts survive a restart) |
| Forecast | Disk full in N days (7-day growth), retention fit; warnings become alerts |
| Liveness | Unauthenticated minimal `/healthz` (or Prometheus metrics) so an external monitor can tell when LogSikka itself is down |

Sources: `/proc`, PostgreSQL statistics views, LogSikka's own counters.

---

## 9. Ready for other organisations

- Setup wizard: database → sites and subnets → firewalls (detects syslog, checks SNMP) → identity (optional) → app
  policy → admin account.
- Packages: .deb, .rpm, Docker; systemd hardening; non-blocking database upgrades.
- Roles: Viewer / Analyst / Admin plus **site-scoped access**, enforced in one central query layer that every endpoint
  (report builder, CSV export, raw log explorer, feeds) passes through; optional SSO via Microsoft Entra ID / LDAP;
  MFA for admins.
- Security: TLS syslog (FortiOS reliable mode with encryption), secrets at rest (no plaintext SNMP / database
  passphrases in `config.json`; DPAPI or environment-supplied), API tokens for wall screens.
- Parsers: FortiGate first, then Cisco IOS / C9800 and generic syslog, behind one parser interface.
- Data protection: retention per tag (e.g. security 1 year, traffic 30 days); optional pseudonymised usernames in
  reports; **audit of who viewed person-level pages** (AI usage by person), with a role gate.
- Tools: a log **anonymiser** (consistent hashing of IPs, users, hostnames) for CI replay and for bug reports from other
  organisations; backup / restore of configuration and database; upgrade and migration tests.
- Docs: admin guide, FortiGate setup checklist, upgrade notes. Licence decided before any outside release (TimescaleDB
  compression and continuous aggregates are under the Timescale License, not Apache; check packaging and redistribution).

---

## 10. Phases

Versions are shifted by one against the previous roadmap: the hardening release takes v6.0.2.

| Phase | Version | Content | Outcome | Status |
|---|---|---|---|---|
| **H. Hardening** | v6.0.2 | Items H1–H13 below | Proven gaps closed, regression tests in place | **Next** |
| **A. Foundations (remaining)** | v6.1 | TimescaleDB CI with replayed (anonymised) real logs; continuous-aggregate prototype for one real dashboard ("AI uploads by department, 30 days"); tag summaries in the database and tag filters on every chart; identity keyed by site; Svelte / TypeScript front-end shell (last, may run in parallel on its own branch) | Same features, clean base, faster | Planned |
| **B. Tags everywhere** | v6.2 | Tag chips, pickers, saved views, tag-scoped reports, custom tag rules (CEL), re-tagging history | No more typing to filter | Planned |
| **C1. App identification: rules** | v6.3 | Evidence engine, category tree, app catalogue and updates, activity levels, DNS → traffic linking, coverage page; AI becomes a category | Wide app coverage, explainable | Planned |
| **C2. App identification: learning** | v6.4 | Learning from application control, discovery with grouping, review queue, re-labelling history, optional Windows DNS log collection | New apps found without manual lists | Planned |
| **D. Insight** | v6.5 | Overview page, what-changed, top actions, rest of server health (section 8), forecasts, normal-range bands; notifications slot in here when released from hold | Highlights worth reading | Planned |
| **E. Performance and edge** | v6.6 | Ingestion benchmark harness and load test; Rust parser only if Go misses the target; Rust edge forwarder | Proven headroom, branch agent | Planned |
| **F. Productise** | v7.0 | Setup wizard, packages, SSO, site-scoped access, TLS syslog, secrets at rest, more parsers, documentation | Usable by other organisations | Planned |

### Phase H detail (v6.0.2)

Each item was found in the v6.0.1 review. Items marked **proven** were reproduced with a test.

| ID | Item | Evidence | Priority |
|---|---|---|---|
| H1 | **Syslog allow-list.** When firewalls are listed, accept only those IPs (plus any extra allowed sources, with CIDR support). List both members of each HA pair. Fix the README, which says other senders are refused | **Proven:** with two firewalls listed, a random host was accepted | High |
| H2 | **Bound the TCP read.** Limit line length before it is buffered (both the newline path and the octet-count prefix); cap concurrent connections and per-connection idle time | **Proven:** 300 MiB without a newline allocated 609 MiB (limit was 64 KiB) | High |
| H3 | **SNMPv3 response authentication.** After discovery, require the auth flag (and privacy flag for authPriv) and a valid digest on every non-Report response; use `hmac.Equal`; check auth-parameter length; check the response engine boots / time window | **Proven:** a forged unauthenticated response was accepted by an authPriv client | High |
| H4 | **HA-aware WAN polling.** Key the counter baseline by SNMP engine ID (and reset when `sysUpTime` goes down); optionally poll each HA member separately through the management interface | Code: `EngineID()` unused; `wan.go` unchanged | High (3 HA sites) |
| H5 | **Exact WAN volumes.** Store counter deltas (bytes in / out and interval seconds) and the measurement time per sample; label "peak" as the highest 30-second average | Code: volume = rate × gap, gap capped at 3 polls | Medium |
| H6 | **AI matching and domain grouping.** Suffix matching for hostnames; Public Suffix List for registrable domains; tests for the collision list in section 5 | **Proven:** `api.x.ai`, `chat.x.ai`, `foo.bar.io` each become their own root | Medium |
| H7 | **Audit and settings.** Element-wise diff for arrays (today an edit that keeps the item count is logged as "no change"); record "secret changed" without the value; reject unknown fields in a section save; compare-and-swap on a configuration revision; validate listener / TLS / database before saving | **Proven:** changing a zone's subnet produced an empty audit diff | Medium |
| H8 | **Accounts.** Enforce "must change password" on the server (allow only `/api/password`); delete `initial-admin-password.txt` after the first change; lock out per username as well as per IP, or honour a trusted `X-Forwarded-For`; remove the stale `admin_token` text from the README | Code review | Medium |
| H9 | **Blocklist feed.** Optionally restrict the feed to the firewalls' source IPs; rate-limit it; default never-block list (public DNS, ISP gateways, big cloud ranges); confirmation when an analyst blocks a public address | Code review | Low |
| H10 | **Background work cannot starve.** The v6.0.1 rule (history work waits 20 s after any dashboard query) can stop summaries, exclusions and back-fills forever when a screen auto-refreshes. Give background work a guaranteed budget, or lower its concurrency and statement timeout instead of pausing it; show waiting hours on System health | Design review of v6.0.1 | Medium |
| H11 | **Sites model polish.** Reject a firewall listed under two sites; a site with firewalls but no zones should still filter (by firewall) instead of a 404; IPv6 in the "not in a zone" suggestions | Code review | Low |
| H12 | **Tests and build.** Turn every proven item into a regression test; fuzz tests for `parseMessage` and `parseKV` (first runs found no panics); mock SNMP agent covering MD5 / SHA1 / SHA256 / SHA512 with AES128 / AES256; HTTP tests for login, lockout, roles and must-change; raise `go.mod` to a supported Go release; add `govulncheck` and `go vet` to CI; target coverage above 50% for `snmp` and the auth / receiver code | Coverage 21.5% / 16.4% | Medium |
| H13 | **Parse once.** `accept()` parses every message twice when subtype filtering is on; parse once and reuse (also the first step of the ingestion benchmark) | Code review | Low |

Out of scope for v6.0.2 (kept in phase F): TLS syslog, secrets at rest, MFA, CSP header.

Bug fixes and small items continue as v6.0.x until v6.1 is released.

---

## 11. Risks

| Risk | Mitigation |
|---|---|
| Large refactor breaks working features | Ship per phase; keep data; old UI reachable until the new one has every feature; Svelte shell last in phase A |
| TimescaleDB behaves differently from plain PostgreSQL | CI against TimescaleDB with replayed (anonymised) samples from each firewall |
| Continuous aggregates cannot express top-N, distinct counts or percentiles natively | Prototype one real dashboard first; may need `timescaledb_toolkit` (extra extension) or keep custom rollups for those |
| Timescale License limits redistribution | Decide licence and packaging (official images) before phase F |
| Retroactive tags change past reports | Decide per tag type (section 4); validity intervals for slowly changing tags |
| Wrong application labels | Confidence and evidence stored per session; learned mappings and discoveries reviewed before use; supplier-CDN guard rules |
| Forged logs or SNMP data feed reports and the blocklist | Phase H (H1, H3); TLS syslog in phase F |
| Hand-written SNMPv3 stack only tested against RFC vectors | Mock agent plus tests against net-snmp (`snmpget`); H3 and H12 |
| Wall screens starve background history work | H10 |
| CEL too slow in the hot path | Pre-index common rules; benchmark in phase E before the engine ships |
| Rust adds maintenance | Limited to the edge forwarder and (only if needed) the parser, behind fixed interfaces |
| Catalogue licences | Credit nDPI (LGPL); check each source before outside release |
| Person-level AI usage is sensitive | Role gate, audit of views, pseudonymised reports (section 9) |
| Scope creep | This file is the single plan; anything new is added to section 13 first |

---

## 12. Inputs needed

| # | Item | Needed for | Status |
|---|---|---|---|
| 1 | Enter the real sites on **Monitor › Sites**: site → firewall → main subnets / VLANs; note any sites that reuse the same private range | Phase A (identity per site), tag tests | Open |
| 2 | Raw log samples per firewall (~10 MB / day each; app-ctrl, webfilter, dns, traffic), **after** the anonymiser exists | Phase A CI replay; C1 coverage | Open |
| 3 | Confirm the front-end switch to Svelte / TypeScript (Node.js on build PC only); v6.0.x stayed on plain JavaScript | Phase A (Svelte shell) | Open |
| 4 | Application control coverage per policy; certificate inspection; DNS filter on the DC → internet path | Phase C1 | Open |
| 5 | HA layout per site (poll the cluster address or each member?), FortiOS version, and which SNMPv3 auth / privacy protocols the FortiGates use | H3, H4, H12 test matrix | Open |
| 6 | Firewall source addresses per HA member (needed to switch the allow-list on without losing logs) | H1 | Open |

---

## 13. Backlog (not yet scheduled)

- Notifications: email (SMTP relay) and Teams webhook for High alerts; scheduled executive report — **on hold**.
- Cisco syslog (switches, C9800 WLC): port flapping, config changes, failed logins, rogue APs.
- Month-on-month trends (needs 60+ days retention and disk planning).
- Sigma rule import for FortiGate log sources (phase D candidate).
- ClickHouse back-end for very large deployments.
- Windows build parity for server health host figures.

---

## 14. Decision log

| ID | Date | Decision | Reason |
|---|---|---|---|
| D-01 | 27 Oct 2026 | LogSikka (then FortiLog) runs on Ubuntu (Linux build is the complete build) | Production host |
| D-02 | 28 Oct 2026 | Plan for use by other organisations; no organisation-specific code | Reuse beyond one company |
| D-03 | 28 Oct 2026 | **Rule-based classification only.** No decision / ML models (e.g. Jev or open "System One" models) for now | Resource use on the Ubuntu server; explainability; no data leaving the network. May be revisited later as an optional, separate component |
| D-04 | 28 Oct 2026 | Keep Go; Rust only for the edge forwarder and, if benchmarks require it, the parser | Biggest gains come from database design and summaries, not language |
| D-05 | 28 Oct 2026 | CEL as the rule language for tags, evidence weights and alert conditions | Free, fast, sandboxed, readable |
| D-06 | 28 Oct 2026 | Application identification covers all applications; AI is one category | Web filter / DNS / traffic logs need the same engine |
| D-07 | 27 Oct 2026 | Notifications on hold | Owner decision |
| D-08 | 29 Oct 2026 | Tags are worked out in memory at query time, with no tag column in the log table (recorded from the v6.0 release; implications in section 4) | Edits to sites apply to history at once; no rewrite of compressed chunks. Cost: past reports follow the current site model |
| D-09 | 29 Oct 2026 | **Proposed:** a hardening release (v6.0.2) goes before the remaining phase A work | Four proven gaps affect forged data and availability; phase F makes them worse. Owner to confirm |
| D-10 | 29 Oct 2026 | **Proposed:** the Svelte shell moves to the end of phase A (or a parallel branch) | It adds no capability by itself; the settings API, Sites and CI reduce risk first. Owner to confirm |

---

## 15. Release history (summary)

| Version | Highlights |
|---|---|
| v5.10–v5.12 | Executive summary, exclusions, traffic directions, data volumes per session |
| v5.13 | Staff directory, Devices & people, permanent assignments, first alerts |
| v5.14 / v5.14.1 | Firewall on every alert, one alert per attacker; non-blocking database upgrade |
| v5.15 | Alert sorting / grouping by firewall, readable log detail, report settings in Customise |
| v5.16 | Endpoint point of view, Advanced tab, site-to-site de-duplication, WAN links (SNMPv3), AI usage report, server health basics, certificate requests |
| v5.17 | Themes, organised dashboards, settings cards, WAN charts and data used |
| v5.18 / v5.18.1 | Slim header, one settings section at a time, WAN diagnostics; WAN query fix |
| v5.19 | WAN passphrases no longer block saving; FortiGate MIB (CPU, memory, SD-WAN, IPsec) |
| v5.20 / v5.20.1 | Settings save no longer wipes passphrases; blocklist threat feed; frozen menu; parallel WAN polling, "same SNMPv3 user as" |
| v5.21 | WAN health history, WAN alerts, Internet circuits report section, blocklist hit counts and repeat attackers |
| v6.0 | **FortiLog is now LogSikka** (service, paths, user, cookie and header aliases; one-time migration in `install.sh`); Sites and tags (Monitor › Sites, site / zone filters, tags in log detail); each settings section saved on its own with a Changes history; server performance on System health (24 h, in memory); new icon, logo, loading bar |
| v6.0.1 | Dashboards faster: history work waits for dashboard queries; one stuck exclusions hour no longer blocks the rest; subnet filters use the address index (address ranges); one extra worker per dashboard query; AI tabs say when the summary is too slow instead of reading raw logs |
