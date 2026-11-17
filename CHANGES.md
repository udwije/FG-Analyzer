### LogSikka v6.0.16 (blocklist feed regression test fix)

- Updates TestFeedNeedsToken for the v6.0.15 feed security rule: a request needs both the correct token and a socket peer matching a configured firewall IP.
- Adds an explicit regression assertion that the correct token from an unapproved source receives 404.
- Production feed authorization is unchanged; the failure was a stale test that still sent requests from httptest's default address.
- Build remains fail-closed, so no Linux package is created unless vet, tests and compilation succeed.

### LogSikka v6.0.15 (H9: threat-feed access hardening)

- Starts roadmap H9. The blocklist threat feed now requires two conditions: the existing random URL token and a
  socket source IP matching a firewall configured in LogSikka. Requests from other addresses return 404.
- `X-Forwarded-For` is deliberately ignored for the feed, so a caller cannot spoof a configured firewall address.
- Feed reads are limited to 30 requests per minute per firewall source address. Excess requests receive HTTP 429
  with `Retry-After: 60`; the next one-minute window opens normally.
- IPv4-mapped IPv6 peers match their configured IPv4 firewall address.
- Added H9 tests for approved/refused sources, forwarding-header bypass, rate limiting and mapped addresses.
- The remaining H9 items (baseline never-block defaults and explicit confirmation for analysts adding public
  addresses) remain separate so this network-facing change can be validated first.

### LogSikka v6.0.14 (H8: remove the one-time administrator password)

- After the bootstrap `admin` account successfully completes its mandatory first password change,
  `initial-admin-password.txt` is deleted automatically. The new password is stored before cleanup is attempted.
- A missing bootstrap file is harmless. A filesystem cleanup failure is logged, but does not undo a successful
  password change or lock the administrator out.
- Password changes by ordinary users do not remove the administrator bootstrap file. Later administrator password
  changes do not repeat bootstrap cleanup.
- Added regression tests for first-admin cleanup, ordinary-user isolation, the new password, and later admin changes.
- Keeps v6.0.13 H7 compare-and-swap protection and the v6.0.12 fail-closed Linux build/package checks.

### LogSikka v6.0.13 (H7: settings are never silently overwritten)

- Two admins (or two browser tabs) editing Settings: the one who saves second now gets "these settings were changed
  by someone else after this page was loaded" and nothing is saved, instead of overwriting the first change.
  Refresh the page to load the latest settings and make the change again.
- How it works: GET /api/config returns the settings revision in the `X-Config-Revision` header; the Settings page
  sends it back in `If-Match`; a stale revision gets HTTP 409. The read, merge and save now happen as one step, so
  two saves can no longer interleave.
- Changes made from other cards of the same page (Sites, executive summary settings, blocklist, certificate install)
  hand the page the new revision, so they do not cause a false conflict.
- Scripts and API clients that send no `If-Match` are saved exactly as before.
- The revision is an HMAC with a key made at start-up: it reveals nothing about the stored passwords. After a
  service restart, a Settings page that was already open gets one 409 - refresh it.
- New tests: stale section save refused with no change, own revision accepted, no-If-Match still saved, stale
  whole-form save refused, revision stability.

### LogSikka v6.0.12 (stable rebuild from v6.0.8)

Rebuilt from v6.0.8, the last version that ran correctly. v6.0.9 - v6.0.11 are withdrawn: v6.0.9 did not compile
(missing import) and the old build script still produced a package with no program in it.

- Build scripts stop at the first failure (`go mod tidy`, `go vet`, `go test`, `go build`, `tar`). No package is
  written unless every step passes, and the package is named from the version in main.go (it said v6.0.1 before).
- install.sh refuses an incomplete package before it changes anything on the server.
- Test suite brought up to date so the stricter build can pass:
  - viewer / cookie tests now model an account that has already changed its first password (the server enforces
    "must change password" since v6.0.2, which made those tests fail with 403);
  - the WAN migration test counts the three counter-delta columns added in v6.0.6;
  - settings audit now really records "secret changed" (without the value) - the v6.0.8 change had not applied.
- Not included (planned again, one at a time, each compiled and tested before release): settings revision
  check (H7 compare-and-swap), removing initial-admin-password.txt, username lockout refinement.

### LogSikka v6.0.8 (settings audit hardening)

- Advances H7: array changes are audited element-by-element.
- Secret modifications are recorded only as "secret changed" without values.
- Section saves reject unknown nested configuration fields.
- Adds focused H7 regression tests.
- Revision compare-and-swap and active listener/TLS/database probes remain pending H7 work.

### LogSikka v6.0.7 (AI domain matching and grouping)

- Implements the compatibility-safe part of roadmap H6. Domain-looking AI rule patterns now match DNS suffix boundaries: x.ai matches x.ai and api.x.ai but not notx.ai.
- Unknown AI services are grouped by a registrable-style domain with explicit handling for common multi-label suffixes including com.lk and co.uk.
- Adds regression tests for the roadmap collision cases api.x.ai, chat.x.ai and foo.bar.io, plus deceptive suffix matches.
- Leaves non-domain application patterns on the existing contains semantics so established application-name rules are not broken.

### LogSikka v6.0.6 (exact WAN volume accounting)

- Implements roadmap H5 storage: every new WAN sample stores exact SNMP counter deltas, the real measurement interval and measurement timestamp.
- WAN daily/monthly volume totals use exact byte deltas for new samples instead of reconstructing bytes from rate times an estimated gap.
- Existing pre-v6.0.6 samples remain readable through the previous bounded-gap fallback calculation.
- Schema migration is additive and nullable, so existing WAN history does not need to be rewritten.
- Preserves v6.0.5 HA/reboot baseline protection and the live-first WAN interface.

### LogSikka v6.0.5 (HA-aware WAN polling)

- WAN counter baselines are now tied to the authoritative SNMP engine ID. A different HA member therefore starts with a fresh baseline instead of generating a false throughput delta.
- WAN polling reads sysUpTime alongside interface counters and resets baselines when uptime moves backwards after a firewall reboot.
- Counter rollback protection remains in place for individual interface resets.
- Preserves the v6.0.3 SNMP protocol-length correction, live-first WAN rendering, and v6.0.4 ingestion changes.

### LogSikka v6.0.4 (ingestion hardening foundation)

- Carries receiver-parsed key/value fields with queued envelopes when subtype filtering is enabled, establishing the H13 parse-once path without changing stored record semantics.
- Retains the v6.0.3 SNMP authentication-length compatibility fix and non-blocking WAN compact/live loading.
- Adds explicit source-level regression coverage for authentication tag lengths.

### LogSikka v6.0.2 (hardening)

- Syslog sender allow-list now activates when firewalls are configured and supports extra CIDR sources.
- TCP syslog newline and octet-count framing is bounded before a complete frame is buffered.
- SNMPv3 rejects responses that do not meet the configured auth/privacy level, uses constant-time digest comparison, validates auth-parameter length, engine identity and engine time.
- Must-change-password is enforced by the API; account and source-IP lockouts both apply.
- Added hardening regression tests for sender restrictions and TCP frame limits.


### LogSikka v6.0.1 (dashboards slow, filters "take forever")

Found on the server after v6.0: an executive-summary exclusions hour (27 Oct 12:00) timed out, was retried every
minute without end, and every retry read a whole hour of raw logs while the dashboards were trying to do the same.

- **Background history work waits for the dashboards.** Re-summarising older hours, the v5.x rebuilds, the AI and
  sign-in back-fills and the exclusions now only run when no dashboard query ran in the last 20 seconds. The live
  summaries (last 15 minutes, current hour) keep running. System health says when the history work is waiting.
- **Exclusions: one stuck hour no longer blocks everything.** Each hour has its own 4-minute limit; an hour that fails
  3 times is skipped (logged, shown in Settings > Executive summary and System health) and retried after a restart.
  At most 3 hours per minute.
- **Site, zone and subnet filters use the address index.** A filter with subnets was `src_ip <<= ANY(...)`, which
  PostgreSQL cannot answer from the index, so every filtered dashboard scanned the whole period. Each subnet is now an
  address range (`src_ip >= first AND src_ip <= last`), which can use it.
- **AI tabs:** when the AI summary is too slow, the page says so instead of falling back to reading the raw logs.
- **One extra worker per dashboard query** (was up to three): six queries no longer start 18 processes at once.
  `Environment=LOGSIKKA_PARALLEL=2` in the service file sets another value.
- No database changes.

### LogSikka v6.0 (FortiLog is now LogSikka)

Roadmap phase A, first part. LogSikka is the new name of FortiLog: *Sikka* is Sri Lankan slang for a security guard.

#### New name, same data
- Service `logsikka`, program `/opt/logsikka/logsikka`, data `/var/lib/logsikka`, system user `logsikka`, Windows
  service `LogSikka` (C:\ProgramData\LogSikka). `install.sh` moves a FortiLog installation over once (user renamed with
  the same UID, data folder moved with a symlink left behind, config paths and the NPS line in /etc/fstab updated,
  old unit disabled and kept as a backup, `fortilog` kept as an alias of the new unit). The database is not renamed.
- Signed-in browsers stay signed in (the old cookie is accepted); `X-FortiLog` is still accepted next to `X-LogSikka`;
  `FORTILOG_DATA` / `FORTILOG_TIMESCALE` still work next to `LOGSIKKA_*`.
- New icon, logo and favicon (header, sign-in page, reports); the version is shown next to the name.

#### Sites and tags (Monitor > Sites)
- Sites with their firewalls and zones (name, type, VLAN, subnets), edited on the Sites page by admins.
- Every internal address gets tags: site, zone, zone type; people get their department and "former staff"; assigned
  devices their role. Worked out in memory, so they apply to history at once.
- Per site and zone: devices, activity, share, blocked share, internet download / upload, all data, busiest devices.
  "Not in a zone" per site, and the busiest internal /24 networks no zone covers, with "Add to a zone".
- A click on a site or zone (on the Sites page or a tag in the log detail) filters the dashboards by its subnets.

#### Settings
- Each section is saved on its own (`PUT /api/config/section`): the other sections are taken from the stored
  configuration, so a Save in one card cannot change another one. The answer lists what changed.
- **Changes** button on every section: who changed what and when (from the audit log, recorded from v6.0 on).

#### System health
- Server performance, one point per minute for 24 hours (in memory): CPU, I/O wait, load, memory, swap, logs received
  and written per second, queue, spool, write time per batch, newest log age, database cache hit ratio and connections.

#### Look
- A thin bar at the top while the page loads; the page title shows its menu group (Monitor > Sites).

#### Not in this release (still phase A)
- Svelte / TypeScript front-end, TimescaleDB continuous aggregates, the tag summaries in the database (tag filters on
  every chart), and tests against TimescaleDB with replayed logs.

#### Upgrade
- `sudo bash install.sh` (see deploy/linux/README-LINUX.md). No database changes.
## FortiLog v5.21

### WAN health history
- CPU, memory and sessions (every poll), SD-WAN health per member and health check, and IPsec tunnels (about once a
  minute) are now stored (wan_sys, wan_sla, wan_vpn), kept as long as the WAN samples.
- WAN links tab, new card "Health over the period" per firewall: CPU / memory chart, SD-WAN latency and packet loss
  charts, link quality per member (share of the time alive with under 2% loss and under 150 ms), and tunnel uptime,
  drops and last down. Tunnels never up in the period (dial-up templates) are listed apart and not counted.

### WAN alerts (Alerts tab; limits in Settings > Alerts)
- Circuit near capacity: above 80% of the capacity for 15 minutes (red at twice as long); capacity from Settings, or
  the estimated bandwidth set on the FortiGate interface.
- SD-WAN member down (3 minutes dead in 15) or losing packets (2% over 15 minutes).
- IPsec tunnel down for 5 minutes (only tunnels that were up earlier in the last 24 hours).
- Firewall CPU or memory above 85% over 15 minutes (red at 95%).
- Firewall not answering the WAN monitor for 15 minutes (a missing passphrase is shown on the tile, not alerted).

### Executive report: Internet circuits (new section)
- Circuits, data downloaded / uploaded (interface counters), link quality, tunnel uptime, incidents; usage against
  capacity per circuit (data used, average, 95th percentile with % of capacity, peak, busy, quality); quality per
  SD-WAN member; IPsec tunnels per firewall; the WAN alerts of the period. The circuits table on the Trends page is
  left out when this section is shown.

### Blocklist
- Settings > Blocklist: "Blocked since added" per entry (connections from it the firewalls blocked and logged, from the
  hourly summary; local-in blocks included) and when the last one was. "none yet" means no blocked connection was
  logged: check that the deny policy uses the feed and logs violations.
- Repeat attackers: a source seen in sign-in attack alerts on more than one day in the last 30 is labelled "repeat
  attacker" on the alert and in the Add to blocklist dialog, and pre-selected there.

## FortiLog v5.20.1

### WAN links with several firewalls
- The firewalls are polled at the same time, each on its own. Before, they were polled one after another while
  holding the lock the WAN links page needs, so a firewall that did not answer (6 s per try) delayed every other
  firewall and froze the page and the Diagnostics.
- **Same SNMPv3 user as**: a firewall can use the user and passphrases of another one (leave its passphrases
  empty). A new firewall starts with the user of the first configured firewall.
- Two firewalls with the same address are refused; two with the same name are renamed "name (address)" (samples
  are stored under the name, so they would have been mixed).
- SNMPv3 errors in plain words: unknown user (create it on the firewall, check it is enabled and the name matches),
  wrong security level, wrong authentication or privacy passphrase.
- A firewall without interfaces says "no interfaces chosen" instead of "none of the chosen interfaces exists".

## FortiLog v5.20

### Fixed: saving Settings wiped the WAN passphrases
- Saving any section of Settings decoded the form into a configuration that shared the WAN firewall list with the live
  one, so the empty passphrase fields of the form blanked the stored passphrases before they could be kept. The save now
  works on a full copy, and the WAN list is decoded fresh. A test reproduces the old behaviour and guards against it.
  Type the passphrases once more after the upgrade.

### Blocklist for the FortiGates (external threat feed)
- Alerts: **Add to blocklist** on sign-in attacks (password spraying, brute force, sign-in after failures). Pick the
  addresses or the whole /24 the alert groups, how long to keep them (7 days to "until removed") and a note. The alert is
  acknowledged. Alerts show "blocklisted" / "partly blocklisted".
- FortiLog publishes the list at https://<server>:<port>/feed/<token>/blocklist.txt (one address or subnet per line),
  read by the FortiGates as an external threat feed of type address and used in deny policies. Copy in
  <data>/blocklist.txt. Expired entries leave the feed by themselves.
- Settings > Blocklist: on / off, default expiry, Never block, the feed address (copy, replace), when a FortiGate last
  read it, the FortiGate commands, the entries (remove, add by hand).
- Never listed: private and internal addresses (Settings > Internal networks), the firewalls' own addresses, Never block,
  subnets larger than /16 (IPv6 /48). Every change is in the audit log.

### Look
- The main menu stays at the top while scrolling.
- WAN links: the tiles show the circuits and a one-line firewall summary (CPU, memory, sessions, SD-WAN / tunnel
  problems); the SD-WAN health and IPsec tunnel tables moved below the charts.

## FortiLog v5.19

### WAN links: "enter the authentication passphrase" blocked every Save
- Since v5.17 a WAN firewall without a stored passphrase made the whole configuration invalid, so saving ANY section
  of Settings failed. A missing passphrase no longer blocks saving: the firewall is kept, it is not polled, and its tile
  and the Diagnostics say "no passphrase saved".
- Stored passphrases are matched by the firewall address (then by name), no longer by address + username, so changing
  the SNMPv3 username or the name keeps them.
- Settings shows "saved" / "not saved" next to each passphrase field (the passphrases themselves never leave the server).
- Test connection and Find interfaces say which passphrase is missing.

### WAN links: more from the FortiGate MIB (same SNMPv3 user, no FortiGate change)
- Capacity: the estimated bandwidth set on the FortiGate interface (fgIntfEntEstDown/UpBandwidth) is shown in Find
  interfaces, pre-fills the capacity when an interface is added, and is used when no capacity is entered.
- Each firewall tile: CPU, memory and sessions (fgSysCpuUsage, fgSysMemUsage, fgSysSesCount); SD-WAN health per
  member link: alive / dead, latency, jitter, packet loss (fgVWLHealthCheckLinkTable); IPsec tunnels: up / down,
  remote gateway, current rate in and out (fgVpn2TunTable). Tables are read about once a minute. These are live
  values (not stored in the database yet). A FortiGate that does not answer them simply shows the interface counters.

## FortiLog v5.18.1

- Fixed: the WAN links tab failed with "operator does not exist: timestamp with time zone >= interval". The data-usage
  query subtracted 15 minutes from an untyped parameter, so PostgreSQL took the parameter for an interval. The polls
  and stored samples were fine; only the page could not read them. Samples collected so far show up after the update.
- A test now refuses this pattern anywhere in the code.

## FortiLog v5.18

### Header
- One slim bar: logo, the tabs, and five icons on the right: collector status (green / amber dot, details on click),
  Reports (executive summary, AI usage report, print / PDF), page options (auto-refresh, customise, refresh now),
  Settings (gear, admins) and Account (password, appearance, sign out). The page title sits under the bar.
- Theme, accent and density moved to Settings > Appearance.

### Settings
- The list on the left now opens ONE section at a time (grouped: Overview, Collection, Detection and reports,
  System); the last one opened is remembered. Search jumps to the first matching section.
- Every section has its own Save button and says when it has unsaved changes. (Saving stores the whole configuration.)

### WAN links
- New Diagnostics panel on the WAN links tab (opens by itself when no circuit has data): per firewall, whether both
  passphrases are saved, the interfaces, the poller's last try and last answer, samples stored, samples in the last
  hour, the result of every database query the tab uses, and what to do.
- An error loading the WAN tab is now shown on the page (it used to leave the page blank).
- The journal says "WAN links <firewall>: first samples stored" once polling works.

## FortiLog v5.17

### Look and layout
- **Themes** (header > Theme): Light, Dark, Midnight, Ocean, High contrast, or follow the system; accent colour;
  density Normal / Compact / Large (wall screens). Kept per browser. Reports and PDFs stay light.
- **Menu grouped**: Monitor (All logs, Alerts, WAN links) · AI usage · People · Analyse · Settings.
- **All logs organised in sections** you can fold: Overview, Traffic and data, Users and devices, Security, Web AI and
  events (and Network devices in Advanced). A section bar jumps to each one; Expand all / Collapse all; remembered.
- **Settings as cards**: a section list on the left with a search box, every section folds and shows a one-line
  summary when closed, full window width, System health and Accounts are cards too, and a Save bar that stays at the
  bottom and says when there are unsaved changes.

### WAN links
- Fixed: the passphrases were cleared every time an interface was added from Find interfaces, so the firewall was
  saved without them and every poll failed authentication (no samples). They are kept now, and saving a firewall
  without them is refused with a clear message. New **Test connection** button.
- **A tile per firewall** with all its circuits: link state, current download / upload against capacity (gauge
  turns amber at 60%, red at 80%), and a 30-minute trend. Poll errors are shown on the tile.
- **Live charts** (last 30 minutes, every poll, refreshed automatically) and period charts as lines with the capacity
  line; hover for values.
- **Data used**: real volume per circuit from the interface counters (what the ISP counts): period, month to date,
  busiest day, and download / upload per day. A gap in polling is not filled in with guesses.

### AI usage report
- Pages end above the footer: a long table continues on the next page with its header repeated; page numbers are
  set after the layout.
- **Apply exclusions** toggle, the same rules as the executive summary (sources, destinations, users, subtypes).
- New **At a glance** page before the detail: allowed and blocked per tool, uploads per tool, people per tool,
  activity by risk rating, departments, new tools and biggest uploaders.

### Other
- Windows build: the certificate test no longer checks Unix file permissions on Windows.

## FortiLog v5.16

### Download and upload from the endpoint's point of view
- "Uploaded" now always means what your user, device or server sent. For sessions opened from the internet
  (published services, VPN), the firewall's sent and received were the internet host's view; they are swapped, so a
  server sending a 500 MB file shows 500 MB **uploaded**. Applies to every dashboard, list, report and the executive
  summary (summaries and raw queries alike).

### Network-device traffic moves to the new Advanced tab
- New traffic classes: **Network devices** (OSPF, VRRP, IGMP, PIM, BGP/LDP/BFD, multicast, and the addresses in
  Settings > Internal networks > Network devices, which may sit in any VLAN) and **Seen twice (site-to-site)**: an
  internal session arriving over a site-to-site tunnel, already logged by the firewall it came from. Recognised
  automatically when the log's incoming interface is its VPN, or from Settings > Site-to-site tunnel interfaces.
- These, and traffic to and from the firewalls, are left out of All logs, the top lists, the executive summary and the
  AI report. Head-office / branch traffic is counted once.
- **Advanced** tab: the All logs page with every log, plus device sources, destinations, services and their share.

### WAN links (SNMPv3, the fgwan tool built in)
- Settings > WAN links: firewalls (address, SNMPv3 user, SHA-2 / AES), **Find interfaces** walks the firewall, pick
  the circuits and enter the contracted capacity. Polled every 30 s (setting), kept 180 days (setting).
- **WAN links** tab: per circuit now / average / 95th percentile / peak, share of time above 80%, download and upload
  charts, busiest hours. Poll errors are shown with the likely cause (trusted host, passphrase, AES type).
- Executive report, Trends page: "Internet circuits" table.
- The SNMPv3 code is fgwan's (standard library only, RFC 3414 test vectors included); runs on Linux.

### AI usage report (new)
- Reports > AI usage report (or /ai-report.html): every AI tool in the period with risk, people, devices, departments,
  activity and trend, uploaded / downloaded, blocked share, first seen, new tools and the busiest users; departments,
  biggest uploaders, blocked attempts by person, most active people; recommendations. Prints to A4 / PDF like the
  executive report (uses its logo and classification).

### Trustworthy totals
- Site-to-site duplicates removed (above).
- The running totals of open sessions are saved on shutdown and restored at start, so the first log of a long session
  after a restart is no longer counted at its full total.

### Settings > System health (new)
- Database size, logs and data per day, the size at the retention period, free disk and how many days it lasts,
  spool, staff list, largest tables, and the background jobs with progress bars.
- Dashboard certificate: details, and **Use a certificate from your own CA**: create a request (key stays on the
  server), paste the signed certificate, install, restart.

### Upgrade
- `sudo bash install.sh`. A new table (wan_samples) is created. The summaries of the last 31 days are rebuilt once in
  the background (about 6 hours); until then older hours show the previous classification.

## FortiLog v5.15

### Alerts
- **Firewall label next to the severity** on every alert (FW HO-FW). An alert seen on several firewalls shows each one.
  When the firewall cannot be worked out the label says "Firewall ?" instead of being left out.
- **Order**: Newest first (default), Most severe, or **By firewall** (one group per firewall with its alert count, open
  count and a High marker; an alert seen on two firewalls is listed under both). The choice is kept in the browser.
- Older alerts get their firewall filled in on every check (merged sign-in alerts and device alerts as well), and one
  failing rule no longer stops the other rules or the firewall fill-in.

### Log explorer: readable log detail
- Clicking a log opens a readable view instead of the raw key list: a header (what happened, action, log type,
  severity, firewall, full local time, user and where the username came from, AI tool), then the fields grouped as
  What happened, Who, Where to, Traffic, Security and Admin and VPN, in plain words, with bytes and durations formatted.
- "only" / "not" buttons next to every value that is a dashboard filter. All other fields and the raw line are still
  there, folded at the bottom.

### Executive report
- Fixed: the Customise menu could not be closed (a style overrode the hidden state).
- Customise now has two tabs: **This report** (sections, cover, logo; kept in the browser) and **Report settings**
  (organisation name, status limits, what to leave out, report layout; saved for everyone, admins only). Saving rebuilds
  the report. Settings > Executive summary is unchanged and edits the same values.

## FortiLog v5.14.1

### Start-up no longer waits on the database upgrade
- Until v5.14 the whole schema was sent as one batch on every start. Statements such as "ALTER TABLE fortigate_logs ADD
  COLUMN IF NOT EXISTS" and "CREATE INDEX IF NOT EXISTS" lock the table before PostgreSQL finds out there is nothing to
  do. On a TimescaleDB hypertable that lock waits for every chunk, so a compression job or any long query on the log table
  kept the collector in "database not connected" (logs held in memory, then spooled) for as long as it ran.
- Each step is now checked first (column, index, table, constraint or function already there?) and only what is missing
  runs, one statement at a time with a 15-second lock timeout. A restart with nothing to change takes no lock at all.
- When a table is busy, the journal says which session holds it (pid, program, state, how long, query) and how to end it;
  the step is retried by itself. The All logs pipeline strip shows the step in progress.
- New journal lines: "database connected (...)" and "database upgrade: N change(s) applied ...".
- The rollup_1h index added in v5.13 (idx_r1h_dim_hour) duplicated the primary key and only slowed down writes: it is no
  longer created, and an existing one is dropped in the background (DROP INDEX CONCURRENTLY).

## FortiLog v5.14

### Alerts: firewall on every alert, one alert per attacker
- **Firewall on every alert**, shown as a tag next to the title (several firewalls are all listed), and a firewall filter
  on the Alerts tab. Alerts raised before v5.14 get the firewall added on the next check.
- **One alert per attacker**: password spraying and brute force from the same source are one "Sign-in attack" alert.
  Internet sources in the same /24 (IPv6 /64) are grouped, e.g. four addresses in 87.251.64.0/24 are one alert that
  lists them. Internal sources stay one alert per address. The v5.13 alerts they replace are removed; their
  acknowledged / ignored state is kept.
- **Admin page or VPN**: the alert says how the firewall was reached (HTTPS or SSH admin, SSL or IPsec VPN) and which
  firewall address was targeted (with the interface when the log carries it). The last 48 hours of sign-ins are
  re-summarised once after the upgrade.
- Counts cover the whole day (the thresholds are still per hour).
- **See activity** opens the Log explorer filtered to the source (address or subnet), the alert's firewall(s) and, for
  sign-ins and changes, the event logs.
- Blocked bursts, large uploads, busy unassigned devices, silent firewalls and out-of-hours changes also carry the firewall.

### Staff export
- deploy/nps-server/fortilog-staff-export.ps1 writes to the NPS log folder by default (C:\NPSLogs). In Settings > Staff
  directory, use the same folder as the NPS logs (e.g. /mnt/nps/nps01).

## FortiLog v5.13

### Speed: AI tabs, User mapping, Reports, executive report
- **Daily summary (rollup_1d).** 7- and 30-day top lists added up 168-720 hourly rows per value (up to 20,000 source
  IPs and users per hour). Finished days are now summarised once into one row per value; only the partial days at the
  edges come from the hourly table. Used by the All logs and executive top lists, the people / device counts, the report
  builder and the filter-box suggestions. Built in the background, newest day first.
- **AI tabs** use the AI summary from 1 hour up (was: over 12 hours). Up to 12 hours the timeline is still read from the
  raw AI logs (5-minute detail). The 6 h / 24 h / 7 day views of the AI source in use are kept ready in the background
  while the AI tabs are used.
- **User mapping** reads "IP addresses without a username" and "seen with" from two new hourly dimensions instead of
  scanning every raw log; the mapping list no longer counts the rows of every mapping on each visit (stored when saved);
  the NPS session list counts events only when you search for an IP or user; the user suggestions no longer ask for 30
  days of raw logs.

### Staff directory (new)
- Nightly export on the NPS server: deploy/nps-server/fortilog-staff-export.ps1 writes staff.csv / computers.csv to a
  folder on the NPS share. Settings > Staff directory: the folder (as mounted on the server). Read whenever it changes.
- Joiners appear after the next export; leavers (disabled or gone) become former staff: their past activity keeps
  their name, they are no longer active people, and devices assigned to them show a warning.
- Usernames are stored in one form (CORP\nimal, nimal@corp.lk, NIMAL -> nimal). A firewall "unauthenticated user"
  guess that is not a member of staff is not used. The people count counts verified staff only.
- Fixed: a backslash inside a quoted log value was dropped (user="CORP\nimal" was stored as "CORPnimal").

### Devices & people (new tab)
- Who is behind the traffic (also on All logs): share of internal activity from people, servers, printers, shared
  devices, network devices and unknown devices, and how much is traced.
- Devices without a user: busiest first, with host name (domain PC badge from computers.csv), MAC, device type and OS
  from the FortiGate, and the last user seen. Assign one, or select several and assign them together.
- Assign dialog: IP, subnet, MAC or host name (quick picks: this address / this device / host name / whole /24), type
  (person, server, printer, shared, network device, camera / IoT, ignore), person from the staff list (shows name and
  department, warns about leavers), department, note, expected MAC, end date.
- Order for a log without a username: firewall user > time-bound manual mapping > permanent person assignment > NPS.
  A person assignment also labels the days already stored that are not compressed yet. Other types only label the device.
- Suggestions (NPS or firewall saw the same person on most of the last 7 days), Assignments (search, filter, CSV import
  and export), Staff (active / former, devices, last seen, usernames that are not staff), Warnings, History.

### Alerts (new tab)
- Every 5 minutes, from the summaries: repeated failed admin / VPN sign-ins, password spraying, a successful sign-in after
  failures, configuration changes outside working hours, a firewall (or FortiLog itself) not sending logs, a device with
  a burst of blocked connections, a large upload to the internet, a busy device with no user or assignment.
- One alert per thing per day. Acknowledge or ignore; open count on the tab. Limits in Settings > Alerts.

## FortiLog v5.12 (includes v5.11)

### Data volumes were too high (users, devices, totals)
- FortiGate writes a "long-lived session" log (log id 20) every 2 minutes for every open session, with the session's
  **running total** in sentbyte / rcvdbyte. Adding those up counted a 1-hour download about 30 times, so busy users,
  backups and video calls looked far larger than they were. Each log now counts only its own increment: the
  FortiGate's sentdelta / rcvddelta when present, otherwise the difference to the previous log of the same session.
  Logs stored before v5.12 are corrected in the summaries (fl_sent / fl_rcvd), and all history is re-summarised once
  in the background (newest first, about 2 hours of logs per minute; progress in /api/status, "directions_from").
- Traffic that never leaves the network (file shares, backups, replication) is no longer mixed into "top users by
  data", "where the data went" and "biggest uploaders": those now count internet traffic only.

### Traffic direction (new)
- Every traffic log is classed as: **To the internet** (internal -> public), **From the internet** (published
  services, VPN, scans), **Internal only** (internal -> internal, LAN to LAN, between sites), **Firewalls themselves**
  (subtype local). Internal = the private ranges plus Settings > Internal networks (for public ranges used inside).
- All logs: KPIs **Internet ↓**, **Internet ↑** and **Internal only** instead of one download/upload total; a new
  **Traffic by direction** panel; **Data over time** with Internet / Internal only / Firewalls / All, download and
  upload as two separate charts (each with its own scale) instead of stacked bars.
- Ranked data lists show download and upload as two separate bars with both values.
- Reports: new field **Traffic direction** (fast, from the summaries) and the ready-made report "Traffic by direction
  per day".

### Executive report
- Headline figure and story: internet traffic (download and upload), with internal-only and firewall traffic beside it.
- Trends: "Internet data per day" and "Internal only per day" as **side-by-side** download / upload bars, and a
  "Where the traffic goes" breakdown. Internet page: top users and destinations by internet data, with download and
  upload shown apart. Exclusions are applied per direction as well.

### Other
- Fixed: a database error while loading the summary state could leave an internal lock held and freeze the summaries
  and the status page.

## FortiLog v5.11 (executive report)
- Fixed A4 pages (no near-empty extra pages); compact health checks; top 4 findings on the summary page.
- Sign-ins and configuration changes from a new hourly summary (rollup_evt) instead of timing out on raw logs.
- Collector / database outages reported once ("Log collection running") and not counted against the firewalls.
- Availability only for the firewalls in Settings > Firewalls; "Firewalls to ignore" for retired / renamed devices.
- Web categories without FortiGuard placeholders (unscanned, unknown) and application categories (Network.Service).
- "Most used destinations" without internal addresses, short host names and your own domains; no "Reserved" country.
- Devices = internal addresses only. AI tool count consistent; "New" only when there is a period to compare with.
- Unusual devices: user and destination from each device's newest logs (no more time-outs).

## FortiLog v5.10

### AI tabs: fixes
- **Slow / "query timed out" on 24 h and 7 day views.** Every refresh scanned the raw logs; with compression after 2 days
  a 7-day AI view had to decompress five day-chunks. A new AI summary (`rollup_ai`, one row per hour x firewall x tool x
  user x device x destination x action x category x risk x app x country) now answers the AI tabs for periods over 12 hours.
  Tool, user, IP / subnet, host, category, app, risk, outcome and action filters still use it, with exact results (checked
  against the raw logs in tests). The search box, destination IP, service, policy, severity and event-message filters, and
  periods up to 12 hours, read the raw logs. The AI bar shows which source answered and why.
- **"First seen" / "New" scanned every stored AI log on each refresh** (min(event_time) over the whole retention). It now
  comes from the summaries.
- **Empty AI tabs when the policies have no web filter / application control profile.** The AI tabs only read UTM events.
  New **AI data** switch in the AI bar: Security events (default), Traffic logs, or All AI logs (kept per browser).
- **"Where the data went" and "Data by country" always showed 0 B** on the AI overview: AI security events carry no byte
  counts. They now use the AI traffic logs, like the upload lists.
- **Heat map and daily tables were in the database server's time zone** (often UTC, i.e. 5.5 h off). Database sessions
  now use the collector's time zone (TZ / systemd setting).
- **Generic app names** were matched three different ways (Go prefix check, SQL regex, reclassify SQL), so e.g. "TLScontact"
  or "Sslvpn-Portal" counted as "not identified" on the dashboard and HTTPS.BROWSER could name an AI tool. One definition now.
- **Re-classify** ran one UPDATE per day (a long transaction over tens of millions of rows) and stopped with an error on
  compressed TimescaleDB chunks on older versions. It now works one hour at a time, newest first, rebuilds the summaries of
  the hours it changed, and stops cleanly (with a note) at compressed chunks it cannot change.
- 18 more built-in AI tools (Qwen, Kimi, Manus, Groq, Phind, Cursor, Codeium / Windsurf, Replit, Lovable, Jasper,
  Writesonic, ElevenLabs, Suno, Runway, Leonardo, Ideogram, Stability AI, OpenRouter). Existing setups: Settings > AI
  detection > **Add missing built-in tools** (your own rules are kept), Save, then Re-classify.

### New widgets
- All logs, new "Usage and risk" row: data over time (download / upload), activity by weekday and hour, web categories,
  high-risk applications, top users by data, blocked by protection (which security feature stopped it).
  All from the summaries, so they cost nothing on long periods.
- AI overview: AI tools over time (top six stacked), **who uses which AI tool** (people x tools matrix with blocked share),
  blocked AI attempts by person; the risk column of "Needs review" is filled from the data.
- **Customise** (header button): hide or show any panel on the All logs and AI tabs; remembered per browser (wall screens).

### Executive summary
- **Exclusions** (Settings > Executive summary > Leave out of the executive summary): sources (IPs / subnets),
  destinations (IPs, subnets, host names with *), usernames and log subtypes. A log matching any rule is removed from the
  totals, previous-period comparison, daily series, firewall share, log types / subtypes, top sources / destinations /
  users, and the people and device counts. Done with exact per-hour totals of the excluded logs (`rollup_excl`), so a
  30-day report still builds in seconds. After a change, history is recalculated in the background (about 12 hours of
  logs per minute); the report shows the coverage until it is done. Toggle "Apply exclusions" on the report to compare.
  AI tools, categories, apps, policies, services, countries and sign-ins are shown as recorded (stated in the report).
- **Premium layout:** cover page (logo, title, prepared for / by, classification, status, key figures, contents),
  numbered sections, page x of y footer with classification, score ring, sparklines in the KPI cards, health-check status
  pills, cleaner tables. **Customise** menu: choose sections, title, logo (kept in the browser). Prints to A4 with one
  section per page.
- "Last 7 / 30 days" now start on the hour, so they line up with the hourly summaries.

### Other fixes
- /api/status (every 10 s from every open browser) looked up max(id) over the whole log table and scanned 30 days for the
  newest event; it now reads only recent chunks and is shared between browsers for 10 s.
- Retention also prunes the new summary tables.

### Upgrade
Same as before (`sudo bash install.sh`). The new tables are created at start-up; the AI summary fills back over existing
data in the background (8 hours of logs per minute, newest first). Check with
`sudo -u postgres psql -d fortilog -c "SELECT * FROM rollup_state"` (row `ai`).

# FortiLog v5.9 (includes v5.8)

## Outage found on a live server (19-20 Oct): one odd log line stopped the database for about 12 hours
- A FortiGate sends `dstip="dstip=192.168.2.1"` (key repeated inside the value). Versions before 5.7 could not store it.
  Worse, the 15-second spool replay then closed the live database connection each time it failed, and while the connection
  was closed every new log went to the spool: one bad file kept the collector disconnected for hours.
- The address inside such a value is now recovered (192.168.2.1) instead of dropped; a value with no address is still
  emptied and the log marked partial. Spooled records written by older versions are repaired the same way.
- A failing spool file no longer closes the live connection: the collector reconnects only if the database does not
  answer a ping. After 3 refused files in one round the replay waits for the next round.

## Disk load (found on a server with 16 cores, 15 GB RAM and a slow disk: 50-70% I/O wait)
- The All logs warmer ran its queries on raw logs every 30 seconds even when nobody had the page open. It now works
  only while the page was used in the last 30 minutes. The first visit after a quiet period takes the normal time.
- While the spool is being replayed (more than 200 files waiting), the warmer and the re-summarising of old hours
  pause. Each replayed batch used to mark old hours dirty again, so every hour was scanned over and over. Old hours
  are summarised once after the replay has finished. Live 5-minute and hourly summaries keep running.
- /api/status shows `spool_backlog` (files waiting) and `spool_lost` (records that could not be saved anywhere).

## Restart
- Logs that arrive while the database is still connecting after a restart are kept in memory (up to 60000) and written
  as one batch, instead of thousands of one-second spool files. If the database is really down, they go to the spool.
- "CRITICAL spool write failed" is logged at most once a minute, with the running count of records not saved.

## Reliability (v5.8)
- TCP syslog waits when the internal queue is full instead of dropping the message, so a FortiGate in reliable mode
  slows down and buffers on the firewall. UDP still drops. `tcp_waits` in /api/status counts how often this happened.
- `spool_max_mb` is now enforced: when the spool folder is full, new batches are refused and reported instead of
  filling the disk. The quarantine folder is capped at 1 GB.

# FortiLog v5.7

## Fix: "quarantined one record the database rejected" (v5.6)
- The messages came from the spool backlog: those logs were parsed by v5.5, so the bad `dstip` value was already
  stored inside the spooled record. v5.6 caught them correctly (one at a time, by splitting each batch), but that is
  slow and reported every one as a "database problem".
- Every record is now checked again just before it is written (`cleanRecord`), so spooled records from older versions
  are corrected (invalid IP -> empty, log marked partial, raw text unchanged) and stored normally, without quarantine.
- A quarantined record is no longer shown as "Last database problem". The pipeline strip shows a separate count of
  records set aside since the service started.
- Fixed in the Reports tab: column names, labels and kinds were sent with capitalised JSON names, so the result
  table could not find them.

## Executive summary (new)
- One-click management view: header button "Executive summary", or Reports > Executive summary. Open to every role.
- Periods: last 7 days, last week (Mon-Sun), last 30 days, this month, last month, custom (up to 92 days), always
  compared with the previous period of the same length.
- Page 1: overall status (green / amber / red), six headline figures with trends, "What happened" in plain language,
  "Needs attention" with recommended actions, and a health-check scorecard.
- Page 2 Trends: activity (allowed / blocked) and data (download / upload) per day, share by firewall, availability.
- Page 3 Internet use: web categories, top destinations, AI tools (people, devices, uploads, new tools), countries, apps.
- Page 4 Security posture: what was blocked by protection type, devices with unusual blocked activity (with user and
  main destination), failed admin / VPN sign-ins (internet sources flagged), configuration changes, risky apps allowed.
- Page 5 Appendix (optional): top tables for the IT team and a note on the data.
- A4 layout: Print / save as PDF from the browser gives a clean multi-page document.
- Status limits and the organisation name: Settings > Executive summary.
- Built from the summaries: web categories and high-risk applications were added to the hourly summaries; hours
  summarised before v5.7 are filled in the background (about 6 hours of logs per minute, newest first).

# FortiLog v5.5

## Sign-in
- Accounts (viewer / analyst / admin) in `<data>/users.json` (bcrypt), sessions in an HttpOnly cookie, kept across restarts.
- First start creates `admin` with a one-time password in `<data>/initial-admin-password.txt`; a new password is required at first sign-in.
- 5 failed sign-ins from one address: 15-minute lock. Audit log of sign-ins, failures, exports, settings and accounts (Settings > Accounts).
- HTTPS on by default (self-signed certificate in the data folder, or your own via Settings > Dashboard access).
- Command line: `fortilog-collector --data DIR user list|add|passwd|role|disable|enable|delete`.

## Speed
- Summary tables (rollup_5m, rollup_1h) answer the All logs page for 6 h, 24 h, 7 days and custom ranges.
- The four main periods are pre-computed every 30 s, so opening or refreshing the page is instant.
- Dashboard queries at once: 3 -> 6 (setting). NPS no longer clears the dashboard cache every 5 seconds.
- API responses are gzip-compressed. TimescaleDB compression age is a setting (default 2 days, was 7).

## Filters
- Every filter box takes a list: `10.1.1.5, 10.2.0.0/16, !10.2.3.4`, `alice, bob`.
- Ctrl+click adds to the filter; Shift+click excludes. One chip per value.
- Main periods: 1 hour, 6 hours, 24 hours, 7 days; Custom for anything up to 90 days.

## All logs page
- One compact summary row; timeline next to firewall status; four rows of ranked lists; clearer chart axes.

## FortiLog v5: v2 + v4 combined, all logs, AI dashboards, multiple firewalls, NPS user mapping

Tabs: All logs | AI overview | AI policy and risk | AI investigation | User mapping | Log explorer | Settings

### 1. All logs (global dashboard, from v2)
Every log type from every firewall: events over time, firewalls (events, last log, Live/Quiet), log types and subtypes,
source IPs, users, destinations, services, policies, severity, most blocked, biggest uploaders, countries, AI tools seen,
system/VPN event messages. New filters: Log type, Scope, Firewall, Subtype, AI tool, Service, Policy, Severity, Event message.

### 2. AI dashboards (from v4)
Overview, Policy and risk and Investigation now show AI only (web filter + application control events tagged as AI),
grouped by tool, so "ChatGPT" covers the app signature and chatgpt.com. Added: AI tool adoption (people, devices,
New flag), data sent to AI tools, biggest uploaders (user and IP), NPS sessions in the investigation.

### 3.1 Multiple firewalls
Settings > Firewalls (name, IP). Every log stores its firewall (configured name > FortiGate devname > sender IP).
Live status per firewall on the All logs tab.

### 3.2 NPS (wireless) user mapping
Tails the NPS log files (DTS or IAS format, several servers), builds IP -> user sessions; a new user on an IP ends the
previous user's session. Logs without a username are labelled automatically (stored, then backfilled within seconds).
Optional MAC learning from FortiGate srcmac. User mapping tab: NPS status, files, session search.

Files
- New: global.go, ai.go, nps.go, nps_test.go
- Changed: config.go, receiver.go, parser.go, schema.go, database.go, query.go, insights.go, mapping.go, handlers.go,
  app.go, web.go, service_windows.go, web/index.html, web/app.js, web/app.css, web/settings.js, README.md
- Unchanged: main.go, service_other.go, go.mod, go.sum, scripts
- New endpoints: /api/global, /api/nps/status, /api/nps/sessions, /api/ai/reclassify

Fixes
- Opening the Settings tab directly from a link no longer fails (scripts start after the page has loaded).
- Saving Settings keeps fields the form does not show; only listener, firewall list and database changes need a restart.

### v5.1 fixes (no logs after upgrade)
- The Firewalls list no longer blocks other senders. Only "Other allowed sources" restricts, as in v2.
  Refused senders are now shown at the top of the dashboard.
- Listener and web UI start immediately; the database upgrade runs in the background and logs queue meanwhile.
- The two new large indexes are built with CREATE INDEX CONCURRENTLY after start-up, so inserts are never blocked.
- AI overview explains when it is empty because older logs are not AI-tagged yet.
- Hover the database badge for received / stored / refused / queue counters.

### v5.2 fix
- All logs: "can't scan into dest[13]: cannot scan NULL into *time.Time" when the selected period (or filter) had no logs.

### v5.3: the log pipeline comes first
- Writing logs can no longer be stopped by v5 additions: if the full insert fails, the batch is written with exactly
  the v2 columns and the error is reported (firewall name / AI tag / NPS user are left empty for that batch).
- Every database write error is now logged (Windows Application log / console) and shown on the All logs tab.
- All four full-table index builds run in the background (CONCURRENTLY), never at start-up.
- NPS MAC lookups during a write time out after 2 s instead of holding the writer.
- All logs tab: pipeline strip "Received -> Refused/filtered -> Written -> Waiting -> In the database", the last one
  read straight from PostgreSQL.
