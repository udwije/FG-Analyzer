# LogSikka v6.0 on Linux

LogSikka is the new name of FortiLog. *Sikka* is Sri Lankan slang for a security guard: LogSikka watches your logs.

## Upgrade from FortiLog v5.x (same server)
```
# on your PC, in the source folder
.\deploy\linux\build.ps1
scp -P 22222 logsikka-linux-v6.0.tar.gz <user>@<server>:~
# on the server
mkdir -p ~/logsikka60 && tar -xzf ~/logsikka-linux-v6.0.tar.gz -C ~/logsikka60 && cd ~/logsikka60
sudo bash install.sh
```
`install.sh` does the rename once, and prints each step:

| Before (FortiLog) | After (LogSikka) | Notes |
|---|---|---|
| service `fortilog` | service `logsikka` | the old unit is stopped, disabled and kept as `fortilog.service.v5-backup`; `systemctl status fortilog` still works (alias) |
| user and group `fortilog` | `logsikka` | renamed, same UID / GID, so every file stays readable |
| `/var/lib/fortilog` | `/var/lib/logsikka` | moved; a symlink stays at the old path for this release; paths in `config.json` are updated (backup `config.json.before-logsikka`) |
| `/opt/fortilog/fortilog-collector` | `/opt/logsikka/logsikka` | remove `/opt/fortilog` once v6.0 runs well |
| NPS share in `/etc/fstab` (`uid=fortilog,gid=fortilog`) | `uid=logsikka,gid=logsikka` | backup `/etc/fstab.before-logsikka`; the share stays mounted |
| database `fortilog` | unchanged | `config.json` keeps pointing at it; no data is moved |
| browser sessions | kept | the old sign-in cookie is still accepted |

Nothing else changes: same ports, same certificate, same accounts, same data. The FortiGates keep sending to the
same address, and the blocklist feed address is unchanged.

Check: `systemctl status logsikka`, `journalctl -u logsikka -f` (first line: `LogSikka v6.0 starting`).
Roll back: `sudo systemctl stop logsikka`, then `sudo mv /etc/systemd/system/fortilog.service.v5-backup /etc/systemd/system/fortilog.service`,
undo the user rename (`usermod -l fortilog logsikka; groupmod -n fortilog logsikka`), restore the fstab backup,
move `/var/lib/logsikka` back and start `fortilog`.

## New installation
```
sudo DB_PASSWORD='choose-a-strong-one' bash setup-postgres.sh    # creates the role and database "logsikka"
sudo bash install.sh
sudo cat /var/lib/logsikka/initial-admin-password.txt     # first sign-in as admin, then choose your own password
sudo rm /var/lib/logsikka/initial-admin-password.txt
```
Then Settings > PostgreSQL: database `logsikka`, user `logsikka` and the password.

## v6.0: what is new
- **Sites** (Monitor > Sites): describe each site, its firewalls and its zones (staff LAN, servers, guest, CCTV ...)
  with their subnets. Every internal address then carries site and zone tags: per-zone activity and internet use,
  the busiest networks not described yet (one click to add them), and a click on a site or zone filters the dashboards
  by its subnets. Works on history straight away (nothing is rebuilt).
- **Log detail** shows the tags of the device and person: site, zone, zone type, department, device role, former staff.
- **Settings are saved one section at a time.** Saving one card can no longer change another one. Each card has a
  **Changes** button: who changed what, and when.
- **System health > Server performance**: CPU, I/O wait, memory, swap, logs per second, write time per batch, newest
  log age, database cache hits and connections, last 24 hours (one point per minute, kept in memory).
- New name, icon and logo; a thin bar at the top shows when the page is loading; the page title shows its menu group.

## Accounts
| Role | Can |
|---|---|
| viewer | dashboards only (wall screens: raise "Stay signed in for") |
| analyst | + log explorer, CSV export, investigation, user mapping, NPS sessions |
| admin | + settings, accounts, audit log |

Manage them in Settings > Accounts, or on the server:
```
sudo -u logsikka /opt/logsikka/logsikka --data /var/lib/logsikka user list
sudo -u logsikka /opt/logsikka/logsikka --data /var/lib/logsikka user add wall viewer
sudo -u logsikka /opt/logsikka/logsikka --data /var/lib/logsikka user passwd admin     # locked out
```
5 failed sign-ins from one address lock it for 15 minutes.

## Fast dashboards (summaries)
The collector keeps two summary tables (`rollup_5m`, `rollup_1h`). The All logs page reads them for 6 h, 24 h,
7 days and custom ranges when the only filters are firewall and log type. Other filters, and the 1-hour view, read
raw logs. After the upgrade the summaries are built back over existing data (about 3 hours of logs per minute, up to
31 days); the page says when a period is still being built.
```
sudo -u postgres psql -d <database> -c "SELECT * FROM rollup_state"
sudo -u postgres psql -d <database> -c "SELECT pg_size_pretty(pg_total_relation_size('rollup_1h')), pg_size_pretty(pg_total_relation_size('rollup_5m'))"
```

## Compression
Default is now 2 days (Settings > Storage > Compress logs older than). The change applies to the TimescaleDB job
straight away.

## v5.7: executive summary
Open **Executive summary** (header button). Pick the period, then **Print / save as PDF** (A4, margins default,
"Background graphics" on). Set the organisation name and status limits in Settings > Executive summary.
Web categories and risky apps for hours before the upgrade are filled in the background; check progress with:
```
sudo -u postgres psql -d <database> -c "SELECT * FROM rollup_state"
```

## v5.10
- AI tabs read the new AI summary for periods over 12 hours; pick the AI data source (security events / traffic / all) in the AI bar.
- Executive summary exclusions: Settings > Executive summary > Leave out of the executive summary. Progress of the
  background recalculation is shown under the boxes.
- Customise (header) hides panels per browser; the executive summary has its own Customise menu (sections, logo, cover).

## v5.11 / v5.12
- Settings > Firewalls: list your active firewalls; Settings > Internal networks: public ranges used inside (if any).
- Settings > Executive summary > Report layout: firewalls to ignore, your own domains.
- After the upgrade, history is re-summarised once in the background (traffic direction, corrected data volumes,
  sign-ins). Check progress: sudo -u postgres psql -d <database> -c "SELECT * FROM rollup_state WHERE name IN ('r512','evt')"

## v5.13
- Staff directory: on the NPS server, copy deploy/nps-server/logsikka-staff-export.ps1, test it, then install the
  nightly task (see the script header). Write the files to a folder on the NPS share, e.g.
  C:\NPSLogs (the default), which this server already mounts as /mnt/nps/nps01.
  Then Settings > Staff directory: tick "Read the staff list" and give that folder.
- Background work after the upgrade: daily summaries of finished days and the user-mapping dimensions for older hours.
  Progress: sudo -u postgres psql -d <database> -c "SELECT * FROM rollup_state WHERE name='map'" -c "SELECT count(*) FROM rollup_1d_done"

### v5.14
- Alerts name the firewall, merge password spraying and brute force from one attacker (internet sources grouped by /24)
  and say whether the admin page (HTTPS / SSH) or the VPN was targeted. After the upgrade the sign-ins of the last 48
  hours are re-summarised once. Progress: sudo -u postgres psql -d <database> -c "SELECT * FROM rollup_state WHERE name='evt514'"

### v5.14.1
- Faster, non-blocking start: the schema check only touches what is missing. If the start still waits, the journal names
  the session holding the table: journalctl -u logsikka | grep "database upgrade"

### v5.15
- Alerts: firewall label, newest first / most severe / by firewall. Readable log detail. Report settings in the
  executive report's Customise menu (admins).

#### v5.16
- After the upgrade every summary of the last 31 days is rebuilt once in the background (endpoint up/down, network
  devices, site-to-site duplicates): about 2 hours of logs per minute, so roughly 6 hours. Progress: Settings > System health.
- WAN links: Settings > WAN links. On each FortiGate the SNMPv3 user needs this server in `trusted-host`
  (`config system snmp user` > `set trusted-host <this server>/32`). The collector only needs outbound UDP/161.
- Network devices and tunnels: Settings > Internal networks > Network devices / Site-to-site tunnel interfaces.

##### v5.17
- No database changes. Install as usual. WAN links: open Settings > WAN links, type both passphrases, Test connection, Save.

###### v5.19
- No database changes. WAN links: firewalls without a saved passphrase no longer block saving Settings; they show
  "no passphrase saved" on the tile. CPU, memory, sessions, SD-WAN health and IPsec tunnels come from the FortiGate MIB
  through the same SNMPv3 user (no FortiGate change needed).

######## v5.20
- A new table (blocklist) is created at start. Settings > Blocklist: turn the feed on, copy the feed address, and add it
  on each FortiGate as an external threat feed of type address (the card shows the commands). The FortiGate must reach
  this server on the dashboard port.

######## v5.21
- Three new tables (wan_sys, wan_sla, wan_vpn) are created at start; the WAN health history fills from the upgrade on.
- New WAN alerts (Settings > Alerts: limits). The executive report has a new "Internet circuits" section.
