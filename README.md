#  FG-Analyzer (formerly LogSikka)

Self-hosted network and security log tool for FortiGate-based organisations: FortiGate syslog into
PostgreSQL / TimescaleDB, dashboards, AI usage, people and devices, sites and zones, alerts, WAN links over SNMPv3,
executive and AI reports, and a blocklist feed for the FortiGates. *Sikka* is Sri Lankan slang for a security guard.

Linux is the main platform: see **deploy/linux/README-LINUX.md** (install, upgrade from FortiLog, what is new).
The notes below are the original Windows notes of FortiLog v5.

# FortiLog Collector v5 (Windows notes)

Single-executable FortiGate syslog receiver, PostgreSQL writer and web dashboard for Windows Server.

* **All logs**: global dashboard for every log type (traffic, UTM, event) from every FortiGate.
* **AI usage**: AI overview, AI policy and risk, AI investigation (the v4 dashboards, limited to AI tools).
* **User mapping**: usernames from the firewall (FSSO), from NPS wireless sign-ins (automatic), or added by hand.
* **Log explorer** and **Settings**.

## Build

Install Go 1.22 or newer, then run:

    Set-ExecutionPolicy -Scope Process Bypass
    .\scripts\build.ps1

## Upgrade from v2 / v4

1. Stop the service: `Stop-Service FortiLogCollector (v5) or LogSikka (v6)`
2. Replace the whole source folder with this one, build, then run `.\scripts\install-service.ps1` as Administrator.
3. Your `C:\ProgramData\FortiLogCollector\config.json` is kept. New settings get defaults (NPS is off).
4. The database is upgraded at start (new columns `device_name`, `src_mac`, `ai_tool`, `nps_id`; new tables
   `nps_sessions`, `nps_offsets`). Nothing is deleted. Older rows have no AI tag: open **Settings > AI detection > Re-classify**.
5. If **Keep only these types or subtypes** was set to `webfilter, app-ctrl`, clear it, or the All logs dashboard
   will only ever see those two.

## FortiGate (do this on every firewall)

    config log syslogd setting
        set status enable
        set server "SERVER_IP"
        set mode reliable
        set port 6514
        set format default
    end
    config log syslogd filter
        set severity information
        set forward-traffic enable
        set local-traffic disable
        set multicast-traffic disable
        set sniffer-traffic disable
        set anomaly enable
    end

Confirm options with `?` on your FortiOS version. Event logs (admin, VPN, system) follow `config log eventfilter`.
Forward traffic is by far the biggest volume: size PostgreSQL disk and `retention_days` for it.

Then list each firewall in **Settings > Firewalls** as `name, IP the logs come from`. Listed IPs are always allowed
to send; once any firewall or allowed source is listed, other senders are refused. Changing the list needs a service restart.

## NPS user mapping (wireless)

1. On the NPS server: **Accounting > Log file properties**: log *Accounting requests* and *Authentication requests*,
   format **DTS Compliant**. Default folder: `C:\Windows\System32\LogFiles`.
2. The wireless controller must send RADIUS accounting to NPS with the client IP (Framed-IP-Address, usually in interim updates).
3. In **Settings > NPS user mapping**: tick *Read NPS logs* and give the folder. A folder means every `IN*.log` file in it.
   Several NPS servers: one path per line.
4. If NPS runs on another server, share the log folder read-only and run the service as a domain account that can read
   the share (`sc.exe config FortiLogCollector obj= DOMAIN\svc-fortilog password= ...`). LocalSystem cannot read network shares.

How it works: a record with a client IP opens a session "this IP belongs to this user". When another user appears on the
same IP, the previous session ends at that moment. A session also ends on Accounting-Stop or after *idle hours* with no news.
Machine accounts (`host/...`, `PC$`) are ignored. When NPS has no IP but has the MAC, and *Use the client MAC* is on,
the first FortiGate log with that `srcmac` opens the session (works where the FortiGate is the clients' gateway).
Precedence: username in the firewall log > manual mapping > NPS.

Notes: NPS timestamps are read in the collector's local time zone. If two firewalls use the same private IP ranges,
NPS sessions apply to both (an IP is treated as unique).

## PostgreSQL preparation

    CREATE USER fortilog WITH PASSWORD 'change-this-password';
    CREATE DATABASE fortilog OWNER fortilog;

## First run, service

    .\fortilog-collector.exe --config "$env:ProgramData\FortiLogCollector\config.json"
    .\scripts\install-service.ps1      # as Administrator

Open http://127.0.0.1:8080. Set legacy administrator token in config.json before exposing the settings API beyond localhost.

## Design notes

- TCP supports RFC 6587 octet-counted and newline-delimited frames. PostgreSQL insertion uses COPY batches.
- Failed database batches are written to disk and replayed in order. Raw messages are always kept.
- AI tags are set at ingest from the rules in Settings (first matching tool wins; otherwise an AI category means
  "AI, named by application or domain"). AI dashboards count web filter and app control events; uploads come from traffic logs.
- Retention uses batched SQL deletion. With forward-traffic logs at high volume, move the table to daily range partitions.
