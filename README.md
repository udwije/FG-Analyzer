<div align="center">

# FG-Analyzer

### Self-hosted FortiGate log analytics, security monitoring, identity attribution, and network visibility

**Formerly known as LogSikka**

[![Go](https://img.shields.io/badge/Go-1.22%2B-00ADD8?logo=go&logoColor=white)](https://go.dev/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-Supported-4169E1?logo=postgresql&logoColor=white)](https://www.postgresql.org/)
[![TimescaleDB](https://img.shields.io/badge/TimescaleDB-Optional-FDB515)](https://www.timescale.com/)
[![FortiGate](https://img.shields.io/badge/FortiGate-Syslog%20%2B%20SNMPv3-EE3124)](https://www.fortinet.com/products/next-generation-firewall)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-555555)](#deployment-options)

FG-Analyzer turns FortiGate syslog, NPS identity data, device assignments, site definitions, and SNMPv3 WAN telemetry into one operational view for network and security teams.

[Features](#major-features) · [Architecture](#architecture) · [Installation](#installation) · [Configuration](#configuration-overview) · [Security](#security-considerations) · [Roadmap](#roadmap)

</div>

---

## Why FG-Analyzer?

Firewall logs contain valuable security and operational context, but raw events are difficult to use during day-to-day monitoring and investigation. FG-Analyzer provides a self-hosted analysis layer that helps answer practical questions:

- What is happening across all FortiGate devices?
- Which users and endpoints are associated with an IP address?
- Which sites, zones, applications, and policies are driving traffic?
- Are authentication failures developing into password spraying or brute-force activity?
- Which WAN links are healthy, congested, or unavailable?
- Which addresses should be added to a FortiGate external threat feed?
- What should be presented in an executive or AI-usage report?

The application is designed for organisations that want to retain control of their telemetry and operate the platform within their own infrastructure.

## Major features

### Centralised FortiGate log collection

- Receives FortiGate syslog and stores parsed events in PostgreSQL.
- Supports traffic, UTM, application-control, web-filter, event, and related log data.
- Provides a global overview across multiple firewalls.
- Includes log search, filtering, facets, investigation views, and CSV export.
- Uses rollups and TimescaleDB-aware storage options for longer-term analysis.
- Includes health, performance, retention, and backpressure controls for dependable collection.

### Security analytics and alerting

- Detects and groups suspicious sign-in behaviour such as password spraying, brute-force attempts, and successful sign-ins following failures.
- Provides alert review and investigation workflows.
- Supports alert exclusions to reduce known noise.
- Exposes operational insights and health series through the dashboard and API.
- Maintains audit history for sensitive administrative actions.

### FortiGate blocklist feed

- Add selected hostile addresses, or the associated `/24`, directly from eligible alerts.
- Apply an expiry period or retain entries until manually removed.
- Record analyst notes for each blocklist entry.
- Publishes a token-protected external threat feed for FortiGate consumption.
- Restricts feed access to configured firewall source addresses.
- Supports review and removal of active entries through the web interface.

### Identity, people, and device attribution

FG-Analyzer combines several sources to associate network activity with users and endpoints:

1. Username supplied directly in the firewall log, such as FSSO data.
2. Manually maintained IP-to-user or device assignments.
3. Microsoft NPS accounting and authentication logs.

Additional capabilities include:

- NPS session ingestion and offset tracking.
- MAC-based fallback when an NPS event does not include an IP address.
- Ignoring machine accounts such as `host/...` and computer accounts ending in `$`.
- Staff directory import and matching.
- Device inventory and assignment history.
- Mapping overview and attribution investigation.
- CSV import and export for operational administration.

### AI and application visibility

- Identifies configured AI tools from FortiGate application and web activity.
- Provides AI usage overview, policy/risk views, and investigation workflows.
- Includes reclassification when detection rules change.
- Supports tags and application-focused analysis.
- Generates dedicated AI activity reports for governance and management review.

> AI visibility in FG-Analyzer refers to analysing network activity associated with AI services. It is not a claim that the platform autonomously replaces analyst judgment.

### WAN and tunnel monitoring with SNMPv3

- Monitors selected FortiGate interfaces using SNMPv3.
- Supports authenticated and encrypted SNMPv3 operation.
- Discovers available interfaces before selection.
- Tracks WAN utilisation and health over time.
- Supports multiple FortiGate devices.
- Provides plain-language diagnostics for common SNMPv3 configuration failures.
- Allows devices to reuse a shared SNMPv3 user configuration where appropriate.

### Sites, zones, and network context

- Define sites and internal network ranges.
- Associate logs with operational locations and network zones.
- Use site and zone context in dashboards, investigations, and reports.
- Reject overlapping site subnets to avoid ambiguous attribution.
- Maintain network context alongside firewall, identity, and application telemetry.

### Reporting

- Executive reporting for management-level visibility.
- AI activity and governance reporting.
- Configurable report fields and report history.
- CSV export for further analysis.
- Organisation branding options for generated reports.

### Administration and resilience

- Browser-based settings and diagnostics.
- Section-based configuration management.
- Configuration revision history and safer configuration saves.
- Authentication and password management.
- TLS configuration support.
- Database connectivity testing.
- Service health endpoints and host metrics.
- Windows service and systemd deployment options.
- Database schema migration during upgrades.

## Feature map

| Area | Capabilities |
|---|---|
| **Monitor** | Overview, all logs, alerts, health, WAN links, sites |
| **Investigate** | Log explorer, facets, attribution, filtering, CSV export |
| **Threat response** | Alert grouping, exclusions, blocklist management, FortiGate feed |
| **AI & applications** | AI usage, policy/risk views, investigation, reclassification, reports |
| **People & devices** | FSSO, NPS sessions, manual mappings, staff directory, assignment history |
| **Network context** | Multiple firewalls, sites, zones, subnets, interfaces, tunnels |
| **Reporting** | Executive reports, AI reports, configurable fields, CSV output |
| **Operations** | Health checks, diagnostics, audit log, config history, migrations |

## Architecture

```text
FortiGate firewalls
  |-- Syslog ---------------------------> FG-Analyzer receiver/parser
  |-- SNMPv3 --------------------------> WAN and interface monitoring
  |-- External threat-feed request ----> Token + source-IP protected feed
                                              |
Microsoft NPS logs --------------------------> Identity/session mapping
Staff lists and manual assignments ----------> People and device attribution
                                              |
                                              v
                                  PostgreSQL / TimescaleDB
                                              |
                                              v
                 Dashboards, investigations, alerts, reports, and exports
```

### Main components

- **Collector:** Receives and parses FortiGate syslog.
- **Database layer:** Stores events, mappings, sessions, alert state, configuration history, and rollups.
- **Analytics layer:** Produces summaries, insights, alerts, attribution, and reports.
- **WAN monitor:** Polls selected interfaces through SNMPv3.
- **Web application:** Embedded dashboard and administration interface.
- **Threat-feed service:** Publishes approved blocklist entries to authorised FortiGate devices.

## Requirements

### Core requirements

- Go 1.22 or newer for source builds.
- PostgreSQL.
- Optional TimescaleDB for time-series-oriented deployment.
- One or more FortiGate devices configured to forward syslog.
- A service account and host with appropriate database and file access.

### Optional integrations

- Microsoft NPS accounting logs for wireless identity attribution.
- SNMPv3 on FortiGate for WAN/interface monitoring.
- Staff directory CSV/export data.
- TLS certificate and key for HTTPS.

## Installation

### Linux deployment

Linux is the recommended primary platform for current FG-Analyzer deployments.

Review the included guide:

```text
./deploy/linux/README-LINUX.md
```

A typical source installation follows this sequence:

```bash
# Build
./deploy/linux/build.sh

# Prepare PostgreSQL using a strong password
sudo DB_PASSWORD='replace-with-a-strong-password' ./deploy/linux/setup-postgres.sh

# Install the service
sudo ./deploy/linux/install.sh
```

The repository also includes:

- `logsikka.service` for systemd.
- `99-logsikka.conf` for host tuning.
- PostgreSQL setup and migration scripts.
- Windows-to-Linux migration tooling.
- An NPS SMB mount example.

> Some internal service names and migration paths retain the historical `logsikka` name for upgrade compatibility.

### Windows deployment

Build with PowerShell:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\scripts\build.ps1
```

Install or update the Windows service from an elevated PowerShell session:

```powershell
.\scripts\install-service.ps1
```

To remove the service:

```powershell
.\scripts\uninstall-service.ps1
```

## FortiGate syslog configuration

Configure every participating FortiGate to send logs to the FG-Analyzer host. Adapt the server address, transport, facility, and source interface to your environment.

```text
config log syslogd setting
    set status enable
    set server "FG_ANALYZER_SERVER_IP"
    set mode reliable
end
```

Also configure the relevant FortiGate log filters and policies so the required traffic, UTM, application-control, web-filter, and event records are forwarded.

> Validate commands against the FortiOS release deployed in your environment. FortiOS syntax and available settings can differ by version and model.

## Configuration overview

Configuration is primarily managed through the web interface. Main areas include:

- Database connection and retention.
- Syslog receiver and accepted event types.
- Firewall definitions.
- Sites, zones, and internal networks.
- AI/application detection rules.
- Alerts and exclusions.
- Blocklist feed and tokens.
- NPS folders and identity mapping.
- Staff and device assignments.
- SNMPv3 WAN monitoring.
- Executive and AI report settings.
- TLS, authentication, and service settings.

### NPS identity mapping

For Microsoft NPS integration:

1. Enable NPS accounting/authentication log output.
2. Ensure RADIUS accounting includes client addressing data, normally `Framed-IP-Address` through interim updates.
3. Provide the FG-Analyzer service account with read access to the NPS log location.
4. Add one NPS folder per line in **Settings > NPS user mapping**.
5. Enable MAC fallback only when it is suitable for the environment.

Identity precedence is:

```text
Firewall/FSSO username > manual mapping > NPS-derived mapping
```

## Security considerations

Before production deployment:

- Use PostgreSQL credentials dedicated to FG-Analyzer and grant only required privileges.
- Store credentials outside the source repository and never commit production secrets.
- Use SNMPv3 with authentication and privacy rather than SNMPv1/v2c.
- Restrict syslog, database, web, and SNMP access with host and network firewalls.
- Enable TLS for browser access.
- Protect the blocklist feed with a strong token and configured FortiGate source addresses.
- Run the service under a dedicated non-interactive account.
- Grant read-only permissions to NPS log shares.
- Review the application audit trail and configuration history.
- Back up both PostgreSQL and the application configuration before upgrades.
- Treat exported reports and CSV files as potentially sensitive security data.

## Upgrade and migration notes

FG-Analyzer evolved from FortiLog and was later known as LogSikka. Existing installations may therefore contain historical names in:

- Service names.
- Database names.
- configuration paths.
- migration scripts.
- documentation and compatibility aliases.

The included migration tooling is designed to preserve existing data and support staged movement from earlier Windows deployments to Linux. Always back up the database and configuration before upgrading.

For release-specific details, review:

- `CHANGES.md`
- `V6.0.16-IMPLEMENTATION.md`
- `deploy/linux/README-LINUX.md`

## Project structure

```text
.
|-- main.go                     Application entry point
|-- receiver.go                 Syslog receiver
|-- parser.go                   FortiGate log parsing
|-- database.go                 Database operations
|-- query.go                    Log queries and exploration
|-- alerts.go                   Detection and alert workflows
|-- blocklist.go                Threat-feed and blocklist management
|-- mapping.go                  Identity mapping
|-- nps.go                      Microsoft NPS ingestion
|-- directory.go               Staff/directory integration
|-- wan.go / wanhealth.go       SNMPv3 WAN monitoring
|-- report.go / aireport.go     Executive and AI reporting
|-- sites.go                    Site and subnet context
|-- auth.go                     Authentication
|-- web/                        Embedded web interface
|-- snmp/                       SNMPv3 client and USM functions
|-- deploy/linux/               Linux installation and migration assets
|-- scripts/                    Windows build and service scripts
|-- CHANGES.md                  Release history
`-- LogSikka-Roadmap.md         Product roadmap and design notes
```

## API surface

FG-Analyzer exposes internal web APIs for the embedded interface, including endpoints for:

- Logs, facets, summaries, global views, and CSV export.
- Alerts, insights, investigations, and audit history.
- Blocklist entries, settings, and the FortiGate threat feed.
- Users, staff, devices, assignments, and attribution.
- NPS sessions and status.
- WAN health and interface discovery.
- Sites, tags, reports, AI reports, and configuration history.
- Authentication, TLS, health, and database diagnostics.

These endpoints are implementation interfaces for the bundled application unless explicitly documented otherwise. Avoid treating them as a stable third-party API without versioning and access-control review.

## Roadmap

Planned and evolving areas are tracked in `LogSikka-Roadmap.md`. Key themes include:

- Stronger application and domain classification.
- Improved site-aware attribution for overlapping private address spaces.
- Additional health and wallboard views.
- Expanded reporting and investigation workflows.
- Better operational editing and validation of network configuration.
- Continued hardening, performance optimisation, and upgrade safety.

## Troubleshooting checklist

### No logs are appearing

- Confirm the FortiGate can reach the configured syslog listener.
- Verify the transport mode and port at both ends.
- Confirm the relevant FortiGate log filters are enabled.
- Review service status, receiver health, and database connectivity.
- Check whether keep/drop filters are excluding the expected subtype.

### NPS identities are missing

- Confirm the service account can read the NPS folders.
- Verify that NPS is writing accounting and authentication records.
- Check that RADIUS accounting supplies `Framed-IP-Address` or usable MAC information.
- Validate time zones and session timestamps.
- Review the NPS status page and offset state.

### SNMPv3 monitoring fails

- Confirm the SNMPv3 username exists and is enabled on the FortiGate.
- Verify the configured security level.
- Re-enter authentication and privacy passphrases.
- Confirm the FortiGate allows SNMP queries from the FG-Analyzer host.
- Use interface discovery before saving monitored interfaces.

### Blocklist feed is rejected

- Confirm the token matches the FortiGate external connector configuration.
- Verify the request originates from a configured firewall address.
- Check feed settings and active entry expiry.
- Review application logs and audit history.

## Responsible use and limitations

FG-Analyzer supports monitoring, investigation, and response, but it does not replace:

- Correct FortiGate policy design and log configuration.
- A tested incident-response process.
- Endpoint telemetry and identity-provider logs.
- Analyst validation of alerts and attribution.
- Formal evidence handling where regulatory or legal requirements apply.

Detection accuracy depends on the completeness, consistency, and timing of the source logs. NAT, shared accounts, stale DHCP assignments, overlapping address spaces, missing RADIUS attributes, and clock differences can affect attribution.

## Contributing

Issues and pull requests are welcome. For material changes:

1. Describe the operational problem.
2. Explain the expected behaviour.
3. Include tests for parser, configuration, database, or security-sensitive changes.
4. Avoid committing production logs, credentials, addresses, or customer data.
5. Update `CHANGES.md` and relevant implementation notes.

## Name history

- **FG-Analyzer:** Current public project name.
- **LogSikka:** Previous project name. *Sikka* is Sri Lankan slang for a security guard.
- **FortiLog:** Earlier collector name retained in some upgrade and compatibility notes.

## License

No license file was identified in the supplied source package. Until a license is added, standard copyright restrictions apply. If public reuse or contribution is intended, add a suitable license such as MIT, Apache-2.0, or GPL-3.0 after reviewing the implications.

---

<div align="center">

**FG-Analyzer: turning FortiGate telemetry into operational network and security intelligence.**

</div>
