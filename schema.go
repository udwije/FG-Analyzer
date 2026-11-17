package main

const schemaSQL = `
CREATE TABLE IF NOT EXISTS fortigate_logs (
 id bigserial PRIMARY KEY, event_time timestamptz NOT NULL, received_at timestamptz NOT NULL DEFAULT now(), source_ip inet NOT NULL,
 device_id text, vdom text, log_id text, log_type text, subtype text, level text, src_ip inet, src_port integer, dst_ip inet, dst_port integer,
 protocol text, action text, policy_id integer, policy_name text, user_name text, application text, category text, hostname text, url text,
 sent_bytes bigint NOT NULL DEFAULT 0, received_bytes bigint NOT NULL DEFAULT 0, duration_seconds bigint NOT NULL DEFAULT 0,
 parse_status text NOT NULL DEFAULT 'parsed', parse_error text, fields jsonb NOT NULL DEFAULT '{}'::jsonb, raw_message text NOT NULL);
CREATE INDEX IF NOT EXISTS idx_fgt_event_time ON fortigate_logs(event_time DESC);
CREATE INDEX IF NOT EXISTS idx_fgt_src_time ON fortigate_logs(src_ip,event_time DESC);
CREATE INDEX IF NOT EXISTS idx_fgt_app_time ON fortigate_logs(application,event_time DESC);
CREATE INDEX IF NOT EXISTS idx_fgt_subtype_time ON fortigate_logs(subtype,event_time DESC);
ALTER TABLE fortigate_logs ADD COLUMN IF NOT EXISTS app_risk text;
CREATE INDEX IF NOT EXISTS idx_fgt_user_time ON fortigate_logs(user_name,event_time DESC);
CREATE INDEX IF NOT EXISTS idx_fgt_host_time ON fortigate_logs(hostname,event_time DESC);
CREATE INDEX IF NOT EXISTS idx_fgt_dst_time ON fortigate_logs(dst_ip,event_time DESC);
DROP INDEX IF EXISTS idx_fgt_fields_gin;
ALTER TABLE fortigate_logs ADD COLUMN IF NOT EXISTS map_id bigint;
CREATE INDEX IF NOT EXISTS idx_fgt_mapid ON fortigate_logs(map_id) WHERE map_id IS NOT NULL;
CREATE TABLE IF NOT EXISTS ip_user_map (id bigserial PRIMARY KEY, ip inet NOT NULL, user_name text NOT NULL, valid_from timestamptz NOT NULL, valid_to timestamptz NOT NULL, note text, created_at timestamptz NOT NULL DEFAULT now());
CREATE INDEX IF NOT EXISTS idx_ipmap_ip ON ip_user_map(ip, valid_from, valid_to);

-- v5: firewall name, client MAC, AI tag, NPS user mapping
ALTER TABLE fortigate_logs ADD COLUMN IF NOT EXISTS device_name text;
ALTER TABLE fortigate_logs ADD COLUMN IF NOT EXISTS src_mac text;
ALTER TABLE fortigate_logs ADD COLUMN IF NOT EXISTS ai_tool text;
ALTER TABLE fortigate_logs ADD COLUMN IF NOT EXISTS nps_id bigint;

CREATE TABLE IF NOT EXISTS nps_sessions (id bigserial PRIMARY KEY, ip inet NOT NULL, user_name text NOT NULL, mac text, nas text,
 origin text NOT NULL DEFAULT 'nps', started timestamptz NOT NULL, last_seen timestamptz NOT NULL, ended timestamptz, end_reason text);
CREATE INDEX IF NOT EXISTS idx_nps_ip ON nps_sessions(ip, started DESC);
CREATE INDEX IF NOT EXISTS idx_nps_user ON nps_sessions(user_name, started DESC);
CREATE INDEX IF NOT EXISTS idx_nps_open ON nps_sessions(last_seen) WHERE ended IS NULL;
CREATE TABLE IF NOT EXISTS nps_offsets (path text PRIMARY KEY, file_offset bigint NOT NULL, updated timestamptz NOT NULL DEFAULT now());
-- v5.5: dashboard summaries (rollups), filled by the collector from the raw logs
CREATE TABLE IF NOT EXISTS rollup_5m (bucket timestamptz NOT NULL, fw text NOT NULL, log_type text NOT NULL, subtype text NOT NULL, level text NOT NULL,
 cnt bigint NOT NULL, blk bigint NOT NULL, byt bigint NOT NULL, snt bigint NOT NULL, usr bigint NOT NULL, nps bigint NOT NULL, mp bigint NOT NULL,
 last_event timestamptz, PRIMARY KEY (bucket, fw, log_type, subtype, level));
CREATE TABLE IF NOT EXISTS rollup_1h (dim text NOT NULL, hour timestamptz NOT NULL, fw text NOT NULL, log_type text NOT NULL, name text NOT NULL,
 cnt bigint NOT NULL, blk bigint NOT NULL, byt bigint NOT NULL, snt bigint NOT NULL, PRIMARY KEY (dim, hour, fw, log_type, name));
CREATE INDEX IF NOT EXISTS idx_r1h_hour ON rollup_1h(hour);
CREATE TABLE IF NOT EXISTS rollup_state (name text PRIMARY KEY, upto timestamptz NOT NULL);
-- v5.5: who signed in, searched, exported or changed settings
CREATE TABLE IF NOT EXISTS audit_log (id bigserial PRIMARY KEY, at timestamptz NOT NULL DEFAULT now(), username text, ip text, action text NOT NULL, detail text);
CREATE INDEX IF NOT EXISTS idx_audit_at ON audit_log(at DESC);
-- v5.6: saved custom reports
CREATE TABLE IF NOT EXISTS report_defs (id bigserial PRIMARY KEY, name text NOT NULL, owner text NOT NULL, shared boolean NOT NULL DEFAULT false,
 spec jsonb NOT NULL, filters text NOT NULL DEFAULT '', created timestamptz NOT NULL DEFAULT now(), updated timestamptz NOT NULL DEFAULT now());
CREATE INDEX IF NOT EXISTS idx_report_owner ON report_defs(owner);
-- v5.10: AI summary. One row per hour x firewall x log type x subtype x AI tool x user x device x destination x action
-- x category x risk x application x country. The AI tabs read it instead of decompressing days of raw logs.
CREATE TABLE IF NOT EXISTS rollup_ai (hour timestamptz NOT NULL, fw text NOT NULL, log_type text NOT NULL, sub text NOT NULL, tool text NOT NULL,
 usr text NOT NULL, src text NOT NULL, dest text NOT NULL, act text NOT NULL, cat text NOT NULL, risk text NOT NULL, app text NOT NULL, country text NOT NULL,
 cnt bigint NOT NULL, blk bigint NOT NULL, byt bigint NOT NULL, snt bigint NOT NULL, gen bigint NOT NULL, nps bigint NOT NULL, mp bigint NOT NULL,
 fe timestamptz, le timestamptz);
CREATE INDEX IF NOT EXISTS idx_rai_hour ON rollup_ai(hour);
CREATE INDEX IF NOT EXISTS idx_rai_tool ON rollup_ai(tool, hour);
-- v5.10: executive summary exclusions. Per hour, what the configured exclusions remove (sig = which rule set).
-- The row with fw = '' is a marker: "this hour was computed for this rule set" (even when nothing matched).
CREATE TABLE IF NOT EXISTS rollup_excl (hour timestamptz NOT NULL, sig text NOT NULL, fw text NOT NULL, log_type text NOT NULL, subtype text NOT NULL,
 cnt bigint NOT NULL, blk bigint NOT NULL, byt bigint NOT NULL, snt bigint NOT NULL, usr bigint NOT NULL, PRIMARY KEY (hour, sig, fw, log_type, subtype));
-- v5.11: sign-ins and configuration changes per hour (kind: failed_admin, failed_vpn, success, cfg)
CREATE TABLE IF NOT EXISTS rollup_evt (hour timestamptz NOT NULL, fw text NOT NULL, kind text NOT NULL, src text NOT NULL, usr text NOT NULL,
 cnt bigint NOT NULL, last_at timestamptz, PRIMARY KEY (hour, fw, kind, src, usr));
-- v5.12: bytes of one log. Long-lived session statistics (log id 20) carry the running total in sent_bytes and the
-- increment in fields; logs stored by v5.12 already hold the increment. Inlined by the planner.
CREATE OR REPLACE FUNCTION fl_sent(lid text, f jsonb, b bigint) RETURNS bigint LANGUAGE sql IMMUTABLE PARALLEL SAFE AS
 $fn$ SELECT CASE WHEN lid = '0000000020' AND f->>'sentdelta' ~ '^[0-9]{1,18}$' THEN (f->>'sentdelta')::bigint ELSE coalesce(b, 0) END $fn$;
CREATE OR REPLACE FUNCTION fl_rcvd(lid text, f jsonb, b bigint) RETURNS bigint LANGUAGE sql IMMUTABLE PARALLEL SAFE AS
 $fn$ SELECT CASE WHEN lid = '0000000020' AND f->>'rcvddelta' ~ '^[0-9]{1,18}$' THEN (f->>'rcvddelta')::bigint ELSE coalesce(b, 0) END $fn$;
-- v5.12: traffic direction in the summaries (internet, inbound, internal, firewall; '' = not a traffic log, or summarised before v5.12)
ALTER TABLE rollup_5m ADD COLUMN IF NOT EXISTS zone text NOT NULL DEFAULT '';
ALTER TABLE rollup_5m DROP CONSTRAINT IF EXISTS rollup_5m_pkey;
CREATE UNIQUE INDEX IF NOT EXISTS ux_r5m ON rollup_5m(bucket, fw, log_type, subtype, level, zone);
ALTER TABLE rollup_excl ADD COLUMN IF NOT EXISTS zone text NOT NULL DEFAULT '';
ALTER TABLE rollup_excl DROP CONSTRAINT IF EXISTS rollup_excl_pkey;
CREATE UNIQUE INDEX IF NOT EXISTS ux_rexcl ON rollup_excl(hour, sig, fw, log_type, subtype, zone);
-- v5.13: daily summary of the hourly top lists (finished days), and which days are built
CREATE TABLE IF NOT EXISTS rollup_1d (dim text NOT NULL, day timestamptz NOT NULL, fw text NOT NULL, log_type text NOT NULL, name text NOT NULL,
 cnt bigint NOT NULL, blk bigint NOT NULL, byt bigint NOT NULL, snt bigint NOT NULL, PRIMARY KEY (dim, day, fw, log_type, name));
CREATE INDEX IF NOT EXISTS idx_r1d_day ON rollup_1d(day);
CREATE TABLE IF NOT EXISTS rollup_1d_done (day timestamptz PRIMARY KEY, built timestamptz NOT NULL);
-- v5.13: rows a manual mapping labelled when it was saved (the list no longer counts them on every visit)
ALTER TABLE ip_user_map ADD COLUMN IF NOT EXISTS rows_applied bigint NOT NULL DEFAULT -1;
-- v5.13: staff directory (from staff.csv), permanent device assignments, their history, and detections
CREATE TABLE IF NOT EXISTS staff (username text PRIMARY KEY, upn text, display text, dept text, title text, email text, active boolean NOT NULL,
 ou text, first_import timestamptz NOT NULL DEFAULT now(), last_import timestamptz NOT NULL DEFAULT now(), left_at timestamptz);
CREATE TABLE IF NOT EXISTS assignments (id bigserial PRIMARY KEY, kind text NOT NULL, value text NOT NULL, type text NOT NULL, owner text NOT NULL,
 dept text, note text, mac text, until timestamptz, created timestamptz NOT NULL DEFAULT now(), updated timestamptz NOT NULL DEFAULT now(), created_by text,
 UNIQUE (kind, value));
CREATE TABLE IF NOT EXISTS assign_log (id bigserial PRIMARY KEY, at timestamptz NOT NULL DEFAULT now(), actor text, action text NOT NULL, assignment_id bigint, detail text);
CREATE INDEX IF NOT EXISTS idx_assign_log_at ON assign_log(at DESC);
CREATE TABLE IF NOT EXISTS alerts (id bigserial PRIMARY KEY, key text NOT NULL UNIQUE, kind text NOT NULL, severity text NOT NULL, title text NOT NULL,
 detail text, subject text, first_seen timestamptz NOT NULL, last_seen timestamptz NOT NULL, count bigint NOT NULL DEFAULT 1,
 status text NOT NULL DEFAULT 'open', ack_by text, updated timestamptz NOT NULL DEFAULT now());
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status, last_seen DESC);
-- v5.14: the sign-in summary keeps how the firewall was reached (https, ssh, ssl vpn ...) and which of its addresses
ALTER TABLE rollup_evt ADD COLUMN IF NOT EXISTS via text NOT NULL DEFAULT '';
ALTER TABLE rollup_evt ADD COLUMN IF NOT EXISTS tgt text NOT NULL DEFAULT '';
ALTER TABLE rollup_evt DROP CONSTRAINT IF EXISTS rollup_evt_pkey;
CREATE UNIQUE INDEX IF NOT EXISTS ux_revt ON rollup_evt(hour, fw, kind, src, usr, via, tgt);
CREATE INDEX IF NOT EXISTS idx_revt_hour ON rollup_evt(hour);
-- v5.14: alerts carry the firewall(s), how they were reached and the source addresses
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS fw text NOT NULL DEFAULT '';
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS via text NOT NULL DEFAULT '';
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS sources text NOT NULL DEFAULT '';
-- v5.16: WAN links over SNMPv3 (bits per second, one row per interface per poll)
CREATE TABLE IF NOT EXISTS wan_samples (ts timestamptz NOT NULL, dev text NOT NULL, iface text NOT NULL, rx double precision NOT NULL,
 tx double precision NOT NULL, up boolean NOT NULL DEFAULT true);
CREATE INDEX IF NOT EXISTS idx_wan_dev_ts ON wan_samples(dev, iface, ts DESC);
CREATE INDEX IF NOT EXISTS idx_wan_ts ON wan_samples(ts);
-- v6.0.6: exact WAN counter deltas and measured interval; nullable keeps pre-upgrade history compatible
ALTER TABLE wan_samples ADD COLUMN IF NOT EXISTS bytes_in bigint;
ALTER TABLE wan_samples ADD COLUMN IF NOT EXISTS bytes_out bigint;
ALTER TABLE wan_samples ADD COLUMN IF NOT EXISTS interval_seconds double precision;
-- v5.21: WAN health history (FortiGate MIB): firewall load, SD-WAN health per member, IPsec tunnels
CREATE TABLE IF NOT EXISTS wan_sys (ts timestamptz NOT NULL, dev text NOT NULL, cpu double precision, mem double precision, sessions double precision);
CREATE INDEX IF NOT EXISTS idx_wsys_dev_ts ON wan_sys(dev, ts DESC);
CREATE TABLE IF NOT EXISTS wan_sla (ts timestamptz NOT NULL, dev text NOT NULL, iface text NOT NULL, chk text NOT NULL, alive boolean NOT NULL,
 latency double precision NOT NULL, jitter double precision NOT NULL, loss double precision NOT NULL);
CREATE INDEX IF NOT EXISTS idx_wsla_ts ON wan_sla(ts);
CREATE TABLE IF NOT EXISTS wan_vpn (ts timestamptz NOT NULL, dev text NOT NULL, tunnel text NOT NULL, up boolean NOT NULL, rx double precision NOT NULL,
 tx double precision NOT NULL);
CREATE INDEX IF NOT EXISTS idx_wvpn_ts ON wan_vpn(ts);
-- v5.20: blocklist published as a FortiGate external threat feed
CREATE TABLE IF NOT EXISTS blocklist (id bigserial PRIMARY KEY, entry text NOT NULL UNIQUE, note text, alert_id bigint, added_by text,
 added timestamptz NOT NULL DEFAULT now(), expires timestamptz);
`

// Built after start-up with CREATE INDEX CONCURRENTLY: on a large v2/v4 table a normal CREATE INDEX
// blocks inserts and holds the service at start-up for minutes.
var backgroundIndexes = []string{
	`CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_fgt_ai_time ON fortigate_logs(event_time DESC) WHERE ai_tool IS NOT NULL`,
	`CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_fgt_npsid ON fortigate_logs(nps_id) WHERE nps_id IS NOT NULL`,
	`CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_fgt_type_time ON fortigate_logs(log_type,event_time DESC)`,
	`CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_fgt_dev_time ON fortigate_logs(device_name,event_time DESC)`,
}
