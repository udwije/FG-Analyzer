-- Only needed if fortigate_logs ALREADY holds rows and you want to convert it in place
-- (for example, you restored a full pg_dump instead of using migrate-from-windows.sh).
-- Stop the collector first: it locks the table and rewrites every row into day chunks. Plan roughly
-- a few minutes per 10 million rows. psql -d fortilog -f migrate-existing-table.sql
\set ON_ERROR_STOP on
CREATE EXTENSION IF NOT EXISTS timescaledb;
BEGIN;
ALTER TABLE fortigate_logs DROP CONSTRAINT IF EXISTS fortigate_logs_pkey;
CREATE INDEX IF NOT EXISTS idx_fgt_id ON fortigate_logs(id);
CREATE INDEX IF NOT EXISTS idx_fgt_ai_time ON fortigate_logs(event_time DESC) WHERE ai_tool IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_fgt_npsid ON fortigate_logs(nps_id) WHERE nps_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_fgt_type_time ON fortigate_logs(log_type, event_time DESC);
CREATE INDEX IF NOT EXISTS idx_fgt_dev_time ON fortigate_logs(device_name, event_time DESC);
SELECT create_hypertable('fortigate_logs', 'event_time', chunk_time_interval => INTERVAL '1 day', migrate_data => true);
ALTER TABLE fortigate_logs SET (timescaledb.compress, timescaledb.compress_segmentby = 'device_name', timescaledb.compress_orderby = 'event_time DESC, id DESC');
COMMIT;
SELECT add_compression_policy('fortigate_logs', INTERVAL '2 days', if_not_exists => true);
VACUUM ANALYZE fortigate_logs;
