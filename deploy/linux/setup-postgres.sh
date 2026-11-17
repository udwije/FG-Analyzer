#!/usr/bin/env bash
# PostgreSQL 16 + TimescaleDB (Community edition) on Ubuntu 22.04/24.04 or Debian 12. Run as root once.
#   sudo DB_PASSWORD='choose-a-strong-one' ./setup-postgres.sh
# Check https://docs.timescale.com (self-hosted install) if a repository URL has changed.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "run as root (sudo)"; exit 1; }
: "${DB_PASSWORD:?set DB_PASSWORD}"
DB="${DB_NAME:-logsikka}"   # role and database name (installations from FortiLog keep "fortilog")
PGV=16
. /etc/os-release

apt-get update
apt-get install -y gnupg postgresql-common apt-transport-https lsb-release wget curl
/usr/share/postgresql-common/pgdg/apt.postgresql.org.sh -y
echo "deb https://packagecloud.io/timescale/timescaledb/${ID}/ $(lsb_release -c -s) main" > /etc/apt/sources.list.d/timescaledb.list
wget -qO- https://packagecloud.io/timescale/timescaledb/gpgkey | gpg --dearmor --yes -o /etc/apt/trusted.gpg.d/timescaledb.gpg
apt-get update
apt-get install -y "postgresql-$PGV" "timescaledb-2-postgresql-$PGV" "postgresql-client-$PGV"

# Adds timescaledb to shared_preload_libraries and sizes memory/workers for this host
timescaledb-tune --quiet --yes --pg-version "$PGV"
CONF=/etc/postgresql/$PGV/main/conf.d
mkdir -p "$CONF"
cat > "$CONF/logsikka.conf" <<'PG'
# Write-heavy log ingest
wal_compression = on
max_wal_size = 8GB
checkpoint_timeout = 15min
synchronous_commit = off          # a crash can lose < 1 s of logs; the collector's spool covers DB outages
# Dashboards must not run forever
statement_timeout = 0             # the collector sets its own per-query timeouts
idle_in_transaction_session_timeout = 10min
log_min_duration_statement = 5000
PG
systemctl restart postgresql

sudo -u postgres psql -v ON_ERROR_STOP=1 <<SQL
DO \$\$BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='${DB}') THEN
    CREATE ROLE ${DB} LOGIN PASSWORD '${DB_PASSWORD}';
  ELSE
    ALTER ROLE ${DB} PASSWORD '${DB_PASSWORD}';
  END IF;
END\$\$;
SELECT 'CREATE DATABASE ${DB} OWNER ${DB}' WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname='${DB}')\gexec
\c ${DB}
CREATE EXTENSION IF NOT EXISTS timescaledb;
SQL
sudo -u postgres psql -d "$DB" -tAc "SELECT 'TimescaleDB ' || extversion FROM pg_extension WHERE extname='timescaledb'"
echo "PostgreSQL listens on localhost only (default). The collector on this host connects to 127.0.0.1:5432."
