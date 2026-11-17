#!/usr/bin/env bash
# Move mappings, NPS sessions and (optionally) log history from the Windows PostgreSQL to the new Linux one.
# Run on the Linux server. The Windows PostgreSQL must accept a connection from this host (pg_hba.conf + firewall).
#
#   export OLD="host=10.0.0.20 port=5432 dbname=fortilog user=fortilog password=..."
#   export NEW="host=127.0.0.1 port=5432 dbname=fortilog user=fortilog password=..."
#   ./migrate-from-windows.sh prepare     # collector STOPPED: identity tables + id offsets
#   (start the Linux collector, point the FortiGates at it)
#   ./migrate-from-windows.sh logs 30     # collector RUNNING: copy the last 30 days of logs, one day at a time
set -euo pipefail
: "${OLD:?set OLD}"; : "${NEW:?set NEW}"
COLS="event_time,received_at,source_ip,device_id,vdom,log_id,log_type,subtype,level,src_ip,src_port,dst_ip,dst_port,protocol,action,policy_id,policy_name,user_name,application,category,hostname,url,sent_bytes,received_bytes,duration_seconds,parse_status,parse_error,fields,raw_message,app_risk,map_id,device_name,src_mac,ai_tool,nps_id"

case "${1:-}" in
prepare)
  if systemctl is-active --quiet logsikka; then echo "stop LogSikka first: sudo systemctl stop logsikka"; exit 1; fi
  psql "$NEW" -tAc "SELECT 1 FROM fortigate_logs LIMIT 0" >/dev/null || { echo "start the collector once so it creates the schema, then stop it"; exit 1; }
  for t in ip_user_map nps_sessions; do
    n=$(psql "$NEW" -tAc "SELECT count(*) FROM $t")
    [[ $n == 0 ]] || { echo "$t already has $n rows on the new server; not copying"; continue; }
    echo "copying $t ..."
    psql "$OLD" -c "\copy $t TO STDOUT (FORMAT binary)" | psql "$NEW" -c "\copy $t FROM STDIN (FORMAT binary)"
    psql "$NEW" -tAc "SELECT setval(pg_get_serial_sequence('$t','id'), greatest(1,(SELECT max(id) FROM $t)))" >/dev/null
  done
  echo "done: mappings and NPS sessions copied."
  echo "NPS file offsets are not copied (paths change); keep 'read back (hours)' small on the first start."
  ;;
logs)
  # Run ONCE, after the Linux collector is live. Copies old logs up to the first log the new collector stored,
  # newest day first, so the dashboards fill backwards and nothing is duplicated.
  days=${2:-30}
  cut=$(psql "$NEW" -tAc "SELECT min(event_time) FROM fortigate_logs")
  [[ -n $cut ]] || { echo "the Linux collector has stored nothing yet; point the FortiGates at it first"; exit 1; }
  [[ -f "$HOME/.logsikka-history-done" ]] && { echo "history was already copied (remove ~/.logsikka-history-done to force)"; exit 1; }
  echo "copying old logs before $cut, last $days days"
  for ((d=0; d<days; d++)); do
    w="event_time < '$cut'::timestamptz - interval '$d days' AND event_time >= '$cut'::timestamptz - interval '$((d+1)) days'"
    echo "  day -$((d+1))"
    psql "$OLD" -c "\copy (SELECT $COLS FROM fortigate_logs WHERE $w) TO STDOUT (FORMAT binary)" \
      | psql "$NEW" -c "\copy fortigate_logs($COLS) FROM STDIN (FORMAT binary)"
  done
  touch "$HOME/.logsikka-history-done"
  echo "History copied. Chunks older than 7 days are compressed by the TimescaleDB job, or right now with:"
  echo "  SELECT compress_chunk(c, true) FROM show_chunks('fortigate_logs', older_than => interval '7 days') c;"
  ;;
*) sed -n '2,12p' "$0"; exit 1;;
esac
