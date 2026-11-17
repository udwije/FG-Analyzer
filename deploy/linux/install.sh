#!/usr/bin/env bash
# Install or upgrade LogSikka. Run as root from the unpacked folder: sudo bash install.sh
# Upgrade = run it again; config, accounts, certificate and spool in /var/lib/logsikka are kept.
#
# v6.0: upgrading from FortiLog (v5.x) is done here, once:
#   - the fortilog service is stopped and disabled (the new unit answers to "fortilog" too, as an alias);
#   - the system user fortilog is renamed logsikka (same UID, so every file and the NPS share mount stay readable);
#   - /var/lib/fortilog moves to /var/lib/logsikka and a symlink is left at the old place for one release;
#   - paths inside config.json and the NPS share line in /etc/fstab follow;
#   - the database is NOT renamed: config.json keeps pointing at it.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "run as root (sudo)"; exit 1; }
cd "$(dirname "$0")"
# v6.0.12: refuse an incomplete package before anything on the server is changed
for f in logsikka logsikka.service 99-logsikka.conf; do
  [[ -f $f ]] || { echo "This package is incomplete: '$f' is missing. Rebuild it - the build must finish without test errors." >&2; exit 1; }
done
sed -i 's/\r$//' ./*.sh 2>/dev/null || true
NEW=/var/lib/logsikka OLD=/var/lib/fortilog

# ------------------------------------------------------------ one-time move from FortiLog
if [[ -f /etc/systemd/system/fortilog.service && ! -L /etc/systemd/system/fortilog.service ]]; then
  echo "Upgrading from FortiLog"
  grep -q '^RequiresMountsFor=' /etc/systemd/system/fortilog.service && KEEP_MOUNTS=1 || KEEP_MOUNTS=0
  systemctl stop fortilog || true
  systemctl disable fortilog || true
  mv /etc/systemd/system/fortilog.service /etc/systemd/system/fortilog.service.v5-backup
  systemctl daemon-reload
else
  KEEP_MOUNTS=0
fi
if id fortilog &>/dev/null && ! id logsikka &>/dev/null; then
  usermod -l logsikka -d "$NEW" fortilog
  getent group fortilog >/dev/null && groupmod -n logsikka fortilog
  echo "  system user fortilog renamed to logsikka (same UID)"
  if grep -qE 'uid=fortilog|gid=fortilog' /etc/fstab; then
    cp /etc/fstab /etc/fstab.before-logsikka
    sed -i 's/uid=fortilog/uid=logsikka/g; s/gid=fortilog/gid=logsikka/g' /etc/fstab
    echo "  /etc/fstab: NPS share now mounted for logsikka (backup in /etc/fstab.before-logsikka)"
  fi
fi
if [[ -d $OLD && ! -L $OLD && ! -e $NEW ]]; then
  mv "$OLD" "$NEW"
  ln -s "$NEW" "$OLD"
  echo "  $OLD moved to $NEW (a symlink stays at the old place)"
fi
if [[ -f $NEW/config.json ]] && grep -q "$OLD/" "$NEW/config.json"; then
  cp "$NEW/config.json" "$NEW/config.json.before-logsikka"
  sed -i "s#$OLD/#$NEW/#g" "$NEW/config.json"
  echo "  config.json paths updated"
fi
[[ -f /etc/sysctl.d/99-fortilog.conf ]] && rm -f /etc/sysctl.d/99-fortilog.conf

# ------------------------------------------------------------ install
id logsikka &>/dev/null || useradd --system --home-dir "$NEW" --shell /usr/sbin/nologin logsikka
install -d -o logsikka -g logsikka -m 0750 "$NEW" "$NEW/spool"
install -d -m 0755 /opt/logsikka
if systemctl is-active --quiet logsikka; then systemctl stop logsikka; fi
[[ -f /opt/logsikka/logsikka ]] && cp /opt/logsikka/logsikka /opt/logsikka/logsikka.previous
install -m 0755 logsikka /opt/logsikka/logsikka
# keep the RequiresMountsFor line if it was enabled for the NPS share
if [[ $KEEP_MOUNTS == 1 ]] || { [[ -f /etc/systemd/system/logsikka.service ]] && grep -q '^RequiresMountsFor=' /etc/systemd/system/logsikka.service; }; then
  sed -i 's|#RequiresMountsFor=|RequiresMountsFor=|' logsikka.service
fi
install -m 0644 logsikka.service /etc/systemd/system/logsikka.service
install -m 0644 99-logsikka.conf /etc/sysctl.d/99-logsikka.conf
sysctl --system >/dev/null
timedatectl set-timezone Asia/Colombo
timedatectl set-ntp true || true
chown -R logsikka:logsikka "$NEW"

systemctl daemon-reload
systemctl enable --now logsikka
sleep 3
systemctl --no-pager --lines=12 status logsikka || true
echo
[[ -f $NEW/initial-admin-password.txt ]] && echo "First sign-in:  sudo cat $NEW/initial-admin-password.txt"
echo "Dashboard:      https://<this server>:<web port>   (self-signed certificate: accept the browser warning once)"
echo "Accounts:       sudo -u logsikka /opt/logsikka/logsikka --data $NEW user list"
echo "Logs:           journalctl -u logsikka -f"
echo "Roll back:      sudo systemctl stop logsikka && sudo cp /opt/logsikka/logsikka.previous /opt/logsikka/logsikka && sudo systemctl start logsikka"
[[ -d /opt/fortilog ]] && echo "The old program folder /opt/fortilog is no longer used: remove it once LogSikka runs well (sudo rm -r /opt/fortilog)."
exit 0
