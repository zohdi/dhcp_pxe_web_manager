#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "ERROR: run this installer as root (sudo)." >&2
  exit 1
fi

TARGET_DIR="${1:-$PWD}"
TARGET_DIR="$(cd "$TARGET_DIR" && pwd)"
PYTHON_BIN="$(command -v python3)"
SERVICE_NAME="dhcp-manager-available-ips.service"
TIMER_NAME="dhcp-manager-available-ips.timer"
PATH_NAME="dhcp-manager-available-ips.path"

if [[ ! -f "$TARGET_DIR/refresh_available_ips.py" ]]; then
  echo "ERROR: refresh_available_ips.py not found in $TARGET_DIR" >&2
  exit 2
fi

DHCP_CONF_PATH="$(cd "$TARGET_DIR" && "$PYTHON_BIN" - <<'PY'
from pathlib import Path
from config import config
print(Path(config.DHCP_CONF).resolve())
PY
)"

cat > "/etc/systemd/system/$SERVICE_NAME" <<EOF
[Unit]
Description=Refresh DHCP Manager available IP cache
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
WorkingDirectory=$TARGET_DIR
ExecStart=$PYTHON_BIN $TARGET_DIR/refresh_available_ips.py
EOF

cat > "/etc/systemd/system/$TIMER_NAME" <<EOF
[Unit]
Description=Periodic DHCP Manager available IP refresh

[Timer]
OnBootSec=2m
OnUnitActiveSec=15m
AccuracySec=30s
RandomizedDelaySec=1m
Unit=$SERVICE_NAME

[Install]
WantedBy=timers.target
EOF

cat > "/etc/systemd/system/$PATH_NAME" <<EOF
[Unit]
Description=Refresh DHCP Manager available IP cache when dhcpd.conf changes

[Path]
PathChanged=$DHCP_CONF_PATH
Unit=$SERVICE_NAME

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "$TIMER_NAME" "$PATH_NAME"
systemctl restart "$TIMER_NAME" "$PATH_NAME"

echo "Installed and started $TIMER_NAME (about every 15 minutes)"
echo "Installed and started $PATH_NAME (watches $DHCP_CONF_PATH)"
echo "Run an immediate scan with: systemctl start $SERVICE_NAME"
echo "Check timer with: systemctl list-timers $TIMER_NAME"
echo "Check watcher with: systemctl status $PATH_NAME"
