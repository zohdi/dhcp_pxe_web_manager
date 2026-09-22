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

if [[ ! -f "$TARGET_DIR/refresh_available_ips.py" ]]; then
  echo "ERROR: refresh_available_ips.py not found in $TARGET_DIR" >&2
  exit 2
fi

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
Description=Daily DHCP Manager available IP refresh

[Timer]
OnCalendar=daily
Persistent=true
RandomizedDelaySec=15m
Unit=$SERVICE_NAME

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now "$TIMER_NAME"

echo "Installed and enabled $TIMER_NAME"
echo "Run an immediate scan with: $PYTHON_BIN $TARGET_DIR/refresh_available_ips.py"
echo "Check timer with: systemctl list-timers $TIMER_NAME"
