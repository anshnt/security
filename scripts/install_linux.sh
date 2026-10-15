#!/usr/bin/env bash
# Install Aegis for the current user on Linux: pip --user + systemd user units
#   monitor service (real-time protection), daily quick-scan timer, 6-hourly signature-update timer.
# Usage: scripts/install_linux.sh [--no-systemd] [--uninstall]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UNIT_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
PYTHON="${PYTHON:-python3}"
WITH_SYSTEMD=1

for arg in "$@"; do
  case "$arg" in
    --no-systemd) WITH_SYSTEMD=0 ;;
    --uninstall)
      systemctl --user disable --now aegis-monitor.service aegis-scan.timer aegis-update.timer 2>/dev/null || true
      rm -f "$UNIT_DIR"/aegis-monitor.service "$UNIT_DIR"/aegis-scan.service "$UNIT_DIR"/aegis-scan.timer \
            "$UNIT_DIR"/aegis-update.service "$UNIT_DIR"/aegis-update.timer
      systemctl --user daemon-reload 2>/dev/null || true
      "$PYTHON" -m pip uninstall -y aegis-security || true
      echo "Aegis removed."
      exit 0 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

echo "==> Installing aegis-security (pip --user)"
"$PYTHON" -m pip install --user --upgrade "$ROOT"
if "$PYTHON" -m pip install --user "yara-python>=4.3" >/dev/null 2>&1; then
  echo "    native YARA engine installed"
else
  echo "    (yara-python not installed - continuing with the built-in rule engine)"
fi

BIN="$("$PYTHON" -c 'import sysconfig; print(sysconfig.get_path("scripts", "posix_user"))')/aegis"
[ -x "$BIN" ] || BIN="$(command -v aegis || true)"
[ -n "$BIN" ] || { echo "could not locate the aegis executable; is ~/.local/bin on PATH?" >&2; exit 1; }
echo "    aegis executable: $BIN"

if [ "$WITH_SYSTEMD" = "1" ]; then
  if ! command -v systemctl >/dev/null 2>&1; then
    echo "systemctl not found - skipping background units (run 'aegis monitor' manually)."; exit 0
  fi
  echo "==> Writing systemd user units to $UNIT_DIR"
  mkdir -p "$UNIT_DIR"
  cat > "$UNIT_DIR/aegis-monitor.service" <<UNIT
[Unit]
Description=Aegis real-time protection
After=default.target

[Service]
Type=simple
ExecStart="$BIN" monitor
Restart=on-failure
RestartSec=10
Nice=10
IOSchedulingClass=idle

[Install]
WantedBy=default.target
UNIT
  cat > "$UNIT_DIR/aegis-scan.service" <<UNIT
[Unit]
Description=Aegis quick scan

[Service]
Type=oneshot
ExecStart="$BIN" scan quick --report html
SuccessExitStatus=0 1
Nice=15
IOSchedulingClass=idle
UNIT
  cat > "$UNIT_DIR/aegis-scan.timer" <<UNIT
[Unit]
Description=Aegis daily quick scan

[Timer]
OnCalendar=*-*-* 12:30:00
Persistent=true
RandomizedDelaySec=300

[Install]
WantedBy=timers.target
UNIT
  cat > "$UNIT_DIR/aegis-update.service" <<UNIT
[Unit]
Description=Aegis signature update
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
ExecStart="$BIN" update
UNIT
  cat > "$UNIT_DIR/aegis-update.timer" <<UNIT
[Unit]
Description=Aegis signature update every 6 hours

[Timer]
OnCalendar=*-*-* 00,06,12,18:05:00
Persistent=true
RandomizedDelaySec=300

[Install]
WantedBy=timers.target
UNIT
  systemctl --user daemon-reload
  systemctl --user enable --now aegis-monitor.service aegis-scan.timer aegis-update.timer
  echo "==> Enabled: aegis-monitor.service, aegis-scan.timer, aegis-update.timer"
  echo "    Tip: 'loginctl enable-linger \$USER' keeps protection running when you are logged out."
  echo "    Status: systemctl --user status aegis-monitor.service"
fi
echo "Done. Try: aegis info"
