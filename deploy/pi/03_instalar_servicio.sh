#!/usr/bin/env bash
# 03_instalar_servicio.sh - Instala el receptor-detector como servicio systemd (arranque automatico)
# Ver docs/RASPBERRY_PI_SETUP.md sec 6.2.
set -euo pipefail
cd "$(dirname "$0")/../.."

ROOT="$(pwd)"
UNIT_SRC="$ROOT/deploy/pi/mllp-receiver.service"
UNIT_DST="/etc/systemd/system/mllp-receiver.service"
SERVICE_USER="${SERVICE_USER:-${SUDO_USER:-$(whoami)}}"

test -f LAB_ONLY.marker || { echo "ERROR: falta LAB_ONLY.marker"; exit 1; }
test -d .venv || { echo "ERROR: falta .venv (correr 01_instalar.sh)"; exit 1; }
id "$SERVICE_USER" >/dev/null 2>&1 || { echo "ERROR: no existe el usuario '$SERVICE_USER'"; exit 1; }
sudo touch /LAB_ONLY.marker

echo "== Instalando unidad systemd con usuario '$SERVICE_USER' y repo '$ROOT' =="
sed \
  -e "s|__REPO_PATH__|$ROOT|g" \
  -e "s|__SERVICE_USER__|$SERVICE_USER|g" \
  "$UNIT_SRC" | sudo tee "$UNIT_DST" > /dev/null

sudo systemctl daemon-reload
sudo systemctl enable --now mllp-receiver
sleep 2
systemctl is-active --quiet mllp-receiver && echo "OK servicio ACTIVO" || { echo "ERROR: servicio caido"; sudo journalctl -u mllp-receiver -n 30 --no-pager; exit 1; }
echo "== Unidad efectiva =="
grep -E '^(User=|WorkingDirectory=|ExecStartPre=|ExecStart=)' "$UNIT_DST"
echo "Logs en vivo: journalctl -u mllp-receiver -f"
