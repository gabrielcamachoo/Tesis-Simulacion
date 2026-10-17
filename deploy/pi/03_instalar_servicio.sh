#!/usr/bin/env bash
# 03_instalar_servicio.sh - Instala el receptor-detector como servicio systemd (arranque automatico)
# Ver docs/RASPBERRY_PI_SETUP.md sec 6.2.
set -euo pipefail
cd "$(dirname "$0")/../.."

ROOT="$(pwd)"
UNIT_SRC="$ROOT/deploy/pi/mllp-receiver.service"
UNIT_DST="/etc/systemd/system/mllp-receiver.service"

test -f LAB_ONLY.marker || { echo "ERROR: falta LAB_ONLY.marker"; exit 1; }
test -d .venv || { echo "ERROR: falta .venv (correr 01_instalar.sh)"; exit 1; }
sudo touch /LAB_ONLY.marker

echo "== Ajustar WorkingDirectory al path real del repo: $ROOT =="
sed "s|/home/pi/wato|$ROOT|g" "$UNIT_SRC" | sudo tee "$UNIT_DST" > /dev/null

sudo systemctl daemon-reload
sudo systemctl enable --now mllp-receiver
sleep 2
systemctl is-active --quiet mllp-receiver && echo "OK servicio ACTIVO" || { echo "ERROR: servicio caido"; sudo journalctl -u mllp-receiver -n 30 --no-pager; exit 1; }
echo "Logs en vivo: journalctl -u mllp-receiver -f"
