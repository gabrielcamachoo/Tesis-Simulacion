#!/usr/bin/env bash
# 02_red_aislada.sh - Firewall de la Pi: SIN egress, solo lab (Tesis G18 WATO)
# La Pi debe estar conectada UNICAMENTE al switch/AP del lab (sin ISP, sin IP publica).
# Ver docs/RASPBERRY_PI_SETUP.md sec 3.
set -euo pipefail

echo "== ufw: denegar entrada/salida por defecto =="
sudo apt-get install -y ufw
sudo ufw default deny outgoing
sudo ufw default deny incoming
# Solo si el emulador corre en otra maquina del lab y habla con el receptor de la Pi:
sudo ufw allow in on eth0 to any port 1550 proto tcp
sudo ufw --force enable
sudo ufw status verbose

echo "OK red aislada. NOTA: si necesitas SSH de mantenimiento, anadir ANTES de enable:"
echo "  sudo ufw allow in on eth0 to any port 22 proto tcp"
