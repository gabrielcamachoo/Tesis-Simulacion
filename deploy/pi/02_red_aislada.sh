#!/usr/bin/env bash
# 02_red_aislada.sh - Firewall de la Pi: SIN egress, solo lab (Tesis G18 WATO)
# La Pi debe estar conectada UNICAMENTE al switch/AP del lab (sin ISP, sin IP publica).
# Ver docs/RASPBERRY_PI_SETUP.md sec 3.
set -euo pipefail

LAB_IFACE="${LAB_IFACE:-eth0}"
WATO_SIM_IP="192.168.5.114"

echo "== ufw: denegar entrada/salida por defecto =="
sudo apt-get install -y ufw
sudo ufw default deny outgoing
sudo ufw default deny incoming
# Solo simulador WATO remoto autorizado -> receptor MLLP (Pi) en red aislada:
sudo ufw allow in on "$LAB_IFACE" from "$WATO_SIM_IP" to any port 1550 proto tcp
sudo ufw --force enable
sudo ufw status verbose

echo "OK red aislada. Receptor habilitado en ${LAB_IFACE}:1550 solo para ${WATO_SIM_IP}."
echo "NOTA IMPORTANTE: si necesitas SSH de mantenimiento, agregalo ANTES de 'ufw enable'"
echo "y limitalo a una IP de administracion conocida (no abrir SSH globalmente)."
echo "Ejemplo:"
echo "  sudo ufw allow in on ${LAB_IFACE} from <IP_ADMIN> to any port 22 proto tcp"
echo "Si aun no conoces la IP de administracion, documentala y define la regla exacta antes"
echo "de habilitar UFW."
