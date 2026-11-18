#!/usr/bin/env bash
# 02_red_aislada.sh - Firewall de la Pi: SIN egress, solo lab (Tesis G18 WATO)
# La Pi debe estar conectada UNICAMENTE al switch/AP del lab (sin ISP, sin IP publica).
# Ver docs/RASPBERRY_PI_SETUP.md sec 3.
#
# Variables:
#   WATO_SIM_IP  IP del emisor WATO autorizado a entrar al 1550 (default 192.168.5.114)
#   ADMIN_IP     IP de administracion para SSH (22/tcp). Si se ejecuta por SSH
#                sin ADMIN_IP, el script se detiene ANTES de activar el
#                firewall para no dejarlo por fuera de la Pi.
#   LAB_IFACE    interfaz del laboratorio (default eth0)
set -euo pipefail

LAB_IFACE="${LAB_IFACE:-eth0}"
WATO_SIM_IP="${WATO_SIM_IP:-192.168.5.114}"
ADMIN_IP="${ADMIN_IP:-}"

if [[ -n "${SSH_CONNECTION:-}" && -z "$ADMIN_IP" ]]; then
  echo "ERROR: estas conectado por SSH y no definiste ADMIN_IP."
  echo "Activar el firewall ahora cortaria tu sesion. Ejecuta, por ejemplo:"
  echo "  ADMIN_IP=${SSH_CONNECTION%% *} bash $0"
  exit 1
fi

echo "== ufw: denegar entrada/salida por defecto =="
sudo apt-get install -y ufw
sudo ufw default deny outgoing
sudo ufw default deny incoming
if [[ -n "$ADMIN_IP" ]]; then
  # SSH primero, antes de 'enable'
  sudo ufw allow in on "$LAB_IFACE" from "$ADMIN_IP" to any port 22 proto tcp
fi
# Solo el emisor WATO autorizado -> receptor MLLP (Pi) en red aislada:
sudo ufw allow in on "$LAB_IFACE" from "$WATO_SIM_IP" to any port 1550 proto tcp
sudo ufw --force enable
sudo ufw status verbose

echo "OK red aislada. Receptor habilitado en ${LAB_IFACE}:1550 solo para ${WATO_SIM_IP}."
[[ -n "$ADMIN_IP" ]] && echo "SSH permitido solo desde ${ADMIN_IP}."
echo "Nota: en modo pasivo (deploy/docker/raspberry) la Pi solo escucha el puerto"
echo "espejo; ufw no bloquea la captura (tcpdump lee antes del firewall)."
