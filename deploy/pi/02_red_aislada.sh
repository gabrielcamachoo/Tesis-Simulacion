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
#   KALI_IP      IP de Kali (VM en modo puente) autorizada a llegar al 1550.
#                Opcional; sin ella UFW descarta el handshake del atacante y
#                el detector solo veria SYN sueltos.
#   LAB_IFACE    interfaz del laboratorio (default wlan0; eth0 si se cablea)
set -euo pipefail

LAB_IFACE="${LAB_IFACE:-wlan0}"
WATO_SIM_IP="${WATO_SIM_IP:-192.168.5.114}"
ADMIN_IP="${ADMIN_IP:-}"
KALI_IP="${KALI_IP:-}"

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
if [[ -n "$KALI_IP" ]]; then
  # Atacante del lab (campañas A01-A16) -> receptor de la Pi.
  sudo ufw allow in on "$LAB_IFACE" from "$KALI_IP" to any port 1550 proto tcp
fi
sudo ufw --force enable
sudo ufw status verbose

echo "OK red aislada. Receptor habilitado en ${LAB_IFACE}:1550 para ${WATO_SIM_IP}${KALI_IP:+ y ${KALI_IP}}."
[[ -n "$ADMIN_IP" ]] && echo "SSH permitido solo desde ${ADMIN_IP}."
echo "Nota: tcpdump (deploy/docker/raspberry) captura antes del firewall, pero si"
echo "ufw bloquea una IP la conexion nunca se establece y no hay mensajes HL7 que ver."
