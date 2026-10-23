#!/usr/bin/env bash
# 07_preparar_prueba_remota.sh - Prepara Pi para prueba remota Windows -> Pi (MLLP 1550)
set -euo pipefail

usage() {
  cat <<'EOF'
Uso:
  sudo bash deploy/pi/07_preparar_prueba_remota.sh --wato-ip <IP_PC_WATO> [opciones]

Opciones:
  --wato-ip <ipv4>        IP del PC Windows con el emulador WATO (requerida).
  --iface <nombre>        Interfaz de laboratorio (default: eth0).
  --service-user <user>   Usuario Linux para systemd (default: SUDO_USER o whoami).
  --repo-path <ruta>      Ruta absoluta del repo (default: autodetectada).
  --pi-ip <ipv4>          Valida que la interfaz tenga esta IP.
  --admin-ip <ipv4>       Si se indica, permite SSH (22/tcp) solo desde esa IP.
  --skip-baseline-update  No modificar baseline.yaml.
  --help                  Mostrar ayuda.
EOF
}

is_ipv4() {
  local ip="$1"
  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  IFS='.' read -r o1 o2 o3 o4 <<<"$ip"
  for oct in "$o1" "$o2" "$o3" "$o4"; do
    ((oct >= 0 && oct <= 255)) || return 1
  done
  return 0
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_REPO="$(cd "$SCRIPT_DIR/../.." && pwd)"

WATO_IP=""
LAB_IFACE="eth0"
SERVICE_USER="${SUDO_USER:-$(whoami)}"
REPO_PATH="$DEFAULT_REPO"
PI_IP_EXPECTED=""
ADMIN_IP=""
UPDATE_BASELINE="yes"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --wato-ip)
      WATO_IP="${2:-}"
      shift 2
      ;;
    --iface)
      LAB_IFACE="${2:-}"
      shift 2
      ;;
    --service-user)
      SERVICE_USER="${2:-}"
      shift 2
      ;;
    --repo-path)
      REPO_PATH="${2:-}"
      shift 2
      ;;
    --pi-ip)
      PI_IP_EXPECTED="${2:-}"
      shift 2
      ;;
    --admin-ip)
      ADMIN_IP="${2:-}"
      shift 2
      ;;
    --skip-baseline-update)
      UPDATE_BASELINE="no"
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "ERROR: opcion no reconocida: $1"
      usage
      exit 1
      ;;
  esac
done

if [[ -z "$WATO_IP" ]]; then
  echo "ERROR: --wato-ip es obligatorio."
  usage
  exit 1
fi

[[ "$WATO_IP" == */* ]] && { echo "ERROR: --wato-ip no acepta CIDR."; exit 1; }
is_ipv4 "$WATO_IP" || { echo "ERROR: --wato-ip invalida: $WATO_IP"; exit 1; }

if [[ -n "$PI_IP_EXPECTED" ]]; then
  [[ "$PI_IP_EXPECTED" == */* ]] && { echo "ERROR: --pi-ip no acepta CIDR."; exit 1; }
  is_ipv4 "$PI_IP_EXPECTED" || { echo "ERROR: --pi-ip invalida: $PI_IP_EXPECTED"; exit 1; }
fi

if [[ -n "$ADMIN_IP" ]]; then
  [[ "$ADMIN_IP" == */* ]] && { echo "ERROR: --admin-ip no acepta CIDR."; exit 1; }
  is_ipv4 "$ADMIN_IP" || { echo "ERROR: --admin-ip invalida: $ADMIN_IP"; exit 1; }
fi

[[ "$REPO_PATH" = /* ]] || { echo "ERROR: --repo-path debe ser absoluto."; exit 1; }
test -d "$REPO_PATH" || { echo "ERROR: no existe repo-path: $REPO_PATH"; exit 1; }
test -f "$REPO_PATH/LAB_ONLY.marker" || { echo "ERROR: falta $REPO_PATH/LAB_ONLY.marker"; exit 1; }
test -x "$REPO_PATH/.venv/bin/python" || { echo "ERROR: falta $REPO_PATH/.venv/bin/python"; exit 1; }
test -f "$REPO_PATH/deploy/pi/mllp-receiver.service" || { echo "ERROR: falta plantilla service"; exit 1; }
id "$SERVICE_USER" >/dev/null 2>&1 || { echo "ERROR: usuario inexistente: $SERVICE_USER"; exit 1; }

if [[ -n "$PI_IP_EXPECTED" ]]; then
  ip -4 -o addr show dev "$LAB_IFACE" | awk '{print $4}' | cut -d/ -f1 | grep -Fx "$PI_IP_EXPECTED" >/dev/null \
    || { echo "ERROR: la interfaz $LAB_IFACE no tiene la IP esperada $PI_IP_EXPECTED"; exit 1; }
fi

echo "== Parametros de preparacion =="
echo "Repo:           $REPO_PATH"
echo "Usuario service:$SERVICE_USER"
echo "Interfaz lab:   $LAB_IFACE"
echo "IP WATO:        $WATO_IP"
[[ -n "$PI_IP_EXPECTED" ]] && echo "IP Pi validada:  $PI_IP_EXPECTED"
[[ -n "$ADMIN_IP" ]] && echo "SSH admin IP:    $ADMIN_IP"

if [[ "$UPDATE_BASELINE" == "yes" ]]; then
  echo "== Actualizando baseline.yaml (allowed_ips) =="
  "$REPO_PATH/.venv/bin/python" - "$REPO_PATH/baseline.yaml" "$WATO_IP" <<'PY'
import pathlib
import re
import sys
import yaml

baseline = pathlib.Path(sys.argv[1])
new_ip = sys.argv[2]

if "/" in new_ip or not re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", new_ip):
    raise SystemExit("IP invalida para baseline.yaml (solo IPv4 exacta, sin CIDR)")
if any(not 0 <= int(o) <= 255 for o in new_ip.split(".")):
    raise SystemExit("IP invalida para baseline.yaml (octeto fuera de rango)")

data = yaml.safe_load(baseline.read_text(encoding="utf-8"))
network = data.setdefault("network_parameters", {})
allowed = network.setdefault("allowed_ips", [])
if not isinstance(allowed, list):
    raise SystemExit("network_parameters.allowed_ips no es lista")
if new_ip not in allowed:
    allowed.append(new_ip)
    baseline.write_text(
        yaml.safe_dump(data, allow_unicode=True, sort_keys=False),
        encoding="utf-8",
    )
    print(f"baseline.yaml actualizado: agregado {new_ip}")
else:
    print(f"baseline.yaml ya contiene {new_ip}")
PY
else
  echo "== baseline.yaml no se modifica (flag --skip-baseline-update) =="
fi

echo "== Marcador de laboratorio global requerido por SafetyGuard =="
sudo touch /LAB_ONLY.marker

echo "== Instalar/actualizar unidad systemd =="
UNIT_SRC="$REPO_PATH/deploy/pi/mllp-receiver.service"
UNIT_DST="/etc/systemd/system/mllp-receiver.service"
sed \
  -e "s|__REPO_PATH__|$REPO_PATH|g" \
  -e "s|__SERVICE_USER__|$SERVICE_USER|g" \
  "$UNIT_SRC" | sudo tee "$UNIT_DST" >/dev/null

echo "== Configurar UFW (solo regla exacta para MLLP 1550/tcp) =="
sudo apt-get install -y ufw >/dev/null
if [[ -n "$ADMIN_IP" ]]; then
  sudo ufw allow in on "$LAB_IFACE" from "$ADMIN_IP" to any port 22 proto tcp
fi
sudo ufw allow in on "$LAB_IFACE" from "$WATO_IP" to any port 1550 proto tcp
sudo ufw --force enable
sudo ufw reload

echo "== Recargar e iniciar servicio =="
sudo systemctl daemon-reload
sudo systemctl enable --now mllp-receiver
sudo systemctl restart mllp-receiver

echo "== Verificaciones =="
sudo systemctl --no-pager --full status mllp-receiver || true
sudo ss -ltnp | grep ':1550' || true
sudo ufw status numbered | grep -E "(1550|22/tcp)" || true
echo "Sugerencia: revisar logs con 'sudo journalctl -u mllp-receiver -n 80 --no-pager'"
