#!/usr/bin/env bash
# Raspberry Pi - detector en vivo con tcpdump sobre la interfaz del lab.
# Topologia actual (opcion A): la Pi es el receptor MLLP (mllp-receiver.service)
# y este proceso captura lo que le llega. Con un switch con mirror/SPAN el
# mismo script sirve para el modo pasivo real (CAPTURE_INTERFACE=eth0).
#
# Un solo proceso (detect_live.py) lanza tcpdump y mantiene el motor de
# detección con estado continuo: no se pierden silencios entre archivos y el
# vigilante de silencio (E3) alerta aunque el canal muera del todo.
# Los pcap crudos quedan como evidencia rotada en $OUT/live_*/pcap con su
# SHA256SUMS.txt. Resumen por regla y por IP en detect_live_summary.json.
set -euo pipefail

INTERFACE="${CAPTURE_INTERFACE:-wlan0}"
PORT="${MLLP_PORT:-1550}"
OUT="${CAPTURE_OUTDIR:-/lab_output}"
FILTER="${CAPTURE_FILTER:-tcp port ${PORT}}"
ROTATE="${ROTATE_SECONDS:-3600}"
EXTRA="${EXTRA_ALLOWED_IPS:-}"
RUN_DIR="$OUT/live_$(date +%Y%m%d_%H%M%S)"

mkdir -p "$RUN_DIR"
export LAB_AUTHORIZED=YES
cd /app

echo "Captura en vivo: interfaz=$INTERFACE filtro='$FILTER' salida=$RUN_DIR"
[[ -n "$EXTRA" ]] && echo "IPs autorizadas extra (solo esta corrida): $EXTRA"

exec python /app/detect_live.py \
  --interface "$INTERFACE" \
  --bpf "$FILTER" \
  --port "$PORT" \
  --outdir "$RUN_DIR" \
  --label "pi-live" \
  --rotate-seconds "$ROTATE" \
  --extra-allowed-ips "$EXTRA"
