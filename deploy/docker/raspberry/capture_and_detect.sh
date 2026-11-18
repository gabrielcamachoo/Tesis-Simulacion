#!/usr/bin/env bash
set -euo pipefail

INTERFACE="${CAPTURE_INTERFACE:-eth0}"
WATO_IP="${WATO_IP:-192.168.5.114}"
PORT="${MLLP_PORT:-1550}"
OUT="${CAPTURE_OUTDIR:-/lab_output}"

mkdir -p "$OUT"
export LAB_AUTHORIZED=YES

echo "Captura pasiva: interface=$INTERFACE WATO=$WATO_IP:$PORT"
exec tcpdump -i "$INTERFACE" -nn -s0 \
  "host $WATO_IP and tcp port $PORT" \
  -G 60 -W 1000 \
  -w "$OUT/capture_%Y%m%d_%H%M%S.pcapng" \
  -z /app/deploy/docker/raspberry/process_capture.sh
