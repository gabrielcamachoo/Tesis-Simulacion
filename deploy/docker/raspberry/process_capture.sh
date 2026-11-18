#!/usr/bin/env bash
# Reprocesa offline un pcap ya guardado (p. ej. uno de runs/docker-pi/live_*/pcap).
# Cada archivo va a su propia carpeta para no pisar el manifiesto de otro.
set -euo pipefail

PCAP="${1:?Uso: process_capture.sh <pcap>}"
OUT="${CAPTURE_OUTDIR:-/lab_output}"
RUN_DIR="$OUT/offline/$(basename "$PCAP" | sed 's/\.[^.]*$//')"

export LAB_AUTHORIZED=YES
mkdir -p "$RUN_DIR"

python /app/detect_pcap.py \
  --pcap "$PCAP" \
  --label "offline-$(basename "$PCAP")" \
  --outdir "$RUN_DIR"
