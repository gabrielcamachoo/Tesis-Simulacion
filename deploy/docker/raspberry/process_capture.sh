#!/usr/bin/env bash
set -euo pipefail

PCAP="${1:?Uso: process_capture.sh <pcap>}"
OUT="${CAPTURE_OUTDIR:-/lab_output}"
RUN_DIR="$OUT/detections"

export LAB_AUTHORIZED=YES
mkdir -p "$RUN_DIR"

python /app/detect_pcap.py \
  --pcap "$PCAP" \
  --label "live-$(basename "$PCAP")" \
  --outdir "$RUN_DIR" \
  --realtime
