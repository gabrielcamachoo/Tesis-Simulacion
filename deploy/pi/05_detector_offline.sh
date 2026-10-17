#!/usr/bin/env bash
# 05_detector_offline.sh - Detector PASIVO (Modalidad B): analiza un PCAP ya capturado.
# No abre red. Anonimizacion activada por defecto (los derivados NO salen del lab).
# Uso: ./05_detector_offline.sh <ruta.pcap|pcapng> [etiqueta]
set -euo pipefail
cd "$(dirname "$0")/../.."

PCAP="${1:?Uso: $0 <ruta.pcap|pcapng> [etiqueta]}"
LABEL="${2:-lab}"
test -f LAB_ONLY.marker || { echo "ERROR: falta LAB_ONLY.marker"; exit 1; }
test -d .venv || { echo "ERROR: falta .venv (correr 01_instalar.sh)"; exit 1; }
test -f "$PCAP" || { echo "ERROR: no existe $PCAP"; exit 1; }
export LAB_AUTHORIZED=YES

OUT="runs/pi_offline_$(date +%Y%m%d_%H%M%S)"
echo "== Detector offline sobre: $PCAP =="
echo "== Salidas en: $OUT =="
.venv/bin/python detect_pcap.py --pcap "$PCAP" --label "$LABEL" --outdir "$OUT"
echo "Resumen:"
cat "$OUT"/*manifest*.json 2>/dev/null || ls -la "$OUT"
