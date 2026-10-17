#!/usr/bin/env bash
# 04_detector_online.sh - Detector EN LINEA: receptor MLLP escuchando y alertando
# Alertas en <outdir>/alerts/alerts.jsonl (JSONL, SHA-256 de evidencia).
# Emisor esperado: wato_emulator (deploy/wato/wato.ps1 o 07_wato_en_pi.sh).
set -euo pipefail
cd "$(dirname "$0")/../.."

test -f LAB_ONLY.marker || { echo "ERROR: falta LAB_ONLY.marker"; exit 1; }
test -d .venv || { echo "ERROR: falta .venv (correr 01_instalar.sh)"; exit 1; }
export LAB_AUTHORIZED=YES

OUT="runs/pi_detector_$(date +%Y%m%d_%H%M%S)"
CFG="evidence_output/settings_deploy.yaml"
# Settings de despliegue: lab_marker_path -> LAB_ONLY.marker del repo
.venv/bin/python deploy/receptor/make_deploy_settings.py "$CFG"
echo "== Detector online: 127.0.0.1:1550 =="
echo "== Evidencia y alertas en: $OUT =="
.venv/bin/python mllp_receiver.py --config "$CFG" --host 127.0.0.1 --port 1550 --verbose --outdir "$OUT"
