#!/usr/bin/env bash
# 06_campana_validacion.sh - Campana completa en la Pi: benigno -> A01-A16 -> benigno -> evaluacion
# Misma metodologia que el host (docs/VALIDATION_PROTOCOL.md). A14 dura ~135 s.
# Uso: ./06_campana_validacion.sh [semilla]   (default 20261014, exclude A14)
set -euo pipefail
cd "$(dirname "$0")/../.."

SEED="${1:-20261014}"
test -f LAB_ONLY.marker || { echo "ERROR: falta LAB_ONLY.marker"; exit 1; }
test -d .venv || { echo "ERROR: falta .venv (correr 01_instalar.sh)"; exit 1; }
export LAB_AUTHORIZED=YES

echo "== Campana en la Pi (semilla $SEED, exclude A14) =="
.venv/bin/python run_experiment.py --mode local --exclude A14 --seed "$SEED"
