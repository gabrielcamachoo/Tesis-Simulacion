#!/usr/bin/env bash
# 01_instalar.sh - Instalacion del detector HL7/MLLP en Raspberry Pi (Tesis G18 WATO)
# Requiere Raspberry Pi OS 64 bits con la red de lab conectada. Ver docs/RASPBERRY_PI_SETUP.md
set -euo pipefail
cd "$(dirname "$0")/../.."

echo "== Verificando repositorio del laboratorio =="
test -f LAB_ONLY.marker || { echo "ERROR: falta LAB_ONLY.marker en la raiz del repo (lab no autorizado)"; exit 1; }
test -f requirements.txt || { echo "ERROR: ejecutar desde el repo completo de la tesis"; exit 1; }

echo "== Paquetes del sistema =="
sudo apt-get update
sudo apt-get install -y python3 python3-venv python3-pip

echo "== Entorno virtual + dependencias =="
if [ ! -d .venv ]; then python3 -m venv .venv; fi
.venv/bin/pip install --upgrade pip
.venv/bin/pip install -r requirements.txt

echo "== Suite de pruebas (debe pasar igual que en el host) =="
.venv/bin/python -m pytest tests -q

echo "== Marcador de laboratorio (SafetyGuard lo exige en /LAB_ONLY.marker) =="
sudo touch /LAB_ONLY.marker

echo "OK instalado. Siguiente paso: 02_red_aislada.sh"
