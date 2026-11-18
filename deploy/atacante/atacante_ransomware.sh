#!/usr/bin/env bash
# Atacante sintetico Linux/Kali para la Raspberry Pi receptora.
# Genera trafico MLLP anomalo etiquetado; no instala ni ejecuta malware.
# Uso:
#   ./deploy/atacante/atacante_ransomware.sh
#   ./deploy/atacante/atacante_ransomware.sh --mode ransomware
#   ./deploy/atacante/atacante_ransomware.sh --dry-run
set -euo pipefail

cd "$(dirname "$0")/../.."

MODE="all"
TARGET="192.168.5.114"
PORT="1550"
COUNT="3"
SEED="2026101401"
EXCLUDE=""
DRY_RUN="0"

usage() {
  cat <<'USAGE'
Uso: atacante_ransomware.sh [opciones]

Opciones:
  --mode all|ransomware  Campana completa A01-A16 o solo ransomware A01/A05/A06/A13/A14/A16
  --target IP            WATO objetivo (default: 192.168.5.114)
  --port PORT            Puerto MLLP (default: 1550)
  --count N              Inyecciones por escenario (default: 3)
  --seed N               Semilla reproducible (default: 2026101401)
  --exclude IDS          Escenarios excluidos, separados por comas
  --exclude-a14          Excluir el silencio prolongado de A14
  --dry-run              Validar seguridad sin enviar trafico
  -h, --help             Mostrar ayuda
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode) MODE="$2"; shift 2 ;;
    --target) TARGET="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --count) COUNT="$2"; shift 2 ;;
    --seed) SEED="$2"; shift 2 ;;
    --exclude) EXCLUDE="$2"; shift 2 ;;
    --exclude-a14) EXCLUDE="${EXCLUDE:+$EXCLUDE,}A14"; shift ;;
    --dry-run) DRY_RUN="1"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "ERROR: opcion desconocida: $1" >&2; usage >&2; exit 2 ;;
  esac
done

case "$MODE" in
  all)
    [[ -n "$EXCLUDE" ]] || EXCLUDE=""
    ;;
  ransomware)
    EXCLUDE="${EXCLUDE:+$EXCLUDE,}A02,A03,A04,A07,A08,A09,A10,A11,A12,A15"
    ;;
  *)
    echo "ERROR: --mode debe ser all o ransomware" >&2
    exit 2
    ;;
esac

if [[ ! -f LAB_ONLY.marker ]]; then
  echo "ERROR: falta LAB_ONLY.marker en la raiz del repositorio" >&2
  exit 1
fi

if [[ ! -f /LAB_ONLY.marker ]]; then
  if command -v sudo >/dev/null 2>&1; then
    echo "== Creando marcador obligatorio /LAB_ONLY.marker =="
    sudo touch /LAB_ONLY.marker
  else
    echo "ERROR: falta /LAB_ONLY.marker" >&2
    exit 1
  fi
fi

export LAB_AUTHORIZED=YES

if [[ ! -d .venv && -z "${PYTHON:-}" ]]; then
  echo "== Creando entorno virtual Python == "
  python3 -m venv .venv
fi

if [[ -x .venv/bin/python ]]; then
  PYTHON=.venv/bin/python
else
  PYTHON="${PYTHON:-python3}"
fi

"$PYTHON" -m pip install --disable-pip-version-check -q -r requirements.txt

if [[ "$DRY_RUN" == "0" ]]; then
  echo "== Verificando alcance: $TARGET:$PORT == "
  "$PYTHON" - "$TARGET" "$PORT" <<'PY'
import socket
import sys

host = sys.argv[1]
port = int(sys.argv[2])
try:
    with socket.create_connection((host, port), timeout=3):
        pass
except OSError as exc:
    print(f"ERROR: no hay receptor MLLP en {host}:{port}: {exc}", file=sys.stderr)
    raise SystemExit(1)
PY
fi

SOURCE_IP=""
if command -v ip >/dev/null 2>&1; then
  SOURCE_IP="$(ip route get "$TARGET" 2>/dev/null | awk '{for (i=1;i<=NF;i++) if ($i=="src") print $(i+1)}' || true)"
fi

echo "== Atacante Linux/Kali: $MODE == "
echo "Destino: $TARGET:$PORT"
[[ -n "$SOURCE_IP" ]] && echo "IP origen detectada: $SOURCE_IP"
echo "Semilla: $SEED"
echo "Escenarios excluidos: ${EXCLUDE:-ninguno}"
if [[ -n "$SOURCE_IP" ]]; then
  echo "Origen del atacante: $SOURCE_IP (no se agrega al baseline autorizado)"
fi

ARGS=(
  anomaly_generator.py
  --all
  --count "$COUNT"
  --host "$TARGET"
  --port "$PORT"
  --config src/config/settings.yaml
  --runs-dir runs
  --seed "$SEED"
)

if [[ -n "$EXCLUDE" ]]; then
  ARGS+=(--exclude "$EXCLUDE")
fi

if [[ "$DRY_RUN" == "1" ]]; then
  ARGS+=(--dry-run)
fi

"$PYTHON" "${ARGS[@]}"
