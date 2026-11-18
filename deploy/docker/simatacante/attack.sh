#!/usr/bin/env bash
set -euo pipefail

TARGET="${WATO_IP:-192.168.5.114}"
PORT="${MLLP_PORT:-1550}"
MODE="${1:-all}"
shift || true

export LAB_AUTHORIZED=YES

ARGS=("$@")
for i in "${!ARGS[@]}"; do
  if [[ "${ARGS[$i]}" == "--exclude-a14" ]]; then
    unset 'ARGS[$i]'
    ARGS+=("--exclude" "A14")
  fi
done
ARGS=("${ARGS[@]}")

case "$MODE" in
  dry-run)
    exec python anomaly_generator.py --all --count 3 --host "$TARGET" --port "$PORT" \
      --config src/config/settings.yaml --seed "${SEED:-2026101401}" --dry-run "${ARGS[@]}"
    ;;
  all)
    exec python anomaly_generator.py --all --count 3 --host "$TARGET" --port "$PORT" \
      --config src/config/settings.yaml --runs-dir /lab_output --seed "${SEED:-2026101401}" "${ARGS[@]}"
    ;;
  ransomware)
    exec python anomaly_generator.py --all --count 3 --host "$TARGET" --port "$PORT" \
      --config src/config/settings.yaml --runs-dir /lab_output --seed "${SEED:-2026101401}" \
      --exclude "A02,A03,A04,A07,A08,A09,A10,A11,A12,A15" "${ARGS[@]}"
    ;;
  *)
    echo "Modo inválido: $MODE (use dry-run, all o ransomware)" >&2
    exit 2
    ;;
esac
