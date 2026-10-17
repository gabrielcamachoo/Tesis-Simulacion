# Raspberry Pi — Detector de ciberataques HL7/MLLP (despliegue)

La Pi ejecuta el **detector** del laboratorio (receptor MLLP + motor de reglas +
alertas JSONL). Nunca va inline en el WATO real: observa/sintetiza tráfico en la
red aislada del lab. Documentación completa: `docs/RASPBERRY_PI_SETUP.md`.

## Orden de uso

| Paso | Script | Qué hace |
|------|--------|----------|
| 1 | `01_instalar.sh` | apt + venv + `requirements.txt` + suite pytest + `/LAB_ONLY.marker` |
| 2 | `02_red_aislada.sh` | ufw: sin egress, sin ingress (solo 1550/tcp del lab) |
| 3 | `03_instalar_servicio.sh` | servicio systemd `mllp-receiver` (arranque automático) |
| 4a | `04_detector_online.sh` | **detector en línea**: escucha 127.0.0.1:1550, alerta al vuelo |
| 4b | `05_detector_offline.sh <pcap>` | **detector pasivo** (Modalidad B): `detect_pcap.py` sin abrir red |
| 5 | `06_campana_validacion.sh [semilla]` | corrida completa benigno→A01–A16→evaluación en la Pi |

## Alimentar al detector

- **WATO (benigno):** `deploy/wato/wato.ps1` desde el PC del lab apuntando
  a la IP de la Pi, o `wato_emulator.py` desde otra máquina autorizada.
- **Atacante (ransomware simulado):** `deploy/atacante/atacante_ransomware.ps1`
  (el orquestador levanta receptor+emulador+atacante él mismo; para la Pi física
  usar `06_campana_validacion.sh` o `run_experiment.py --mode local`).

## Interlocks (no negociables)

- `LAB_AUTHORIZED=YES` + `/LAB_ONLY.marker` (si falta, nada arranca).
- Red de lab aislada: sin IP pública, sin Internet en runtime
  (`block_public_ips: true`).
- Cualquier IP emisora nueva debe agregarse exacta (sin CIDR) en
  `baseline.yaml → network_parameters.allowed_ips`.
- H2 (p95 ≤ 500 µs) **solo** se verifica con `latency_bench.py` en esta Pi física.
