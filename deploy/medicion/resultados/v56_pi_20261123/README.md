# Corrida física v5.6 en la Raspberry Pi — 23/24-11-2026

Paso 2 de `docs/HANDOFF_HARDWARE_PI.md`: confirmación en vivo de E10, D-02, D-04 y D-06
sobre `main` `c360eea`, con ground truth registrado en Kali.

## Montaje

| Equipo | IP | Rol |
|---|---|---|
| Raspberry Pi 3 Model B Rev 1.2 (`RaspiTesis`, wlan0) | 192.168.5.134 | receptor MLLP (systemd) + `pi-mllp-detector` (detect_live.py en Docker) |
| PC Windows | 192.168.5.114 | emisor benigno `wato-benign` (STANDBY, 1 msg/10 s) + `medir_simwato.ps1` |
| Kali | 192.168.5.160 | `anomaly_generator.py --all --exclude A14 --count 3`, semillas 200001+ |

- Relojes: Pi y Kali `System clock synchronized: yes`; PC sin `w32tm /resync` (requería admin).
- UFW de la Pi estaba **inactivo** antes de la corrida; se activó con `deploy/pi/02_red_aislada.sh`
  (`ADMIN_IP=192.168.5.114 KALI_IP=192.168.5.160 LAB_IFACE=wlan0`).
- Detector reconstruido (`up -d --build --force-recreate`), receptor reiniciado, carpeta de salida nueva.
- Suite en la Pi: 294 passed, 1 failed (`test_bench_smoke` asume `es_raspberry_pi is False`; en la Pi es `True`, es decir D-06 funcionando).

## Fases (UTC)

| Fase | Inicio | Fin |
|---|---|---|
| REPOSO1 | 23:36:25 | 23:43:56 |
| CARGA | 23:43:56 | 00:05:19 (último ataque 00:04:25) |
| REPOSO2 | 00:05:19 | 00:10:19 (+~30 s hasta detener medidores) |

**Incidente:** entre 23:41:34 y 23:43:56 las fases se marcaron `CARGA` pero Kali no atacaba
(su loop falló por falta de `.venv`; se usó `python3` del sistema). Por eso REPOSO1 dura ~7,5 min.
`pi_v56_rep1.csv` es el crudo sin tocar; `pi_v56_rep1_fases.csv` reetiqueta esas 67 filas a
`REPOSO1` y es el que se analiza. En `pc_v56_rep1.csv` no se reetiquetó (el emisor es constante).

## Resultados

| Criterio | Resultado | Veredicto |
|---|---|---|
| E10: alertas sobre 192.168.5.114 en la ventana de 30 min | **0** | cumple |
| D-02: pendiente `detector_rss_mb` en CARGA | **+0,009 MB/min**; `lab_rss_mb` máx **41,0 MB** (≤ 64) | cumple |
| H2 CPU: `lab_cpu_pct` promedio en CARGA | **9,9 %** (≤ 50 %) | cumple |
| D-04: A15 → R-MLLP-001 | **228/228** | cumple |
| D-06: `es_raspberry_pi` / `modelo_placa` | `true` / `Raspberry Pi 3 Model B Rev 1.2` | cumple |
| Recall / Precisión / F1 (`evaluate.py`, 4864 inyecciones) | **1,0000 / 0,9998 / 0,9999** (TP 4864, FP 1, FN 0) | cumple (recall ≥ 0,90) |
| H2 latencia p95 (`latency_bench.py`, 3×1000) | **1744,41 µs** vs 500 µs | **FAIL** (Pi 3B, igual que antes) |
| Throttling | `0x50000` antes y después; dmesg sin eventos nuevos | válida |

- El único FP es `R-TIME-002` por **silencio** sobre 192.168.5.114 a las 00:11:11, después del fin
  de la corrida, cuando se detuvo el emisor (canal caído real). No se eliminó del registro.
- Latencia de detección: p50 473,8 ms, p95 1013,9 ms. 19 284 alertas, 14 419 correlacionadas.
- `injection_id` se repite entre iteraciones del loop de Kali (64 únicos en 4864); `evaluate.py`
  empareja por origen y ventana temporal, no por ID.
- PCAP de la captura en vivo: `live_20261123_233625.pcap` (12,7 MB).

## Archivos

`*_rep1.csv` crudos, `pi_v56_rep1_fases.csv`, resúmenes `*_resumen.md` + SVG, `latency_pi_v56.json`,
`detect_live_summary.json`, `evaluation_hardware.json`, `ground_truth.jsonl.gz` (Kali),
`alerts.jsonl.gz` (Pi), `dmesg_*`, `throttled_*`, `inicio/fin_corrida.txt`. Hashes en `SHA256SUMS.txt`.
