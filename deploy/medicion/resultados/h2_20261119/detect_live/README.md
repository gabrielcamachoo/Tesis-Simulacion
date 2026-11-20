# Salida de detect_live en la Pi (medicion H2, 19-11-2026)

Copia de runs/docker-pi/live_20261120_015237/ (runs/ esta en .gitignore, por eso no se habia subido).

- alerts_pi_h2.jsonl.gz: alerts.jsonl completo de la sesion (59.599 lineas). Alertas con origen 192.168.5.160: 58.972; R-NET-001: 14.109; primera 02:08:03 UTC, ultima 03:27:49 UTC (fases CARGA).
- detect_live_summary.json: resumen acumulado de toda la sesion del detector (01:52 a 11:00 UTC del 20-11), no solo de las fases CARGA. latencia_proceso_ms: p50 3,36; p95 4,52; max 59,67.
- live_20261120_015249.pcap y live_20261120_025250.pcap: capturas rotadas del detector (trafico del emulador WATO y de Kali, sin datos de pacientes).
- SHA256SUMS.txt: hashes de estos archivos y del alerts.jsonl sin comprimir.
