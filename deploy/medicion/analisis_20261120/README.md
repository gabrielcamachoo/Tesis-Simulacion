# Análisis sobre los registros de la Pi (20-11-2026)

Análisis hechos después de la medición H2 del 19-11-2026, con la salida de `detect_live` de la Pi
(`../resultados/h2_20261119/detect_live/`). No cambian el código del detector; solo leen o repiten ese tráfico.

## 1. Cobertura por campaña (`pi_campaigns.py`)

`python3 pi_campaigns.py ../resultados/h2_20261119/detect_live/alerts_pi_h2.jsonl.gz pi_campaigns.json`

- 58.972 alertas con origen en Kali (192.168.5.160), en **224 campañas** completas de unos 15 s (74, 75 y 75 por repetición; el README de la medición anota 73 en la segunda).
- En las 224 campañas, **14 de los 15 escenarios dispararon siempre su regla esperada**.
- **A15** (mensaje de ~32 KB) no disparó R-MLLP-001 en ninguna: se detectó por R-HL7-003 y R-NET-001 (672 inyecciones). `detect_live.py` no aplica el límite de 5120 B; ese límite solo existe en el framer del receptor (`src/mllp/framing.py`).
- No es recall: no hay ground truth en la Pi y R-NET-001 marca todo mensaje de Kali.

## 2. Falsos positivos sobre el emisor legítimo y propuesta E10

En el `alerts.jsonl` de la Pi, el emisor legítimo (192.168.5.114) recibió **355 alertas R-TIME-002**: 354 de sus 366 mensajes durante las fases de carga y 1 de 261 en reposo. Es la cadencia global de R-TIME-002: casi siempre había un mensaje de Kali en los 5 s previos.

Repitiendo los dos pcap con `memdiag.py` (que alimenta `detect_live.LiveDetector` paquete a paquete):

| Código | Alertas sobre el emisor legítimo | Alertas sobre Kali |
|---|---|---|
| `feat/medicion-recursos` (= main) | 354 (`memdiag_main.json`) | 58.972 |
| main + `propuesta_E10_rtime002.diff` | **0** (`memdiag_e10.json`) | 58.972, ninguna otra regla cambia |

La corrección está en el pull request #10.

## 3. Crecimiento de memoria (`memdiag.py`)

`LAB_AUTHORIZED=YES python deploy/medicion/analisis_20261120/memdiag.py . salida.json <pcap1> <pcap2>` (desde la raíz del repo)

- El motor (`src/detection/engine.py`) guarda un `SessionState` por conexión TCP y **nunca lo libera** al cerrarse la conexión. Al final había 1345 sesiones retenidas (unas 6 por campaña).
- Memoria asignada (tracemalloc) entre las 02:23 y las 03:37 UTC: **+2,93 MB** (`memdiag_main.json`).
- Con `LIBERAR_SESIONES=1` (libera el estado de la sesión al cerrar su flujo): **+0,80 MB**, con exactamente las mismas alertas (`memdiag_liberando_sesiones.json`).
- El resto: 636 flujos TCP que `detect_live` nunca ve cerrarse (`self.flows`) y los hashes globales (`global_content_hashes`), que no se podan. El receptor además conserva `EvidenceWriter.session_metadata` de cada sesión cerrada.
- La corrección no está integrada.
