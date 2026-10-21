# Resultados de la Tesis — Compilado para Defensa

**Proyecto:** Detector determinista de anomalías/ataques HL7/MLLP para el monitor
anestésico Mindray WATO EX-35 (Tesis G18 SIDRE, Pontificia Universidad Javeriana)
**Fecha de este compilado:** 2026-10-17 · **Host de medición:** PC Windows (declarado)
**Fuentes:** corridas selladas en `analysis_output/validation/` + `docs/RESULTS_20261014.md`

> Taxonomía usada: **MEDIDO** = número de corrida sellada; **OBSERVADO** = evidencia
> real del WATO; **NO_VERIFICADO** = pendiente de hardware o aprobación.

## 0. Resumen ejecutivo (para la defensa)

| Hipótesis | Enunciado | Estado | Evidencia |
|---|---|---|---|
| **H1 — Efectividad** | ADR ≥ 90 % sobre ataques ATT&CK ICS inyectados | **ACEPTADA (MEDIDO)** | ADR **100 %** (2010/2010 TP), IC95 Wilson [99.8, 100.0], 60 corridas selladas (2026-10-14) |
| **H2 — Latencia** | p95 lectura→alerta ≤ 500 µs por mensaje | **PASS en PC / NO_VERIFICADO en Pi** | Bench 3×1000 msgs: p95 **177.5 µs** (PC). Requiere repetir en la Pi física |
| **H3 — Falsos positivos** | FP sobre corpus benigno = 0 | **CUMPLE en STANDBY y RUNNING (MEDIDO)** | Evidencia real: **FP = 0** en STANDBY (43 ORU) y **FP = 0** en RUNNING (99 ORU, 6 modos) con baseline bimodal v1.1 + E1–E8 |

| Entrega operativa (2026-10-17) | Resultado |
|---|---|
| Topología Raspberry Pi (docker) — A01–A16 | **recall 1.0000**, precision 0.9846 (1 FP jitter), 15/15 escenarios 100 % |
| Campaña atacante ransomware — A01,A05,A06,A13,A14,A16 | **TP=20 FP=0 FN=0**, recall=precision=F1 **1.0000** |
| Despliegue WATO standalone (benigno) | 8/8 ORU + 8/8 ACK `AA`, **0 alertas**, sesión 42.1 s, evidencia con SHA-256 |
| Suite de pruebas | **251 passed** (2026-10-20, incluye enmiendas E1–E9) |

## 1. Metadatos de la campaña principal (Fase 9, 2026-10-14)

| Campo | Valor |
|-------|-------|
| Commit sellado | `2017af16320ddcb2faabdcc1bf71ceefc64788b5` |
| Semillas | 100001–100030 por fase (main y A14) |
| Python | 3.11.9 (venv) |
| Modo fase 1 | `run_experiment.py --mode docker --exclude A14` (topología de la tesis) |
| Modo fase 2 | `run_experiment.py --mode local` (solo A14) |
| Integridad | SHA-256 de `settings/rules/baseline` + `SHA256SUMS.txt` (314 archivos) |

## 2. H1 — Efectividad por escenario (60 corridas, 2010 inyecciones)

| Escenario | Qué modela | Regla esperada | Inyectados | TP | ADR % |
|-----------|------------|----------------|------------|----|-------|
| A01 | Origen lógico desconocido (suplantación) | R-ID-001 | 90 | 90 | 100.0 |
| A02 | Control ID duplicado | R-SEQ-001 | 90 | 90 | 100.0 |
| A03 | Replay de mensaje | R-SEQ-002 | 90 | 90 | 100.0 |
| A04 | Timestamp regresivo | R-TIME-001 | 90 | 90 | 100.0 |
| A05 | Delimitador final ausente (stream cortado) | R-MLLP-001 | 90 | 90 | 100.0 |
| A06 | Bytes basura antes del SB (stream corrompido) | R-MLLP-001 | 90 | 90 | 100.0 |
| A07 | Segmento MSH ausente | R-HL7-001 | 90 | 90 | 100.0 |
| A08 | Orden de segmentos inválido | R-HL7-003 | 90 | 90 | 100.0 |
| A09 | Tipo de mensaje desconocido | R-HL7-002 | 90 | 90 | 100.0 |
| A10 | OBX con datatype sintético | R-OBX-003 | 90 | 90 | 100.0 |
| A11 | OBX con unidad no autorizada | R-OBX-002 | 90 | 90 | 100.0 |
| A12 | Frecuencia fuera de baseline (tormenta) | R-TIME-002 | 600 | 600 | 100.0 |
| A13 | Reconexiones repetidas | R-TIME-002 | 150 | 150 | 100.0 |
| A14 | Silencio periódico (secuestro del canal) | R-TIME-002 | 90 | 90 | 100.0 |
| A15 | Mensaje sobredimensionado (>5120 B, Enmienda E9) | R-MLLP-001 | 90 | 90 | 100.0 |
| A16 | Cambio de identidad a mitad de sesión | R-ID-001 | 90 | 90 | 100.0 |
| **GLOBAL** | | | **2010** | **2010** | **100.0** |

- IC95 (Wilson) global: **[99.8, 100.0]**; por escenario ≥ [95.9, 100.0].
- Precisión global: **99.7 %** (7 FP benignos `R-TIME-002` por jitter de timing ≈ 0.3 %,
  en ~20 % de corridas bajo carga concurrente; umbral NO ajustado post-hoc).
- Fuente cruda: `analysis_output/validation/main_20261014_162606/` +
  `a14_20261014_172034/validation_summary.json`.

## 3. H2 — Latencia (bench `latency_bench.py`, peor caso sintético)

| Corrida | Mensajes | p50 (µs) | p95 (µs) | p99 (µs) | máx (µs) |
|---------|----------|----------|----------|----------|----------|
| 1 | 1000 | 112.3 | 166.96 | 287.73 | 3628.1* |
| 2 | 1000 | 114.3 | 195.89 | 349.61 | 591.8 |
| 3 | 1000 | 113.55 | 178.53 | 325.26 | 737.1 |
| **Agregado** | 3000 | 113.2 | **177.52** | 325.0 | 3628.1 |

\* outlier de calentamiento (corridas 2-3: máx ≤ 737 µs). Umbral: 500 µs → **PASS en PC**.
Crudo: `analysis_output/validation/latency_20261014_140421.json`.
**Declaración obligatoria en defensa:** H2 es NO_VERIFICADO para Raspberry Pi hasta
correr `latency_bench.py --messages 1000 --runs 5` en la placa física.

## 4. H3 — Falsos positivos sobre evidencia real (replay)

| Corpus | Mensajes | FP (Fase 9 unimodal) | FP (v1.1 bimodal + E2–E8) | Interpretación |
|--------|----------|----------------------|---------------------------|----------------|
| STANDBY (`LECTURACONACK25AGOSTO.pcapng`) | 43 ORU | **0** | **0** (43/43 `NORMAL`) | Cumple protocolo §3.2 (×5 reproducciones idénticas) |
| RUNNING (`LECTURAACK27AGOSTO.pcapng`) | 99 ORU (13 STANDBY + 86 RUNNING) | 256 (`R-OBX-001/002/003` pre-bimodal) | **0** (99/99 `NORMAL`, 1 transición `STANDBY->RUNNING`) | Con `baseline.yaml` v1.1 (33 códigos OBX, 9 unidades MDC, 6 modos ventilatorios) + E2–E5 se logra **FP = 0** sobre las 2 capturas clínicas reales |

## 5. Campaña de ransomware en tiempo real (simulación compuesta)

Modelo: un ransomware que secuestra el canal de telemetría (sin malware real;
`docs/SIMULACION_RANSOMWARE.md`). Escenarios: A01 (suplantación), A05/A06
(corrupción del stream), A13 (reconexiones), A14 (silencio/hostage), A16 (cambio de identidad).

| Corrida | Modo | TP / FP / FN | Recall / Precision | Latencia p50 / p95 | Duración |
|---|---|---|---|---|---|
| `20261014_175952` (sellada) | local, seed 2026101401 | 20 / 0 / 0 | 1.0000 / 1.0000 | 2.0 / 8.8 ms | 201 s |
| **`20261017_110410` (hoy)** | local, seed 2026101401 | **20 / 0 / 0** | **1.0000 / 1.0000** | 1.59 / 7.23 ms | 201 s |

Evidencia cualitativa (idéntica en ambas corridas):

- `FRAMING_ERROR ... garbage_before_sb:9_bytes` ×3 → A06 (payload corrompido).
- Sesión de 136.8 s con 9 mensajes → ventana A14 (silencio forzado de 45 s ×3).
- 5 sesiones cortas de reconexión → A13.
- `R-ID-001 Unauthorized sending application: MALICIOUS_APP^hacker^L` → A01;
  `MINDRAY_WATOPRO-SERIES^…` → A16.

Selladas: `analysis_output/validation/ransomware_sim_20261014_175952/` y
`ransomware_sim_20261017_110410/`.

## 6. Topología Raspberry Pi (simulación docker)

Mismo `docker-compose.yml` que usará la Pi física: red interna `172.30.0.0/24`
(sin egress), IPs fijas (emulador .10, generador .11, receptor .20), código idéntico.

| Corrida | TP / FP / FN | Recall | Precision | Latencia p50 / p95 | Escenarios |
|---|---|---|---|---|---|
| `20261014_175742` (sellada) | 64 / 1 / 0 | 1.0000 | 0.9846 | 0.95 / 1.78 ms | 15/15 = 100 % |
| **`20261017_110211` (hoy)** | **64 / 1 / 0** | **1.0000** | 0.9846 | 0.93 / 1.93 ms | 15/15 = 100 % |

- FP único: 1 × `R-TIME-002` benigno (jitter; comportamiento documentado Fase 9).
- **NO simulado:** CPU ARM, consumo/térmico y **H2 (latencia ≤ 500 µs)** — requiere Pi física.
- Selladas: `analysis_output/validation/pi_sim_20261014_175742/` y `pi_sim_20261017_110211/`.

## 7. Despliegue WATO standalone (2026-10-17, tráfico benigno)

Receptor-detector (`deploy/receptor/receptor.ps1`) + emulador WATO
(`deploy/wato/wato.ps1`, STANDBY, 8 msg / 6 s):

| Métrica | Valor |
|---|---|
| Mensajes ORU^R01 enviados / recibidos | 8 / 8 (100 %) |
| ACK validados `AA` | 8/8 (0 timeouts) |
| Sesión | 42.1 s, 5720 bytes, 0 errores |
| **Alertas de seguridad** | **0** (8 eventos `NORMAL` INFO) |
| Evidencia | `raw`+`hl7`+`logs` con SHA-256 por sesión |

## 8. Cómo leer las métricas (glosario de defensa)

- **TP / FP / TN / FN**: inyección detectada en su ventana / alerta fuera de ventana /
  mensaje benigno sin alerta / inyección no detectada (evaluate.py).
- **ADR (recall)** = TP / (TP+FN): mide detección; **Precision** = TP / (TP+FP): mide ruido.
- **IC95 Wilson**: intervalo del ADR por muestreo de corridas (protocolo §3.1).
- **Latencia inyección→alerta**: delta entre ground truth y alerta correlacionada (ms).
- **Throughput / pérdida**: msg/s del receptor y msgs perdidos vs. esperado (seed.txt).
- **`manifest.json`** por corrida: commit, hashes de insumos/salidas, semilla, runtime —
  reproducibilidad total.

Ejemplo de alerta real (`runs/20261017_110410/alerts/alerts.jsonl`):

```json
{"alert_id": "ALERT-000001-1792253082197", "rule_id": "R-ID-001",
 "timestamp_utc": "2026-10-17T16:04:42.197749+00:00", "severity": "HIGH",
 "reason": "R-ID-001: Unauthorized sending application: MALICIOUS_APP^hacker^L",
 "evidence_hash": "667bb690718b0117cfa1c1a07fc80597df85e72b7c8b92563e300ffafddcc919",
 "label": "ANOMALO", "synthetic": false}
```

## 9. Mapa de la evidencia (rutas para el jurado)

| Qué | Dónde |
|---|---|
| Resumen de esta tesis | `docs/RESULTADOS_TESIS.md` (este archivo) |
| Resultados Fase 9 crudos + decisiones | `docs/RESULTS_20261014.md` |
| Corridas completas (regenerables) | `runs/<timestamp>/` (gitignored) |
| Evidencia sellada + SHA-256 | `analysis_output/validation/` (+ `SHA256SUMS.txt`) |
| Manifiestos de campaña | `analysis_output/validation/{main,a14}_20261014_*/validation_summary.json` |
| Bench latencia H2 | `analysis_output/validation/latency_20261014_140421.json` |
| Evidencia original WATO (solo lectura) | `evidence_raw/` (+ `evidence_inventory.csv` SHA-256) |
| Matriz requisito→escenario→regla→métrica | `docs/TRACEABILITY_MATRIX.csv` |
| Protocolo de medición | `docs/VALIDATION_PROTOCOL.md` |

## 10. Limitaciones que SÍ deben citarse en la defensa

1. H2 sin verificar en Pi física (p95 177.5 µs es de PC x86, no extrapolable).
2. Baseline bimodal `STANDBY` + `RUNNING` (6 modos): logra 0 FP en ambas capturas reales; las alarmas fisiológicas activas y la transición `RUNNING -> STANDBY` permanecen como `NO_VERIFICADO` por no figurar en `evidence_raw/`.
3. Jitter de timing benigno genera ~0.3 % FP bajo carga (umbral no tunneado).
4. Aprobación clínica PENDING: ninguna regla clínica activa.
5. Sin malware real ni equipo clínico: simulación de comportamientos de ataque en
   laboratorio aislado (alcance declarado en `docs/ETHICS_AND_SAFETY.md`).
