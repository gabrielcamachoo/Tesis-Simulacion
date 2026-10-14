# Plantilla de Resultados (Fase 9 — diligenciar al ejecutar VALIDATION_PROTOCOL.md)

> Regla: números crudos, sin redondeos selectivos. Todo NO VERIFICADO se queda en blanco.
> Copiar este archivo a `RESULTS_YYYYMMDD.md` al iniciar la Fase 9; no sobrescribir la plantilla.

## 1. Metadatos de la corrida

| Campo | Valor |
|-------|-------|
| Fecha | |
| Commit (`git rev-parse HEAD`) | |
| SHA-256 `settings.yaml` / `rules.yaml` / `baseline.yaml` | / / |
| Host de medición (Pi / PC, modelo) | |
| Python | 3.11.9 |
| Semillas (rango) | |
| Árbol limpio (`git status`) | |

## 2. H1 — Efectividad (ADR ≥ 90 %)

Corpus negativo previo: replay evidencia STANDBY (43 ORU+43 ACK) → FP = ___
Corpus RUNNING (99 ORU+99 ACK) → FP = ___ (reportar sin umbral)

| Escenario | N corridas | Mensajes inyectados | TP | FN | ADR % | IC95 % (Wilson) | ≥90 % |
|-----------|-----------|---------------------|----|----|-------|------------------|-------|
| A01 | | | | | | | |
| A02 | | | | | | | |
| A03 | | | | | | | |
| A04 | | | | | | | |
| A05 | | | | | | | |
| A06 | | | | | | | |
| A07 | | | | | | | |
| A08 | | | | | | | |
| A09 | | | | | | | |
| A10 | | | | | | | |
| A11 | | | | | | | |
| A12 | | | | | | | |
| A13 | | | | | | | |
| A14 | | | | | | | |
| A15 | | | | | | | |
| A16 | | | | | | | |
| **GLOBAL** | | | | | | | |

**Decisión H1:** ACEPTADA / RECHAZADA — motivo:

## 3. H2 — Latencia ≤ 500 µs

| Corrida | Mensajes | p50 (µs) | p95 (µs) | p99 (µs) | máx (µs) |
|---------|----------|----------|----------|----------|----------|
| 1 | | | | | |
| 2 | | | | | |
| 3 | | | | | |

**Decisión H2:** ACEPTADA / RECHAZADA / NO VERIFICADO (no se midió en Pi) — motivo:

## 4. H3 (descriptiva) — Falsos positivos

| Corpus | Mensajes | FP | FPR % | Reglas que alertan |
|--------|----------|----|-------|--------------------|
| STANDBY evidencia | 86 (43+43) | | | |
| RUNNING evidencia | 198 (99+99) | | | |

## 5. Anomalías de la corrida y desviaciones del protocolo

- (Qué se salió del protocolo: interrupciones, límites alcanzados, etc.)

## 6. Conclusión

- H1: · H2: · H3 (observación):
- Implicaciones para `LIMITATIONS.md` y para el texto de la tesis:

## 7. Evidencia asociada

- Crudos: `analysis_output/validation/` (sellados con SHA-256 → anexar lista al final)
