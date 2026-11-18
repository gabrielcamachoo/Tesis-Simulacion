# Resultados campaña H1 (run_matrix)

- Fecha (UTC): 2026-10-14T15:33:51.782744+00:00
- Commit: 025693e1e30a288bcebf4736d0be9119e09aad65
- Modo: local | Corridas: 2 | seed_base: 100000
- Parámetros: benign=6 anomaly=3 interval=6.0s exclude=A14
- Host: PC (declarado) | Python: 3.14.7
- Cobertura ADR≥90%: 15/15 escenarios

## H1 — Efectividad por escenario (ADR ≥ 90%)

| Escenario | N corridas | Inyectados | TP | FN | ADR % | IC95 % (Wilson) | ≥90% |
|-----------|-----------|-----------|----|----|-------|------------------|------|
| A01 | 2 | 6 | 6 | 0 | 100.0 | [61.0, 100.0] | ✅ |
| A02 | 2 | 6 | 6 | 0 | 100.0 | [61.0, 100.0] | ✅ |
| A03 | 2 | 6 | 6 | 0 | 100.0 | [61.0, 100.0] | ✅ |
| A04 | 2 | 6 | 6 | 0 | 100.0 | [61.0, 100.0] | ✅ |
| A05 | 2 | 6 | 6 | 0 | 100.0 | [61.0, 100.0] | ✅ |
| A06 | 2 | 6 | 6 | 0 | 100.0 | [61.0, 100.0] | ✅ |
| A07 | 2 | 6 | 6 | 0 | 100.0 | [61.0, 100.0] | ✅ |
| A08 | 2 | 6 | 6 | 0 | 100.0 | [61.0, 100.0] | ✅ |
| A09 | 2 | 6 | 6 | 0 | 100.0 | [61.0, 100.0] | ✅ |
| A10 | 2 | 6 | 6 | 0 | 100.0 | [61.0, 100.0] | ✅ |
| A11 | 2 | 6 | 6 | 0 | 100.0 | [61.0, 100.0] | ✅ |
| A12 | 2 | 40 | 40 | 0 | 100.0 | [91.2, 100.0] | ✅ |
| A13 | 2 | 10 | 10 | 0 | 100.0 | [72.2, 100.0] | ✅ |
| A15 | 2 | 6 | 6 | 0 | 100.0 | [61.0, 100.0] | ✅ |
| A16 | 2 | 6 | 6 | 0 | 100.0 | [61.0, 100.0] | ✅ |
| **GLOBAL** | 2 | 128 | 128 | 0 | 100.0 | [97.1, 100.0] | ✅ |

**Precisión global:** 100.0% | **FP totales:** 0 | **TN (mensajes benignos):** 22 | **Alertas totales:** 314

> Nota: FP sobre corpus de inyecciones sintéticas (mensajes benignos intercalados). El FP sobre evidencia real (STANDBY/RUNNING) se mide aparte con replay_evidence.py (H3).
