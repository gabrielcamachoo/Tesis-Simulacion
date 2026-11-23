# Resultados campaña H1 (run_matrix)

- Fecha (UTC): 2026-11-23T20:08:28.894854+00:00
- Commit: 0453c0314a316c474b1c4f72e57ff255b3e6da96
- Modo: local | Corridas: 30 | seed_base: 100000
- Parámetros: benign=6 anomaly=3 interval=6.0s exclude=A14
- Host: PC (declarado) | Python: 3.14.7
- Cobertura ADR≥90%: 15/15 escenarios

## H1 — Efectividad por escenario (ADR ≥ 90%)

| Escenario | N corridas | Inyectados | TP | FN | ADR % | IC95 % (Wilson) | ≥90% |
|-----------|-----------|-----------|----|----|-------|------------------|------|
| A01 | 30 | 90 | 90 | 0 | 100.0 | [95.9, 100.0] | ✅ |
| A02 | 30 | 90 | 90 | 0 | 100.0 | [95.9, 100.0] | ✅ |
| A03 | 30 | 90 | 90 | 0 | 100.0 | [95.9, 100.0] | ✅ |
| A04 | 30 | 90 | 90 | 0 | 100.0 | [95.9, 100.0] | ✅ |
| A05 | 30 | 90 | 90 | 0 | 100.0 | [95.9, 100.0] | ✅ |
| A06 | 30 | 90 | 90 | 0 | 100.0 | [95.9, 100.0] | ✅ |
| A07 | 30 | 90 | 90 | 0 | 100.0 | [95.9, 100.0] | ✅ |
| A08 | 30 | 90 | 90 | 0 | 100.0 | [95.9, 100.0] | ✅ |
| A09 | 30 | 90 | 90 | 0 | 100.0 | [95.9, 100.0] | ✅ |
| A10 | 30 | 90 | 90 | 0 | 100.0 | [95.9, 100.0] | ✅ |
| A11 | 30 | 90 | 90 | 0 | 100.0 | [95.9, 100.0] | ✅ |
| A12 | 30 | 600 | 600 | 0 | 100.0 | [99.4, 100.0] | ✅ |
| A13 | 30 | 150 | 150 | 0 | 100.0 | [97.5, 100.0] | ✅ |
| A15 | 30 | 90 | 90 | 0 | 100.0 | [95.9, 100.0] | ✅ |
| A16 | 30 | 90 | 90 | 0 | 100.0 | [95.9, 100.0] | ✅ |
| **GLOBAL** | 30 | 1920 | 1920 | 0 | 100.0 | [99.8, 100.0] | ✅ |

**Precisión global:** 100.0% | **FP totales:** 0 | **TN (mensajes benignos):** 360 | **Alertas totales:** 4593

> Nota: FP sobre corpus de inyecciones sintéticas (mensajes benignos intercalados). El FP sobre evidencia real (STANDBY/RUNNING) se mide aparte con replay_evidence.py (H3).
