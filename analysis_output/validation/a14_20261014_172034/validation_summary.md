# Resultados campaña H1 (run_matrix)

- Fecha (UTC): 2026-10-14T19:00:17.471043+00:00
- Commit: 2017af16320ddcb2faabdcc1bf71ceefc64788b5
- Modo: local | Corridas: 30 | seed_base: 100000
- Parámetros: benign=6 anomaly=3 interval=6.0s exclude=A01,A02,A03,A04,A05,A06,A07,A08,A09,A10,A11,A12,A13,A15,A16
- Host: PC (declarado) | Python: 3.11.9
- Cobertura ADR≥90%: 1/1 escenarios

## H1 — Efectividad por escenario (ADR ≥ 90%)

| Escenario | N corridas | Inyectados | TP | FN | ADR % | IC95 % (Wilson) | ≥90% |
|-----------|-----------|-----------|----|----|-------|------------------|------|
| A14 | 30 | 90 | 90 | 0 | 100.0 | [95.9, 100.0] | ✅ |
| **GLOBAL** | 30 | 90 | 90 | 0 | 100.0 | [95.9, 100.0] | ✅ |

**Precisión global:** 100.0% | **FP totales:** 0 | **TN (mensajes benignos):** 330 | **Alertas totales:** 120

> Nota: FP sobre corpus de inyecciones sintéticas (mensajes benignos intercalados). El FP sobre evidencia real (STANDBY/RUNNING) se mide aparte con replay_evidence.py (H3).
