# Protocolo de Validación

**Objetivo:** verificar (o refutar) las hipótesis de la tesis con métricas reproducibles.
**Fase:** 9 del plan · **Fecha de redacción:** 2026-10-13 (protocolo, no resultados)

## 1. Hipótesis

| ID | Hipótesis | Criterio de aceptación | Estado |
|----|-----------|------------------------|--------|
| H1 | El detector identifica los escenarios A01–A16 con efectividad alta | **ADR ≥ 90 %** global y ≥ 80 % en cada escenario individual, con IC 95 % de Wilson | NO VERIFICADO |
| H2 | El procesamiento por mensaje es viable en la Raspberry Pi objetivo | **Latencia ≤ 500 µs** en percentil 95 por mensaje (lectura→alerta) | NO VERIFICADO |
| H3 (descriptiva) | El tráfico normal no genera alertas | FP = 0 sobre replay de evidencia STANDBY; FP de RUNNING se **reporta** sin umbral previo | NO VERIFICADO |

Las hipótesis son **refutables**: si no se alcanzan, se documenta el resultado y se analiza la
causa; no se ajustan los umbrales post hoc para alcanzarlas.

## 2. Artefactos congelados antes de medir

1. Commit del código (hash registrado en el resultado).
2. `settings.yaml`, `rules.yaml`, `baseline.yaml` (SHA-256 de cada uno).
3. Semilla PRNG por corrida (registrada).
4. Entorno: Python 3.11.9, host de medición (Pi o PC, **declarado**), sin cargas paralelas.

## 3. Diseuento experimental

### 3.1 Datos positivos (para ADR)

- Generación por escenario con el techo de `ATTACK_SCENARIOS.md` (3–20 msg), repetida en
  **≥ 30 corridas** por escenario con semillas distintas (o todas las corridas posibles si el
  techo lo limita; se declara N real por escenario).
- Salida medida: alerta emitida por la regla mapeada al escenario (TP) o ausencia (FN);
  alerta en mensajes sintácticamente normales (FP); TN sobre mensajes benignos intercalados.

### 3.2 Datos negativos

- Replay de las 2 sesiones con HL7 de la evidencia (142 ORU + 142 ACK) en modo observador:
  expectativa FP = 0 sobre STANDBY.
- Tráfico RUNNING de evidencia: se ejecuta y se **reportan** los FP (códigos NM/SN
  NO_VERIFICADOS ya anticipados) sin reclamar H3 sobre este conjunto.

### 3.3 Latencia (H2)

- Marca `time.perf_counter()` en el motor: entrada de mensaje parseado → `DetectionResult`.
- ≥ 1 000 mensajes por corrida, ≥ 3 corridas; se reportan p50/p95/p99/máx y se comparan con
  500 µs. Si se mide en PC en vez de Pi, se declara explícitamente y la H2 queda
  NO VERIFICADO para la Pi.

## 4. Métricas

| Métrica | Fórmula | Reporte |
|---------|---------|---------|
| ADR (por escenario y global) | TP / (TP + FN) | % + IC 95 % Wilson |
| FPR | FP / (FP + TN) | % sobre cada corpus (STANDBY / RUNNING) |
| Precisión | TP / (TP + FP) | % |
| Latencia | perf_counter por mensaje | p50/p95/p99/máx (µs) |
| Cobertura de escenarios | escenarios con ADR ≥ 90 % / 16 | conteo |

## 5. Procedimiento

1. Verificar guardas (`LAB_AUTHORIZED`, `LAB_ONLY.marker`) y límites `safety`.
2. Congelar artefactos (§2) y registrar `git rev-parse HEAD`.
3. Correr corpus negativo (evidencia) → registrar FP.
4. Correr A01–A16 según §3.1 → matriz TP/FP/FN por corrida
   (herramienta: `run_experiment.py --mode docker`, prerequisito de la corrida de latencia).
5. Correr latencia (§3.3).
6. Rellenar `RESULTS_TEMPLATE.md` con los números crudos (sin redondeos selectivos).
7. Decisión: H1/H2 aceptadas o rechazadas; si se rechazan, `LIMITATIONS.md` y análisis de
   causa raíz (sin iterar sobre los mismos datos).

## 6. Amenazas a la validez (y mitigación)

- **Sesgo de calibración:** el baseline y las reglas se congelan antes de las corridas.
- **Overfitting a la evidencia:** los escenarios A01–A16 provienen de amenazas del modelo, no
  de ajustar reglas a cada corrida; los FP de RUNNING se reportan completos.
- **Efecto de orden:** alternar orden de escenarios entre corridas (semilla registra orden).
- **Medición de latencia en host incorrecto:** declarado en §3.3; sin Pi no hay H2.
- **Interferencia de sesión paralela de desarrollo:** ejecutar validación solo con árbol limpio
  (`git status` sin modificaciones sin commitear).

## 7. Salidas

- `RESULTS_TEMPLATE.md` diligenciado (Fase 9).
- Tablas y corridas crudas en `analysis_output/validation/` (selladas con SHA-256).
- Este protocolo no se modifica después de iniciar la Fase 9 salvo enmienda versionada.
