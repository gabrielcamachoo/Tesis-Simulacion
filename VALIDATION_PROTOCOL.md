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

## 8. Enmiendas versionadas

### E1 (2026-10-14) — R-OBX-002: CWE con unidad

- **Disparador:** primer replay del corpus negativo STANDBY (§5.3,
  `analysis_output/validation/replay_STANDBY_20261014/`): 43/43 FP,
  todos R-OBX-002 (`Unauthorized unit: 262656^MDC_DIM_DIMLESS^MDC`).
- **Defecto (no ajuste de umbral):** la regla trataba CWE con OBX-6 como
  inválido *siempre*, con la premisa "STANDBY usa CWE sin unidades"
  (rules.yaml limitations; baseline `obx_units_observed: []`). La
  evidencia real demuestra la premisa falsa: los 4 OBX CWE del STANDBY
  (43/43 ORU, pcap 25-08) traen OBX-6 = `262656^MDC_DIM_DIMLESS^MDC`.
  El E2E con emulador nunca lo detectó porque el emulador genera CWE sin
  unidad (los mensajes sintéticos no reproducen el corpus real).
- **Fix:**
  1. `src/hl7/validator.py` (`validate_obx_constraints`): R-OBX-002 solo
     alerta si el baseline tiene unidades observadas y la unidad del
     mensaje está fuera de la lista (eliminada la cláusula
     `cwe_with_unit`). A11 (CWE + `mg/dL`) sigue siendo detectable.
  2. `src/evidence/baseline_builder.py` + `baseline.yaml`:
     `obx_units_observed` registra la unidad OBSERVADA del corpus
     (`262656^MDC_DIM_DIMLESS^MDC`, 43/43 ORU).
  3. `config/rules.yaml`: descripción y limitaciones de R-OBX-002
     actualizadas.
- **Artefactos pre-enmienda:** HEAD `025693e` + SHA-256 de
  settings/rules/baseline en `analysis_output/validation/freeze_manifest.json`.
- **Decisión:** aprobada por el autor de la tesis (opción "enmienda
  versionada + fix"). Transparencia: `RESULTS_20261014.md` publica AMBOS
  resultados (pre-enmienda 43 FP / post-enmienda).
- **Re-medida:** replay STANDBY re-ejecutado con artefactos
  post-enmienda; nuevo HEAD y hashes registrados en el freeze manifest.
