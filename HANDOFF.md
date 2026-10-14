# HANDOFF — Contexto y pasos siguientes

> Última actualización: 2026-10-13 (fin de sesión + adenda de la sesión asistente, ver §7).

## 1. Contexto del proyecto

- Tesis G18 (Pontificia Universidad Javeriana): laboratorio reproducible y aislado para
  detección black-box de anomalías/ataques en comunicaciones HL7 v2.x/MLLP del equipo
  anestésico Mindray WATO EX-35, sobre Raspberry Pi.
- Sin pruebas ofensivas, sin malware, sin contacto con el equipo real.
- Directivas del usuario: trabajar por fases; cambios pequeños; correr tests tras cada
  módulo; **nunca** sobrescribir `evidence_raw/`; sin afirmaciones sin fuente; **siempre
  dejar este HANDOFF.md al terminar el paso**.
- Seguridad: `SafetyGuard` (solo localhost/hostnames fijos), `LAB_AUTHORIZED=YES` +
  `LAB_ONLY.marker`, rate limit, `strict_validation=True` por defecto.
- Host Windows, PowerShell (sin `&&`, usar `;`), Python:
  `C:\Users\OsoGa\AppData\Local\Python\bin\python.exe` (pyyaml + pytest instalados).
- Docker Desktop 29.8.2 + WSL2 (Ubuntu) **instalados y con motor corriendo** (2026-10-13
  ~22:35, sesión asistente — ver §7): `docker compose config` OK y contenedor healthy,
  pero E2E en contenedor tuvo estancamiento de I/O en `evidence_output/` (§7).
  En shells nuevos hace falta antes de usar docker:
  `$env:PATH = "C:\Program Files\Docker\Docker\resources\bin;" + $env:PATH`
  (si no: `docker-credential-desktop ... not found`).

## 2. Estado completado

- Fases 1–3 completas y probadas: módulos `src/mllp|hl7|evidence|detection|alerting|config/`,
  `wato_emulator.py`, `anomaly_generator.py` (A01–A16), `evaluate.py` (matching por ventana,
  `run_from_dir`), 15 reglas R-* con mapeos MITRE ICS.
- MSH corregido a 4 pipes + `||UNICODE UTF-8` (fuente autoritativa: `wato_captures.txt`).
- `run_experiment.py` (orquestador local/docker) **probado end-to-end en modo local**:
  `runs/20261013_230110/` → recall=1.000, precision=1.000, fp=0, fn=0
  (50 inyecciones, 112 alertas, 5 mensajes normales), con
  `--benign-count 3 --anomaly-count 2 --exclude A14`.
- Fix de regresión de tests (161 passed): `SafetyGuard.check` ahora honora estrictamente
  `safety.lab_marker_path` (se eliminó el fallback al marcador del repo que anulaba la
  ruta configurada); la conveniencia de desarrollo (usar `LAB_ONLY.marker` del repo cuando
  la ruta por defecto `/LAB_ONLY.marker` no existe, p.ej. Windows) vive solo en
  `anomaly_generator.main()`.
- Suite completa: **161 passed** (`python -m pytest tests/ -q`).
- Docs Fase 5 existentes: README, THREAT_MODEL, ETHICS_AND_SAFETY, LAB_ARCHITECTURE,
  ATTACK_SCENARIOS, VALIDATION_PROTOCOL, RESULTS_TEMPLATE, LIMITATIONS,
  TRACEABILITY_MATRIX.csv.

## 3. Hallazgo crítico de esta sesión (SIN RESOLVER — primera tarea)

**El límite global `max_anomalies_per_run: 50` (`src/config/settings.yaml:289`) trunca
corridas por defecto y silencia escenarios completos.**

Fórmula exacta (ver `anomaly_generator.run_scenario`, líneas 584–624):
- A12 = 20 (ráfaga, UNA sola llamada), A13 = 5 (UNA sola llamada) → 25 fijos.
- Los otros 14 escenarios: `min(count, safety_limit)` cada uno.
  safety_limits: A01–A04,A09–A11=10; A05–A08=5; **A14=3**; A15,A16=5.
- Totales: count=1 → 39 ✓ | count=2 → **53 ✗** (A16 queda en 1, observado en el smoke
  test) | count=3 (default de `run_experiment`) → **67 ✗✗** (el cap corta DURANTE A12 →
  A13, A15, A16 **jamás se ejecutan**, y aun así evaluate.py reportaría recall=1.0).

Plan acordado (no implementado):
1. `src/config/settings.yaml`: `max_anomalies_per_run: 50` → **70** (cubre 14×3+25=67).
2. Actualizar las dos docs que fijan el presupuesto:
   - `ETHICS_AND_SAFETY.md` línea 36 (`≤ 50` → `≤ 70`).
   - `ATTACK_SCENARIOS.md` línea 39 (presupuesto 50 → 70, añadir fórmula 25 + 14×count).
3. `run_experiment.py`: **preflight fail-fast** — importar `SCENARIOS` de
   `anomaly_generator`, calcular inyecciones esperadas (respetando `--exclude` y la
   lógica de ráfaga A12=`min(params.max_burst_messages, safety_limit)`,
   A13=`min(params.max_reconnects, safety_limit)`), leer el presupuesto de settings.yaml
   y `die(...)` con mensaje claro si no cabe (evita truncamiento silencioso para siempre).
4. Re-correr `pytest tests/ -q` (ningún test asume 50, verificado por grep).

## 4. Pasos siguientes (en orden)

1. Implementar el fix del §3 (settings + 2 docs + preflight) y re-correr la suite.
2. Re-ejecutar el orquestador con parámetros default reales
   (`LAB_AUTHORIZED=YES python run_experiment.py --mode local`) y confirmar que TODOS los
   escenarios (salvo exclusiones) aparecen en `ground_truth.jsonl` (conteo por escenario).
3. Revisar docs Fase 5 por consistencia con los cambios recientes: `--exclude`,
   SafetyGuard estricto, run_experiment, A13 (espera R-TIME-002) / A14 (hueco de 45 s,
   también R-TIME-002; `--exclude A14` recomendado por lentitud).
4. Fase 6: escribir doc de setup Raspberry Pi OS (falta; pendiente también WSL/Docker
   para validar `--mode docker`).
5. `docker-compose.yml` + `Dockerfile`: `docker compose config` ya OK y contenedor
   healthy; falta re-validar E2E tras los fixes de ~22:59 (antes hubo estancamiento de
   I/O en contenedor, ver §7) y probar `--mode docker` de run_experiment.
6. Actualizar este HANDOFF al terminar.

## 5. Comandos útiles

```powershell
# Suite completa (debe decir 161 passed)
& "C:\Users\OsoGa\AppData\Local\Python\bin\python.exe" -m pytest tests/ -q

# Corrida local rápida (smoke)
$env:LAB_AUTHORIZED="YES"
& "C:\Users\OsoGa\AppData\Local\Python\bin\python.exe" run_experiment.py --mode local `
  --benign-count 3 --anomaly-count 2 --exclude A14

# Evaluación de una corrida existente
& "C:\Users\OsoGa\AppData\Local\Python\bin\python.exe" -c "from evaluate import run_from_dir; print(run_from_dir('runs/20261013_230110'))"
```

## 6. Decisiones de diseño relevantes (no rehacer)

- Motor de detección: MCIDs/hashes/último timestamp **globales entre sesiones**;
  `replay_window_s = 5`; intervalo benigno must be [5, 15.015] s (tests usan 6 s).
- Semillas (`_send_setup` de A02/A03/A04) NO cuentan como inyecciones en ground truth.
- Evaluador: alertas dentro de la ventana de inyección → correlacionadas (no FP).
- `allowed_ips` exact-match (sin CIDR): 192.168.23.250, 127.0.0.1, ::1, 172.30.0.10/11.
- framer `max_message_size: 4096` → A15 dispara R-MLLP-001.
- `runs/` sí se puede regenerar; `evidence_raw/` es solo lectura.

## 7. Adenda — sesión asistente (2026-10-13, ~21:55–23:15)

Commits de esta sesión (además de los previos): `23c476b` THREAT_MODEL + corrección de
mapeos MITRE en configs · `4cca06e` ETHICS_AND_SAFETY · `a2d1d64` LAB_ARCHITECTURE ·
`fa1e530` ATTACK_SCENARIOS · `2cd891f` VALIDATION_PROTOCOL + LIMITATIONS · `8fca852`
RESULTS_TEMPLATE + TRACEABILITY_MATRIX · `ab6735b` docker-compose + test MITRE +
receptor `--host` por defecto `127.0.0.1` · `1d2107a` mapeos MITRE en
`anomaly_generator.py` + test de sincronía + `runs/` en `.gitignore`.

- **MITRE ATT&CK ICS v20** verificado 2026-10-13 en attack.mitre.org: `T0855` redirige a
  `T1692.001` y `T0857` a `T1693.001` (Modify Firmware). Mapeos corregidos en
  `settings.yaml`/`rules.yaml`/`rules.py`/`anomaly_generator.py` → **T1692.002**
  (mensaje de reporte no autorizado) y **T0814** (DoS, A12–A15). Guardia de regresión:
  `tests/test_mitre_mappings.py` (falla si reaparecen IDs obsoletos o si
  generator/settings/rules divergen en técnica).
- **E2E host (22:48): OK** — emulador 2/2 ACKs AA, alertas emitidas (R-NET-001,
  R-HL7-002*, R-TIME-002, R-OBX-001*), evidencia con hashes SHA-256. *R-HL7-002 fue FP
  por config vieja de22:24; el fix posterior (3 partes) de la otra sesión lo resuelve.
  Método: TODO en un solo comando (Start-Process receptor → emulador → Stop-Process);
  el wrapper de la shell **mata procesos hijos vivos** (`ChildProcess.kill`) — no dejar
  receptores detachados entre llamadas.
- **E2E Docker (22:38): FALLÓ por I/O** — el contenedor creó `evidence_output/**` en
  **0 bytes** y los hilos quedaron bloqueados dentro de `open_session` (sesiones subían
  sin `SESSION_START`/`MSG_RECV`, RLock retenido ⇒ sin ACKs). Síntoma típico de
  escritura de bind-mount OneDrive↔Docker Desktop estancada. Plan: (a) reintentar con
  los fixes posteriores a 22:59, (b) si persiste → named volume en
  `/app/evidence_output` + `docker compose cp`, o repo fuera de OneDrive para Docker.
- Si se reutiliza `%TEMP%\settings_lab_smoke.yaml` (config de pruebas con marcador en
  TEMP): **regenerarla** — `settings.yaml` cambió después de copiarla y produce falsos
  positivos confusos (p.ej. R-HL7-002 por `message_types_allowed` desactualizado).
- `evidence_output/` agregado a `.gitignore` (runtime, análogo a `runs/`). El
  `LAB_ONLY.marker` de la raíz sigue sin trackear: decidir si se committea o se
  documenta como artefacto local (lo usa la comodidad de `anomaly_generator.main()`).
- Python: además del sistema (`AppData\Local\Python\bin\python.exe`), el venv del repo
  `.venv\Scripts\python.exe` sirve igual (ambos con pyyaml+pytest).
- Confirmado a las23:09: **161 passed**.
