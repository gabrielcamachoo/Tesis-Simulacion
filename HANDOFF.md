# HANDOFF — Contexto y pasos siguientes

> Última actualización: 2026-10-14 (sesión asistente 2: E2E docker validado, §7).

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
- Docker Desktop 29.8.2 + WSL2 con motor corriendo; git 2.55 con identidad repo-local
  `Tesis G18 SIDRE <tesis-g18@local>`; el proyecto **ya es un repo git** (rama `main`).

## 2. Estado completado (todo probado)

- Fases 1–4 completas: módulos `src/`, `wato_emulator.py`, `anomaly_generator.py`
  (A01–A16), `evaluate.py`, `run_experiment.py`, 15 reglas R-* con MITRE ICS v20.
- MSH corregido a 4 pipes + `||UNICODE UTF-8` (fuente: `wato_captures.txt`).
- **Presupuesto de inyecciones resuelto** (§3 del HANDOFF anterior):
  `max_anomalies_per_run: 70` en `src/config/settings.yaml` (25 + 14×count = 67 con
  count=3); `preflight_budget()` fail-fast en `run_experiment.py` (exit 4 si no cabe);
  docs ETHICS_AND_SAFETY y ATTACK_SCENARIOS actualizadas.
- **E2E local completo** (2026-10-14, `runs/20261014_091151`): 67/67 inyecciones
  (A12=20, A13=5, resto=3), recall=1.000, precision=1.000, fp=0, fn=0.
- **E2E docker completo** (2026-10-14, `runs/20261014_094347`, `--exclude A14`):
  64/64 inyecciones, recall=1.000, precision=1.000, fp=0, fn=0. Ver §7 para los dos
  fixes de entorno que hizo falta.
- Fix SafetyGuard estricto + conveniencia de desarrollo solo en `anomaly_generator.main()`.
- `anomaly_generator.py`: sustitución del marcador ANTES de `load_settings`
  (estricto exige marcador válido al cargar).
- A13/A14 alineados en settings/docs (A13 `inter_reconnect_seconds: 0.5`;
  A14 `periodic_silence` gap 45 s, safety_limit 3).
- Docs Fase 5/6 sincronizadas: README, THREAT_MODEL, ETHICS_AND_SAFETY, LAB_ARCHITECTURE,
  ATTACK_SCENARIOS, VALIDATION_PROTOCOL, RESULTS_TEMPLATE, LIMITATIONS,
  TRACEABILITY_MATRIX.csv, **RASPBERRY_PI_SETUP.md** (borrador Fase 6, sin ejecutar).
- Suite completa: **161 passed** (re-correr tras cualquier cambio).

## 3. Pendientes (en orden)

1. **Raspberry Pi (Fase 6):** ejecutar `RASPBERRY_PI_SETUP.md` en hardware real;
   marcar la checklist del doc. Medir H2 (latencia ACK) ahí.
2. **Fase 9 (validación):** ≥30 corridas/escenario con semillas fijas, según
   `VALIDATION_PROTOCOL.md`; diligenciar `RESULTS_TEMPLATE.md`.
3. Limpieza opcional: `docker volume rm investigacion-de-la-tesis_lab_output`
   (los datos de cada corrida ya viven en `runs/<ts>/` tras el cp).

## 4. Comandos útiles

```powershell
# Suite completa (debe decir 161 passed)
& "C:\Users\OsoGa\AppData\Local\Python\bin\python.exe" -m pytest tests/ -q

# Corrida local completa (67 inyecciones, ~3 min)
$env:LAB_AUTHORIZED="YES"
& "C:\Users\OsoGa\AppData\Local\Python\bin\python.exe" run_experiment.py --mode local

# Corrida docker (metodología de la tesis; ~3 min; requiere Docker corriendo)
$env:LAB_AUTHORIZED="YES"
& "C:\Users\OsoGa\AppData\Local\Python\bin\python.exe" run_experiment.py --mode docker --exclude A14

# Evaluación de una corrida existente
& "C:\Users\OsoGa\AppData\Local\Python\bin\python.exe" -c "from evaluate import run_from_dir; print(run_from_dir('runs/20261014_094347'))"
```

## 5. Decisiones de diseño relevantes (no rehacer)

- Motor de detección: MCIDs/hashes/último timestamp **globales entre sesiones**;
  `replay_window_s = 5`; intervalo benigno must be [5, 15.015] s (tests usan 6 s).
- Semillas (`_send_setup` de A02/A03/A04) NO cuentan como inyecciones en ground truth.
- Evaluador: alertas dentro de la ventana de inyección → correlacionadas (no FP).
- `allowed_ips` exact-match (sin CIDR): 192.168.23.250, 127.0.0.1, ::1, 172.30.0.10/11.
- framer `max_message_size: 4096` → A15 dispara R-MLLP-001.
- `runs/` y `evidence_output/` en `.gitignore` (regenerables); `evidence_raw/` solo lectura.
- **Evidencia docker en named volume** `lab_output` (montado en `/lab_output`), NO en el
  bind del repo; `run_experiment.py` la copia al host con `docker compose cp` antes del
  `down`. Razón: el bind sobre OneDrive estancó el I/O (§7).
- **Salud del receptor por healthcheck del contenedor** (`wait_healthy`), no por puerto
  publicado: con redes `internal: true`, Docker Desktop WSL2 no materializa el publish
  (§7). Las fases docker van por DNS interno (`mllp-receiver`), sin depender del host.
- `--mode local` sigue escribiendo directo en `runs/<ts>/` (Python en el host no tiene
  el problema de I/O del contenedor).

## 6. Riesgos conocidos

- Validación clínica pendiente (`clinical_approval_status: PENDING`): ninguna regla
  clínica activa hasta aprobación (ETHICS_AND_SAFETY.md).
- RUNNING: códigos OBX NM/SN no baselineados → posible semitono de FP en Fase 9.
- A14 completo cuesta ~135 s/corrida; en Fase 9 decidir si se corre completo o se
  excluye documentando la exclusión.
- Si se reutiliza `%TEMP%\settings_lab_smoke.yaml` de sesiones viejas: regenerarla
  (settings.yaml cambió y produce FPs confusos).

## 7. Adenda — sesión asistente 2 (2026-10-14, ~09:00–15:00)

Contexto: el HANDOFF anterior quedó a medias tras la sesión 2026-10-13 (§ del E2E
docker fallido). El usuario pidió "Sigue haz todo".

- **Docker/WSL ya estaban disponibles** (instalados tras la sesión 13; el blocker
  "falta Docker" del HANDOFF anterior quedó obsoleto).
- **Fix named volume** (`docker-compose.yml`): volumen `lab_output` montado en
  `/lab_output` en los tres servicios; receptor con `--outdir ${LAB_OUTDIR:-/lab_output/evidence}`;
  `run_experiment.py --mode docker` usa `LAB_OUTDIR=/lab_output/<ts>` y tras las fases
  copia al host con `docker compose cp mllp-receiver:/lab_output/<ts>/. runs/<ts>`.
  Motivo: el E2E docker del 13 falló con archivos de 0 bytes y threads bloqueados en
  `open_session` (RLock retenido) — estancamiento de I/O del bind OneDrive↔Docker.
- **Fix `wait_healthy`** (`run_experiment.py`): el modo docker ya no usa
  `wait_port("127.0.0.1", 1550)`. Verificado empíricamente 2026-10-14: con redes
  `internal: true`, Docker Desktop WSL2 acepta el `ports:` en la config pero
  `NetworkSettings.Ports` queda vacío (el publish no se materializa; control con red
  default SÍ funciona). `wait_healthy` consulta `docker inspect` del healthcheck
  (contenedor interno, sin host). El `ports: 127.0.0.1:1550:1550` se dejó anotado como
  solo-útil-en-Linux/Pi.
- **Corrida docker de verificación:** `runs/20261014_094347` — 64/64 (A01–A11=3,
  A12=20, A13=5, A15=3, A16=3; A14 excluido), 153 alertas + 11 normales,
  recall=1.000 precision=1.000 fp=0 fn=0. Estructura del run idéntica a la local
  (alerts/, hl7/, logs/, raw/, ground_truth.jsonl, evaluation.*).
- Identidad git repo-local configurada (antes solo existía en commits previos):
  `git config user.name/user.email` → `Tesis G18 SIDRE <tesis-g18@local>`.
- `LAB_ONLY.marker` decidido para commit: es un flag de cero contenido que marca
  "este árbol es el repo del lab autorizado" (el gate real es `LAB_AUTHORIZED=YES`,
  que NO se commitea). Hacerlo tracking facilita clones/Pi sin paso manual extra.
- Docs actualizadas con el estado nuevo: README (Fase 4 ✅ local+docker), LAB_ARCHITECTURE
  (tabla de despliegue), LIMITATIONS (§2 Docker: dos particularidades del entorno).
- Commits de la sesión: `19fbdf3` (todo lo anterior, 29 archivos) + este commit (HANDOFF).

## 8. Adenda — sesión asistente 3 (2026-10-14, Fase 9 + E1)

Contexto: usuario pidió "hazlo todo" (ejecutar todo lo pendiente de §3 del HANDOFF:
validación Fase 9). Hubo una **sesión paralela activa** trabajando en los archivos
compartidos (advertencia en §6).

- **Tooling Fase 9 verificado** (commits `025693e` paralelo + `416b6f1` mío):
  - `replay_evidence.py`: extracción OK (STANDBY = 43 ORU, intervals ~10 s).
  - `latency_bench.py`: p95=178 µs ≪ 500 µs (PASS, host PC). Fix mío: ruta `--out`
    relativa rompía `relative_to(ROOT)` → resolver contra ROOT.
  - `run_matrix.py` (mío): campaña N corridas + ADR/IC95 Wilson; smoke N=2 OK
    (ADR 100%, IC95 [97.1,100], 15/15 escenarios). Fix mío: leer stdout del
    subproceso con `encoding="utf-8"` (cp1252 rompía con `≥`/UTF-8).
- **Hallazgo E1 (FP 43/43 en replay STANDBY)**: el replay real sobre
  `LECTURACONACK25AGOSTO.pcapng` produjo 43 FP, todos R-OBX-002
  ("Unauthorized unit: 262656^MDC_DIM_DIMLESS^MDC"). Causa raíz doble:
  1. `baseline.yaml` tenía `obx_units_observed: []` (el builder asumía
     "STANDBY CWE sin unidades"; falso — el STANDBY real SÍ trae OBX-6 DIMLESS).
  2. `src/hl7/validator.py` disparaba R-OBX-002 para *todo* OBX CWE
     (`or cwe_with_unit`), incluso unidad legítima.
  **La sesión paralela lo arregló (Enmienda E1, sin commitear):** builder popula
  `obx_units_observed=['262656^MDC_DIM_DIMLESS^MDC']`, validador quita la cláusula
  `cwe_with_unit`, baseline.yaml + rules.yaml documentan. Suite verde **179 tests**.
  Archivos E1 sin commitear: `src/hl7/validator.py`, `src/evidence/baseline_builder.py`,
  `baseline.yaml`, `config/rules.yaml`, `tests/test_validation_tools.py`.
- **Campaña H1 abortada (contaminada)**: lancé `run_matrix` 30 docker + 30 A14 en
  background; docker monta `./src` en vivo y el fix E1 cayó a mitad de campaña
  (corridas 1-8 código viejo fp=0; corrida 9 código nuevo fp=1) → resultados no
  sellables. Proceso orquestador + contenedor docker huérfano limpiados.
- **Pendiente inmediato (§3)**: (a) commitear E1 (completo y verde; decidir si lo
  commiteo yo o la sesión paralela); (b) re-ejecutar replay STANDBY con E1 (esperar
  FP=0); (c) re-lanzar campaña H1 limpia desde commit sellado (30 docker sin A14 +
  30 solo-A14); (d) bench 1000×3; (e) replay RUNNING; (f) diligenciar
  `RESULTS_YYYYMMDD.md`; (g) hardware Pi (Fase 6) sigue fuera de alcance.
- Commits de esta sesión: `416b6f1` (run_matrix + tests + fix bench). Fix run_matrix
  UTF-8 pendiente de commit.
