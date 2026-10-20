# HANDOFF — Contexto y pasos siguientes

> Última actualización: 2026-10-14 (sesión asistente 2: E2E docker validado, §7).

## 1. Contexto del proyecto

- Tesis G18 (Pontificia Universidad Javeriana): laboratorio reproducible y aislado para
  detección black-box de anomalías/ataques en comunicaciones HL7 v2.x/MLLP del equipo
  anestésico Mindray WATO EX-35, sobre Raspberry Pi.
- Sin pruebas ofensivas, sin malware, sin contacto con el equipo real.
- Directivas del usuario: trabajar por fases; cambios pequeños; correr tests tras cada
  módulo; **nunca** sobrescribir `evidence_raw/`; sin afirmaciones sin fuente; **siempre
  dejar este docs/HANDOFF.md al terminar el paso**.
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
  docs/TRACEABILITY_MATRIX.csv, **docs/RASPBERRY_PI_SETUP.md** (borrador Fase 6, sin ejecutar).
- Suite completa: **161 passed** (re-correr tras cualquier cambio).

## 3. Pendientes (en orden)

1. **Raspberry Pi (Fase 6):** ejecutar `docs/RASPBERRY_PI_SETUP.md` en hardware real;
   marcar la checklist del doc. Medir H2 (latencia ACK) ahí.
2. **Fase 9 (validación):** ≥30 corridas/escenario con semillas fijas, según
   `docs/VALIDATION_PROTOCOL.md`; diligenciar `docs/RESULTS_TEMPLATE.md`.
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
  clínica activa hasta aprobación (docs/ETHICS_AND_SAFETY.md).
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

## 9. Adenda - sesion asistente 2/4 (2026-10-14, cierre Fase 9)

Continuacion directa de la sesion asistente 2 (ver 5/6/7). El usuario pidio terminar
todo el plan de validacion. La sesion asistente 3 (paralela) colaboro: reconocio E1,
aborto su piloto contaminado y lanzo la campana oficial; esta sesion ejecuto replays,
bench y cierre documental. Estado final: Fase 9 COMPLETA en PC.

- **Commit E1 + tooling conjunto**: 70025c4 (E1 validator/baseline/rules + adopcion
  run_matrix/run_campaign + resultados piloto pre-E1 sellados).
- **Freeze manifest v2**: analysis_output/validation/freeze_manifest.json (HEAD 70025c4
  + hashes pre/post-E1 + orden de medicion). La campana oficial corrio despues en el
  commit 2017af16 (fix de conteo replay) - sellado en los summaries.
- **H3 replays (contador corregido, commit 2017af1)**:
  - STANDBY: FP = 0 confirmado 5x (v2 mio replay_STANDBY_postE1_v2_112757 + 4 de la
    sesion paralela). Pre-E1: 43/43 FP R-OBX-002 (2 replays historicos).
  - RUNNING: fp = 256 (R-OBX-001:86, R-OBX-002:86, R-OBX-003:84; 13 NORMAL)
    confirmado 3x identico (determinismo). Causa: baseline unimodal STANDBY.
- **Campana H1 (ambas fases exit=0, commit 2017af16)**:
  - FASE1 main_20261014_162606 (30 docker, exclude A14): ADR 100 % 15/15, Wilson
    global [99.8,100], precision 99.6 % (7 FP R-TIME-002 benignos por jitter).
  - FASE2 a14_20261014_172034 (30 local, solo A14): ADR 100 % (90/90), precision 100 %.
  - H1 ACEPTADA (RESULTS sec 2). Semillas 100001-100030 por fase.
- **H2 bench (latency_20261014_140421.json)**: 3x1000 peor caso; p95 agregado
  177.5 us << 500 us -> PASS de referencia en PC; H2 NO VERIFICADO para Pi.
- **Docs cerradas**: docs/RESULTS_20261014.md (completada con A14 + H2 + decisiones),
  LIMITATIONS (sec 5 actualizada + sec 9 hallazgos), este HANDOFF, SHA256SUMS.txt
  de analysis_output/validation/.
- **Pendiente unico (Fase 6/9 hardware)**: repetir latency_bench en Raspberry Pi
  (docs/RASPBERRY_PI_SETUP.md) antes de afirmar H2 en la tesis.
- Leccion de coordinacion: dos sesiones pueden colisionar en replays (puertos auto OK)
  pero NUNCA en docker (bind-mount vivo = contaminacion). Regla: todo cambio de
  src/config/baseline exige commit + re-freeze antes de cualquier corrida.

## 10. Adenda - sesion asistente 5 (2026-10-14, completar entregables spec)

El usuario pidio (tras un dump de spec OT/IoMT) completar lo que faltaba de los
18 entregables y dejar el proyecto funcionando. Inventario vs spec + cierre de gaps:

- **Gap 1 - diagrama Mermaid (entregable 17)**: anadido `docs/LAB_ARCHITECTURE.md` sec 1.1
  (`flowchart` con Modalidad A local + Modalidad B pasiva + pipeline offline + flujo
  de datos + interlock SafetyGuard; leyenda observado/sintetico/interlock).
- **Gap 2 - metricas faltantes en evaluate.py**: throughput (msg/s, desde timestamps
  de alerts.jsonl) y perdida de mensajes (esperado=benign_count+anomaly_count desde
  seed.txt vs recibido; NO_CALCULABLE si falta seed.txt). Nuevos campos
  `throughput`, `message_loss`, `resource_usage` en EvaluationResult + lineas de
  reporte. +8 tests (test_evaluate.py). load_alerts ahora devuelve 3 valores
  (alerts, normal, timestamps); test_integration ajustado.
- **Gap 2b - CPU/memoria en runtime**: nuevo `src/evidence/resource_monitor.py`
  (CPU via time.process_time portable; RSS pico via ctypes GetProcessMemoryInfo en
  Windows / resource.getrusage en POSIX; None=NO_VERIFICADO). `mllp_receiver.py`
  lo arranca y escribe `resource_usage.json` al cierre limpio; evaluate.py lo lee
  si existe. +4 tests (test_resource_monitor.py).
- **Fix - detect_pcap.py (sesion paralela, untracked)**: 2 typos rompian la suite
  (llamada `anomalicas_str` inexistente -> `format_anomalias`; var `anomalias` ->
  `anomalies`). Corregidos. El fixture de test_detect_pcap.py (IP fuente) lo corrigio
  la sesion paralela en paralelo (192.168.23.250, en allowed_ips).
- **Gap 3 - artefactos ausentes marcados**: `docs/EVIDENCE_ANALYSIS.md` sec 4 anade
  NO_VERIFICADO/NO PRESERVADO para los binarios de sesion de ackdummy
  (raw_*.bin, mensajes.hl7, sesion.log) - solo se conservan el codigo y los PCAPNG.
- **Verificacion metodologica**: sin frases de exito/demo no demostrado; taxonomia
  OBSERVADO/DOCUMENTADO/INFERIDO/NO_VERIFICADO presente en los 11 docs clave.
- **Suite**: 200 passed (antes 179). Dependencias: solo PyYAML (requirements.txt OK).
- **NO commitado a proposito**: la sesion paralela tiene cambios activos en
  docs/ATTACK_SCENARIOS.md, docs/TRACEABILITY_MATRIX.csv, requirements.txt, run_experiment.py
  + untracked (detect_pcap.py, test_manifest.py, etc.). Coordinar commit antes de
  mezclar trabajo incompleto ajeno.
- **Pendiente unico critico (hardware)**: H2 en Raspberry Pi (Fase 6) sigue NO
  VERIFICADO - requiere el hardware del usuario.

## 11. Adenda - sesion asistente 6 (2026-10-14, cierre de gaps spec + integracion)

Continuo la auditoria spec->repo y completo/integre lo que faltaba, absorbiendo
los cambios simultaneos de la sesion asistente 5 (ver §10) sin conflictos:

- **manifest.json por corrida** (`run_experiment.write_manifest`): id, UTC inicio/fin,
  commit Git (+dirty), config, semilla/phase_seeds, escenarios ejecutados/excluidos,
  SHA-256 de entradas (settings_lab/seed/baseline/rules) y salidas
  (ground_truth/alerts/evaluation), runtime (platform/python/contenedor), resultado
  (tp..fn, recall/precision/F1/FPR, latencia), advertencia LAB ONLY. Recursos del
  receptor via `ProcessSampler` (psutil opcional, 0.5 s; sin psutil -> nota honesta).
  +5 tests (tests/test_manifest.py). Smoke local verificado: runs/20261014_163236.
- **detect_pcap.py** (Modalidad B offline): reutiliza el pipeline
  analyze_evidence (reasm. TCP + MLLP + anonimizacion por defecto) y ejecuta el
  motor + AlertLogger sin abrir red. Limitaciones documentadas en su manifiesto
  (R-MLLP-001 no evaluable; R-TIME-002 depende de reloj -> flag --realtime).
  Corregido el lado cliente (_flow_key ordena lexicograficamente: emisor = lado
  != :1550). Smoke sobre LECTURACONACK25AGOSTO.pcapng: 43 ORU, 1 NORMAL +
  42 R-TIME-002 (esperado sin pacing). +4 tests (tests/test_detect_pcap.py).
- **Desviacion A14 documentada** en docs/ATTACK_SCENARIOS.md (spec decia "ACK ausente";
  el receptor no observa su propio ACK -> hueco de periodicidad R-TIME-002;
  el ACK ausente se valida desde el emulador --ack-timeout).
- **docs/TRACEABILITY_MATRIX.csv** reescrito: estados post-Fase 9 (VERIFICADO/MEDIDO_
  PC/IMPLEMENTADO) + columna `evidencia` con rutas de artefactos reales; +4 filas
  (MAN-01, OFF-01, GEN-01, H3-01).
- **docs/JUSTIFICACION_METODOLOGICA.md** nuevo: seccion academica de 13 puntos +
  referencias verificables (HL7, NIST SP 800-82r3, MITRE ICS, FDA, CISA, IEC 62443).
- **docs/LAB_ARCHITECTURE.md**: estado actualizado (Fase 9 completa), Modalidad B del
  Mermaid con detect_pcap/replay, puntos de entrada ampliados, psutil opcional.
- **docs/GUIA_USO.md**: receta §4.8 (detect_pcap + manifest), fila manifest.json en §5.1,
  herramientas y docs index actualizados. **README.md**: estado + entregables spec.
- **requirements.txt**: psutil (opcional, comentado) para el muestreo del manifest.
- **Integracion con sesion 5**: evaluate.py (throughput/message_loss/resource_usage
  + read_resource_usage), mllp_receiver + src/evidence/resource_monitor.py,
  EVIDENCE_ANALYSIS §4 (binarios ackdummy NO PRESERVADOS) - todos commiteados juntos.
- **Suite final: 200 passed** (2026-10-14). Smoke E2E local recall=1.0 fp=0 con
  manifest completo.
- **Pendientes inalterados**: H2 en Pi (hardware), gate clinico/etico, redaccion
  de la tesis por el usuario.

## 12. Adenda - sesion asistente 7 (2026-10-17, despliegue Pi + campana ransomware)

El usuario pidio "en base a lo demas desplegar la raspberry pi y la simulacion del
wato y el atacante con ransomware". Decidio simulacion docker de la Pi (hardware
fisico sigue sin IP/disponible). Sin cambios de codigo; interlocks de siempre.

- **Suite pre-vuelo: 204 passed** (2026-10-17, `.venv` Python 3.11.9). Docker
  Desktop estaba apagado; se arranco antes del modo docker.
- **Despliegue topologia Pi (docker)**: `run_experiment.py --mode docker
  --exclude A14 --seed 20261014` -> `runs/20261017_110211`, exit=0.
  64/64 inyecciones, TP=64 FP=1 FN=0, recall=1.0000, precision=0.9846,
  F1=0.9922, latencia p50=0.93 ms p95=1.93 ms; 15/15 escenarios al 100 %.
  FP unico: 1 x R-TIME-002 benigno (jitter, comportamiento ya documentado Fase 9).
  Sellada: `analysis_output/validation/pi_sim_20261017_110211/`.
- **Campana ransomware (WATO emulador + atacante)**: `run_experiment.py
  --mode local --exclude "A02,A03,A04,A07,A08,A09,A10,A11,A12,A15" --seed
  2026101401` -> `runs/20261017_110410`, exit=0. 20/20 inyecciones
  (A01=3, A05=3, A06=3, A13=5, A14=3, A16=3), TP=20 FP=0 FN=0,
  recall=precision=F1=1.0000, latencia p50=1.59 ms p95=7.23 ms, duracion 201 s.
  Sellada: `analysis_output/validation/ransomware_sim_20261017_110410/`.
  Evidencia cualitativa identica a la corrida de 2026-10-14: FRAMING_ERROR
  garbage_before_sb x3 (A06), sesion 136.8 s con hueco (A14), 5 sesiones de
  reconexion (A13), R-ID-001 MALICIOUS_APP/MINDRAY_WATOPRO (A01/A16).
- Alcance: sin malware real, sin equipo clinico (docs/SIMULACION_RANSOMWARE.md);
  H2 en Pi fisica sigue NO VERIFICADO.
- **Scripts de despliegue creados** (mismo dia; rutas finales tras la
  reorganizacion por componente): `deploy/receptor/receptor.ps1` +
  `deploy/receptor/make_deploy_settings.py` (settings con marker del repo),
  `deploy/wato/wato.ps1`, `deploy/atacante/atacante_ransomware.ps1`,
  `deploy/pi/pi_detector_docker.ps1`, `deploy/validacion/suite.ps1`,
  `deploy/validacion/evaluar.ps1` (ASCII puro, cultura invariante) +
  `deploy/pi/` (01_instalar, 02_red_aislada ufw, 03_instalar_servicio systemd,
  04/05 detector online/offline, 06_campana, mllp-receiver.service con
  ExecStartPre) + `.gitattributes` (sh/service LF). Referencias internas de
  paths actualizadas en scripts y docs (MANUAL, README, RESULTADOS_TESIS).
- **Demo WATO standalone**: `receptor/receptor.ps1` + `wato/wato.ps1` (STANDBY 8 msg/6 s)
  -> 8/8 ORU, 8/8 ACK `AA`, 0 alertas (8 eventos NORMAL INFO), sesion 42.1 s,
  5720 B; evidencia `evidence_output/wato_demo_20261017_112431/` con SHA-256.
- **Reorganizacion para GitHub** (sin cambios de src): 15 docs -> `docs/`
  (refs actualizadas en el codigo, 0 rotas); PDFs/DOCX/bib -> `documentos_tesis/`;
  `ackdummy (1).py` -> `legacy/`; archivos sueltos de la carpeta externa
  `Wato/` -> `Wato/capturas_y_textos_sueltos/`.
- **Documentos de entrega**: `MANUAL_TESIS.md` (raiz: uso, despliegues Pi/WATO/
  atacante, salida de resultados, guion de defensa) y `docs/RESULTADOS_TESIS.md`
  (compilado H1/H2/H3 + ransomware + Pi docker + demo WATO + bench + mapa de
  evidencia). `README.md`: seccion Estructura reescrita + estado sesion 7.
- **Verificacion final sesion**: suite `204 passed` (27.68 s); `evidence_raw/`
  SHA-256 OK (9/9 contra `evidence_inventory.csv`); evidencia sellada 2026-10-17
  en `analysis_output/validation/{pi_sim,ransomware_sim}_20261017_*`.
- Estado git: solo docs/deploy/nuevos .md; nada de src/config/baseline.
  Sin commits en esta sesion (coordinar con sesion paralela, ver §10).

## 13. Adenda - rama pruebas-santi (2026-10-19, enmiendas E2 y E3)

Trabajo de Santiago (con asistente) sobre `main` descargado el 2026-10-19. Sin tocar
`evidence_raw/`; todo cambio de baseline se aplica en `baseline.yaml` Y en
`src/evidence/baseline_builder.py`, igual que la Enmienda E1. Propuesta para revisión
de Gabriel antes de mezclar a `main`.

- **Enmienda E2 - R-STATE-001 (FSM).** Hallazgo: `_infer_state` buscaba 'STANDBY'
  en el componente 0 de OBX-5, que es numérico (`202836`), así que los 158 ORU reales
  quedaban `SESION_ESTABLECIDA_UNKNOWN` y la regla nunca podía disparar (el FP=0 de la
  matriz de trazabilidad era por regla inerte). Cambios:
  - Estado por código OBSERVADO: `202836` STANDBY, `202902` RUNNING (respaldo por nombre).
  - Mensaje sin OBX 202886 no se trata como transición.
  - Transición STANDBY->RUNNING agregada (OBSERVADA 1 vez en LECTURAACK27AGOSTO:
    13 STANDBY -> 86 RUNNING). RUNNING->STANDBY sigue NO_VERIFICADO y alerta.
  - Coherencia: estado RUNNING exige `184352^MDC_VENT_MODE` (presente 86/86 RUNNING,
    0/56 STANDBY). Nº de OBX en RUNNING varía 17-28 según modo: no se exige conteo.
- **Enmienda E3 - vigilante de silencio (R-TIME-002).** Hallazgo: un canal caído sin
  mensaje posterior nunca alertaba (60 s -> 0 alertas). `DetectionEngine.check_silence()`
  alerta una vez por episodio al superar el límite de baseline (p95*1.5 = 15 s);
  `mllp_receiver.py` lo consulta cada 1 s. No se arma antes del primer mensaje.
- **Pruebas:** `tests/test_enmiendas_e2_e3.py` (13 pruebas con ORU reales de
  `evidence_raw/`). Las 13 fallan sobre `main` y pasan con E2/E3. Suite: **217 passed**.
- **Verificación (2026-10-19, local, semilla 100001):**
  - Capturas reales con reloj de captura: STANDBY 43/43 reconocidos, 0 alertas;
    RUNNING 13 STANDBY + 86 RUNNING, 0 R-STATE-001 (R-OBX sin cambio: 256, fuera de
    alcance); Nessus 14-sep: estados STANDBY, R-TIME-002=4 sin cambio.
  - Campaña A01-A16 a 6 s y 10 s: 67/67 TP, recall 1.000 (igual que antes).
    Aparecen 3 alertas fuera de ventana por corrida: son los 3 silencios de A14,
    detectados por E3 ~30 s ANTES del timestamp de ground truth (A14 registra la
    inyección al enviar el mensaje posterior al silencio de 45 s). No son FP reales;
    queda por decidir cómo etiquetar A14 en `anomaly_generator.py`/`evaluate.py`.
  - Prueba de evasión (ORU STANDBY real con OBX-5 cambiado a RUNNING, IP/MSH-3/
    cadencia correctas): antes 0 alertas -> ahora 3 R-STATE-001 HIGH.
    Prueba de caída (60 s sin mensajes): antes 0 -> ahora 1 alerta a los 16 s.
- **Pendientes (no hechos a propósito):** perfil OBX de RUNNING (256 alertas), reloj de
  captura en `detect_pcap.py`, razón correcta en alertas R-OBX-002/003, límite 4096 B
  frente a RUNNING real de hasta 3894 B, texto "SYN cada ~30s" (real: ciclo 47.6 s).
