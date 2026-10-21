# HANDOFF — Contexto y pasos siguientes

> Última actualización: 2026-10-20 (cierre post-integración PR #1: baseline bimodal v1.1 + Enmiendas E2–E8, §16).

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
- Suite completa: **252 passed, 0 xfailed** (re-correr tras cualquier cambio).

## 3. Pendientes y áreas de mejora continua (en orden de prioridad)

1. **Hardware en Raspberry Pi física (Fase 6):**
   - Ejecutar el despliegue con `deploy/pi/` (01_instalar...06_campana) en la Pi 4 real sobre red aislada.
   - Medir formalmente H2 con `latency_bench.py --messages 1000 --runs 5` directamente en hardware ARM y verificar p95 ≤ 500 µs (hasta ahora PASS en PC x86, clasificado honestamente como `NO_VERIFICADO` en hardware).
2. **Campaña Docker de 30 corridas con `run_matrix.py` bajo baseline bimodal v1.1 + E1–E9:**
   - Se selló el paquete de verificación bimodal `analysis_output/validation/bimodal_v12_20261020/` (E2E local TP=64 FP=0 TN=12, H2 bench p95=206.31 µs PASS, H3 STANDBY 43/43 NORMAL y RUNNING 99/99 NORMAL) con `SHA256SUMS.txt` actualizado. Cuando se desee regenerar la matriz de 30 corridas en contenedores con Docker Desktop activo, ejecutar `run_matrix.py --runs 30 --mode docker --exclude A14 --tag bimodal_main`.
4. **Captura y perfilado de alarmas fisiológicas reales:**
   - El estado `ALARM_SIMULATED` del emulador es sintético. Si en el sandbox hospitalario futuro se logra capturar tráfico con alarma real activa (o desaturación en pulmón de prueba), modelar los códigos y transiciones fisiológicas correspondientes, sujetas a la aprobación clínica formal (`clinical_approval_status: PENDING`).
5. **Limpieza y mantenimiento de entorno Docker:**
   - Limpieza periódica de volúmenes temporales: `docker volume rm investigacion-de-la-tesis_lab_output` o `docker compose down -v`.

## 4. Comandos útiles

```powershell
# Suite completa (debe decir 252 passed)
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
- framer `max_message_size: 5120` (Enmienda E9: +1143 B sobre SIMV-VC+PS 3977 B) → A15 dispara R-MLLP-001.
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

## 14. Adenda - rama pruebas-santi (2026-10-20, enmiendas E4 a E7)

Continuación de §13, mismas reglas (sin tocar `evidence_raw/`; baseline en
`baseline.yaml` Y `baseline_builder.py`). Propuesta para revisión de Gabriel.

- **E4 - motivo de R-OBX-002/003** (`src/detection/engine.py`). Todas las alertas R-OBX
  usaban `errors[0]`, así que R-OBX-002/003 mostraban "Unauthorized OBX code: 184352".
  Ahora cada una lleva su propio error (p. ej. "Unauthorized unit: 263762^MDC_DIM_MILLI_L
  for code 20015"). Los conteos no cambian (RUNNING real: 86/86/84).
- **E5 - hora de captura en `detect_pcap.py`.** `process_message(..., now=None)`: con
  `None` (receptor en vivo) el comportamiento es idéntico; offline se pasa la hora del
  paquete. Los mensajes se procesan en el orden en que TCP los entrega (máximo
  acumulado por flujo) e intercalados entre flujos (`delivery_order`). `--realtime`
  queda solo como ritmo de reproducción. Resultados:
  - STANDBY 25-ago: antes 1 NORMAL + 42 R-TIME-002 -> ahora **43 NORMAL**.
  - RUNNING 27-ago: 0 alertas de tiempo; quedan solo R-OBX (86/86/84, ver pendientes).
  - Nessus 14-sep (`analconnessusactivo`, fuera del repo): **R-TIME-002=5, R-TIME-001=0**.
    El arnés de §13 (orden por hora de paquete) daba además R-TIME-001=1; el MCID 91 se
    retransmitió (primera copia capturada a los 916 s, después de la 92) y TCP entrega
    91 antes que 92, así que no hay timestamp regresivo real. Las 5 alertas: hueco de
    25.8 s, entrega simultánea 91/92 (0 s), 4.2 s y dos huecos de 20 s.
- **E6 - evaluación por conexión** (`anomaly_generator.py`, `evaluate.py`). Ajusta la
  decisión de §5 "alertas en ventana -> correlacionadas": el ground truth guarda
  `source` (ip:puerto local de la conexión de la inyección) y `started_utc` (inicio de
  la anomalía; en A14 el comienzo del silencio). Una alerta solo se correlaciona con
  inyecciones de su misma conexión, desde `started_utc` hasta `timestamp_utc`+ventana.
  Ground truth antiguo sin esos campos se evalúa igual que antes (re-evaluada la corrida
  `20261019_105937`: mismo TP=67 FP=3).
- **E7 - texto SIN_GATEWAY** (baseline). Medido en LECTURA25AGOSYO (19 ciclos, puertos
  2048-2066): SYN a 0, +1.6, +16.6, +31.6 s, RST del WATO a +46.6 s, nuevo puerto a
  +47.6 s. Antes decía "SYN cada ~30s". En esa misma captura hay 30 SYN de .200 hacia
  el puerto 1550 del WATO respondidos con RST (el WATO no escucha en 1550).
- **Pruebas:** `tests/test_enmiendas_e4_e5.py` (10) y `tests/test_enmienda_e6.py` (8);
  17 de las 18 fallan sin las enmiendas. Suite: **235 passed**.
- **Verificación (2026-10-20, local, semilla 100001):**
  - Campaña A01-A16 a 6 s y a 10 s: TP=67 FN=0 FP=1 TN=11 (+94 correlacionadas), igual
    en las dos. Antes: FP=3. Cambio de composición: los 3 silencios de A14 pasan a
    correlacionados (son detecciones reales, §13), y aparece 1 FP que antes quedaba
    oculto: el primer mensaje benigno de la fase 2 (conexión del emulador) alerta
    R-TIME-002 "Interval too short: 0.33 s" porque llega justo después de la última
    inyección (R-TIME-002 es global entre sesiones, §5).
  - Evasión y caída (arnés de §13): sin cambio, 3 R-STATE-001 y 1 silencio a los 16 s.
  - Modo docker: NO_VERIFICADO en esta rama (no hay Docker en el entorno de prueba).
    `source` sale de `getsockname()` del generador; en la red interna sin NAT debería
    coincidir con el `source` de la alerta.
- **No hecho a propósito:** intervalos por sesión en R-TIME-002. Evitaría el FP de arriba,
  pero contradice §5 (estado global) y rompería A13, que se detecta justamente por
  reconexiones en sesiones nuevas. Decisión para Gabriel.
- **Pendientes:** perfil OBX de RUNNING (las 256 alertas R-OBX sobre RUNNING real
  siguen porque la baseline es solo STANDBY), límite `max_message_size: 4096` frente a
  RUNNING real de hasta 3894 B (margen 5 %).

## 15. Adenda - integración pruebas-santi sobre main del 2026-10-20 (rama pruebas-santi-v2)

Main descargado el 2026-10-20 (commits de Gabriel del 19-oct ~22:25: baseline bimodal
STANDBY+RUNNING, emulador de 6 modos, `capture_time` en el motor, estados por código,
anonimizador sin romper el OID IHE). Las enmiendas §13-§14 se re-aplicaron encima con
este criterio: **donde main ya resolvía lo mismo, queda la versión de main**; de
pruebas-santi entra solo lo que main no tiene.

- **Fallo en main: `wato_emulator.py` no compila.** Tiene 4 bloques de conflicto de git
  sin resolver (`<<<<<<< HEAD` / `>>>>>>> f15c0259...`), así que `tests/test_integration.py`
  no se puede ni recolectar y el emulador no corre. Resuelto con el lado `f15c0259`
  (6 modos), que es el único coherente con el resto del archivo (`_build_running_obx`,
  `--vent-mode`, `RUNNING_HEADER_OBX` están fuera del conflicto y solo existen en ese
  lado) y con las pruebas nuevas de main. **Gabriel debe confirmarlo**: el lado HEAD
  quitaba la línea NTE "SYNTHETIC-NOT-FOR-CLINICAL-USE".
- **Queda la versión de main (descartado lo nuestro):** E5 `now` -> se usa
  `capture_time` de main; `_infer_state` de main (además devuelve un estado propio para
  valores desconocidos, que alerta: mejor que la E2, que los ignoraba). Las pruebas E2-E5
  se adaptaron a `capture_time` y a que el RUNNING real ya no da alertas R-OBX.
- **Se conserva de pruebas-santi (main no lo tiene):** coherencia RUNNING ⇒ OBX 184352
  (E2), vigilante de silencio (E3), motivo propio en R-OBX con varias violaciones en un
  mismo mensaje (E4), orden de entrega TCP en `detect_pcap` (E5), evaluación por
  conexión (E6) y ciclo SYN medido en SIN_GATEWAY (E7; se mantiene el ARP y el rango
  0-299 s de main). Sobre el main resuelto, 19 de nuestras pruebas fallan (los huecos).
- **E8 nueva - R-TIME-001 con zona horaria** (`src/hl7/validator.py`). Al integrar
  apareció un FP nuevo: el emulador de main escribe MSH-7 con -0500 (como el WATO) y el
  generador en UTC (+00:00); el validador comparaba solo dígitos, así que el primer
  benigno de la fase 2 (17:03:21-0500 = 22:03:21Z) era "regresivo" frente a 22:03:21+00:00.
  Ahora, si ambos traen offset se comparan instantes; si no, como antes. A04 sigue 3/3.
  En main este FP existe pero el evaluador anterior lo oculta.
- **Para decisión de Gabriel:** `state_transitions_observed` incluye RUNNING->STANDBY,
  pero ninguna captura lo muestra (27-08: solo STANDBY->RUNNING). Se dejó como está en
  main; `test_running_a_standby_no_verificado_sigue_alertando` queda `xfail(strict)`.
- **Verificación (2026-10-20, local, semilla 100001):** suite 245 passed + 1 xfailed.
  STANDBY 43/43 NORMAL; RUNNING 99/99 NORMAL; Nessus R-TIME-002=5 (sin el -5.797 s que
  da main por la retransmisión). Evasión 3 R-STATE-001, caída 1 alerta (main: 0 y 0).
  Campaña 6 s y 10 s: TP=67 FN=0 FP=1 TN=11 (el FP es el R-TIME-002 global de §14).
  Main resuelto sin enmiendas: FP=0 reportado, con 2 alertas falsas ocultas como
  "correlacionadas" (R-TIME-001 por zona horaria y R-TIME-002 0.32 s).
- **Riesgo:** emulador SIMV-VC+PS = trama de 3977 B (real máx. 3897 B; +80 B por la NTE),
  a 119 B del `max_message_size: 4096`.
- **Docs de main desactualizados (no tocados):** `GUIA_USO.md` línea "baseline es
  unimodal STANDBY" y `RESULTADOS_TESIS.md` (256 alertas RUNNING) describen el estado
  anterior a la baseline bimodal.

## 16. Adenda - cierre de integración sobre main (2026-10-20, post PR #1)

Continuación directa tras el merge de `Pruebas-santi` en `main` (`850ba39`). Se
resolvieron todos los puntos pendientes dejados para decisión/confirmación en §14 y §15:

- **Limpieza post-merge en `wato_emulator.py`:** el merge commit `a34f6da` había
  duplicado la definición de `_build_running_obx`; se eliminó el duplicado y se
  confirmó la versión de 6 modos ventilatorios (`VCV`, `SIMVVC_PLUS_PS`, `PCV`,
  `SIMVPC_PLUS_PS`, `PS`, `MANUAL`, `CYCLE`) con el segmento opcional de auditoría
  `NTE|1|SYNTHETIC-NOT-FOR-CLINICAL-USE...` (la trama máxima en `SIMV-VC+PS` es
  3977 B < `max_message_size: 4096`).
- **Decisión FSM `RUNNING -> STANDBY` (E2):** dado que ninguna captura de
  `evidence_raw/` contiene la transición `SESION_ESTABLECIDA_RUNNING ->
  SESION_ESTABLECIDA_STANDBY` (`LECTURAACK27AGOSTO.pcapng` solo muestra 13 `STANDBY`
  → 86 `RUNNING`), se retiró de `state_transitions_observed` tanto en `baseline.yaml`
  como en `src/evidence/baseline_builder.py` y se quitó el `@pytest.mark.xfail` de
  `test_running_a_standby_no_verificado_sigue_alertando` en
  `tests/test_enmiendas_e2_e3.py`. Toda transición no observada alerta `R-STATE-001`.
- **Decisión sobre el FP de transición en `run_experiment.py` (§14):** se mantiene
  `R-TIME-002` **global entre sesiones** (§5, indispensable para que `A13`
  `repeated_reconnections` detecte 5/5). La causa del único FP en la transición
  `FASE ANÓMALA -> FASE BENIGNA 2` (0.33 s < 5.0 s) era que el orquestador lanzaba el
  emulador de la fase 2 inmediatamente al terminar el generador de anomalías. Se
  añadió `time.sleep(args.interval)` antes de `FASE BENIGNA 2` (en `run_local` y
  `run_docker`), respetando la cadencia benigna sin disparar el vigilante de silencio
  E3 (15 s).
- **Verificación ejecutada (2026-10-20):**
  - Suite completa: **`246 passed` en 39.28 s** (`0 xfailed`).
  - Detección offline (`detect_pcap.py`):
    - `LECTURACONACK25AGOSTO.pcapng` (`STANDBY_v11`): **43/43 `NORMAL`, 0 anomalías**.
    - `LECTURAACK27AGOSTO.pcapng` (`RUNNING_v11`): **99/99 `NORMAL`, 0 anomalías**.
  - Corrida E2E local (`runs/20261020_212558`, `--exclude A14 --seed 100001`):
    **64/64 inyecciones detectadas (TP=64, FN=0), 12/12 mensajes benignos limpios
    (TN=12, FP=0), `recall=1.000`, `precision=1.000`, `F1=1.000`**.
- **Documentación sincronizada:** `README.md`, `MANUAL_TESIS.md`, `docs/GUIA_USO.md`,
  `docs/RESULTADOS_TESIS.md`, `docs/LIMITATIONS.md`, `docs/SRS_Resultados.md` (v1.2),
  `docs/SPMP_Resultados.md` (v1.2), `docs/TRACEABILITY_MATRIX.csv` y este
  `docs/HANDOFF.md` actualizados al estado bimodal v1.1 + Enmiendas E1–E8.

- **Próximos pasos y mejoras recomendadas:**
  1. Ejecución del banco en placa Raspberry Pi física (medición ARM de H2).
  2. Ajuste preventivo del margen `max_message_size` (4096 vs 3977 B en SIMV-VC+PS).
  3. Re-sellado de campaña oficial 30 corridas con `run_matrix.py` bajo baseline bimodal.

## 17. Adenda - Enmienda E9, saneamiento de deudas técnicas y sellado bimodal v1.2 (2026-10-20)

Desarrollo de los puntos de mejora del Handoff (§3 y `docs/AUDITORIA_REPO.md` §10):

- **Enmienda E9 — Margen `max_message_size: 5120` y sincronización de `settings.yaml`:**
  - Se elevó `wato_observed_standby.mllp.max_message_size` de `4096` a **`5120` B (5 KiB)** en
    `src/config/settings.yaml`, otorgando **+1143 B (~29 %)** de holgura sobre la trama
    máxima de `RUNNING` (`SIMV-VC+PS` emulado con `NTE` = 3977 B; real máx. = 3945 B) y
    conservando la detección al 100 % de `A15` (`oversized_message`, ~16 KiB).
  - Se sincronizó la sección `baseline_builder` de `src/config/settings.yaml` con
    `baseline.yaml` v1.1 bimodal (`source_sessions`, `schema_version: "1.1"`, `message_length`
    hasta 3945 B, 36 entradas de códigos OBX, 9 unidades MDC, `["CWE", "NM", "SN"]` y las
    5 transiciones FSM observadas).
- **Cierre de deudas técnicas en `src/` (`docs/AUDITORIA_REPO.md` §10):**
  - Creados `src/hl7/__init__.py`, `src/detection/__init__.py` y `src/config/__init__.py`
    (y documentados `src/mllp/__init__.py` y `src/evidence/__init__.py`), unificando los 6
    subpaquetes de `src/`.
  - Eliminado el bloque de código muerto inalcanzable tras `return None, 0` en
    `src/mllp/framing.py::_try_extract_frame`.
  - Nuevas pruebas en `tests/test_enmienda_e9.py` (5 pruebas, incluyendo verificación AST
    contra código muerto post-`return`). Suite total: **`252 passed, 0 xfailed`**.
- **Bench H2 y sellado `analysis_output/validation/bimodal_v12_20261020/`:**
  - `latency_bench.py --messages 1000 --runs 3 --seed 20261020` →
    `analysis_output/validation/latency_20261020_214029.json`: **p50 = 71.8 µs,
    p95 = 206.31 µs, p99 = 374.71 µs** (≪ 500 µs → **PASS en PC**; Pi física sigue
    `NO_VERIFICADO`).
  - Paquete sellado en `analysis_output/validation/bimodal_v12_20261020/`
    (`validation_bimodal_summary.json`, `evaluation.json`, `manifest.json`, manifiestos
    offline `STANDBY` 43/43 y `RUNNING` 99/99, y bench H2) + `SHA256SUMS.txt` regenerado
    (210 archivos sellados).

## 18. Adenda - API pública (`__all__`) en `src/` y soporte bimodal en `run_experiment.py` (2026-10-20)

- **API pública (`__all__`) en los 6 subpaquetes de `src/`:**
  - `src/config/__init__.py`, `src/alerting/__init__.py` y `src/evidence/__init__.py`
    re-exportan sus clases y funciones públicas en `__all__`.
  - `src/hl7/__init__.py` y `src/detection/__init__.py` exponen su `__all__` completo
    usando carga perezosa a nivel de módulo (`__getattr__`, PEP 562) para `validator` y
    `engine`, evitando el ciclo de importación `hl7.validator <-> detection.baseline`.
- **Soporte bimodal (`--state RUNNING --vent-mode`) en `run_experiment.py`:**
  - Añadidos `--state {STANDBY,RUNNING}` y `--vent-mode {VCV,SIMVVC_PLUS_PS,PCV,SIMVPC_PLUS_PS,PS,MANUAL,CYCLE}`
    al orquestador (`run_local`, `run_docker` y `manifest.json`), permitiendo ejecutar
    campañas E2E con tráfico benigno multimodo en `RUNNING`.
- **Suite completa:** **`252 passed, 0 xfailed`**.

