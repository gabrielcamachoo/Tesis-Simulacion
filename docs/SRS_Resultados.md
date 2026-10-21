# Especificación de Requerimientos de Software (SRS)

**Proyecto:** G18 — Nodo de monitoreo de seguridad de red para equipos médicos
(Caso de estudio: monitor anestésico Mindray WATO EX-35)
**Documento:** SRS_Resultados.md — especificación de lo **implementado** en el
repositorio (laboratorio de software), no del sistema embebido BIW planeado.
**Versión:** 1.0 · **Fecha:** 2026-10-17 · **Commit de referencia:** `72515e6`
**Base normativa:** IEEE 830-1998 (withdrawn; contenido absorbido por
ISO/IEC/IEEE 29148:2018 [5]) · estructura alineada con `documentos_tesis/SRS_Tesis.pdf`
· auditoría factual en `docs/AUDITORIA_REPO.md`.

| Versión | Fecha | Cambio |
|---|---|---|
| 1.0 | 2026-10-17 | Versión inicial basada en auditoría completa del código |
| 1.1 | 2026-10-19 | Alineación completa con las 3 capturas reales (`WATOPARANALIZAR18AGOSTO.pcap`, `LECTURACONACK25AGOSTO.pcapng`, `LECTURAACK27AGOSTO.pcapng`): baseline bimodal STANDBY+RUNNING (33 códigos OBX, 9 unidades MDC, 6 modos ventilatorios), emulador WATO fiel al protocolo IHE PCD-01 / IEEE 11073-10101 MDC + `99MNDRY`, y corrección de anonimización de OIDs ISO |
| 1.2 | 2026-10-20 | Integración de Enmiendas E2–E8: coherencia `R-STATE-001` (`184352^MDC_VENT_MODE` obligatorio en `RUNNING` y alerta en `RUNNING->STANDBY` no observado), vigilante de silencio `check_silence()` (E3), motivo propio por regla en `R-OBX-001/002/003` (E4), orden de entrega TCP + `capture_time` en `detect_pcap.py` (E5), evaluación por conexión `source` + `started_utc` (E6), ciclo SYN 47.6 s en `SIN_GATEWAY` (E7) y comparación con zona horaria en `R-TIME-001` (E8); suite en **246 pruebas** |

---

## 1. Introducción

### 1.1 Propósito

Este SRS especifica los requerimientos del **software de laboratorio G18**: un
detector determinista de anomalías/ataques sobre el canal HL7/MLLP del monitor
anestésico Mindray WATO EX-35, operado como banco de pruebas aislado (caja negra).
El documento describe lo que **realmente existe en el código** al commit de
referencia; los elementos no implementados se marcan explícitamente como
*Pendiente* o *No verificado*.

El producto original planeado en `SRS_Tesis.pdf` es un nodo embebido
Bump-in-the-Wire (BIW); este SRS acota la **entregable software construida**:
receptor-detectar, emulador, generador de anomalías, evaluador y herramientas de
validación, todos en Python 3.11+.

### 1.2 Alcance

**Incluido:**
- Receptor MLLP/HL7 v2.x con motor de detección de 15 reglas deterministas.
- Emulador sintético del WATO (tráfico benigno) y generador de anomalías A01–A16
  con verdad de terreno (ground truth).
- Pipeline de evaluación (TP/FP/TN/FN, recall, precision, latencia, throughput).
- Detección offline sobre PCAP/PCAPNG y replay de evidencia real.
- Interlocks de seguridad laboratorial y evidencia forense con SHA-256.
- Despliegues Windows (`deploy/receptor|wato|atacante|validacion`) y Raspberry Pi
  (`deploy/pi/`), más topología Docker aislada.

**Excluido (Pendiente/No verificado):**
- Nodo BIW embebido en línea (Raspberry Pi/Jetson entre WATO y red).
- Modificación del firmware del WATO o de la red IT hospitalaria.
- Reglas clínicas activas (`clinical_approval_status: PENDING`).
- Verificación en hardware clínico real o en la Pi física (H2 NO_VERIFICADO).
- Machine learning de cualquier tipo (el motor es determinista por diseño).

### 1.3 Definiciones, siglas y abreviaturas

| Término | Definición |
|---|---|
| HL7 v2.x | Estándar de mensajería clínica (segmentos/campos delimitados); la evidencia observada declara HL7 2.6 [6] |
| MLLP | *Minimal Lower Layer Protocol*: encapsulación de HL7 sobre TCP con delimitadores SB `0x0B`, EB `0x1C`, CR `0x0D` [3] |
| ACK | Application Level Acknowledgment; `MSA` con código `AA` (accept), `AE` (error), `AR` (reject) |
| MSH | Message Header segment (campos MSH-3 app emisora, MSH-7 timestamp, MSH-9 tipo, MSH-10 control ID, MSH-16 ack, MSH-18 charset) |
| OBX | Observation Result segment (OBX-2 tipo dato, OBX-3 identificador, OBX-5 valor, OBX-6 unidad) |
| ORU^R01 | Tipo de mensaje HL7 de resultados observados (único tipo en baseline) |
| IHE PCD-01 | Perfil de integración de IHE *Patient Care Devices* para telemetría de monitores [3] |
| DOR/DOC | (Del SRS de tesis original) perfiles IHE de dispositivos; no implementados en este software |
| ADR | Attack Detection Rate (recall sobre inyecciones); = tasa de detección |
| MoSCoW | Must / Should / Could / Won't have |
| FSM | Máquina de estados finitos (SIN_GATEWAY → HANDSHAKE → SESION_ESTABLECIDA_*) |
| MCID | Message Control ID (MSH-10) |
| Ground truth | `ground_truth.jsonl` con cada inyección (timestamp, escenario, regla esperada) |
| Interlock | Barrera de seguridad que impide operar sin autorización de laboratorio |

### 1.4 Referencias

Enlaces verificados con respuesta HTTP 200 el 2026-10-17:

[1] MITRE ATT&CK for ICS, T1692 *Unauthorized Message* (subtécnica T1692.002
*Reporting Message*), v20 — https://attack.mitre.org/techniques/T1692/
[2] MITRE ATT&CK for ICS, T0814 *Denial of Service* — https://attack.mitre.org/techniques/T0814/
[3] IHE International, *Technical Frameworks* (dominio Devices/PCD) — https://www.ihe.net/Technical_Frameworks/
[4] RFC 5424, *The Syslog Protocol* — https://www.rfc-editor.org/rfc/rfc5424
[5] ISO/IEC/IEEE 29148:2018, *Requirements engineering* — https://www.iso.org/standard/72089.html
[6] Health Level Seven International — https://www.hl7.org
[7] Mindray, *WATO EX-35 Anesthesia Machine* (página oficial de producto) — https://www.mindray.com/en/products/anesthesia/wato-ex-35

Referencias bibliográficas (sin enlace público verificable):
[8] IEEE 830-1998, *IEEE Recommended Practice for Software Requirements Specifications*
(retirado; absorbido por [5]).
[9] IEEE Std 1058-2002, *IEEE Standard for Software Project Management Plans*.
[10] HL7 Version 2.6, *HL7 Version 2 Product List / estándar* (miembros HL7; ver [6]).
[11] Mindray WATO EX-35 Specifications (datasheet oficial, P/N ENG-WATO EX-35
datasheet-210285X4P-20180828), servido desde mindray.com [7].

### 1.5 Visión general

El software recibe tráfico MLLP/HL7 (real, emulado o inyectado), lo parsea, lo
valida contra una **línea base** derivada de evidencia capturada del WATO real y
aplica 15 reglas deterministas mapeadas a MITRE ATT&CK ICS v20 [1][2]. Cada
mensaje genera alerta o evento NORMAL; todo queda sellado con SHA-256. Un
orquestador encadena fases benigno → ataque → benigno → evaluación, y los
hipótesis H1/H2/H3 se miden con `run_matrix.py`, `latency_bench.py` y
`replay_evidence.py` respectivamente.

## 2. Descripción general

### 2.1 Perspectiva del producto

El producto es un componente de seguridad de red para entornos clínicos
(IoMT/ICS hospitalario), dentro del sistema mayor "protección del flujo HL7 del
WATO EX-35". Interactúa con: (a) el dispositivo emisor (WATO real o emulador) por
TCP/1550; (b) el investigador por CLI y archivos de salida; (c) sistemas SIEM
opcionales vía syslog [4] (implementado, deshabilitado por defecto). No modifica
el dispositivo ni el flujo clínico: es observador (o receptor sintético en lab).

### 2.2 Funciones del producto

1. Recibir y desenmarcar tráfico MLLP sobre TCP (puerto 1550).
2. Parsear HL7 v2.x (ORU^R01 observado) y extraer campos clave MSH/OBX.
3. Validar estructura, identidad, temporalidad y contenido contra baseline.
4. Evaluar 15 reglas deterministas con estado por sesión y entre sesiones.
5. Emitir alertas explicables (JSONL) y eventos NORMAL con hash de evidencia.
6. Responder ACK `MSA|AA` o operar en modo observador.
7. Preservar evidencia forense por sesión (raw/HL7/log/meta) con SHA-256.
8. Anonimizar datos clínicos (PID/PV1/NTE) por defecto en artefactos derivados.
9. Generar tráfico benigno (emulador) y anómalo etiquetado (A01–A16).
10. Evaluar corridas (TP/FP, recall, precision, latencia, throughput, pérdida).
11. Detectar offline sobre PCAP y reenviar evidencia real (replay).
12. Ejecutar campañas N corridas con IC95 de Wilson (H1).

### 2.3 Características del usuario

Usuario único: **investigador de laboratorio** con línea de comandos. No hay GUI.
Requiere autorización explícita (interlocks §3.1, RF-012). Perfiles de despliegue:
Windows (PowerShell), Raspberry Pi OS (bash + systemd) y Docker.

### 2.4 Restricciones

- Sin malware, exploits, persistencia ni DoS real; sin objetivo externo.
- Red de pruebas declarada: `192.168.23.0/24` (servidor .200, WATO .250) y red
  Docker interna `172.30.0.0/24` sin egress.
- Sin datos reales de pacientes: anonimización irreversible por defecto.
- Hardware Pi física no disponible en el laboratorio (topología Pi simulada en Docker).

### 2.5 Modelo del dominio y pila de protocolos verificada

El monitor anestésico **Mindray WATO EX-35** (*WATO Pro Series*) opera como un actor **DOR (*Device Observation Reporter*)** dentro del perfil de integración **IHE PCD-01** (*Device Enterprise Communication — Communicate PCD Data*) [3], transmitiendo telemetría no solicitada hacia un receptor **DOC (*Device Observation Consumer*)** sobre la siguiente pila de protocolos verificada empíricamente en las tres capturas del proyecto:

1. **Capa de enlace y red (Ethernet / ARP / IPv4):** MAC de origen `00:0f:14:35:86:ec` (OUI Mindray Bio-Medical Electronics; EUI-64 `000F14002D3586ec`), IP de origen `192.168.23.250/24` hacia el gateway/receptor `192.168.23.200/24`. En `WATOPARANALIZAR18AGOSTO.pcap` (1 664 tramas) se observa la fase `SIN_GATEWAY` con solicitudes ARP `Who has 192.168.23.200? Tell 192.168.23.250`.
2. **Capa de transporte (TCP):** El WATO actúa como **cliente TCP activo** iniciando el *three-way handshake* (`SYN → SYN-ACK → ACK`) desde un puerto efímero (`2070` en la captura del 25-08; `2048` en la captura del 27-08) hacia el puerto destino **TCP/1550**.
3. **Capa de sesión/encapsulación (MLLP v1):** Cada mensaje HL7 se encapsula mediante *Minimal Lower Layer Protocol*:
   $$\text{Trama MLLP} = \underbrace{\texttt{0x0B}}_{\text{SB (VT)}} \,\|\, \text{Payload HL7 (UTF-8, sep. }\texttt{0x0D}\text{)} \,\|\, \underbrace{\texttt{0x1C}\,\texttt{0x0D}}_{\text{EB (FS) + CR}}$$
4. **Capa de aplicación y semántica clínica (HL7 v2.6 + IHE PCD-01 + ISO/IEEE 11073-10101 MDC + `99MNDRY`):**
   - **MSH:** `MSH-3 = MINDRAY_WATOPRO-SERIES^000F14002D3586ec^EUI-64`, `MSH-9 = ORU^R01^ORU_R01`, `MSH-11 = P`, `MSH-12 = 2.6`, `MSH-15 = NE`, `MSH-16 = AL`, `MSH-18 = UNICODE UTF-8`, `MSH-21 = IHE_PCD_001^IHE PCD^1.3.6.1.4.1.19376.1.6.1.1.1^ISO`.
   - **OBR:** `OBR-4 = 70040^MDC_DEV_SYS_ANESTH^MDC` (identificador MDC de máquina de anestesia).
   - **Modo `STANDBY`** (`LECTURACONACK25AGOSTO.pcapng`, 43 ORU + 43 ACK, y mensajes 1–13 de `LECTURAACK27AGOSTO.pcapng`): 4 segmentos `OBX` tipo `CWE` con estado `OBX-11 = F` y unidad adimensional `262656^MDC_DIM_DIMLESS^MDC` (`202886^MDC_EVT_STAT_DEV^MDC = 202836^MDC_EVT_STAT_STANDBY^MDC`, `30002^MNDRY_EVT_STAT_MODE_DEV^99MNDRY`, `30005^MNDRY_EVT_PATIENT_TYPE^99MNDRY`, `30007^MNDRY_EVT_STAT_WARMER_ON_BOOL^99MNDRY`).
   - **Modo `RUNNING`** (`LECTURAACK27AGOSTO.pcapng`, mensajes 14–99, 86 ORU + 86 ACK): `OBX|1` cambia a `202902^MDC_EVT_STAT_RUNNING^MDC` y `OBX|5` reporta el modo ventilatorio activo (`184352^MDC_VENT_MODE^MDC`) recorriendo **6 modos ventilatorios reales**: `VCV` (`50005`, 23 OBX), `SIMV-VC+PS` (`50008`, 28 OBX), `PCV` (`50011`, 22 OBX), `SIMV-PC+PS` (`50010`, 26 OBX), `PS` (`50006`, 25 OBX) y `MANUAL` (`50000`, 17 OBX), combinando hasta 11 ajustes ventilatorios (`99MNDRY`, `OBX-11 = F`) y 12 mediciones fisiológicas/mecánicas (`MDC`, `OBX-11 = R`, o `OBX-8 = INV` / `OBX-11 = X` cuando un sensor como el de $\text{FiO}_2$ `152196^MDC_CONC_AWAY_O2_INSP^MDC` no está activo).
   - **Confirmación de aplicación (`ACK^R01^ACK`):** El receptor responde en `< 1 ms` con `MSA|AA|<ctrl_id>` por cada `ORU^R01` recibido.

### 2.6 Suposiciones y dependencias

- Python ≥ 3.11; PyYAML ≥ 6.0; pytest ≥ 8.0; psutil opcional.
- Docker Desktop + WSL2 para el modo docker (opcional).
- La evidencia original (`evidence_raw/`) permanece inmutable.
- La autoridad clínica no ha aprobado reglas clínicas (gate PENDING).

## 3. Requisitos específicos

### 3.1 Requisitos funcionales

Prioridad MoSCoW. Estado: **Implementado** (cubierto por pruebas o corridas),
**Parcial** (funciona con limitaciones declaradas), **Pendiente**.

| ID | Descripción | MoSCoW | Entrada | Proceso | Salida | Implementación | Estado |
|---|---|---|---|---|---|---|---|
| RF-001 | Servidor MLLP/TCP multihilo en puerto configurable (1550) | Must | TCP clients | `ThreadingTCPServer`; sesión por conexión con timeout | Bytes HL7+MLLP a todos los módulos aguas abajo | `src/mllp/server.py::run_server`, `MLLPServer`; `mllp_receiver.py::main` | Implementado |
| RF-002 | Desenmarque MLLP tolerante a fragmentación TCP, múltiples frames por recv y basura previa | Must | Bytes de stream | `MLLPFramer` (WAITING_SB/READING/WAITING_EOM); límites anti-DoS (65535 B/1 MB) | `MLLPFrame` con payload HL7 | `src/mllp/framing.py::MLLPFramer.feed` | Implementado |
| RF-003 | Parseo HL7 v2.x: separadores dinámicos, segmentos, MSH (incl. charset MSH-18), OBX | Must | Payload HL7 | Análisis por segmentos/campos con fallbacks de encoding | `HL7Message`, `extract_msh_fields` | `src/hl7/parser.py::parse_hl7_message` | Implementado |
| RF-004 | Validación estructural vs baseline: secuencia de segmentos, tipo MSH-9, OBX-2/3/6 | Must | `HL7Message` + `Baseline` | Validadores deterministas (toleran OBX repetidos y NTE final) | `ValidationResult` con rule_violations | `src/hl7/validator.py` (todas las funciones `validate_*`) | Implementado |
| RF-005 | Motor de detección con las 15 reglas habilitadas y severidad por regla | Must | Mensaje + estado | `_check_rules` aplica R-NET/ID/MLLP/HL7/SEQ/TIME/OBX/STATE | `DetectionResult` con `Alert[]` | `src/detection/engine.py::DetectionEngine.process_message`; `config/rules.yaml` | Implementado |
| RF-006 | Estado de detección por sesión **y** global del emisor entre sesiones TCP (MCID vistos, hash de contenido con ventana replay, último timestamp, frecuencia) | Must | Alertas/normalización | `SessionState` + mapa global por identidad lógica | Estado persistente en memoria del proceso | `engine.py::SessionState`, `_update_session_state`, `normalize_hl7_for_hash` | Implementado |
| RF-007 | Inferencia de estado FSM desde OBX de estado (código 202886) y validación de transiciones | Should | OBX estado | `_infer_state` + `validate_state_transition` | `current_state`, alertas R-STATE-001 | `engine.py::_infer_state`; `validator.py::validate_state_transition` | Implementado (FSM bimodal STANDBY ↔ RUNNING verificado sobre `LECTURAACK27AGOSTO.pcapng`) |
| RF-008 | Respuesta ACK `MSA|AA` (MSH-16=AL) o modo observador `--no-ack` | Must | MSH del mensaje | `build_ack`/`parse_ack`/`validate_ack`; el servidor envía ACK solo si habilitado | ACK MLLP al emisor | `src/mllp/ack.py`; `server.py::_build_ack` | Implementado |
| RF-009 | Alertas JSONL explicables (rule_id, severity, reason, evidence_hash, label) y eventos NORMAL (fuente de TN) | Must | `Alert`/normal | `AlertLogger.log_alert`/`log_normal` | `alerts/alerts.jsonl` | `src/alerting/json_logger.py` | Implementado |
| RF-010 | Evidencia forense por sesión: bytes crudos, HL7 anonimizado, bitácora, metadatos, hashes SHA-256, rotación por tamaño | Must | Datos de sesión | `EvidenceWriter` abre/cierra sesiones y rota archivos | `raw/raw_<sid>.bin`, `hl7/messages_<sid>.hl7`, `logs/session_<sid>.log`, `logs/meta_<sid>.json` | `src/evidence/writer.py`, `hashing.py` | Implementado |
| RF-011 | Anonimización irreversible por defecto de PID/PV1/NTE e IPs/MAC en artefactos derivados (preservando OIDs ISO en MSH-21); alertas anonimizadas antes de escribir | Must | Mensajes/ alertas | `anonymize_hl7_message`, `_anonymize_alert` (ANON_ENABLED=True) | Artefactos sin datos clínicos identificables | `analyze_evidence.py`; `writer.py::_anonymize_alert` | Implementado |
| RF-012 | Interlocks: exige `LAB_AUTHORIZED=YES` + `LAB_ONLY.marker`; bloquea IPs públicas, rutas hospitalarias y targets no privados; rate/size limits; allowlists | Must | Entorno + settings | `_validate_safety` (falla cerrado), `SafetyGuard` del generador, `validate_target` | Arranque denegado si falta cualquiera | `src/config/settings.py::Settings`; `anomaly_generator.py::SafetyGuard` | Implementado |
| RF-013 | Emulador WATO benigno con estados STANDBY/RUNNING (6 modos ventilatorios reales: VCV, SIMV-VC+PS, PCV, SIMV-PC+PS, PS, MANUAL)/ALARM/SESSION_END, periodicidad y perfil de OBX de las capturas reales; validación de ACK | Must | CLI (host/estado/vent-mode/intervalo/seed) | Genera ORU^R01 sintéticos con identidad Mindray y estructura exacta IHE PCD-01, espera ACK | Tráfico MLLP benigno + estadísticas | `wato_emulator.py::WATOEmulator` | Implementado (STANDBY y RUNNING alineados con capturas del 25-08 y 27-08; ALARM sintético) |
| RF-014 | Generador de anomalías A01–A16 etiquetado, con techos de seguridad y ground truth | Must | CLI (`--scenario/--all/--exclude`, seed) | `SafetyGuard` + `_send_raw/_send_hl7` por escenario | Tráfico anómalo + `ground_truth.jsonl` + `scenario_order.txt` | `anomaly_generator.py` (SCENARIOS A01–A16) | Implementado |
| RF-015 | Evaluación de corridas: matching 1:1 greedy en ventana (5 s), TP/FP/TN/FN, recall, precision, F1, FPR, accuracy, latencia p50/p95/p99, throughput, pérdida, recursos | Must | `ground_truth.jsonl` + `alerts.jsonl` | `match_injections`, `compute_metrics`, percentiles | `evaluation.json`, `evaluation.txt` | `evaluate.py` | Implementado |
| RF-016 | Orquestador end-to-end (benigno → anomalías → benigno → evaluación) en modo local o docker con semillas por fase | Must | CLI (`--mode`, counts, seed) | Procesos/contenedores, esperas de puerto/salud, semillas derivadas (+1000003/+2000003) | `runs/<ts>/` completo | `run_experiment.py::run_local`, `run_docker` | Implementado |
| RF-017 | Detección **offline** sobre PCAP/PCAPNG sin abrir red (Modalidad B), usando timestamps de captura para validación temporal | Should | `--pcap` requerido | `pcap_reader` (Python puro) + extracción MLLP emisor→:1550 + motor con `capture_time` | `alerts.jsonl` + `detect_pcap_manifest.json` | `detect_pcap.py`; `src/evidence/pcap_reader.py` | Implementado (0 FP en `LECTURACONACK25AGOSTO.pcapng` [43/43 NORMAL] y `LECTURAACK27AGOSTO.pcapng` [99/99 NORMAL]) |
| RF-018 | Replay de evidencia real con pacing original en modo observador para medir FP (H3) | Must | `--pcap`, `--label` | Extracción ORU anónima + reenvío `--no-ack` + conteo de alertas | `replay_manifest.json`, `receiver.log` | `replay_evidence.py` | Implementado (FP=0 tanto en STANDBY [43 ORU] como en RUNNING [99 ORU]) |
| RF-019 | Bench de latencia del motor (H2) con ≥1000 msgs × ≥3 corridas y umbral 500 µs | Must | CLI (`--messages`, `--runs`) | `DetectionResult.processing_time_ms` (perf_counter, parseo excluido) | JSON PASS/FAIL + percentiles | `latency_bench.py` | Implementado (PASS en PC: p95 177.5 µs; Pi física NO_VERIFICADO) |
| RF-020 | Campaña H1: N corridas con semillas derivadas; ADR global y por escenario con IC95 de Wilson | Must | CLI (`--runs`, `--mode`, `--seed-base`) | subprocess a `run_experiment.py` + agregación | `validation_summary.json/.md` | `run_matrix.py::wilson_ci`, `aggregate` | Implementado (60 corridas, ADR 100 %, IC95 [99.8, 100.0]) |
| RF-021 | Baseline bimodal (STANDBY + RUNNING) trazable a hashes de evidencia fuente (SHA-256), con 33 códigos OBX, 9 unidades MDC y estado de aprobación clínica | Must | Capturas del 18-08, 25-08 y 27-08 | `baseline_builder` (desde CSV o valores documentados de las 3 capturas) | `baseline.yaml` con `source_hashes` | `src/evidence/baseline_builder.py`; `baseline.yaml` | Implementado (baseline bimodal STANDBY + RUNNING) |
| RF-022 | Manifest de reproducibilidad por corrida: commit git, hashes de insumos/salidas, semilla, runtime, recursos, resultado | Must | Corrida en curso | `write_manifest` al cierre | `runs/<ts>/manifest.json` | `run_experiment.py::write_manifest` | Implementado |
| RF-023 | Monitoreo de CPU y RSS pico del receptor durante corridas | Could | Proceso receptor | `ResourceMonitor` (process_time + ctypes/getrusage) | `resource_usage.json` | `src/evidence/resource_monitor.py` | Implementado (psutil opcional en orquestador) |
| RF-024 | Exportación opcional a syslog RFC 5424 | Could | Alertas | `Alert.to_syslog`, `AlertLogger._setup_syslog` | UDP 514 (solo si `syslog_enabled: true`) | `json_logger.py` | Implementado pero **deshabilitado por defecto** |
| RF-025 | Análisis forense de `evidence_raw/`: inventario SHA-256, correlación ORU↔ACK, CSVs y reporte Markdown | Should | `evidence_raw/` | `analyze_evidence` (pcap/bin/hl7/log) | `evidence_inventory.csv`, `sessions.csv`, `messages_metadata.csv`, `segment_frequency.csv`, `timing_statistics.csv`, `evidence_report.md` | `src/evidence/analyze_evidence.py::main` | Implementado |

### 3.2 Requisitos de interfaces externas

**RIF-001 Red/TCP.** Puerto **1550/tcp** (emisor WATO → receptor). En el
laboratorio: servidor `192.168.23.200:1550`, WATO `192.168.23.250` (OBSERVADO en
evidencia); en Docker: `172.30.0.20:1550` en red interna. Bind por defecto del
CLI de desarrollo: `127.0.0.1` (settings del servidor de laboratorio: `0.0.0.0`).

**RIF-002 MLLP.** Delimitadores SB `0x0B` … EB `0x1C` CR `0x0D`; payload UTF-8
(MSH-18 `UNICODE UTF-8`); `max_message_size` de laboratorio 4096 B (para detectar
A15; el máximo del protocolo configurado es 65535 B).

**RIF-003 HL7.** Perfil observado: v2.6, ORU^R01^ORU_R01, IHE PCD-01 [3],
separadores `|^~\&`, processing ID `P`, ACK requerido (`AL`). *(La afirmación de
contexto "Mindray usa HL7 v2.3.1" no está verificada; ver Apéndice A.)*

**RIF-004 Archivos de entrada.** `src/config/settings.yaml`, `baseline.yaml`,
`config/rules.yaml`, PCAP/PCAPNG (detección offline/replay), `analysis_output/*.csv`
(baseline_builder `--from-csv`).

**RIF-005 Archivos de salida.** Evidencia por sesión (§RF-010), `alerts.jsonl`,
`evaluation.json/.txt`, `manifest.json`, `ground_truth.jsonl`, `seed.txt`,
`scenario_order.txt`, `validation_summary.json/.md`, CSVs forenses,
`resource_usage.json`, `evidence_inventory.csv`.

**RIF-006 Syslog (opcional).** UDP 514, RFC 5424 [4]; deshabilitado por defecto.

### 3.3 Requisitos no funcionales

| ID | Categoría | Requerimiento | Estado (evidencia) |
|---|---|---|---|
| RNF-001 | Rendimiento | Latencia p95 de procesamiento del motor ≤ 500 µs/mensaje | **PASS en PC** (177.5 µs, 3×1000 msgs); **NO_VERIFICADO en Pi física** |
| RNF-002 | Rendimiento | Throughput objetivo ≥ 100 msg/s (umbral de settings `evaluation`) | Implementado en settings; no fue el cuello de botella en corridas (p50 end-to-end ≤ 2 ms) |
| RNF-003 | Confiabilidad | Framer tolerante a fragmentación; timeouts de sesión; reconexiones controladas (máx 3 en emulador) | Implementado; probado en `test_framing.py` (23 pruebas) |
| RNF-004 | Seguridad | Sin IP pública en bind/targets; bloqueo de rutas hospitalarias; rate ≤ 10 msg/s; ≤ 5 conexiones concurrentes; cooldown 30 s; payload generador ≤ 32768 B; presupuesto ≤ 70 anomalías/corrida | Implementado (settings + SafetyGuard + preflight) |
| RNF-005 | Portabilidad | Python 3.11+; runtime solo stdlib + PyYAML; PCAP reader en Python puro (Raspberry Pi OS sin dependencias de sistema) | Implementado; verificado en Windows y en contenedores `python:3.11-slim` |
| RNF-006 | Reproducibilidad | Semillas PRNG por corrida/fase; SHA-256 de artefactos; manifest con commit; evidencia sellada con `SHA256SUMS.txt` | Implementado (corridas 2026-10-14 y 2026-10-17) |
| RNF-007 | Mantenibilidad | Suite automatizada ≥ 200 pruebas; sin ML; reglas declarativas YAML | Implementado: **246 pruebas** |
| RNF-008 | Disponibilidad del lab | El sistema no arranca sin interlocks (marker + env) | Implementado (fail-closed) |
| RNF-009 | Privacidad | Datos clínicos anonimizados por defecto en todos los derivados; `evidence_raw/` inmutable | Implementado (ANON_ENABLED=True) |

### 3.4 Restricciones de diseño

- Lenguaje Python 3.11+; sin dependencias de sistema en runtime (salvo PyYAML).
- Motor determinista: **prohibido** ML/heurísticas estocásticas en la detección.
- Arquitectura por capas: framing → parser → validador → motor → alerting/evidence.
- Toda regla nueva debe declarar MITRE ICS v20, justificación y limitaciones
  (patrón de `rules.yaml`, verificado por `test_mitre_mappings.py`).
- El laboratorio no despliega en línea (BIW) hasta gate clínico/ético aprobado.

## 4. Matriz de trazabilidad (Requisito → Módulo/función → Evidencia de prueba)

| RF | Módulo / función | Evidencia de prueba |
|---|---|---|
| RF-001 | `mllp/server.py::run_server` | `test_integration.py`, corridas E2E (`runs/20261017_110410`) |
| RF-002 | `mllp/framing.py::MLLPFramer` | `test_framing.py` (23) |
| RF-003 | `hl7/parser.py::parse_hl7_message` | `test_hl7_parser.py` (21) |
| RF-004 | `hl7/validator.py::validate_*` | `test_detection_rules.py` (32), `test_validation_tools.py` (18) |
| RF-005 | `detection/engine.py::process_message` | `test_detection_rules.py`, `test_integration.py` |
| RF-006 | `engine.py::SessionState` | `test_detection_rules.py` (uniqueness/replay/frequency) |
| RF-007 | `engine.py::_infer_state` | `test_detection_rules.py` (state transitions) |
| RF-008 | `mllp/ack.py` | `test_ack.py` (18) |
| RF-009 | `alerting/json_logger.py` | `test_evaluate.py` (matching NORMAL/ANOMALO) |
| RF-010 | `evidence/writer.py` | `test_evidence_analysis.py` (10) + corridas con `raw/hl7/logs` |
| RF-011 | `analyze_evidence.anonymize_hl7_message` | `test_evidence_analysis.py`, `test_detect_pcap.py` (anonimización) |
| RF-012 | `config/settings.py::_validate_safety`; `SafetyGuard` | `test_anomaly_generator.py` (23, incl. guard) |
| RF-013 | `wato_emulator.py::WATOEmulator` | Demo WATO standalone 2026-10-17 (8/8 ACK, 0 alertas) |
| RF-014 | `anomaly_generator.py::SCENARIOS` | `test_anomaly_generator.py`; corridas con GT |
| RF-015 | `evaluate.py` | `test_evaluate.py` (38) |
| RF-016 | `run_experiment.py` | Corridas `runs/20261017_110211` (docker) y `20261017_110410` (local) |
| RF-017 | `detect_pcap.py` | `test_detect_pcap.py` (4) |
| RF-018 | `replay_evidence.py` | Replay STANDBY FP=0 ×5 (Fase 9, `docs/RESULTS_20261014.md`) |
| RF-019 | `latency_bench.py` | `analysis_output/validation/latency_20261014_*.json` (PASS PC) |
| RF-020 | `run_matrix.py` | `validation/main_20261014_162606/` (ADR 100 %, IC95) |
| RF-021 | `baseline_builder.py` | `baseline.yaml` (source_hashes SHA-256) |
| RF-022 | `run_experiment.write_manifest` | `test_manifest.py` (5) + `manifest.json` por corrida |
| RF-023 | `resource_monitor.py` | `test_resource_monitor.py` (4) |
| RF-024 | `json_logger.to_syslog` | Pruebas unitarias del logger (deshabilitado en runtime) |
| RF-025 | `analyze_evidence.main` | `test_evidence_analysis.py` + CSVs en `analysis_output/` |

## 5. Apéndice A — Hallazgos y vacíos

1. **Códigos propietarios Mindray (`99MNDRY`):** además de los códigos de estado de `STANDBY` (`30002`, `30005`, `30007`), la captura `LECTURAACK27AGOSTO.pcapng` permitió verificar empíricamente los **6 modos ventilatorios** (`50005` VCV, `50008` SIMV-VC+PS, `50011` PCV, `50010` SIMV-PC+PS, `50006` PS, `50000` MANUAL) y **16 códigos de ajustes ventilatorios** (`20000`–`20044^...^99MNDRY`). Todos están incorporados en `baseline.yaml` como `OBSERVADO`.
2. **Versión HL7 del fabricante:** se ha declarado contextualmente "HL7 v2.3.1"; en series recientes (WATO Pro Series / A-Series con perfil IHE PCD-01 DEC) la evidencia capturada declara **2.6** en `MSH-12` y el perfil `IHE_PCD_001^IHE PCD^1.3.6.1.4.1.19376.1.6.1.1.1^ISO` en `MSH-21`.
3. **Codificación:** el contexto histórico mencionaba ISO-8859-1; el software actual usa **UTF-8** (`MSH-18 = UNICODE UTF-8`). ISO-8859-1 solo sobrevive en `legacy/ackdummy (1).py`, marcado INCORRECTO en settings.
4. **Corpus RUNNING verificado:** a partir del análisis de `LECTURAACK27AGOSTO.pcapng` (99 ORU + 99 ACK: 13 `STANDBY` y 86 `RUNNING`), los **12 códigos de medición ISO/IEEE 11073-10101 MDC** (`151586`, `151688`, `151784`, `151819`, `151832`, `151840`, `151880`, `151957`, `151976`, `152196`, `152660`, `152664`) y las **9 unidades MDC** pasaron de `NO_VERIFICADO` a **`OBSERVADO`**, logrando **0 falsos positivos** en detección offline y replay tanto para `STANDBY` (43 ORU) como para `RUNNING` (99 ORU).
5. **H2 en Raspberry Pi física:** `NO_VERIFICADO` (no hay hardware con IP asignado en este host; la topología Pi está simulada en Docker y local).
6. **Aprobación clínica:** `clinical_approval_status: PENDING`; las reglas de rangos fisiológicos siguen deshabilitadas hasta contar con aval clínico.
7. **Deuda técnica de código:** faltan `__init__.py` en `src/hl7`, `src/detection`, `src/config`; dos parseadores HL7 paralelos (`src/hl7/parser.py` y `analyze_evidence.py`).
8. **Limitación de replay/offline:** `R-MLLP-001` no es evaluable en detección offline (solo tramas MLLP completas); `R-TIME-002` en modo offline evalúa los timestamps de captura del PCAP (`capture_time`).

## 6. Evidencia para demostración (pasos exactos)

**A. Receptor + emulador benigno (esperado: 0 alertas de seguridad):**

```powershell
# Terminal 1 — detector (genera evidence_output/settings_deploy.yaml)
deploy\receptor\receptor.ps1

# Terminal 2 — WATO emulado (STANDBY, 8 mensajes, 6 s)
deploy\wato\wato.ps1 -Count 8 -Interval 6.0
```

Salida esperada en la Terminal 1: por cada mensaje
`ACK received and validated: code=AA` (emulador) y en
`evidence_output\alerts\alerts.jsonl` eventos:
`{"rule_id": "NORMAL", "severity": "INFO", "reason": "Normal message processed", ...}`
con `evidence_hash`. En `evidence_output\hl7\messages_<sid>.hl7`: mensajes ORU^R01
anonimizados; en `evidence_output\logs\session_<sid>.log`: bitácora con timestamps.

**B. Corrida completa con ataque (esperado: TP>0, evaluación automática):**

```powershell
$env:LAB_AUTHORIZED = "YES"
.venv\Scripts\python run_experiment.py --mode local --exclude A14
# Resultado: runs/<timestamp>/evaluation.txt con recall/precision/F1 y latencias
```

**C. Verificación de pruebas:** `deploy\validacion\suite.ps1` → `246 passed`.

---

*Documento generado a partir de la auditoría `docs/AUDITORIA_REPO.md`. Toda
afirmación no respaldada por código o corrida sellada está marcada como
Pendiente/No verificado.*
