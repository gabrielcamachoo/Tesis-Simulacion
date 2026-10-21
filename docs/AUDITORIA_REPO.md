# AUDITORÍA DEL REPOSITORIO — Proyecto G18 (WATO EX-35 / HL7-MLLP)

**Fecha de auditoría:** 2026-10-17 · **Commit auditado:** `72515e6` (rama `main`)
**Alcance:** todo el código, configuración y pruebas del repositorio. Solo lectura:
ningún archivo fue modificado durante la auditoría.
**Propósito:** insumo factual para el SRS (`docs/SRS_Resultados.md`) y el SPMP
(`docs/SPMP_Resultados.md`), basado **únicamente en lo que existe en el código**.

---

## 1. Método

1. Inventario del árbol completo (raíz, `src/`, `config/`, `tests/`, `deploy/`, `docs/`).
2. Lectura de los 9 scripts CLI de la raíz y de los 16 módulos de `src/` (incluidos
   los `argparse` con flags y defaults, verificados por grep exhaustivo: 41 flags).
3. Lectura íntegra de `config/rules.yaml`, `baseline.yaml`, `src/config/settings.yaml`
   (482 líneas), `requirements.txt` y `docker-compose.yml`.
4. Conteo de pruebas por archivo (`def test_`): **204** en 14 archivos.
5. Historial `git log`: 29 commits, de `4d245c8` (2026-10-13, snapshot inicial) a
   `72515e6` (2026-10-17).

## 2. Inventario de scripts CLI de la raíz (9)

| Archivo | Líneas | Propósito | CLI principal (defaults) |
|---|---:|---|---|
| `mllp_receiver.py` | 192 | **Receptor = detector**: carga settings/baseline/reglas, arma EvidenceWriter + DetectionEngine + AlertLogger + ResourceMonitor, sirve MLLP en hilo con SIGINT/SIGTERM | `--host 127.0.0.1` `--port 1550` `--config src/config/settings.yaml` `--baseline baseline.yaml` `--rules config/rules.yaml` `--outdir evidence_output` `--no-ack` `--verbose` `--create-marker` |
| `wato_emulator.py` | 480 | Emulador sintético WATO: ORU^R01 benigno con periodicidad de la evidencia; estados STANDBY/RUNNING/ALARM_SIMULATED/SESSION_END/DISCONNECTED | `--host mllp-receiver` `--port 1550` `--state STANDBY` `--interval 10.0` `--count 0` `--seed` `--no-ack` `--ack-timeout 5.0` `--max-reconnects 3` |
| `anomaly_generator.py` | 790 | Generador de anomalías A01–A16 con `SafetyGuard` (fail-safe) y `ground_truth.jsonl` | `--scenario A01..A16` `--all` `--exclude` `--seed` `--count 5` `--host mllp-receiver` `--port 1550` `--dry-run` |
| `evaluate.py` | 607 | Evaluación: matching inyección↔alerta 1:1 greedy en ventana; TP/FP/TN/FN, recall, precision, F1, latencia p50/p95/p99, throughput, pérdida, recursos | `--run <dir>` `--window 5.0` |
| `run_experiment.py` | 568 | Orquestador de 4 fases (benigno → anomalías → benigno → evaluación); modos `local`/`docker`; semillas por fase; `manifest.json` con SHA-256 + commit | `--mode auto` `--benign-count 6` `--interval 6.0` `--anomaly-count 3` `--exclude` `--window 5.0` `--seed` |
| `detect_pcap.py` | 334 | Detección **offline** sobre PCAP/PCAPNG (Modalidad B), sin red; extrae MLLP emisor→:1550 | `--pcap` (requerido) `--label` `--realtime` `--max-sleep 2.0` `--no-anonymize` |
| `replay_evidence.py` | 313 | Replay de evidencia real (H3): reenvía ORU con pacing original en modo `--no-ack`; mide FP | `--pcap` `--label` `--speed 1.0` `--start-receiver` `--dry-run` |
| `latency_bench.py` | 191 | Bench de latencia (H2): ≥1000 msgs × ≥3 corridas con `time.perf_counter()` del motor; umbral 500 µs | `--messages 1000` `--runs 3` `--seed 20261014` |
| `run_matrix.py` | 260 | Campaña H1: N corridas con semillas derivadas; agrega ADR + IC95 Wilson; `validation_summary.json/.md` | `--runs 30` `--mode docker` `--exclude A14` `--seed-base 100000` `--tag main` |

## 3. Inventario `src/` (16 módulos)

### 3.1 `src/mllp/` (tiene `__init__.py`; re-exporta API pública)

| Módulo | Líneas | Contenido |
|---|---:|---|
| `framing.py` | 367 | Framer stateful MLLP: SB=`0x0B`, EB=`0x1C`, CR=`0x0D`; tolera TCP fragmentado, múltiples frames por recv, basura antes de SB; `MAX_MESSAGE_SIZE=65535`, `MAX_BUFFER_SIZE=1 MB`. Clases `MLLPFramer`, `MLLPIterator`, `FrameState`; funciones `frame_hl7_message`, `deframe_hl7_message`, `validate_mllp_frame`, `extract_frames_simple`, `count_frames` |
| `ack.py` | 312 | ACK HL7 v2.x: `MSA|AA/AE/AR` con MSH-16=AL; `build_ack`, `build_ack_bytes`, `parse_ack`, `validate_ack`; constructores `build_experimental_ack`, `build_emulator_ack` |
| `server.py` | 284 | Servidor `socketserver.ThreadingTCPServer`; por sesión: EvidenceWriter → framer → parser → DetectionEngine → alertas/NORMAL → ACK; framing error ⇒ R-MLLP-001 (incluye frame incompleto al cerrar, escenario A05). `run_server(settings, evidence_writer, detection_engine, alert_logger, send_ack=True)` |

### 3.2 `src/hl7/` (sin `__init__.py`; namespace package)

| Módulo | Líneas | Contenido |
|---|---:|---|
| `parser.py` | 307 | Parser ORU^R01: separadores desde MSH-1/MSH-2, segmentos, campos MSH (incl. MSH-18 charset con fallbacks), OBX. `parse_hl7_message`, `extract_msh_fields`, `normalize_hl7_for_hash` (excluye MSH-7 y MSH-10 para replay) |
| `validator.py` | 257 | Validadores deterministas que disparan las 15 reglas. Enmienda E1 (2026-10-14): CWE con unidad ya no es inválido (STANDBY real trae OBX-6 `262656^MDC_DIM_DIMLESS^MDC`; la cláusula previa causaba 43/43 FP). `validate_frequency` usa tope p95×1.5 (15 s) |

### 3.3 `src/detection/` (sin `__init__.py`)

| Módulo | Líneas | Contenido |
|---|---:|---|
| `baseline.py` | 204 | Cargador tipado de `baseline.yaml`; sets O(1) de IPs/apps/OBX; `load_baseline`, `create_baseline_from_evidence` |
| `rules.py` | 278 | Catálogo `DEFAULT_RULES` (15 `Rule` con MITRE y limitaciones); `RuleSet.load_from_yaml`, enable/disable |
| `engine.py` | 297 | Motor determinista sin ML: estado por sesión **y** estado global del emisor rastreado **a través de sesiones TCP** (MCID, hash de contenido con ventana replay = intervalo/2, timestamp, frecuencia); infiere FSM desde OBX código `202886`; genera `Alert` con `evidence_hash` SHA-256 |

### 3.4 `src/alerting/`

| Módulo | Líneas | Contenido |
|---|---:|---|
| `json_logger.py` | 175 | JSONL `alerts/alerts.jsonl`; severidades CRITICAL/HIGH/MEDIUM/LOW/INFO; etiquetas NORMAL/ANOMALO; syslog RFC 5424 opcional **deshabilitado por defecto**; anonimización antes de alertar |

### 3.5 `src/evidence/`

| Módulo | Líneas | Contenido |
|---|---:|---|
| `writer.py` | 325 | Evidencia por sesión: `raw/raw_<sid>.bin`, `hl7/messages_<sid>.hl7`, `logs/session_<sid>.log`, `logs/meta_<sid>.json`, `alerts/alerts_<sid>.jsonl`; rotación por tamaño; SHA-256 por archivo |
| `hashing.py` | 24 | `sha256_bytes`, `sha256_file` (bloques 1 MiB) |
| `pcap_reader.py` | 245 | Lector PCAP/PCAPNG en **Python puro** (sin pyshark/scapy); Ethernet+VLAN, ARP, IPv4/IPv6, TCP/UDP/ICMP; solo linktype 1, sin reensamblado de fragmentos IP |
| `resource_monitor.py` | 108 | CPU (`process_time`) y RSS pico (ctypes en Windows / `getrusage` POSIX); `resource_usage.json` |
| `analyze_evidence.py` | 837 | Análisis forense ejecutable: inventario SHA-256, PCAP/BIN/HL7/LOG, correlación ORU↔ACK por MSA-2==MSH-10; anonimización irreversible por defecto (PID 2/3/5/7/8, PV1-19, NTE-3, IPs/MAC); salidas CSV+MD |
| `baseline_builder.py` | 364 | Baseline desde sesiones etiquetadas o valores documentados STANDBY (43 ORU + 43 ACK, 25-08-2026); `baseline.yaml` trazable con hashes |

### 3.6 `src/config/`

| Módulo | Líneas | Contenido |
|---|---:|---|
| `settings.py` | 324 | Cargador fail-safe: exige `LAB_AUTHORIZED=YES` + `LAB_ONLY.marker`; bloquea IPs públicas, rutas hospitalarias y targets no privados; rate/size limits |
| `settings.yaml` | 482 | Configuración completa: red (server 192.168.23.200:1550, WATO 192.168.23.250), safety, emulador (identidad `MINDRAY_WATOPRO-SERIES^000F14002D3586ec^EUI-64`), escenarios A01–A16 con límites, umbrales de evaluación |

## 4. Configuración y dependencias

- **`requirements.txt`:** `PyYAML>=6.0` (única runtime), `pytest>=8.0`, `psutil>=5.9`
  (opcional, manifest). El lector PCAP y el framer MLLP son Python puro a propósito
  (Raspberry Pi sin dependencias de sistema).
- **`docker-compose.yml`:** red `wato-lab` **`internal: true`** (172.30.0.0/24, sin
  egress); servicios `mllp-receiver` (.20, siempre), `wato-emulator` (.10, profile
  `benign`), `anomaly-generator` (.11, profile `anomalies`); healthcheck TCP 1550;
  named volume `lab_output`; `LAB_AUTHORIZED=YES` por ancla `x-lab-env`.

## 5. `config/rules.yaml` — las 15 reglas

| rule_id | Nombre | Sev. | MITRE ICS v20 |
|---|---|---|---|
| R-ID-001 | unauthorized_sending_application (MSH-3) | HIGH | T1692.002 |
| R-ID-002 | unauthorized_sending_facility (MSH-4) | MEDIUM | T1692.002 |
| R-NET-001 | unauthorized_network_origin (IP TCP) | HIGH | T1692.002 |
| R-MLLP-001 | invalid_mllp_framing | HIGH | T1692.002 |
| R-HL7-001 | missing_msh_segment | HIGH | T1692.002 |
| R-HL7-002 | unknown_message_type (MSH-9) | HIGH | T1692.002 |
| R-HL7-003 | invalid_segment_sequence | HIGH | T1692.002 |
| R-SEQ-001 | duplicate_message_control_id (MSH-10) | HIGH | T1692.002 |
| R-SEQ-002 | replay_normalized_content_hash | HIGH | T1692.002 |
| R-TIME-001 | regressive_timestamp (MSH-7) | MEDIUM | T1692.002 |
| R-TIME-002 | frequency_out_of_baseline (p95×1.5) | MEDIUM | T0814 (DoS/supresión) |
| R-OBX-001 | unauthorized_obx_identifier (OBX-3) | HIGH | T1692.002 |
| R-OBX-002 | unauthorized_obx_unit (OBX-6; Enmienda E1) | MEDIUM | T1692.002 |
| R-OBX-003 | incompatible_obx_value_type (OBX-2) | HIGH | T1692.002 |
| R-STATE-001 | invalid_state_transition (FSM) | HIGH | T1692.002 |

13 HIGH + 2 MEDIUM; todas `enabled: true`, `safety_limit: 0`.

## 6. `baseline.yaml` (153 líneas, generado 2026-10-14)

- Fuente única: sesión STANDBY `standby_20260825` (captura `LECTURACONACK25AGOSTO.pcapng`,
  43 ORU + 43 ACK, 509 s); `clinical_approval_status: PENDING`.
- Tipo permitido: `ORU^R01^ORU_R01`; secuencia `[MSH, PID, PV1, OBR, OBX×4]`;
  app emisora única `MINDRAY_WATOPRO-SERIES^000F14002D3586ec^EUI-64`; HL7 2.6; IHE_PCD_01.
- Tamaño 968–972 B (moda 971); intervalo 10.000 s exactos; 4 OBX CWE
  (`202886` estado, `30002` modo, `30005` tipo paciente, `30007` calentador);
  unidad observada DIMLESS; transiciones FSM `SIN_GATEWAY→HANDSHAKE→SESION_ESTABLECIDA_STANDBY`.
- `allowed_ips`: 192.168.23.250 (OBSERVADO), 127.0.0.1, ::1, 172.30.0.10/.11 (lab).

## 7. Pruebas (`tests/`, 204 `def test_`)

| Archivo | # | Cubre |
|---|---:|---|
| `test_evaluate.py` | 38 | matching, métricas, percentiles, pérdidas |
| `test_detection_rules.py` | 32 | RuleSet, validadores, Baseline |
| `test_anomaly_generator.py` | 23 | 16 escenarios, SafetyGuard, dry-run |
| `test_framing.py` | 23 | framer MLLP (fragmentación, basura, límites) |
| `test_hl7_parser.py` | 21 | parser, MSH, OBX, normalización replay |
| `test_ack.py` | 18 | build/parse/validate ACK |
| `test_validation_tools.py` | 18 | herramientas de validación |
| `test_evidence_analysis.py` | 10 | pipeline de evidencia |
| `test_mitre_mappings.py` | 6 | mapeos MITRE de reglas |
| `test_manifest.py` | 5 | manifest.json |
| `test_detect_pcap.py` | 4 | detección offline |
| `test_resource_monitor.py` | 4 | CPU/RSS |
| `test_integration.py` | 2 | flujo integrado |
| **Total** | **204** | |

## 8. Despliegue (`deploy/`)

| Ruta | Contenido |
|---|---|
| `deploy/receptor/` | `receptor.ps1` (detector en línea Windows) + `make_deploy_settings.py` (settings con marker del repo) |
| `deploy/wato/` | `wato.ps1` (emulador benigno) |
| `deploy/atacante/` | `atacante_ransomware.ps1` (campaña A01/A05/A06/A13/A14/A16) |
| `deploy/pi/` | `01_instalar.sh`…`06_campana_validacion.sh`, `mllp-receiver.service` (systemd con ExecStartPre), `pi_detector_docker.ps1` (simulación docker), `README.md` |
| `deploy/validacion/` | `suite.ps1` (pytest 204), `evaluar.ps1` |

## 9. Puertos, protocolos y formatos (verificados en código)

- **TCP 1550** en toda la cadena (receptor escucha; emulador/generador conectan).
- **MLLP:** SB `0x0B`, EB `0x1C`, CR `0x0D`; payload **UTF-8** (MSH-18 `UNICODE UTF-8`).
  El prototipo histórico `ackdummy` usaba ISO-8859-1, marcado como INCORRECTO en
  `settings.yaml` (no es el comportamiento actual).
- **Syslog UDP 514** opcional (RFC 5424), **deshabilitado por defecto**.
- **Salidas:** evidencia por sesión (raw/hl7/logs/meta/alerts + SHA-256),
  `alerts.jsonl`, `evaluation.json/.txt`, `manifest.json`, CSVs forenses,
  `validation_summary.json/.md` (ADR + IC95 Wilson).

## 10. Hallazgos y deudas técnicas

1. *(Resuelto 2026-10-20, E9)* `src/hl7/`, `src/detection/` y `src/config/` cuentan ahora con `__init__.py` explícito, unificando los 6 subpaquetes de `src/`.
2. Dos parseadores HL7 paralelos: `src/hl7/parser.py::parse_hl7_message` (objetos) y
   `src/evidence/analyze_evidence.py::parse_hl7_message` (dict); coexisten sin conflicto.
3. *(Resuelto 2026-10-20, E9)* Eliminado el código muerto inalcanzable en `src/mllp/framing.py::_try_extract_frame`.
4. *(Resuelto 2026-10-20, v1.1 + E2–E5)* Baseline bimodal (`STANDBY` + `RUNNING` 6 modos, 33 códigos OBX, 9 unidades MDC): 0 FP en `STANDBY` (43/43 NORMAL) y 0 FP en `RUNNING` (99/99 NORMAL).
5. Reloj WATO con offset observado **+17 min 10 s** respecto al host.
6. H2 (latencia ≤ 500 µs) medido en PC x86; **NO_VERIFICADO en Raspberry Pi física**.
7. Escenario A14 (silencio 45 s ×3) dura ~135 s: corridas rápidas usan `--exclude A14`.
8. La afirmación contextual "Mindray usa HL7 v2.3.1" **no es verificable en fuentes
   públicas**; la evidencia capturada declara HL7 2.6 (`settings.yaml`/`baseline.yaml`).

## 11. Historial git (29 commits, 2026-10-13 → 2026-10-17)

Fases cubiertas por commit: Fase 0 (snapshot) → 1 (evidencia/baseline) → 3 (docs:
threat model, ética, arquitectura, escenarios, protocolo) → 2/4 (emulador, generador,
evaluador, docker, orquestador) → 6 (guía Pi) → 9 (validación H1/H2/H3 + tooling) →
entrega (despliegues, manual, reorganización, evidencia sellada).

## 12. Discrepancias contexto declarado vs. código

| Afirmación de contexto | Verificación en código |
|---|---|
| Codificación ISO-8859-1 | **No vigente**: UTF-8 en settings, baseline y MSH-18; ISO-8859-1 solo en `ackdummy` histórico (legacy/) marcado INCORRECTO |
| Mindray usa HL7 v2.3.1 | **No verificado públicamente**; la evidencia declara HL7 2.6 + IHE PCD-01 |
| Puerto TCP 1550 | **Confirmado** (settings, baseline, docker-compose, servidor) |
| Red 192.168.23.200/24 | **Confirmado** (server_ip; WATO en .250) |
| Guarda `raw_<ip>_<puerto>.bin` | **Parcial**: el nombre real es `raw_<session_id>.bin` (session_id incluye ip:puerto:ts) |
| ACK MSA\|AA y `--no-ack` | **Confirmado** (`ack.py`, `server.py`, CLI del receptor) |

---

*Auditoría realizada como insumo de `docs/SRS_Resultados.md` y `docs/SPMP_Resultados.md`.*
