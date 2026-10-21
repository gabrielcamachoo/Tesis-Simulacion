# Guía de uso — Laboratorio de detección HL7/MLLP (Tesis WATO EX-35, G18)

Guía práctica para ejecutar, inspeccionar y entender el banco de pruebas.
Complementa: `README.md` (estado), `docs/LAB_ARCHITECTURE.md` (detalles de diseño),
`docs/VALIDATION_PROTOCOL.md` (metodología) y `docs/RESULTS_20261014.md` (resultados sellados).

---

## 1. Qué hace el laboratorio (en 2 minutos)

Simula la red de un monitor anesthesia WATO EX-35 (equipo real: **no** se toca) y
evalúa un **detector determinista de anomalías de comunicación HL7/MLLP** — caja
negra, sin ML, sin acceso al equipo clínico.

```
  wato_emulator.py ──ORU^R01 (MLLP)──┐         anomaly_generator.py ──ORU mutados──┐
  (tráfico benigno, periodicidad     │                                             │
   extraída de capturas reales)      ▼                                             ▼
                              ┌─────────────────────────────────────────────────────┐
                              │  mllp_receiver.py  (puerto 1550 o loopback)         │
                              │    └─ src/mllp → src/hl7/parser → src/detection     │
                              │         reglas R-* (MITRE ICS v20) + baseline.yaml  │
                              │    salida: alerts/alerts.jsonl (evento/mensaje)     │
                              └─────────────────────────────────────────────────────┘
                                                     │
                              evaluate.py ◄──────────┘  cruza alerts.jsonl con
                              (ADR, FP, FN)            ground_truth del generador
```

Tres hipótesis que el laboratorio evalúa:

| Hipótesis | Umbral | Estado (PC, 2026-10-14) |
|---|---|---|
| **H1** efectividad | ADR ≥ 90 % por escenario | **ACEPTADA** — 100 % en 16/16 (60 corridas) |
| **H2** latencia | p95 ≤ 500 µs | PASS en PC (177.5 µs); **NO VERIFICADO en Pi** |
| **H3** FP reales | descriptiva, sin umbral | STANDBY FP=0; RUNNING 256 alertas "fuera de baseline" |

---

## 2. Mapa de archivos

### Motor (código)

| Archivo | Qué hace | Cómo probarlo |
|---|---|---|
| `src/mllp/` | Framing MLLP (start `0x0b`, end `0x1c 0x0d`), ACK | `pytest tests/test_mllp.py` |
| `src/hl7/parser.py` | Parser HL7 v2.6 (segmentos MSH/PID/PV1/OBR/OBX) | `pytest tests/test_hl7_parser.py` |
| `src/hl7/validator.py` | Validación estructural → alimenta reglas | `pytest tests/test_validator*.py` |
| `src/detection/rules.py` | 15 reglas R-* mapeadas a MITRE ICS v20 | `pytest tests/test_rules*.py` |
| `src/detection/baseline.py` | Carga `baseline.yaml` (estadísticas de STANDBY real) | `pytest tests/test_baseline*.py` |
| `src/alerting/` | Log JSONL de eventos (alertas + NORMAL) | integrado en los E2E |
| `src/evidence/` | Lector PCAP (Python puro), anonimización, baseline builder | `pytest tests/test_evidence*.py` |

### Herramientas de laboratorio (raíz)

| Archivo | Qué hace | Duración típica |
|---|---|---|
| `run_experiment.py` | Orquesta una corrida completa: benigno → anomalías → benigno → evaluación | ~2 min local / ~110 s docker (sin A14); +135 s con A14 |
| `run_matrix.py` | Campaña: N corridas con semillas + agregación ADR/IC95 Wilson | 30 corridas ≈ 55 min docker |
| `run_campaign.ps1` | Wrapper: FASE1 (30 docker sin A14) + FASE2 (30 A14 local) | ≈ 2.5 h |
| `replay_evidence.py` | Replay de evidencia real (corpus negativo H3) | 7 min (STANDBY) / 17 min (RUNNING) |
| `detect_pcap.py` | Detección **offline** sobre un PCAP (Modalidad B, sin red) | instantáneo (~0.05 s por 43 ORU) |
| `latency_bench.py` | Bench de latencia del pipeline completo (H2) | segundos |
| `evaluate.py` | Métricas de una corrida (suele invocarlo run_experiment) | instantáneo |
| `mllp_receiver.py` | Receptor MLLP (laboratorio, solo localhost/red interna) | continuo |
| `wato_emulator.py` | Emulador benigno (STANDBY/RUNNING intercalables) | continuo |
| `anomaly_generator.py` | Inyector de escenarios A01–A16 con techos de seguridad | continuo |

### Evidencia y salidas

| Ruta | Contenido | Regla |
|---|---|---|
| `evidence_raw/pcap/` | Capturas originales del WATO (solo lectura) | **Nunca modificar**; hashes en `evidence_inventory.csv` |
| `baseline.yaml` | Línea base trazable a SHA-256 de la evidencia | Congelada por commit; cambios = enmienda versionada |
| `runs/<timestamp>/` | Crudos de cada corrida | gitignored; regenerables |
| `analysis_output/validation/` | Evidencia de Fase 9 (replays, campañas, bench) | Sellada con `SHA256SUMS.txt` |
| `analysis_output/` (resto) | Reportes de evidencia (CSV/MD), regenerables | gitignored parcialmente |

---

## 3. Puesta en marcha (una sola vez)

```powershell
# 1. Entorno (ya creado en este repo: .venv con Python 3.11.9)
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt

# 2. Autorización de laboratorio (obligatoria en TODA sesión nueva de PowerShell)
$env:LAB_AUTHORIZED = "YES"
# (el marcador LAB_ONLY.marker ya existe en la raíz; ambos son exigidos por el código)

# 3. Verificación rápida: la suite completa debe dar 179 passed
.venv\Scripts\python.exe -m pytest -q
```

> En PowerShell 5.1 no existe `&&`; encadena con `; if ($?) { ... }`.
> Docker: `$env:PATH = "C:\Program Files\Docker\Docker\resources\bin;" + $env:PATH`

---

## 4. Recetas

### 4.1 Corrida rápida de desarrollo (loopback, sin Docker)

```powershell
$env:LAB_AUTHORIZED = "YES"
.venv\Scripts\python.exe run_experiment.py --mode local --exclude A14 --seed 42
```

Sale `Corrida completa: runs/<timestamp>` con `evaluation.json`,
`ground_truth.jsonl`, `alerts/alerts.jsonl`, `seed.txt`, `scenario_order.txt`.
`--seed` fija el PRNG (obligatorio en cualquier corrida que se reporte).
`--exclude A14` evita los ~135 s del escenario de silencio.

### 4.2 Corrida metodológica (Docker — la de la tesis)

```powershell
$env:LAB_AUTHORIZED = "YES"
.venv\Scripts\python.exe run_experiment.py --mode docker --seed 42
```

Topología: red interna `wato-lab` (172.30.0.0/24, sin egress), IPs fijas
(emulador .10, generador .11, receptor .20), evidencia en el named volume
`lab_output` (no sobre OneDrive — evita el stall de I/O). **No editar nada del
repo mientras corre**: docker monta `./` en vivo.

### 4.3 Inspección manual paso a paso (3 terminales)

```powershell
# Terminal 1 — receptor
$env:LAB_AUTHORIZED = "YES"
.venv\Scripts\python.exe mllp_receiver.py --host 127.0.0.1 --port 1550 --outdir runs\manual

# Terminal 2 — emulador benigno (10 msg, 1 por segundo por defecto)
$env:LAB_AUTHORIZED = "YES"
.venv\Scripts\python.exe wato_emulator.py --host 127.0.0.1 --port 1550 --count 10 --interval 1.0
# (--interval 1.0 para verlo ágil; el default del emulador es 10 s, como la evidencia)

# Terminal 3 — ver los eventos en vivo
Get-Content runs\manual\alerts\alerts.jsonl -Wait
# → eventos "NORMAL" (INFO) por mensaje limpio; eventos R-* si algo dispara
```

Para inyectar una anomalía concreta (Terminal 4):

```powershell
$env:LAB_AUTHORIZED = "YES"
.venv\Scripts\python.exe anomaly_generator.py --host 127.0.0.1 --port 1550 --scenario A02 --count 3
.venv\Scripts\python.exe anomaly_generator.py --dry-run --scenario A11   # solo imprime el HL7 mutado
```

### 4.4 Replay de evidencia real (H3 — corpus negativo)

```powershell
$env:LAB_AUTHORIZED = "YES"
# STANDBY: ~7 min, espera FP=0
.venv\Scripts\python.exe replay_evidence.py `
  --pcap evidence_raw\pcap\LECTURACONACK25AGOSTO.pcapng --label STANDBY --start-receiver
# RUNNING: ~17 min, reporta alertas sin umbral (baseline es unimodal STANDBY)
.venv\Scripts\python.exe replay_evidence.py `
  --pcap evidence_raw\pcap\LECTURAACK27AGOSTO.pcapng --label RUNNING --start-receiver
```

Extrae los ORU de la captura (pipeline de anonimización incluido), los reenvía
con el pacing original y observa con receptor `--no-ack`. Manifiesto JSON con
SHA-256 del PCAP, conteo de anomalías (no-NORMAL) y eventos normales.

### 4.5 Bench de latencia (H2)

```powershell
$env:LAB_AUTHORIZED = "YES"
.venv\Scripts\python.exe latency_bench.py --messages 1000 --runs 3
```

Peor caso: ráfaga sin sleep con mensajes que disparan R-TIME-002+R-SEQ-002.
Imprime p50/p95/p99/max en µs y escribe JSON en `analysis_output/validation/`.
PASS si p95 ≤ 500 µs. **En la Pi**: repetir allí antes de afirmar H2 (ver
`docs/RASPBERRY_PI_SETUP.md`).

### 4.6 Campaña H1 completa (N corridas + Wilson)

```powershell
$env:LAB_AUTHORIZED = "YES"
# Fase única (la que corrió la tesis: 30 corridas docker sin A14):
.venv\Scripts\python.exe run_matrix.py --runs 30 --mode docker --exclude A14 --tag main
# Solo A14 (corrida dedicada local, ~3.3 min c/u):
.venv\Scripts\python.exe run_matrix.py --runs 30 --mode local --tag a14 `
  --exclude A01,A02,A03,A04,A05,A06,A07,A08,A09,A10,A11,A12,A13,A15,A16
# Ambas fases en secuencia + log:
powershell -File run_campaign.ps1
```

Semillas: corrida i usa `seed_base+i` (default base 100000 → 100001…).
Salida: `analysis_output/validation/<tag>_<ts>/validation_summary.{json,md}`
con tabla por escenario, ADR, IC 95 % de Wilson y cobertura ≥ 90 %.

### 4.7 Evaluación suelta de una corrida existente

```powershell
.venv\Scripts\python.exe evaluate.py --run runs\<timestamp>
```

### 4.8 Detección offline sobre un PCAP (Modalidad B)

Ejecuta el motor directamente sobre un PCAP **sin abrir conexión de red**
(anonimización por defecto; requiere el mismo guardrail LAB_AUTHORIZED):

```powershell
$env:LAB_AUTHORIZED = "YES"
.venv\Scripts\python.exe detect_pcap.py `
  --pcap evidence_raw\pcap\LECTURACONACK25AGOSTO.pcapng --label STANDBY
```

Salidas: `analysis_output/offline_detect_<label>_<ts>/alerts/alerts.jsonl` y
`detect_pcap_manifest.json` (hash del PCAP, anomalías por regla, normales,
limitaciones). R-TIME-002 se evalúa con la hora de cada paquete de la captura
(Enmienda E5, HANDOFF §14), en el orden en que TCP los entrega: sobre STANDBY real
43 mensajes → 43 NORMAL (antes de E5: 1 NORMAL + 42 R-TIME-002 por la velocidad de
CPU). `--realtime` solo reproduce el ritmo de la captura; no cambia el resultado.
R-MLLP-001 no es evaluable offline (solo llegan tramas completas).

```powershell
# Manifest de una corrida ya ejecutada (protocolo §6)
Get-Content runs\<timestamp>\manifest.json | ConvertFrom-Json |
  Select-Object identificador_experimento, advertencia
```

---

## 5. Cómo leer las salidas

### 5.1 `runs/<timestamp>/` (corrida individual)

| Archivo | Qué contiene |
|---|---|
| `manifest.json` | Manifiesto de corrida (protocolo §6): id, UTC, commit Git, config, semilla, escenarios, SHA-256 de entradas/salidas, plataforma, recursos CPU/RAM del receptor (psutil), resultado y advertencia LAB ONLY |
| `evaluation.json` | tp/fn/fp/tn, recall, precisión, **per_scenario** (inyectados/detectados por A01…A16), throughput (msg/s), message_loss, resource_usage |
| `ground_truth.jsonl` | Una línea por inyección: escenario, hash, ventana temporal, regla esperada |
| `alerts/alerts.jsonl` | Un evento por mensaje: `rule_id=NORMAL` (limpio) o `R-*` (anomalía). Campos: severity, evidence_hash, session_id… |
| `seed.txt` / `scenario_order.txt` | Semilla derivada por fase (benign1/anomalies/benign2) y orden alternado de escenarios |
| `hl7/`, `raw/`, `logs/` | Mensajes (anonimizados), bytes crudos MLLP, log de sesión |

### 5.2 `analysis_output/validation/` (Fase 9)

| Artefacto | Qué acredita |
|---|---|
| `freeze_manifest.json` | Congelamiento v2: HEAD git, SHA-256 de settings/rules/baseline, pre/post-E1 |
| `replay_*/replay_manifest.json` | H3: PCAP hasheado, mensajes enviados, anomalías vs normales, entorno |
| `main_*/validation_summary.md` | H1 fase 1: 30 corridas docker, tabla ADR/Wilson |
| `a14_*/validation_summary.md` | H1 fase 2: 30 corridas A14 |
| `latency_*.json` | H2: percentiles por corrida y agregados |
| `campaign_log.txt` | Transcripción de ambas fases (exit=0/0) |
| `SHA256SUMS.txt` | Sello de integridad de los 314 archivos de la carpeta |

### 5.3 Métricas en lenguaje llano

- **ADR** (Anomaly Detection Rate) = TP/(TP+FN) = % de inyecciones detectadas.
- **IC 95 % de Wilson** = incertidumbre de esa proporción; el umbral del protocolo
  se evalúa contra el límite inferior.
- **FP** = eventos `R-*` sin inyección correspondiente (mensajes benignos alertados).
- **eventos NORMAL** = mensajes procesados sin anomalía (cuentan como TN, no como FP).
- **Precisión** = TP/(TP+FP).

---

## 6. Los 16 escenarios de ataque (A01–A16)

Fuente de verdad: `anomaly_generator.SCENARIOS` (detalle y mapeos MITRE en
`docs/ATTACK_SCENARIOS.md`).

| ID | Nombre | Qué simula | Regla esperada (campo `expected_rule`) |
|----|--------|------------|----------------|
| A01 | unknown_logical_source | Emisor no autorizado (MSH-3/4) | R-ID-001 |
| A02 | duplicate_control_id | MSH-10 repetido | R-SEQ-001 |
| A03 | replay_synthetic_message | Replay byte a byte (hash normalizado) | R-SEQ-002 |
| A04 | regressive_timestamp | MSH-7 en el pasado | R-TIME-001 |
| A05 | missing_final_delimiter | MLLP sin delimitador final (0x1C 0x0D) | R-MLLP-001 |
| A06 | unexpected_bytes_before_start | Bytes antes del SB (0x0B) | R-MLLP-001 |
| A07 | missing_msh_segment | Mensaje sin MSH | R-HL7-001 |
| A08 | invalid_segment_order | Segmentos fuera de orden (OBX antes de MSH) | R-HL7-003 |
| A09 | unknown_message_type | Tipo fuera de baseline (ADT^A01) | R-HL7-002 |
| A10 | synthetic_obx_unexpected_datatype | OBX-2 inesperado (NM donde baseline dice CWE) | R-OBX-003 |
| A11 | synthetic_obx_unauthorized_unit | OBX-6 fuera de `allowed_units` | R-OBX-002 |
| A12 | frequency_out_of_baseline | Ráfaga (≤20 msg / 5 s) fuera del p95*1.5 | R-TIME-002 |
| A13 | repeated_reconnections | Reconexiones repetidas (≤5, cooldown 60 s) | R-TIME-002 |
| A14 | periodic_silence | Silencios de 45 s (3×) | R-TIME-002 |
| A15 | oversized_message | Mensaje grande (dentro del límite duro seguro) | R-MLLP-001 |
| A16 | logical_identity_change_mid_session | Cambio de identidad MSH-3/4 en sesión | R-ID-001 |

Cada uno tiene **techo de seguridad** (3–20 msg) y rate-limit; el generador se
niega a excederlos (`SafetyGuard`). A14 dura ~135 s por diseño.

---

## 7. Reglas de oro (metodología y seguridad)

1. **Toda sesión de PowerShell**: `$env:LAB_AUTHORIZED = "YES"` (más
   `LAB_ONLY.marker`). Sin ello, las herramientas se niegan a correr.
2. **Semillas siempre explícitas** (`--seed`) en corridas que se reporten; el
   orden de escenarios se alterna y queda registrado (`scenario_order.txt`).
3. **Congelar antes de medir**: cualquier cambio en `src/`, `config/` o
   `baseline.yaml` exige commit nuevo + actualizar `freeze_manifest.json`.
   Historia real: una campaña piloto quedó contaminada porque docker monta el
   repo en vivo y el código cambió a mitad de corrida.
4. **No dos campañas a la vez** (colisión Docker) y bench aislado de campañas
   (contaminación de CPU).
5. **Ajustes post-hoc prohibidos**: si un umbral falla, se documenta como
   hallazgo o se tramita enmienda versionada (§8 de `docs/VALIDATION_PROTOCOL.md`;
   precedente: enmienda E1, commit `70025c4`).
6. `evidence_raw/` es solo lectura; los datos clínicos salen anonimizados
   (PID/PV1/NTE tokenizados con SHA-256 truncado).
7. Sin acceso a red hospitalaria: `load_settings` se **niega** (RuntimeError en
   modo strict) si falta la autorización, falta el marcador o la IP del servidor
   es pública y no-loopback; los rangos 10/8, 172.16/12 y 192.168/16 generan
   advertencias de auditoría en cada arranque (son rangos legítimos del lab).

---

## 8. Qué significa cada documento

| Documento | Léelo cuando… |
|---|---|
| `README.md` | Quieres el estado general y la lista de comandos mínimos |
| `docs/GUIA_USO.md` (este) | Quieres ejecutar o entender el laboratorio |
| `docs/RESULTS_20261014.md` | Necesitas los números sellados para la tesis |
| `docs/VALIDATION_PROTOCOL.md` | Vas a repetir la validación o discutir metodología |
| `docs/ATTACK_SCENARIOS.md` | Quieres el detalle de A01–A16 y sus mapas MITRE |
| `docs/THREAT_MODEL.md` | Preguntas de amenazas, activos y supuestos |
| `docs/LAB_ARCHITECTURE.md` | Preguntas de diseño del motor y topología |
| `docs/EVIDENCE_ANALYSIS.md` / `EVIDENCE_ANALYSIS_RESUMEN.md` | Preguntas sobre las capturas originales |
| `docs/ETHICS_AND_SAFETY.md` | Preguntas de seguridad, anonimización y ética |
| `docs/LIMITATIONS.md` | Vas a citar resultados y necesitas los matices |
| `docs/JUSTIFICACION_METODOLOGICA.md` | Vas a redactar/incrustar la sección metodológica de la tesis |
| `docs/RASPBERRY_PI_SETUP.md` | Vas a montar la Pi (único pendiente de hardware) |
| `docs/HANDOFF.md` | Historial de sesiones de desarrollo y pendientes |

---

## 9. Pendientes conocidos (no los olvides al citar)

1. **H2 en Raspberry Pi**: repetir `latency_bench.py --messages 1000 --runs 3`
   en la Pi (setup en `docs/RASPBERRY_PI_SETUP.md`). Hasta entonces H2 es
   "NO VERIFICADO en Pi; PASS de referencia en PC".
2. **Gate clínico y revisión ética** (Ley 1581/2012): trámite institucional
   pendiente; ninguna regla clínica se activa hasta entonces.
3. **Baseline unimodal**: para usar el detector contra tráfico RUNNING real sin
   alertas "fuera de baseline", ampliar `baseline.yaml` con una sesión RUNNING
   representativa (hoy: 256 alertas esperadas sobre 99 ORU de RUNNING, todas
   legítimas — documentado, no es regresión).
4. **Reversibilidad de la anonimización** es interna por diseño (tokens de 8 hex);
   fuera del lab los PCAP crudos son sensibles.
