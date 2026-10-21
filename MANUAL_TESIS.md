# MANUAL DE LA TESIS — Detector de anomalías/ataques HL7/MLLP para el WATO EX-35

**Proyecto:** G18 SIDRE · Pontificia Universidad Javeriana
**Versión:** 2026-10-17 · Acompaña a `README.md` (estado) y `docs/RESULTADOS_TESIS.md` (números)

> **Alcance en una frase:** laboratorio reproducible y aislado (caja negra) que detecta
> indicadores observables de un host comprometido en la red del monitor anestésico
> Mindray WATO EX-35, usando solo tráfico HL7 v2.x/MLLP, sin contacto con equipo
> clínico real y sin malware.

---

## 0. Hipótesis que responde la tesis

| # | Hipótesis | Estado |
|---|-----------|--------|
| H1 | Un detector determinista black-box logra ADR ≥ 90 % sobre ataques con técnicas MITRE ATT&CK ICS | **ACEPTADA** — ADR 100 % (2010/2010, IC95 [99.8, 100.0], 60 corridas) |
| H2 | La detección ocurre con p95 ≤ 500 µs por mensaje | **PASS en PC** (177.5 µs); **NO_VERIFICADO en Pi física** |
| H3 | FP sobre corpus benigno real = 0 | **CUMPLE** en STANDBY (43/43 NORMAL, FP = 0) y RUNNING (99/99 NORMAL, FP = 0 con baseline bimodal v1.1 + E1–E8) |

## 1. Mapa rápido: "quiero hacer X"

| Quiero… | Ejecuto / abro |
|---|---|
| Entender el proyecto completo | **Este manual** → luego `docs/LAB_ARCHITECTURE.md` |
| Ver los números para la defensa | `docs/RESULTADOS_TESIS.md` (+ `docs/RESULTS_20261014.md`) |
| Instalar todo (Windows) | §2 de este manual |
| **Desplegar la Pi como detector** | `deploy/pi/` (física) o `deploy/pi/pi_detector_docker.ps1` (simulación) |
| **Desplegar el WATO (emulador)** | `deploy/receptor/receptor.ps1` + `deploy/wato/wato.ps1` |
| **Desplegar el atacante (ransomware simulado)** | `deploy/atacante/atacante_ransomware.ps1` |
| Corrida completa automatizada | `run_experiment.py --mode local\|docker` |
| Ejecutar las pruebas | `deploy/validacion/suite.ps1` (246 tests) |
| Saber qué hace cada escenario A01–A16 | `docs/ATTACK_SCENARIOS.md` |
| Metodología de medición | `docs/VALIDATION_PROTOCOL.md` |
| Seguridad/ética | `docs/ETHICS_AND_SAFETY.md` |
| Historial de desarrollo | `docs/HANDOFF.md` |

## 2. Requisitos e instalación

### 2.1 Windows (host de desarrollo y corridas)

```powershell
# 1) Python 3.11+ y git instalados. Desde la raíz del repo:
python -m venv .venv
.venv\Scripts\pip install -r requirements.txt

# 2) Verificar (debe decir N passed, hoy 204):
deploy\validacion\suite.ps1

# 3) Autorización del lab (obligatoria, ver §9):
#    - existe LAB_ONLY.marker en la raíz del repo (viene con el repo)
#    - los scripts de deploy fijan LAB_AUTHORIZED=YES automáticamente
```

### 2.2 Raspberry Pi (detector físico)

```bash
# Pi conectada SOLO a la red aislada del lab (sin ISP)
cd <repo> && ./deploy/pi/01_instalar.sh     # apt+venv+tests+/LAB_ONLY.marker
./deploy/pi/02_red_aislada.sh                # ufw sin egress
./deploy/pi/03_instalar_servicio.sh          # servicio systemd (arranque auto)
```
Detalle y troubleshooting: `docs/RASPBERRY_PI_SETUP.md`.

### 2.3 Docker (topología de la tesis, opcional pero recomendado)

Docker Desktop + WSL2 corriendo. La red es `internal: true` (172.30.0.0/24, sin
salida a Internet): emulador `.10`, generador `.11`, receptor `.20`.

## 3. Estructura del repositorio

```
├── README.md                  Estado del proyecto y comandos
├── MANUAL_TESIS.md            ← ESTE MANUAL
├── docs/                      Toda la documentación de la tesis
│   ├── RESULTADOS_TESIS.md      Números para la defensa (compilado)
│   ├── RESULTS_20261014.md      Validación Fase 9 cruda y sellada
│   ├── LAB_ARCHITECTURE.md      Arquitectura + diagrama Mermaid
│   ├── ATTACK_SCENARIOS.md      Escenarios A01–A16 y su mapeo MITRE
│   ├── THREAT_MODEL.md          Modelo de amenazas
│   ├── VALIDATION_PROTOCOL.md   Protocolo de medición (H1/H2/H3)
│   ├── ETHICS_AND_SAFETY.md     Límites éticos y cuantitativos
│   ├── SIMULACION_RANSOMWARE.md Campaña ransomware + topología Pi
│   ├── RASPBERRY_PI_SETUP.md    Guía de montaje de la Pi
│   ├── GUIA_USO.md              Recetas prácticas
│   ├── LIMITATIONS.md           Limitaciones declaradas
│   ├── EVIDENCE_ANALYSIS.md     Análisis de la evidencia original
│   ├── JUSTIFICACION_METODOLOGICA.md  Sección metodológica para redactar
│   ├── TRACEABILITY_MATRIX.csv  Requisito → escenario → regla → métrica
│   ├── RESULTS_TEMPLATE.md      Plantilla de resultados
│   └── HANDOFF.md               Historial de sesiones de desarrollo
├── deploy/                    Puntos de despliegue (uno por componente)
│   ├── receptor/               receptor.ps1 + make_deploy_settings.py (el detector)
│   ├── wato/                   wato.ps1 (emulador WATO, trafico benigno)
│   ├── atacante/               atacante_ransomware.ps1 (campana A01/A05/A06/A13/A14/A16)
│   ├── pi/                     01_instalar…06_campana (.sh), systemd,
│   │                           pi_detector_docker.ps1 (simulacion docker)
│   └── validacion/             suite.ps1 (pruebas) · evaluar.ps1 (metricas)
├── documentos_tesis/          Formatos, bitácora, SRS/VPP, PDFs y bib de la tesis
├── legacy/                    ackdummy (prototipo histórico, no se ejecuta)
├── src/                       Motor del detector (mllp, hl7, detection, evidence…)
├── tests/                     204 pruebas automatizadas (pytest)
├── config/rules.yaml          15 reglas con severidad y MITRE
├── baseline.yaml              Línea base trazable a hashes de la evidencia
├── mllp_receiver.py           Receptor = DETECTOR
├── wato_emulator.py           Emulador del WATO (trafico benigno)
├── anomaly_generator.py       Generador del ATACANTE (A01–A16)
├── run_experiment.py          Orquestador (benigno → ataque → benigno → evaluación)
├── evaluate.py                Métricas TP/FP/TN/FN, recall, precision, latencia
├── detect_pcap.py             Detector offline sobre PCAP (Modalidad B)
├── replay_evidence.py         Replay de la evidencia real (H3)
├── latency_bench.py           Bench de latencia (H2)
├── run_matrix.py              Campañas múltiples con IC95
├── evidence_raw/              Evidencia original SOLO LECTURA (SHA-256 verificable)
├── analysis_output/           Reportes + evidencia sellada (validation/)
└── runs/                      Corridas completas (gitignored, regenerables)
```

## 4. Cómo funciona

### 4.1 Arquitectura (una línea)

```
wato_emulator (WATO sintético)  ──MLLP/TCP:1550──▶  mllp_receiver (detector)
anomaly_generator (atacante)    ──MLLP/TCP:1550──▶    ├─ framing MLLP (SB/EOM)
                                                      ├─ parser HL7 v2.6
                                                      ├─ validator (estructura + baseline)
                                                      ├─ engine (15 reglas + estado por sesión)
                                                      ├─ alerting → alerts.jsonl (+ SHA-256)
                                                      └─ evidence  → raw/hl7/logs
                                                                  │
                                             evaluate.py ◀─ ground truth + alertas
```

No hay componente inline en el WATO real: el detector es externo y **no altera** el
flujo clínico (observa o recibe tráfico sintético en el lab).

### 4.2 Flujo de un mensaje (paso a paso)

1. El emulador envía un `ORU^R01` delimitado por MLLP (SB `0x0B` … EOM `0x1C0D`).
2. El receptor reensambla la trama y la parsea por segmentos/campos HL7.
3. El validador comprueba estructura y **baseline** (qué es "normal" para ESTE WATO:
   tipos de mensaje, códigos OBX, unidades, IP permitidas, intervalos 5–15 s…).
4. El motor evalúa las **15 reglas deterministas** con estado por sesión (FSM,
   último timestamp, hashes vistos, control IDs).
5. Si alguna regla dispara → **alerta JSONL** con `rule_id`, `severity`, `reason`,
   `evidence_hash` (trazabilidad byte a byte). Si no → evento `NORMAL` (INFO).
6. Todo queda sellado: bytes crudos, mensajes HL7 anonimizados, logs y `manifest.json`
   con commit + hashes + semilla → reproducibilidad.

### 4.3 Las 15 reglas deterministas (`config/rules.yaml`)

| Regla | Detecta | Escenarios |
|---|---|---|
| R-ID-001 | Aplicación emisora MSH-3 no autorizada | A01, A16 |
| R-ID-002 | Institución emisora MSH-4 no autorizada | (refuerzo de A01) |
| R-NET-001 | IP de origen TCP fuera de la allowlist | tráfico de red |
| R-MLLP-001 | Framing MLLP inválido (bytes basura, EOM ausente, >4096 B) | A05, A06, A15 |
| R-HL7-001 | Mensaje sin segmento MSH | A07 |
| R-HL7-002 | Tipo de mensaje MSH-9 no baselineado | A09 |
| R-HL7-003 | Secuencia de segmentos inválida | A08 |
| R-SEQ-001 | Message Control ID (MSH-10) duplicado | A02 |
| R-SEQ-002 | Replay por hash de contenido normalizado | A03 |
| R-TIME-001 | Timestamp MSH-7 regresivo | A04 |
| R-TIME-002 | Intervalo fuera de baseline (corto/largo/silencio) | A12, A13, A14 |
| R-OBX-001 | Código OBX-3 no baselineado | RUNNING |
| R-OBX-002 | Unidad OBX-6 no autorizada (Enmienda E1) | A11 |
| R-OBX-003 | Tipo de dato OBX-2 incompatible | A10 |
| R-STATE-001 | Transición de FSM no permitida | estado de sesión |

Severidades, justificación MITRE ATT&CK ICS v20 y limitaciones: `config/rules.yaml`
(verificado contra ATT&CK v20 en `docs/THREAT_MODEL.md` §4).

### 4.4 El atacante "ransomware" (qué es y qué NO es)

**NO hay malware.** La campaña compone escenarios del catálogo para modelar los
efectos black-box de un ransomware que secuestra la telemetría del monitor
(`docs/SIMULACION_RANSOMWARE.md` §1):

| Fase del ataque | Efecto observable | Escenario | Regla |
|---|---|---|---|
| Bloqueo (hostage) | El latido ORU desaparece cada ~10 s | A14 silencio 45 s | R-TIME-002 |
| Corrupción / cifrado del stream | Bytes basura, delimitador ausente | A06, A05 | R-MLLP-001 |
| Inestabilidad | Reconexiones repetidas | A13 | R-TIME-002 |
| Suplantación | MSH con origen desconocido / identidad cambia | A01, A16 | R-ID-001 |

El detector no "sabe" que es ransomware: detecta las violaciones de comportamiento
que el ataque produce (eso es lo publicable).

### 4.5 Interlocks de seguridad (presentes en todos los modos)

1. `LAB_AUTHORIZED=YES` + marcador `LAB_ONLY.marker` (sin ambos, nada arranca).
2. Límites de `laboratory.safety`: ≤70 anomalías/corrida, rate limit, tamaño, cooldown.
3. Solo localhost / red Docker internal; `block_public_ips: true` (sin IP pública).
4. `evidence_raw/` inmutable + SHA-256 verificable en `evidence_inventory.csv`.
5. Anonimización por defecto de PID/PV1/NTE en todo artefacto derivado.
6. Ninguna regla clínica activa sin aprobación (`clinical_approval_status: PENDING`).

## 5. Despliegues

### 5.1 Raspberry Pi como detector de ciberataques

**Opción A — Pi física** (ver `deploy/pi/README.md`): instalar con los 3
scripts de §2.2; luego:

```bash
# Detector EN LINEA (servicio siempre activo o a demanda):
systemctl status mllp-receiver            # ya corriendo (systemd)
./deploy/pi/04_detector_online.sh   # o manual con outdir por corrida

# Detector PASIVO sobre un PCAP capturado (sin abrir red):
./deploy/pi/05_detector_offline.sh evidencia.pcapng STANDBY

# Validación completa en la propia Pi (misma semilla que el PC → mismo orden):
./deploy/pi/06_campana_validacion.sh 20261014

# H2 OBLIGATORIO en la Pi (único pendiente de hardware):
.venv/bin/python latency_bench.py --messages 1000 --runs 5
```

**Opción B — Simulación docker de la topología** (mismo código y red que la Pi):

```powershell
deploy\pi\pi_detector_docker.ps1          # A01–A16 sin A14, semilla 20261014
```

### 5.2 Despliegue del WATO (emulador benigno)

```powershell
# Terminal 1 — detector escuchando:
deploy\receptor\receptor.ps1

# Terminal 2 — WATO enviando STANDBY (10 msg, 6 s):
deploy\wato\wato.ps1 -Count 10 -Interval 6.0
```
Esperado: `ACK received and validated: code=AA` por mensaje, 0 alertas, eventos
`NORMAL` en `alerts.jsonl`, evidencia con SHA-256 en `evidence_output/`.

### 5.3 Despliegue del atacante (ransomware simulado)

```powershell
# Corrida completa orquestada: benigno → A01,A05,A06,A13,A14,A16 → benigno → evaluación
deploy\atacante\atacante_ransomware.ps1            # ~201 s, semilla 2026101401
```
Resultado esperado (reproducido 2×): **TP=20, FP=0, FN=0**, recall y precision = 1.0.
Salida en `runs/<timestamp>/` (ver §6).

### 5.4 Campaña completa A01–A16 (metodología de la tesis)

```powershell
$env:LAB_AUTHORIZED = "YES"
.venv\Scripts\python run_experiment.py --mode docker --exclude A14 --seed 20261014   # topología Pi
.venv\Scripts\python run_experiment.py --mode local                                  # completo (A14 dura ~135 s)
```

### 5.5 Detección offline sobre PCAP (Modalidad B)

```powershell
.venv\Scripts\python detect_pcap.py --pcap evidence_raw\pcap\LECTURACONACK25AGOSTO.pcapng --label STANDBY
```

## 6. Salidas y cómo leerlas

Cada corrida escribe `runs/<timestamp>/`:

| Archivo | Contenido |
|---|---|
| `ground_truth.jsonl` | Qué se inyectó, cuándo y qué regla debía disparar |
| `alerts/alerts.jsonl` | Eventos: `NORMAL` (INFO) o alerta con `rule_id`, `severity`, `reason`, `evidence_hash` |
| `evaluation.txt/json` | TP/FP/TN/FN, recall, precision, F1, latencias, throughput, pérdida, por escenario |
| `manifest.json` | Commit git, hashes SHA-256 de insumos/salidas, semilla, runtime, resultado |
| `seed.txt` / `scenario_order.txt` | Semillas y orden de escenarios (reproducibilidad) |
| `raw/ · hl7/ · logs/` | Bytes crudos, mensajes anonimizados, logs por sesión |

Ejemplo de alerta real de un ataque:

```json
{"rule_id": "R-ID-001", "severity": "HIGH",
 "reason": "R-ID-001: Unauthorized sending application: MALICIOUS_APP^hacker^L",
 "evidence_hash": "667bb690718b0117…", "label": "ANOMALO"}
```

Re-evaluar una corrida existente: `deploy\validacion\evaluar.ps1 -RunDir runs\20261017_110410`.

## 7. Resultados obtenidos (resumen)

Consolidado completo con tablas por hipótesis y por corrida:
**`docs/RESULTADOS_TESIS.md`**. Cifras clave:

- H1: ADR **100 %** en 16/16 escenarios (2010/2010 TP; IC95 [99.8, 100.0]; 60 corridas).
- H2: p95 **177.5 µs** en PC (PASS < 500 µs); Pi física pendiente.
- H3: FP = **0** sobre evidencia STANDBY real (×5).
- Ransomware: **20/20 TP, 0 FP** (reproducido 2026-10-14 y 2026-10-17).
- Topología Pi (docker): **64/64 TP, 1 FP** benigno (jitter), recall 1.0.
- WATO standalone: 8/8 mensajes + ACK, **0 alertas** (benigno limpio).
- Suite: **246 pruebas automatizadas** en verde (incluye enmiendas E1–E8).

## 8. Validación y reproducibilidad

- **Semillas fijas** por corrida (registradas en `seed.txt` y `manifest.json`).
- **Corridas selladas** en `analysis_output/validation/` con `SHA256SUMS.txt`.
- **Commit congelado** por campaña (H1 en `2017af16`; ver `docs/RESULTS_20261014.md` §1).
- Protocolo completo (n ≥ 30 por escenario, IC95 Wilson, sin tuning post-hoc):
  `docs/VALIDATION_PROTOCOL.md`.
- Pruebas: `deploy\validacion\suite.ps1` → **246 passed** (2026-10-20).

## 9. Seguridad y ética (no negociables)

- Solo laboratorio aislado: sin IP pública, sin Internet en runtime, sin objetivo externo.
- **Sin ransomware real, malware, exploits, persistencia ni DoS** (los escenarios son
  composiciones de comportamientos modelados; ver `docs/ETHICS_AND_SAFETY.md`).
- Sin contacto con el WATO real: `evidence_raw/` solo lectura y el equipo clínico no
  participa en ninguna ejecución.
- Datos clínicos anonimizados por defecto en todo derivado.
- Reglas clínicas desactivadas hasta aprobación (`clinical_approval_status: PENDING`).

## 10. Guion de defensa (10 puntos)

1. **Problema:** en hospitales, la red de monitores (HL7/MLLP) es un canal de
   telemetría sin autenticación; un host comprometido puede suplantar, corromper o
   secuestrar ese canal (modelo de amenazas: `docs/THREAT_MODEL.md`).
2. **Pregunta:** ¿se puede detectar black-box, con determinismo y evidencia, en
   tiempo real sobre ese canal?
3. **Método:** laboratorio aislado; emulador WATO + generador de anomalías A01–A16
   mapeadas a MITRE ATT&CK ICS v20; receptor con 15 reglas + baseline derivado de
   evidencia real (hashes).
4. **Interlocks:** LAB_AUTHORIZED + marker, red sin egress, anonimización, sin
   malware ni equipo clínico real (decisión ética documentada).
5. **H1 → aceptada:** ADR 100 % (2010/2010), IC95 [99.8, 100.0], 60 corridas.
6. **H2 → PASS en PC:** p95 177.5 µs (umbral 500 µs); honestamente: pendiente en Pi.
7. **H3 → FP=0** tanto en `STANDBY` (43/43 NORMAL) como en `RUNNING` (99/99 NORMAL, 6 modos) con la baseline bimodal v1.1 + enmiendas E1–E8.
8. **Demo en vivo:** campaña ransomware 20/20 TP, 0 FP, latencia p95 ≈ 7 ms
   (inyección→alerta, end-to-end incluyendo red).
9. **Reproducibilidad:** semillas + `manifest.json` + SHA-256 + commit congelado →
   el jurado puede regenerar cada número.
10. **Limitaciones declaradas:** H2 en Pi, baseline unimodal, ~0.3 % FP de jitter,
    aprobación clínica pendiente (`docs/LIMITATIONS.md`).

## 11. Índice de documentos

| Documento | Para qué |
|---|---|
| `README.md` | Estado, requisitos, comandos |
| `docs/RESULTADOS_TESIS.md` | **Números de la defensa** |
| `docs/RESULTS_20261014.md` | Validación Fase 9 cruda |
| `docs/LAB_ARCHITECTURE.md` | Arquitectura y diagrama Mermaid |
| `docs/ATTACK_SCENARIOS.md` | A01–A16 en detalle + MITRE |
| `docs/THREAT_MODEL.md` | Amenazas, activos, supuestos |
| `docs/VALIDATION_PROTOCOL.md` | Protocolo estadístico |
| `docs/ETHICS_AND_SAFETY.md` | Límites éticos/cuantitativos |
| `docs/SIMULACION_RANSOMWARE.md` | Campaña ransomware y topología Pi |
| `docs/RASPBERRY_PI_SETUP.md` | Montaje de la Pi |
| `docs/GUIA_USO.md` | Recetas prácticas paso a paso |
| `docs/LIMITATIONS.md` | Qué NO se demostró (y por qué) |
| `docs/EVIDENCE_ANALYSIS.md` | Análisis de la evidencia original |
| `docs/JUSTIFICACION_METODOLOGICA.md` | Texto metodológico para redactar |
| `docs/TRACEABILITY_MATRIX.csv` | Trazabilidad requisito→métrica |
| `docs/HANDOFF.md` | Historial de desarrollo |
| `documentos_tesis/` | Formatos, bitácora, SRS/VPP, referencias (BibTeX) |
