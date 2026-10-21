# Detector de anomalías HL7/MLLP — Tesis WATO EX-35 (SIDRE, Grupo 18)

Banco de pruebas aislado (caja negra) para detectar indicadores observables de un
host comprometido en la red de monitores multiparámetro Mindray WATO EX-35.
No existe contacto con equipo clínico real: todo se ejecuta contra evidencia
capturada previamente y un emulador en red aislada.

## Estructura

```
MANUAL_TESIS.md      Manual completo de la tesis (uso, despliegues, resultados, defensa).
docs/                Toda la documentación de la tesis (ver §Índice al final de este README).
deploy/
  receptor/          Detector (producto): receptor.ps1 + make_deploy_settings.py.
  wato/              Emulador WATO (trafico benigno): wato.ps1.
  atacante/          Atacante (ransomware simulado): atacante_ransomware.ps1.
  pi/                Raspberry Pi: instalacion, red aislada, systemd, detector
                     online/offline, campana + pi_detector_docker.ps1 (simulacion).
  validacion/        suite.ps1 (pruebas) · evaluar.ps1 (metricas de corridas).
evidence_raw/        Evidencia original SOLO LECTURA (pcap, informes, código). No modificar.
analysis_output/     Reportes derivados (CSV/Markdown) + evidencia sellada en validation/.
documentos_tesis/    Formatos, bitácora, SRS/VPP, PDFs y referencias (BibTeX).
legacy/              ackdummy (prototipo histórico, no se ejecuta).
src/
  evidence/          Lector PCAP (Python puro), hashing, anonimización, baseline.
  hl7/               Parser y validador HL7 v2.6.
  mllp/              Framing MLLP, ACK, servidor.
  detection/         Motor de detección, reglas, baseline.
  config/            Ajustes YAML.
  alerting/          Log JSON de alertas.
tests/               Pruebas pytest (incluye verificación contra los PCAP reales).
baseline.yaml        Línea base estadística trazable a hashes de evidencia.
mllp_receiver.py     Receptor MLLP = detector (solo localhost/red interna).
wato_emulator.py     Emulador sintético ORU^R01 (periodicidad de evidencia).
anomaly_generator.py Generador de escenarios A01–A16 con techos de seguridad.
evaluate.py          Evaluación de corridas (ADR/FP) contra ground truth.
run_experiment.py    Orquestador de corridas (benigno → anomalías → benigno → evaluación).
docker-compose.yml   Topología de laboratorio (requiere Docker Desktop).

Documentación clave: docs/RESULTADOS_TESIS.md (números de defensa),
docs/GUIA_USO.md (recetas paso a paso), docs/HANDOFF.md (historial),
docs/ATTACK_SCENARIOS.md, docs/THREAT_MODEL.md, docs/VALIDATION_PROTOCOL.md,
docs/ETHICS_AND_SAFETY.md, docs/SIMULACION_RANSOMWARE.md, docs/RASPBERRY_PI_SETUP.md,
docs/TRACEABILITY_MATRIX.csv (trazabilidad requisito→métrica).
```

## Requisitos

- Python 3.11+ (probado en 3.11.9; sin dependencias de sistema: el lector de
  PCAP está implementado en Python puro).
- `pip install -r requirements.txt`

## Comandos

```bash
python -m venv .venv && .venv/Scripts/python -m pip install -r requirements.txt

# Pruebas (incluye análisis de las capturas reales)
.venv/Scripts/python -m pytest tests -q

# Regenerar análisis de evidencia (anonimización activada por defecto)
.venv/Scripts/python -m src.evidence.analyze_evidence evidence_raw -o analysis_output

# Regenerar baseline trazable a hashes
.venv/Scripts/python -m src.evidence.baseline_builder \
  --source-files "evidence_raw/pcap/LECTURACONACK25AGOSTO.pcapng" \
                 "evidence_raw/informes/WATO STANDBY 25-08-2026.docx"

# Receptor MLLP de laboratorio (solo entorno autorizado)
.venv/Scripts/python mllp_receiver.py --help

# Emulador benigno (otra terminal) y escenarios de anomalía
.venv/Scripts/python wato_emulator.py --host 127.0.0.1 --count 10
.venv/Scripts/python anomaly_generator.py --dry-run --scenario A01

# Corrida completa del laboratorio (benigno → A01–A16 → benigno → evaluación).
# El modo docker es el de la metodología de la tesis; --mode local es loopback
# para desarrollo/CI. A14 dura ~135 s (3 × 45 s de silencio): usar --exclude A14
# para corridas rápidas.
LAB_AUTHORIZED=YES .venv/Scripts/python run_experiment.py --mode docker
LAB_AUTHORIZED=YES .venv/Scripts/python run_experiment.py --mode local --exclude A14

# Topología en Docker (cuando Docker Desktop esté instalado)
docker compose up -d mllp-receiver wato-emulator
docker compose --profile anomalies run --rm anomaly-generator
```

## Reglas de seguridad (no negociables)

- Autorización explícita requerida (`LAB_AUTHORIZED=YES` + marcador `LAB_ONLY.marker`).
- Solo localhost y redes Docker internas: sin IP pública, sin objetivo externo.
- Sin ransomware, malware, exploits, persistencia ni DoS.
- `evidence_raw/` es de solo lectura: los hashes de `evidence_inventory.csv`
  deben seguir coincidiendo.
- Anonimización de datos clínicos activada por defecto (PID/PV1/NTE); los
  identificadores de dispositivo y red se conservan solo para atribución.
- Ninguna regla clínica se activa sin aprobación clínica (`clinical_approval_status: PENDING`).

## Estado

- **Fase 0** ✅ toolchain (Python 3.11.9, Git, venv).
- **Fase 1** ✅ análisis de evidencia verificado: 142 ORU + 142 ACK correlacionados,
  baseline trazable, anonimización por defecto.
- **Fase 3** ✅ documentación: threat model, ética, arquitectura, escenarios A01–A16
  con técnicas ATT&CK ICS v20 verificadas (2026-10-13) y matriz de trazabilidad al SRS.
- **Fase 2** ✅ emulador, generador A01–A16 y evaluador; 179 pruebas automatizadas.
- **Fase 4** ✅ orquestador `run_experiment.py` end-to-end en modo local
  (67/67 inyecciones, recall=1.0, fp=0) y en modo docker (64/64 con `--exclude A14`;
  evidencia en named volume `lab_output` copiada al host con `docker compose cp`).
- **Fase 6** ✅ guía de montaje `docs/RASPBERRY_PI_SETUP.md`; la ejecución en el hardware
  Pi sigue pendiente (recurso externo).
- **Fase 9** ✅ validación en PC (2026-10-14, `docs/RESULTS_20261014.md`):
  - **H1 ACEPTADA**: ADR 100 % en 16/16 escenarios (60 corridas selladas,
    IC95 Wilson global [99.8, 100.0], precisión 99.7 %).
  - **H2**: PASS de referencia en PC (p95 177.5 µs ≪ 500 µs); **NO VERIFICADO en
    Pi** hasta repetir el bench allí.
  - **H3**: replay STANDBY FP = 0 (×5); RUNNING = 256 alertas "fuera de baseline"
    (×3, determinista; baseline unimodal STANDBY — documentado, sin umbral).
  - Evidencia sellada: `analysis_output/validation/SHA256SUMS.txt` (314 archivos).
- **Entregables de spec completados** (2026-10-14, sesión asistente 5+6):
  - `manifest.json` por corrida (commit, hashes, semilla, runtime, recursos CPU/RAM).
  - `detect_pcap.py`: detección offline sobre PCAP (Modalidad B), sin red.
  - Diagrama Mermaid en `docs/LAB_ARCHITECTURE.md` §1.1; `docs/JUSTIFICACION_METODOLOGICA.md`.
  - Métricas extra en `evaluate.py`: throughput, message_loss, resource_usage.
  - `docs/TRACEABILITY_MATRIX.csv` actualizado con estados post-Fase 9 y columna evidencia.
  - Suite: **200 pruebas automatizadas** (2026-10-14).
  - `docs/SIMULACION_RANSOMWARE.md`: campaña ransomware en tiempo real
    (A01+A05+A06+A13+A14+A16 → 20/20 TP, FP=0) + simulación de topología
    Raspberry Pi en docker (A01–A16 → recall 1.0); selladas en
    `analysis_output/validation/{ransomware_sim,pi_sim}_20261014_*`.
  - Suite actual: **204 pruebas** (incluye fix de pérdida de mensajes con
    conteo real `hl7/*.hl7`).
- **Sesión 7** ✅ 2026-10-17 — Reorganización para entrega/GitHub:
  - 15 documentos movidos a `docs/` (referencias actualizadas en el código);
    PDFs/DOCX/bib a `documentos_tesis/`; `ackdummy (1).py` a `legacy/`;
    `.gitattributes` (`*.sh eol=lf`, `*.service eol=lf`).
  - `MANUAL_TESIS.md` (manual completo de uso y defensa) y
    `docs/RESULTADOS_TESIS.md` (compilado de números: H1/H2/H3, ransomware,
    Pi docker, demo WATO, bench).
  - Reproducción de campañas: topología Pi docker (`20261017_110211`, recall 1.0)
    y campaña ransomware (`20261017_110410`, 20/20 TP, 0 FP); evidencia sellada
    en `analysis_output/validation/{pi_sim,ransomware_sim}_20261017_*`.
  - Demo WATO standalone: 8/8 ORU + 8/8 ACK `AA`, 0 alertas benignas;
    evidencia en `evidence_output/wato_demo_20261017_112431/`.
  - Suite verde: **204 passed**; `evidence_raw/` intacto (SHA-256 verificado).
- **Integración baseline bimodal v1.1 + Enmiendas E2–E8** ✅ 2026-10-20:
  - `baseline.yaml` v1.1 bimodal (`STANDBY` + `RUNNING` 6 modos, 33 códigos OBX, 9 unidades MDC) y `wato_emulator.py` multimodo: **0 FP** en `STANDBY` (43/43 NORMAL) y **0 FP** en `RUNNING` (99/99 NORMAL).
  - Enmiendas E2 (coherencia `R-STATE-001` con `184352^MDC_VENT_MODE` y alerta en `RUNNING->STANDBY` no verificado), E3 (vigilante de silencio `check_silence`), E4 (motivo propio en `R-OBX-001/002/003`), E5 (orden de entrega TCP + `capture_time` en `detect_pcap.py`), E6 (evaluación por conexión `source` + `started_utc`), E7 (ciclo SYN 47.6 s en `SIN_GATEWAY`) y E8 (`R-TIME-001` con zona horaria ISO/HL7).
  - Suite verde: **246 passed**.
