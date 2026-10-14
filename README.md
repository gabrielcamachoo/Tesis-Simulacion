# Detector de anomalías HL7/MLLP — Tesis WATO EX-35 (SIDRE, Grupo 18)

Banco de pruebas aislado (caja negra) para detectar indicadores observables de un
host comprometido en la red de monitores multiparámetro Mindray WATO EX-35.
No existe contacto con equipo clínico real: todo se ejecuta contra evidencia
capturada previamente y un emulador en red aislada.

## Estructura

```
evidence_raw/       Evidencia original SOLO LECTURA (pcap, informes, código). No modificar.
analysis_output/    Reportes derivados (CSV/Markdown), regenerables.
src/
  evidence/         Lector PCAP (Python puro), hashing, anonimización, baseline.
  hl7/              Parser y validador HL7 v2.6.
  mllp/             Framing MLLP, ACK, servidor.
  detection/        Motor de detección, reglas, baseline.
  config/           Ajustes YAML.
  alerting/         Log JSON de alertas.
tests/              Pruebas pytest (incluye verificación contra los PCAP reales).
baseline.yaml       Línea base estadística trazable a hashes de evidencia.
mllp_receiver.py    Receptor MLLP de laboratorio (solo localhost/red interna).
wato_emulator.py    Emulador sintético ORU^R01 (periodicidad de evidencia).
anomaly_generator.py Generador de escenarios A01–A16 con techos de seguridad.
evaluate.py         Evaluación de corridas (ADR/FP) contra ground truth.
docker-compose.yml  Topología de laboratorio (requiere Docker Desktop).

Documentos de fase (raíz): THREAT_MODEL.md, ETHICS_AND_SAFETY.md,
LAB_ARCHITECTURE.md, ATTACK_SCENARIOS.md, VALIDATION_PROTOCOL.md,
RESULTS_TEMPLATE.md, LIMITATIONS.md, TRACEABILITY_MATRIX.csv,
EVIDENCE_ANALYSIS.md.
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
- **Fase 2/4** 🔄 emulador, generador de anomalías y evaluación en desarrollo.
- **Pendiente externo:** Docker Desktop (instalación manual; código de error
  4294967291 vía winget) y ejecución en Raspberry Pi (Fase 5+).
- **NO VERIFICADO:** H1 (ADR ≥ 90 %) y H2 (≤ 500 µs) hasta la Fase 9.
