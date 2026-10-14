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

Fase 0 (toolchain, Git) y Fase 1 (análisis de evidencia verificado: 142 ORU +
142 ACK correlacionados, baseline trazable) completadas. El resto de fases
(emulador, motor de detección, escenarios, validación) está en construcción.
