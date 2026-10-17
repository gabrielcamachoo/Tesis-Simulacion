# Análisis de evidencia HL7/MLLP — capturas WATO EX-35

**Fecha de análisis:** 2026-10-13 (Fase 1)
**Herramienta:** `src/evidence/analyze_evidence.py` con `pcap_reader` (Python puro, sin dependencias de sistema)
**Modo:** anonimización de datos clínicos activada por defecto; `evidence_raw/` en solo lectura

Etiquetas usadas: **OBSERVADO** = medido directamente de los bytes de la captura;
**DOCUMENTADO** = declarado en informes/entregables de la tesis;
**INFERIDO** = deducción razonada a partir de OBSERVADO + DOCUMENTADO;
**NO VERIFICADO** = no comprobable con la evidencia disponible.

## 1. Inventario de capturas

| Archivo | Paquetes | Sesiones HL7 | ORU | ACK | SHA-256 (prefijo) |
|---|---|---|---|---|---|
| `LECTURACONACK25AGOSTO.pcapng` | 639 | 1 | 43 | 43 | `41761f0a9d8b…` |
| `LECTURAACK27AGOSTO.pcapng` | 728 | 1 | 99 | 99 | `67ec6034317e…` |
| `LECTURA25AGOSYO.pcapng` | 867 | 0 | 0 | 0 | `cd9122c67bd3…` |
| `SEPTIEMBRE 02.pcapng` | 1275 | 0 | 0 | 0 | `45d8b60608c1…` |
| `WATOPARANALIZAR18AGOSTO.pcap` | 1664 | 0 | 0 | 0 | `c78679317975…` |

- **OBSERVADO:** solo 2 de 5 capturas contienen tráfico HL7/MLLP; las otras 3 no
  tienen paquetes TCP con payload MLLP (18-08 es tráfico ARP de descubrimiento).
- **OBSERVADO:** todos los hashes coinciden con `evidence_raw/evidence_inventory.csv`.
- **NOTA:** la captura `LECTURA25AGOSYO.pcapng` *no* contiene HL7; no puede ser
  fuente de los 43 mensajes STANDBY (esto corrigió el error de trazabilidad del
  `baseline.yaml` original).

## 2. Sesiones observadas

### 2.1 STANDBY — `LECTURACONACK25AGOSTO.pcapng` (25-08-2026)

- **OBSERVADO:** una conexión TCP `192.168.23.250:2070 → 192.168.23.200:1550`
  con 43 mensajes `ORU^R01^ORU_R01` y 43 `ACK` (86 MLLP en total).
- **OBSERVADO:** cadencia de los ORU por tiempo de captura entre 9.996 s y
  10.004 s; por MSH-7 es exactamente 10.000 s (documentado en informe STANDBY).
- **OBSERVADO:** tamaño en crudo de los ORU: 971 bytes ×34 y 968 bytes ×9
  (coincide con `baseline.yaml`).
- **OBSERVADO:** latencia ORU→ACK correlacionado por `MSA-2 == MSH-10`:
  mín 1.5 ms, promedio 4.7 ms, máx 9.5 ms.
- **OBSERVADO:** segmentos por ORU: `MSH PID PV1 OBR OBX×4`; 4 códigos OBX CWE
  (estado del dispositivo, modo, tipo de paciente, calentador).
- **DOCUMENTADO:** los ACK provienen del receptor de laboratorio
  (`G18NODE|JAVERIANA` en MSH-3/MSH-4), no del WATO.

### 2.2 RUNNING — `LECTURAACK27AGOSTO.pcapng` (27-08-2026)

- **OBSERVADO:** una conexión TCP `192.168.23.250:2048 → 192.168.23.200:1550`
  con 99 ORU y 99 ACK (198 MLLP).
- **OBSERVADO:** cadencia de captura entre 9.649 s y 10.36 s (jitter mayor que
  en STANDBY); tamaños de ORU variables (968–3945 bytes en crudo) porque
  incorpora observaciones numéricas.
- **OBSERVADO:** latencia ORU→ACK: mín 1.9 ms, promedio 3.0 ms, máx 5.9 ms.
- **INFERIDO:** el patrón de ~10 s se mantiene en RUNNING; el contenido OBX es
  distinto (numérico vs CWE de estado), consistente con el informe RUNNING.

## 3. Correlación global (ambas capturas)

- **OBSERVADO:** 142 ORU y 142 ACK en total; correlación `MSA-2 == MSH-10`
  exitosa al 100 % (142/142, sin fallback posicional).
- **OBSERVADO:** 284 mensajes MLLP, 3129 segmentos; OBX = 72.77 % de los segmentos.

## 4. Limitaciones del análisis

- **NO VERIFICADO:** parámetros fisiológicos (no existen valores numéricos en
  la captura STANDBY; en RUNNING no hay contexto clínico asociado).
- **NO VERIFICADO / NO PRESERVADO:** los artefactos de sesión en crudo que
  `ackdummy_original.py` escribía durante la captura real
  (`raw_<ip>_<puerto>.bin`, `mensajes.hl7`, `sesion.log`) **no están en el
  repositorio**; solo se conservan el código (`evidence_raw/codigo/ackdummy_original.py`)
  y las 5 capturas PCAPNG. Todo el análisis se apoya en los PCAPNG, no en esos
  binarios sueltos.
- El reensambla TCP por número de secuencia no resuelve solapamientos parciales
  ni fragmentación IP: las 5 capturas están completas y sin fragmentos
  (**OBSERVADO**: 0 paquetes con flag MF/offset), pero otras capturas podrían
  requerir extensión.
- La latencia ACK mide el receptor de laboratorio (ackdummy), no el WATO.
- Los offsets de reloj (+17 min 10 s declarados para el WATO) afectan valores
  absolutos de MSH-7, no los intervalos (diferencias).
- Anonimización: los campos clínicos PID/PV1/NTE se reemplazan por tokens
  determinísticos SHA-256 truncado (pseudonimización); identificadores de
  dispositivo y red se conservan solo para atribución.

## 5. Reproducibilidad

```bash
.venv/Scripts/python -m src.evidence.analyze_evidence evidence_raw -o analysis_output
.venv/Scripts/python -m pytest tests/test_evidence_analysis.py -q
```

Las cifras de este documento están cubiertas por
`tests/test_evidence_analysis.py` (conteos 43/43, 99/99, correlación ACK,
intervalos y estructura de anonimización).
