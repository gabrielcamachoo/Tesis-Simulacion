# Modelo de Amenazas — Banco de Pruebas MLLP/HL7

**Proyecto:** Detector determinista de anomalías en comunicaciones HL7/MLLP (Tesis G18 SIDRE)
**Versión ATT&CK de referencia:** ICS Matrix v20 (content v20.0)
**Fecha de verificación de técnicas:** 2026-10-13 (vía attack.mitre.org)
**Estado:** documento vivo — cualquier cambio de matriz obliga a reverificar (ver §7)

---

## 1. Alcance y activos

El banco de pruebas **no** compromete equipos clínicos reales. El "objetivo" es un pipeline
propio (emulador → receptor → detector) dentro de un laboratorio aislado, y las amenazas se
modelan como las que observó el incidente original: un **host comprometido dentro de la misma
red** que habla el protocolo estándar sin autenticación.

| ID | Activo | Propiedad protegida | En este laboratorio |
|----|--------|---------------------|---------------------|
| A1 | Dispositivo WATO EX-35 (fuente) | Integridad, disponibilidad | Solo modo externo con protocolo público; **nunca** se ataca ni se explota |
| A2 | Canal HL7/MLLP (TCP) | Integridad, autenticidad, disponibilidad | Puerto 1550 local/Docker; sin cifrado por diseño del protocolo |
| A3 | Receptor / gateway (sink) | Disponibilidad, corrección de ACK | Emulado (`mllp_receiver.py`); sin sistema real |
| A4 | Detector (reglas, baseline, settings) | Integridad de configuración | Archivos versionados; baseline con SHA-256 |
| A5 | Evidencia (PCAP, salidas, logs) | Trazabilidad, cadena de custodia | SHA-256 + copias RO en `evidence_raw/` |
| A6 | Datos clínicos de pacientes | Confidencialidad | Anonimización por defecto (SHA-256 truncado 8 hex) |
| A7 | Host del laboratorio (Raspberry Pi) | Aislamiento | Guardas `LAB_AUTHORIZED=YES` + `LAB_ONLY.marker`; solo localhost/Docker internal |

## 2. Fronteras de confianza

```
 [host comprometido]                ← adversario modelado (misma red, sin credenciales)
        │ F1: red de laboratorio
        ▼
 [WATO emulado] ──MLLP/TCP 1550──▶ [receptor/gateway]      ← F2: sin auth/cifrado (T0869)
        │                               │
        │        (mirror/pcap)          ▼
        └───────────────────────▶ [detector offline]        ← F3: no inline; análisis por ventana
                                       │
                                       ▼
                               [evidencia RO + alertas]     ← F4: escritura con hash, verificación post-lab
```

- **F1**: el adversario ya está dentro de la red (como en el incidente). No se modela escalada
  de privilegios ni acceso inicial externo.
- **F2**: no existe autenticación ni integridad criptográfica en HL7/MLLP — de ahí que
  *cualquier* mensaje bien formado es indistinguible de uno legítimo sin baseline.
- **F3**: el detector no está en línea del proceso; su valor es analítico (hipótesis ADR/latencia
  aún NO verificadas, ver §6).
- **F4**: la evidencia se escribe una vez y se sella con hash (SHA-256) para custodia.

## 3. Análisis STRIDE

| Categoría | Amenaza modelada | Escenarios del lab | Técnica ICS (v20) |
|-----------|------------------|--------------------|-------------------|
| **S**poofing | Identidad lógica falsificada en MSH-3/MSH-4 o IP de origen no autorizada | A01, A09, A16 | T1692.002 |
| **T**ampering | Contenido de mensaje alterado (OBX, timestamp, unidades) o framing malformado | A04–A08, A10, A11 | T1692.002 |
| **R**epudiation | Mensajes sin firma/autenticación → quien envió no es verificable | A02, A03 (replay) | T1692.002 |
| **I**nformation disclosure | Tráfico HL7 sin cifrado con datos identificables | (propiedad inherente) | N/A — mitigado con anonimización en evidencia |
| **D**enial of service | Ráfagas, reconexiones, silencio de canal, mensajes sobredimensionados | A12, A13, A14, A15 | T0814 |
| **E**levation of privilege | Escalada o persistencia en el dispositivo | — | **Fuera de alcance** (el lab no explota software; prohibido por el plan) |

## 4. Técnicas ATT&CK ICS verificadas (v20, 2026-10-13)

Verificadas directamente en attack.mitre.org el día de la fecha:

| ID | Nombre | Tácticas | Estado en v20 |
|----|--------|----------|---------------|
| T1692 | Unauthorized Message | Evasion, Impair Process Control | Nueva (creada 2026-04-20) |
| T1692.001 | Command Message | " | **Reemplaza a T0855** |
| T1692.002 | Reporting Message | " | Nueva — aplica a ORU/telemetría |
| T1693 | Modify Firmware | Persistence, Inhibit Response Function, Impair Process Control | Nueva |
| T1693.001 | System Firmware | " | Destino de la redirección de **T0857** |
| T0814 | Denial of Service | Inhibit Response Function | Vigente |
| T0831 | Manipulation of Control | Impact, Impair Process Control | Vigente (no usado: ver §5) |
| T0860 | Wireless Compromise | Initial Access | Vigente (no usado: ver §5) |
| T0869 | Standard Application Layer Protocol | Command and Control | Vigente (no usado: ver §5) |
| T0887 | Wireless Sniffing | Discovery, Collection | Vigente (no usado: ver §5) |

**Redirecciones confirmadas:** `T0855` → `/techniques/T1692/001` y `T0857` → `/techniques/T1693/001`.
El SRS/SPMP cita T0855 (heredado de ATT&CK v13/v14): se documenta la equivalencia
**T0855 ≡ T1692.001** para no perder trazabilidad con los documentos previos.

## 5. Criterio de mapeo y correcciones aplicadas

**Criterio:** el lab solo genera **mensajes de reporte (ORU)** y su efecto observable es en el
canal, no en el proceso físico. Por tanto:

- Mensajes no autorizados, malformados, con identidad falsa, replay o contenido falsificado →
  **T1692.002 (Reporting Message)**. La descripción de T1692 cubre explícitamente "evade
  defenses" y "make it appear as if everything is working correctly", y su estrategia de
  detección AN2044 (mensaje inválido desde fuente inesperada) / AN2045 (cambios inválidos de
  estado de sesión) coinciden con nuestras reglas de red y FSM.
- Sobrecarga de recursos (ráfaga, sobredimensión, reconexiones) → **T0814 (DoS)**.
- **T0831 no se reclama:** exige manipulación de control físico; el lab falsifica telemetría
  sin actuadores → queda NO_VERIFICADO.
- **T0860/T0887/T0869 no se reclaman:** corresponden a compromiso/sniffing inalámbrico y a C2
  sobre protocolo estándar — no describen lo que hace el emulador.
- **T1692.001 queda reservada** para mensajes de comando (CMD/ORU de actuación); el tráfico
  observado en evidencia es solo ORU^R01 → no se asigna.

**Discrepancias detectadas y corregidas en la configuración (2026-10-13):**

| Ubicación | Valor previo | Problema | Corrección |
|-----------|-------------|----------|------------|
| `settings.yaml` A01, A16; 4 reglas | T0855 | Redirige a T1692.001 (comandos); el lab genera reporting | T1692.002 |
| `settings.yaml` A09; R-HL7-002 | T0857 | Redirige a T1693.001 = Modify Firmware (sin relación) | T1692.002 |
| `settings.yaml` A02, A03; R-SEQ-001/002 | T0860 | Wireless Compromise = acceso inicial inalámbrico | T1692.002 |
| `settings.yaml` A04–A08; R-MLLP-001, R-HL7-001/003, R-TIME-001 | T0887 | Wireless Sniffing = descubrimiento/colección pasiva | T1692.002 |
| `settings.yaml` A10, A11; R-OBX-001/002/003 | T0831 | Manipulation of Control exige control físico (no hay) | T1692.002 |
| `settings.yaml` A13, A14; R-STATE-001 | T0869 | Nombre real = Standard Application Layer Protocol; justificación decía "Connection Proxy" (inexistente) | A13/A14 → T0814; R-STATE-001 → T1692.002 (AN2045) |
| `settings.yaml` A12, A15; R-TIME-002 | T0814 | Correcta | Se mantiene |

Justificaciones con nombres de técnica incorrectos ("Manipulate I/O Image", "Connection Proxy",
"Unauthorized Command Message") corregidas en `src/detection/rules.py` y `config/rules.yaml`.

## 6. Supuestos y limitaciones del modelo

- **Hipótesis, no garantías:** ADR ≥ 90 % y latencia ≤ 500 µs están **NO VERIFICADOS** hasta
  Fase 9 (validación); el modelo no los asume como ciertos.
- FSM de sesión inferida de **1 captura** (STANDBY); transiciones RUNNING/ALARM NO_VERIFICADO.
- Baseline STANDBY con 4 códigos OBX CWE; ~23 códigos NM/SN de RUNNING NO_VERIFICADOS →
  reglas OBX pueden generar falsos positivos en RUNNING (semitono documentado).
- Reloj WATO con offset documentado (+17 min 10 s): correlación temporal usa timestamp de red.
- El adversario modelado **no** tiene capacidad de modificar el detector ni la evidencia
  (F3/F4); ataques al propio host del lab quedan fuera de alcance.
- Sin reglas clínicas (umbrales de valores de laboratorio) hasta aprobación clínica explícita.

## 7. Historial de verificación

| Fecha | Versión | Hallazgo |
|-------|---------|----------|
| 2026-10-13 | v20 (content v20.0) | T0855→T1692.001 y T0857→T1693.001 confirmadas; T1692/T1693 nuevas; T0814/T0831/T0860/T0869/T0887 vigentes; mapeos de config corregidos |

## 8. Referencias

- https://attack.mitre.org/matrices/ics/v20/
- https://attack.mitre.org/techniques/T1692/ (T1692.001, T1692.002)
- https://attack.mitre.org/techniques/T1693/ (T1693.001, T1693.002)
- https://attack.mitre.org/techniques/T0814/ · /T0831/ · /T0860/ · /T0869/ · /T0887/
- https://attack.mitre.org/techniques/T0855/ y /T0857/ (páginas de redirección)
