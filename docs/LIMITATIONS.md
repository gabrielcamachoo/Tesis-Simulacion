# Limitaciones y Amenazas a la Validez

**Fecha:** 2026-10-13 · **Regla:** todo lo marcado NO VERIFICADO no se afirma en el texto de la
tesis como resultado; se declara como limitación. Complementa `docs/THREAT_MODEL.md` §6.

## 1. Evidencia disponible

- **2 de 5 capturas contienen HL7** (43 y 99 ORU+ACK); las otras 3 son tráfico no HL7
  (ARP/otro). Las cifras del baseline provienen de **una sola sesión STANDBY** (25-ago) y una
  RUNNING (27-ago) — muestra pequeña.
- La **FSM de sesión** (SIN_GATEWAY→HANDSHAKE→ESTABLECIDA) está inferida de 1 captura;
  transiciones de RUNNING/ALARM: NO_VERIFICADO.
- Resolución temporal de captura limita la medición de latencias ACK (µs de pcapng, no del
  dispositivo).

## 2. Fidelidad del laboratorio

- **No hay WATO real en el loop:** el emulador reproduce estructura y periodicidad observadas,
  pero no su pila de red, ni su reloj (offset documentado +17 min 10 s), ni su comportamiento
  de error → validez externa parcial.
- ACK del receptor basado en `ackdummy`: valida correlación MSA-2↔MSH-10, no la semántica
  clínica del WATO.
- Docker Desktop 29.8.2 + WSL2 en el host: topología `docker-compose` validada E2E
  (2026-10-14). Dos particularidades del entorno: (a) con redes `internal: true` el
  publish de puertos no se materializa en Docker Desktop (la salud del receptor se
  consulta desde el contenedor, no desde el host); (b) escribir evidencia sobre el
  bind del repo (OneDrive) desde un contenedor estancó el I/O (archivos de 0 bytes,
  2026-10-13) → la evidencia vive en el named volume `lab_output` y se copia al host.

## 3. Baseline y falsos positivos

- Baseline STANDBY: 4 códigos OBX tipo CWE; RUNNING contiene ~23 códigos NM/SN
  **NO_VERIFICADOS** → las reglas OBX pueden alertar sobre tráfico legítimo en RUNNING
  (semitono esperado, cuantificable en Fase 9).
- MSH-4 frecuentemente vacío en WATO → R-ID-002 con baja discriminación.
- Límites `p95*1.5` de frecuencia calibrados sobre intervalos de ~10 s de STANDBY.

## 4. Alcance del detector

- **Offline/no inline:** el detector no bloquea ni mitiga; su rol es analítico (detección y
  evidencia), no prevención.
- Detección por **baseline y reglas estructurales**, no criptográfica: HL7/MLLP no autentica
  remitentes; un atacante que respeta la baseline evadirá las reglas actuales (limitación
  inherente al protocolo, no al implementador).
- Sin capacidad de atribución de atacante (solo de origen de sesión).

## 5. Hipótesis pendientes

- **H1 (ADR ≥ 90 %): VERIFICADA** en Fase 9 (2026-10-14): 16/16 escenarios, ADR 100 %,
  60 corridas selladas (`docs/RESULTS_20261014.md` §2). Queda pendiente solo el reporte a
  texto de tesis.
- **H2 (latencia ≤ 500 µs): NO VERIFICADO para la Raspberry Pi** — PASS de referencia
  en PC (p95 177.5 µs agregado, peor caso sintético). Repetir el bench en la Pi antes
  de afirmar H2 (`docs/RESULTS_20261014.md` §3, `docs/RASPBERRY_PI_SETUP.md`).
- FP en RUNNING: **cuantificado** (256 alertas no-NORMAL sobre 99 ORU de evidencia
  real, ~2.6/mensaje; reglas R-OBX-001/002/003 sobre códigos fuera de baseline
  STANDBY). STANDBY: FP = 0 (5 replays independientes).

## 6. Mapeo MITRE ATT&CK

- Matriz **ICS v20 publicada 2026-10-13**, recién verificada; técnicas nuevas (T1692/T1693)
  pueden cambiar en versiones futuras → `docs/THREAT_MODEL.md` §7 obliga a reverificar.
- El SRS/SPMP citan **T0855** (heredado de versiones previas): hoy redirige a T1692.001;
  la equivalencia queda documentada, pero los documentos fuente no la actualizan.
- **No existe técnica ICS dedicada a malformación de framing/mensajes:** se usa T1692 como
  categoría paraguas con justificación explícita (posible objector: sobre-asignación).
- T0831 (Manipulation of Control) queda **sin reclamar** a propósito: exige efecto sobre
  control físico, cosa que el lab no produce.

## 7. Ética, privacidad y gobernanza

- Anonimización con token SHA-256 truncado a **8 hex**: colisión teórica no excluida (2^32) y
  re-identificación interna posible por diseño (necesaria para auditoría); fuera del lab, los
  PCAP crudos son sensibles.
- Marco de protección de datos (Ley 1581/2012 y Decreto 1377/2013): **NO VERIFICADO** por
  revisión institucional (`docs/ETHICS_AND_SAFETY.md` §7).
- Gate clínico: sin revisor clínico no hay reglas de umbrales clínicos → la tesis solo evalúa
  detección de anomalías de **comunicación**, no de contenido médico.

## 8. Reproducibilidad

- Windows (OneDrive) como entorno de desarrollo; ejecución en Raspberry Pi **pendiente** →
  métricas de rendimiento no transferibles hasta medir allí.
- La otra sesión de desarrollo modifica `src/mllp|hl7|detection` en paralelo: toda corrida de
  validación exige árbol limpio y commit congelado (VALIDATION §6).


## 9. Hallazgos de Fase 9 (2026-10-14)

- **FP benigno por jitter de timing (R-TIME-002)**: bajo carga concurrente del
  emulador+generador, intervalos benignos nominales de 6.0 s bajan esporadicamente a
  ~4.94 s (< umbral pre-fijado 5.0 s) → 7 FP / 2017 mensajes benignos (0.3 %) en la
  campaña H1. El umbral NO se ajustó tras medir (protocolo §6); se documenta como
  fuente de ruido esperable en el despliegue real.
- **Enmienda E1 (commit 70025c4)**: el corpus STANDBY real trae OBX-6 =
  `262656^MDC_DIM_DIMLESS^MDC` en los 4 OBX CWE (43/43 mensajes); la premisa
  "STANDBY CWE sin unidades" del baseline inicial era falsa y producía 43 FP
  (R-OBX-002) en replay. Corregido y congelado antes de la campaña.
- **Conteo NORMAL vs anomalía**: `alerts.jsonl` contiene un evento NORMAL (INFO)
  por mensaje benigno; solo los eventos `rule_id != NORMAL` son alertas. El fix
  (commit 2017af1) alinea el replay con `evaluate.py`.
- Coordinación multi-sesión: la campaña piloto pre-E1 quedó contaminada por el
  bind-mount vivo de `./` en docker (código cambiando a mitad de corrida); la
  campaña oficial corrió sobre commit congelado y con ambas fases exit=0.
