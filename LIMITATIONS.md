# Limitaciones y Amenazas a la Validez

**Fecha:** 2026-10-13 · **Regla:** todo lo marcado NO VERIFICADO no se afirma en el texto de la
tesis como resultado; se declara como limitación. Complementa `THREAT_MODEL.md` §6.

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

- **ADR ≥ 90 % (H1) y latencia ≤ 500 µs (H2): NO VERIFICADOS** hasta Fase 9
  (`VALIDATION_PROTOCOL.md`).
- FP en RUNNING: sin cuantificar aún.

## 6. Mapeo MITRE ATT&CK

- Matriz **ICS v20 publicada 2026-10-13**, recién verificada; técnicas nuevas (T1692/T1693)
  pueden cambiar en versiones futuras → `THREAT_MODEL.md` §7 obliga a reverificar.
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
  revisión institucional (`ETHICS_AND_SAFETY.md` §7).
- Gate clínico: sin revisor clínico no hay reglas de umbrales clínicos → la tesis solo evalúa
  detección de anomalías de **comunicación**, no de contenido médico.

## 8. Reproducibilidad

- Windows (OneDrive) como entorno de desarrollo; ejecución en Raspberry Pi **pendiente** →
  métricas de rendimiento no transferibles hasta medir allí.
- La otra sesión de desarrollo modifica `src/mllp|hl7|detection` en paralelo: toda corrida de
  validación exige árbol limpio y commit congelado (VALIDATION §6).
