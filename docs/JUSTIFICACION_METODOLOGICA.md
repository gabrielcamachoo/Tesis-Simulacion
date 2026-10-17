# Justificación Metodológica (sección para el texto de la tesis)

**Proyecto:** G18 SIDRE — Sistema externo de detección de anomalías en comunicaciones
HL7/MLLP de una máquina de anestesia Mindray WATO EX-35 sobre Raspberry Pi.
**Fecha:** 2026-10-14 · **Estado:** redacción técnica para integrar en el capítulo de
metodología; lenguaje prudente, sin afirmaciones causales no demostradas.

---

## 1. Por qué el desconocimiento del sistema operativo no impide analizar las interfaces externas

El fabricante no ha suministrado la distribución embebida ni el firmware de la WATO EX-35.
Esa ausencia de información interna no invalida el análisis de las **interfaces de red
visibles** en el punto de conexión: en las capturas disponibles (WATO First Try 18-08-2026,
STANDBY 25-08-2026, RUNNING 27-08-2026) se observa un flujo TCP hacia el puerto 1550 que
transporta mensajes HL7 v2.6 encapsulados en MLLP (start-block 0x0B, end-block 0x1C 0x0D).
HL7 v2.x y MLLP son estándares publicados por HL7 International; un observador externo puede
caracterizar mensaje a mensaje (tipo, segmentos, identificadores, periodicidad, ACK) sin
conocer el sistema operativo emisor. La capa de análisis elegida es la de **protocolo**, no
la de plataforma.

## 2. Por qué se adopta un enfoque de caja negra

Sin documentación del fabricante, sin credenciales y sin acceso privilegiado, el único camino
metodológicamente válido es el black-box: tratar la WATO como una caja que emite y recibe
tráfico por una interfaz observable. Este enfoque es compatible con las guías de ciberseguridad
de dispositivos médicos de la FDA, que enfatizan la evaluación de interfaces externas y el
riesgo de red, y con NIST SP 800-82 (security of ICS), que recomienda monitorizar el tráfico
de protocolos como control compensatorio. No se realiza ingeniería inversa invasiva ni
explotación de vulnerabilidades (ver `docs/ETHICS_AND_SAFETY.md`).

## 3. Por qué la equivalencia se establece en HL7/MLLP y no en el sistema operativo

El gemelo experimental reproduce únicamente lo medido en las capturas: rol TCP cliente del
equipo emisor, puerto 1550, encapsulamiento MLLP, HL7 2.6, tipo ORU^R01^ORU_R01, secuencia
MSH–PID–PV1–OBR–OBX×4, codificación UTF-8 declarada en MSH-18, periodicidad de 10.000 s por
MSH-7 y ACK MSA|AA. Afirmar que el laboratorio replica el «sistema operativo del equipo»
(Ubuntu, Debian, u otro) sería una conjetura sin respaldo del fabricante; la equivalencia
declarada es **funcional y de protocolo**, y así queda en `docs/LAB_ARCHITECTURE.md` y
`docs/LIMITATIONS.md`.

## 4. Por qué no se debe crear ransomware real

El objetivo de la tesis es detectar **indicadores observables** del canal HL7/MLLP que
podrían aparecer después del compromiso de un equipo de la red clínica. Generar ransomware,
cifrar archivos, obtener persistencia o explotar el dispositivo añade riesgo sin añadir
evidencia científica: el experimento no mide capacidad de compromiso, mide detección de
comunicaciones anómalas. Además, cualquier artefacto ofensivo real estaría sujeto a
restricciones legales y éticas (Ley 1581/2012 en Colombia; política institucional) que este
proyecto no necesita invocar porque el alcance es un laboratorio aislado (`docs/ETHICS_AND_SAFETY.md`).

## 5. Cómo las cargas anómalas representan efectos observables de un compromiso

Se modela un escenario en el que un actor o malware ha comprometido un equipo conectado a la
red clínica. El experimento no reproduce el malware ni explota el dispositivo médico;
reproduce exclusivamente **indicadores y comportamientos observables en el canal HL7/MLLP**
que podrían presentarse después del compromiso: identidad lógica desconocida (A01/A16),
replay y duplicación (A02/A03), timestamps regresivos (A04), tramas malformadas (A05–A08),
tipos de mensaje no contemplados (A09), telemetría alterada (A10/A11), frecuencia anómala y
conexiones repetidas (A12/A13), silencio prolongado (A14), sobredimensión acotada (A15).
Cada escenario se mapea a una regla del detector y, cuando la correspondencia es defendible,
a una técnica de MITRE ATT&CK for ICS (v20), explicando qué parte del escenario se corresponde
y qué parte no fue reproducida (`docs/THREAT_MODEL.md` §4–§5, `docs/ATTACK_SCENARIOS.md`).

## 6. Cómo las capturas permiten construir la línea base

`analyze_evidence.py` recorre los PCAP en modo solo lectura, calcula SHA-256, reensambla el
flujo TCP, extrae los mensajes MLLP, los anonimiza de forma irreversible y produce
estadísticas descriptivas (tipos de mensaje, aplicaciones emisoras, secuencias de segmentos,
longitudes, intervalos, unidades OBX observadas). `baseline_builder.py` las consolida en
`baseline.yaml` con hash de la fuente, número de sesiones/mensajes y limitaciones explícitas
(baseline unimodal STANDBY; RUNNING no verificado). No hay modelo de machine learning: la
línea base es un conjunto de hechos medidos y trazables.

## 7. Cómo ackdummy permitió establecer la sesión, conservar bytes, extraer mensajes y responder ACK

`legacy/ackdummy (1).py` (preservado en `evidence_raw/codigo/ackdummy_original.py`) es el prototipo
del receptor: escucha TCP/MLLP, guarda todos los bytes recibidos en `raw_<ip>_<puerto>.bin`,
delimita SB/EOM, extrae el contenido HL7, lo decodifica, identifica MSH y segmentos, registra
`mensajes.hl7` y `sesion.log`, y responde ACK MSA|AA con el mismo Message Control ID. De él
derivan `mllp_receiver.py` y los paquetes `src/mllp`, `src/hl7`, `src/evidence`,
`src/detection` y `src/alerting`, con límites de tamaño, rotación de evidencia, hashes y
pruebas unitarias.

## 8. Por qué ackdummy no es completamente pasivo cuando responde

Una captura SPAN/TAP es observación pasiva: no modifica ni responde. ackdummy (y el receptor
derivado) **participan activamente** en la sesión porque emiten ACK hacia el emisor; eso
puede mantener abierta la conexión y alterar el comportamiento del equipo respecto a una
mera copia del tráfico. Por ello el corpus de replay (H3) usa `--no-ack`, y la Modalidad B
(`detect_pcap.py`) procesa el PCAP sin abrir ninguna conexión. La distinción
captura-pasiva / servidor-activo queda explícita en `docs/EVIDENCE_ANALYSIS.md`.

## 9. Cómo la Raspberry Pi actúa como control compensatorio externo

La Pi no sustituye controles del equipo médico ni intercepta su flujo clínico (no inline,
no fail-open). Se despliega como **control compensatorio externo** en la red: recibe o lee
copia del tráfico HL7/MLLP y genera alertas con evidencia forense. Este patrón es coherente
con NIST SP 800-82 (monitoreo de protocolos ICS) y con las recomendaciones de defensa en
profundidad para entornos clínicos (CISA, guías de ciberseguridad de la FDA para dispositivos
médicos). El dispositivo clínico no se modifica.

## 10. Cómo se asegura la reproducibilidad

- Semilla PRNG por corrida registrada en `runs/<ts>/seed.txt` y `scenario_order.txt`.
- `manifest.json` por corrida con commit de Git, hashes de entradas/salidas, configuración,
  plataforma y advertencia LAB ONLY (protocolo §6).
- Baseline y reglas versionadas con hash; enmiendas documentadas (Enmienda E1).
- Docker Compose con red `internal: true` para aislar y repetir el entorno.
- Suite pytest (unitaria + integración) y orquestador `run_experiment.py`/`run_matrix.py`.

## 11. Qué evidencia permite afirmar que el detector funciona

Respecto a los escenarios incluidos en el conjunto experimental (y solo a ellos):
campaña H1 con 60 corridas (30 docker + 30 A14 local) con ADR 100% (2010/2010 TP, IC de
Wilson global [99.8, 100]), precisión 99.7% y 7 FP benignos por jitter de red en R-TIME-002;
replay H3 post-Enmienda E1 con FP=0 sobre el corpus STANDBY (×5) y 256 FP reportados sin
umbral sobre RUNNING (códigos NM/SN no verificados, anticipados); bench H2 con p95=177.52 µs
en PC. Números sellados en `docs/RESULTS_20261014.md` con manifiestos y SHA-256.

## 12. Qué no puede conclusse a partir del experimento

- Que un ransomware pueda controlar físicamente la WATO EX-35.
- Que el detector funcione contra anomalías no incluidas en A01–A16 o contra variaciones
  clínicas reales (parámetros fisiológicos NO_VERIFICADOS).
- Que la latencia H2 se cumpla en Raspberry Pi hasta ejecutar el bench en esa hardware.
- Que el baseline unimodal STANDBY sea suficiente en producción (se requiere validación
  clínica y possibly baseline multimodal con RUNNING/ALARM).
- Que el comportamiento observado refleje vulnerabilidades internas del equipo.

## 13. Qué riesgos residuales permanecen

- Jitter de red puede producir FP en R-TIME-002 (medido: 7 en 675 TN benignos).
- Codigos OBX numéricos (NM/SN) del modo RUNNING no validados clínicamente → FP conocidos.
- A14 modela hueco de periodicidad, no ACK ausente (desviación documentada).
- Equivalencia limitada a una captura STANDBY para la línea base.
- Revisión ética (Ley 1581/2012) y gate clínico: trámite institucional pendiente del autor.
- Sin inline ni bloqueo, el detector es solo detective/preventivo externo, no un control de
  prevención en el dispositivo.

---

## Referencias citables (verificables)

- HL7 International — *HL7 Version 2 Product Brief* y capítulo de transportes MLLP
  (https://hl7.org). Estándar HL7 v2.x observado en las capturas (versión 2.6).
- NIST — *SP 800-82 Rev. 3, Guide to Operational Technology Security*
  (https://csrc.nist.gov/pubs/sp/800/82/r3/final).
- MITRE — *ATT&CK for ICS* (https://attack.mitre.org/techniques/ics/), v20; mapeo
  verificado en `docs/THREAT_MODEL.md` (T1692.002, T0814; T0855 redirigido).
- FDA — *Content of Premarket Submissions for Management of Cybersecurity in Medical
  Devices* (guía de ciberseguridad de dispositivos médicos).
- CISA — material de ICS y ciberseguridad hospitalaria
  (https://www.cisa.gov/topics/critical-infrastructure-security-and-resilience).
- IEC 62443 (series) — seguridad de sistemas de automatización y control industrial
  (referencia normativa; no certificación del laboratorio).
- Mindray — documentación pública del producto WATO EX-35 (manual de operación del
  fabricante; no incluye distribución embebida).
- Literatura revisada por pares sobre forense ICS y detección de ataques replay:
  ver `documentos_tesis/BibTeXReferencias.bib` del repositorio.

*Nota de método:* las citas anteriores se dan como referencias de contexto verificables por
el lector; los números experimentales citados provienen exclusivamente de la evidencia del
propio repositorio (`docs/RESULTS_20261014.md`, manifiestos de `analysis_output/validation/`).
