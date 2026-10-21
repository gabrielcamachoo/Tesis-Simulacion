# Plan de Gestión de Proyecto de Software (SPMP)

**Proyecto:** G18 — Nodo de monitoreo de seguridad de red para equipos médicos
(Caso de estudio: monitor anestésico Mindray WATO EX-35)
**Documento:** SPMP_Resultados.md — plan basado en IEEE 1058 [9], alineado con la
estructura de `documentos_tesis/SPMP_Tesis (1).pdf` y la plantilla IngESoft
(cita ISO/IEC/IEEE 16326). Describe lo **realmente ejecutado** (git + bitácora).
**Versión:** 1.0 · **Fecha:** 2026-10-17 · **Commit de referencia:** `72515e6`
**Insumo factual:** `docs/AUDITORIA_REPO.md` · `docs/SRS_Resultados.md`

| Versión | Fecha | Cambio |
|---|---|---|
| 1.0 | 2026-10-17 | Versión inicial (planeado vs. real según bitácora y git) |
| 1.1 | 2026-10-19 | Alineación con las 3 capturas reales (18-08 ARP, 25-08 STANDBY, 27-08 RUNNING 6 modos), baseline bimodal (33 OBX, 9 unidades MDC), emulador WATO multimodo y validación 0 FP en STANDBY y RUNNING |
| 1.2 | 2026-10-20 | Integración PR #1 (`Pruebas-santi`) con Enmiendas E2–E8, cierre de decisiones de diseño y suite consolidada en **246 pruebas** (`0 xfailed`) |

---

## 1. Visión general

### 1.1 Propósito del plan

Establecer la organización, procesos, plan de trabajo, riesgos y control de
calidad del proyecto G18, cubriendo tanto lo planeado (bitácora C1–C29,
6 ago – 6 nov 2026) como lo realmente ejecutado y verificable en el repositorio
(29 commits, 2026-10-13 → 2026-10-17).

### 1.2 Alcance y objetivos

**Alcance:** laboratorio de software (detector HL7/MLLP, emulador, generador de
anomalías, evaluación y validación estadística) para el WATO EX-35 [7], en red
aislada; **sin** equipo clínico real, sin malware y sin despliegue BIW embebido
(queda como trabajo futuro sujeto a gate clínico).

**Objetivos medibles (hipótesis de la tesis):**

| # | Objetivo | Meta | Resultado al cierre (medido) |
|---|---|---|---|
| H1 | Efectividad de detección (ADR) | ≥ 90 % | **100 %** (2010/2010 TP en campaña de 60 corridas + corrida `runs/20261019_220221` 64/64 TP, FP=0, F1=1.0) |
| H2 | Latencia p95 procesamiento | ≤ 500 µs | **PASS en PC** (177.5 µs); **NO_VERIFICADO en Pi física** |
| H3 | FP sobre corpus benigno real | = 0 | **FP = 0** en STANDBY (`LECTURACONACK25AGOSTO.pcapng`, 43/43 NORMAL) **y** en RUNNING (`LECTURAACK27AGOSTO.pcapng`, 99/99 NORMAL) |

### 1.3 Entregables principales

| ID | Entregable | Estado | Ubicación |
|---|---|---|---|
| D1 | Evidencia capturada + baseline trazable | Completo | `evidence_raw/`, `baseline.yaml` |
| D2 | Software del laboratorio (receptor, emulador, generador, evaluador, tooling) | Completo | `src/`, raíz `*.py` (ver SRS) |
| D3 | Documentación de ingeniería (threat model, ética, arquitectura, escenarios A01–A16, protocolo, límites) | Completo | `docs/` (17 documentos) |
| D4 | Validación experimental H1/H2/H3 con evidencia sellada | Completo (H2-Pi pendiente) | `analysis_output/validation/` |
| D5 | Despliegues (Windows por componente, Pi, Docker) | Completo (ejecución en Pi física pendiente) | `deploy/` |
| D6 | Manual de uso + resultados para defensa | Completo | `MANUAL_TESIS.md`, `docs/RESULTADOS_TESIS.md` |
| D7 | SRS y SPMP de resultados (estos documentos) | Completo | `docs/SRS_Resultados.md`, `docs/SPMP_Resultados.md` |
| D8 | Memoria de tesis (capítulos según Formato TG) | En curso | Redacción por el equipo (fuera del repo) |

### 1.4 Evolución del plan

| Evento | Impacto en el plan |
|---|---|
| Enmienda E1 (2026-10-14) | Se retiró la cláusula "CWE con unidad inválido" tras 43/43 FP en replay STANDBY; regla R-OBX-002 redefinida |
| Desviación A14 | Escenario de silencio 45 s×3 (~135 s) se excluye en corridas rápidas (`--exclude A14`); documentado |
| Disponibilidad de hardware | La Pi física y el sandbox HUSI no estuvieron disponibles: topología Pi simulada en Docker; WATO real reemplazado por emulador + evidencia |
| Reorganización 2026-10-17 | `deploy/` por componente, `docs/`, `documentos_tesis/`; commits particionados (4) y push a GitHub |
| Baseline bimodal v1.1 + Enmiendas E2–E8 (2026-10-20) | 0 FP en `STANDBY` (43 ORU) y `RUNNING` (99 ORU, 6 modos); vigilante de silencio E3, coherencia FSM E2, evaluación por conexión E6, zona horaria E8; 246 pruebas en verde |

## 2. Referencias y definiciones

Enlaces verificados HTTP 200 (2026-10-17):

[1] MITRE ATT&CK for ICS T1692 *Unauthorized Message* — https://attack.mitre.org/techniques/T1692/
[2] MITRE ATT&CK for ICS T0814 *Denial of Service* — https://attack.mitre.org/techniques/T0814/
[3] IHE Technical Frameworks (Devices/PCD) — https://www.ihe.net/Technical_Frameworks/
[4] RFC 5424 Syslog — https://www.rfc-editor.org/rfc/rfc5424
[5] ISO/IEC/IEEE 29148:2018 — https://www.iso.org/standard/72089.html
[6] HL7 International — https://www.hl7.org
[7] Mindray WATO EX-35 — https://www.mindray.com/en/products/anesthesia/wato-ex-35

Bibliográficas (sin enlace público verificable): [8] IEEE 830-1998;
[9] IEEE 1058-2002; [10] ISO/IEC/IEEE 16326:2009 (citada por la plantilla PUJ);
[11] HL7 v2.6 (estándar de miembros).

**Definiciones clave:** ADR (Attack Detection Rate); BIW (Bump-in-the-Wire);
FCP (Falsos positivos); interlock (barrera fail-closed de laboratorio); sellado
(artefactos con SHA-256 + manifest + commit); ground truth (verdad de terreno de
las inyecciones).

## 3. Organización del proyecto

### 3.1 Roles del equipo (según `SPMP_Tesis (1).pdf` §2.3)

| Integrante | Rol principal | Responsabilidades ejecutadas (evidencia repo) |
|---|---|---|
| Gabriel Alejandro Camacho Rivera | Ingeniería de hardware y forense digital | Arquitectura del laboratorio, orquestador (`run_experiment.py`), despliegues (Docker/Pi/Windows), evidencia y manifests, validación end-to-end |
| David Santiago Piñeros Rodríguez | Analista de ciberseguridad (ICS) | Reglas deterministas (FSM/15 reglas), modelado MITRE ATT&CK ICS v20 [1][2], escenarios A01–A16, evaluación |
| Santiago Ávila Barbudo | Analista de protocolos IoMT | Baseline document, perfiles HL7/MLLP observados, análisis de latencias de la evidencia |
| Ing. Jhon Alberto Talero Patiarroyo | Director de tesis | Revisión, aprobación de alcance y gate clínico/ético |

Entidad colaboradora: sandbox del Centro de Simulación del Hospital Universitario
San Ignacio (HUSI) — **no utilizado en esta etapa** (equipo no disponible;
mitigado con emulador, ver riesgo R1).

### 3.2 Interfaces externas

- **HUSI (sandbox):** captura de evidencia previa al repositorio; sin acceso
  durante el sprint de software.
- **Fabricante Mindray:** producto WATO EX-35 [7]; sin canal directo de
  especificación (códigos MNDRY propietarios, riesgo R2).
- **Normativas de referencia:** IHE PCD-01 [3], MITRE ATT&CK ICS v20 [1][2],
  HL7 v2.x [6][11], RFC 5424 [4].
- **Repositorio:** `https://github.com/gabrielcamachoo/Tesis-Simulacion.git`
  (rama `main`).

## 4. Procesos de gestión

### 4.1 Objetivos de gestión

Entregar el laboratorio validado con evidencia reproducible dentro del periodo
de la bitácora (13 semanas), manteniendo semáforo de desviación (verde ≥ −5 %,
amarillo −5/−10 %, rojo > −10 % con reunión obligatoria con director).

### 4.2 Supuestos

1. Evidencia STANDBY capturada (43 ORU + 43 ACK) es representativa del tráfico
   baseline del WATO.
2. El emulador reproduce la periodicidad/perfil suficientes para pruebas E2E.
3. El equipo cuenta con PC Windows + Docker; Python 3.11+ disponible.

### 4.3 Dependencias

- PyYAML, pytest (psutil opcional); Docker Desktop + WSL2 para modo docker.
- Disponibilidad futura de Raspberry Pi física (para H2-Pi y despliegue real).
- Aprobación clínica para cualquier regla clínica (gate actual: PENDING).

### 4.4 Restricciones

- Presupuesto hardware del plan original: ≈ $810 000 COP (RPi4/Jetson, ESP32×2,
  tap) — **no ejecutado** en esta etapa.
- Sin Internet en runtime (red Docker `internal: true`); sin IP pública.
- Ventana de entrega: 6 ago – 6 nov 2026 (bitácora C1–C29).

### 4.5 Monitoreo y control

| Mecanismo | Frecuencia | Artefacto |
|---|---|---|
| Checkpoints (estilo bitácora) | Cada 3 días | `docs/HANDOFF.md` (sesiones de desarrollo) |
| Corte semanal / semáforo | Domingos | Bitácora TG (C1–C29) |
| Suite de pruebas | Cada sesión de cambio | `deploy/validacion/suite.ps1` → 246 passed |
| Métricas de producto | Por campaña | `evaluation.json`, `validation_summary.json` |
| Integridad de configuración | Por commit | `git log`, `manifest.json` (commit+SHA-256) |

## 5. Procesos técnicos

### 5.1 Modelo de ciclo de vida y metodología

Metodología **híbrida** (heredada del SPMP de tesis): base IEEE 1074 +
**iterativa-incremental** por fases (0–9) + verificación en **V** para el
sub-sistema de detección (evidencia → baseline → reglas → inyecciones → métricas).
El avance por fase quedó registrado en commits (`git log --oneline`).

### 5.2 Herramientas

| Área | Herramienta |
|---|---|
| Lenguaje/runtime | Python 3.11.9 (venv); contenedores `python:3.11-slim` |
| Dependencias | PyYAML≥6.0, pytest≥8.0, psutil≥5.9 (opcional) |
| Pruebas | pytest (246 pruebas) |
| Orquestación | scripts bash/PowerShell (`deploy/`), systemd en Pi |
| Topología aislada | Docker Compose (red `wato-lab` internal 172.30.0.0/24) |
| Control de versiones | Git + GitHub (`main`) |
| Evidencia | SHA-256 nativo, `SHA256SUMS.txt`, manifests por corrida |

### 5.3 Documentación

Documentos vivos en `docs/` (17): threat model, ética, arquitectura, escenarios,
protocolo de validación, límites, análisis de evidencia, resultados Fase 9,
manual de uso, resultados de defensa, SRS/SPMP de resultados, auditoría,
matriz de trazabilidad (`TRACEABILITY_MATRIX.csv`), guía de uso, guía Pi,
simulación ransomware, justificación metodológica, handoff.

### 5.4 Criterios de aceptación

1. H1: ADR ≥ 90 % con n ≥ 30 corridas/escenario e IC95 de Wilson.
2. H2: p95 ≤ 500 µs en bench (≥ 1000 msgs × ≥ 3 corridas).
3. H3: FP = 0 sobre replay STANDBY (≥ 5 reproducciones).
4. Suite completa en verde (≥ 200 pruebas).
5. Evidencia sellada (SHA-256 + manifest + commit) de toda campaña reportada.
6. Interlocks verificables (arranque falla sin autorización).

**Cumplimiento al cierre:** 1 ✓, 2 ✓(PC)/△(Pi), 3 ✓, 4 ✓, 5 ✓, 6 ✓.

## 6. Plan de trabajo

### 6.1 Descomposición de actividades (WBS)

| WBS | Actividad | Fase bitácora | Entregable |
|---|---|---|---|
| 1.0 | Levantamiento y requisitos | Sem 1–2 | SRS v1.0 (15 %) |
| 1.1 | Análisis de evidencia (PCAP, informes) | Sem 1–2 | D1 baseline |
| 2.0 | Diseño (arquitectura, escenarios, protocolo) | Sem 3–4 | SDD/docs (30 %) |
| 3.0 | Desarrollo core (framing, parser, motor, receptor) | Sem 5–8 | D2 (60 %) |
| 3.1 | Emulador y generador de anomalías A01–A16 | Sem 6–8 | D2 |
| 4.0 | Pruebas e integración (unitarias + E2E + validación H1/H2/H3) | Sem 9–10 | D4 (78 %) |
| 5.0 | Despliegues (Docker/Pi/Windows) y documentación final | Sem 11–12 | D5, D6, SPMP (95 %) |
| 6.0 | Buffer, memoria y entrega | Sem 13 | D8 (100 %) |

### 6.2 Cronograma de 12 semanas (6 ago – 28 oct 2026)

| Sem | Fecha | Actividad principal | Hito |
|---|---|---|---|
| 1 | 6–12 ago | Requisitos: actores, RF/RNF, casos de uso | C1–C2 (4–8 %) |
| 2 | 13–19 ago | SRS v1.0 cerrado | **C4: SRS v1.0 (15 %)** |
| 3 | 20–26 ago | Arquitectura, threat model, diseño de escenarios | C5–C7 |
| 4 | 27 ago–2 sep | SDD v1.0; baseline document | **C8: SDD (30 %)** |
| 5 | 3–9 sep | MLLP framing + parser HL7 + servidor | Núcleo receptor |
| 6 | 10–16 sep | Motor de detección + 15 reglas + alerting | Motor completo |
| 7 | 17–23 sep | Emulador WATO + generador A01–A16 + safety guards | Laboratorio E2E |
| 8 | 24–30 sep | Evaluador + orquestador + Docker | **C17: feature complete (60 %)** |
| 9 | 1–7 oct | Unitarias + integración + fix pérdida de mensajes | 200+ tests |
| 10 | 8–14 oct | Validación H1/H2/H3 (60 corridas, bench, replay) + Enmienda E1 | **C23: validado (78 %)** |
| 11 | 15–21 oct | Despliegues, campañas Pi/ ransomware, manual, SRS/SPMP resultados | Entregables D5–D7 |
| 12 | 22–28 oct | Memoria, revisión con director, push GitHub, cierre | **C27: 95 %** |

*(Semana 13 adicional de la bitácora: 29 oct – 6 nov, buffer y entrega final C29.)*

### 6.3 Semana de desarrollo según git (13–17 oct 2026): lo hecho vs. lo pendiente

El repositorio fue inicializado el 2026-10-13 (`4d245c8`) y consolidado en un
bloque intensivo de 5 días (29 commits). Equivalencia con las fases del plan:

| Área | Lo hecho (evidencia: commits) | Lo pendiente |
|---|---|---|
| Fase 0–1: toolchain, evidencia, baseline | ✅ `4d245c8`, `71ada56`, `1128178` (anonimización, baseline con hashes, 104→204 tests) | — |
| Fase 3: documentación de ingeniería | ✅ `54e9a56`…`8fca852` (threat model, ética, arquitectura, escenarios, protocolo, trazabilidad) | Actualizar con resultados finales de defensa |
| Fase 2/4: emulador, generador, evaluador, docker | ✅ `ab6735b`, `1d2107a`, `19fbdf3` (E2E local 67/67 y docker 64/64) | — |
| Fase 6: guía Raspberry Pi | ✅ `19fbdf3` (`RASPBERRY_PI_SETUP.md`) + `deploy/pi/` completo | Ejecutar en Pi física |
| Fase 9: validación H1/H2/H3 | ✅ `025693e`…`13bd3b5` (ADR 100 %, bench PC, replay STANDBY, sellado SHA-256) | H2 en Pi física; corpus RUNNING verificado |
| Entrega: despliegues, manual, reorganización, evidencia 2026-10-17 | ✅ `747976b`, `ed3d95e`, `a125c74`, `72515e6` (commits por partes + push) | Memoria de tesis; defensa |
| Hardware/BIW | ❌ No ejecutado (sin Pi/Jetson/tap) | Nodo embebido BIW completo |
| Gate clínico | ❌ `clinical_approval_status: PENDING` | Aprobación para reglas clínicas |

## 7. Gestión de riesgos

| ID | Riesgo | Prob. | Impacto | Mitigación (ejecutada/planificada) |
|---|---|---|---|---|
| R1 | Sin acceso al equipo médico ni sandbox HUSI durante el desarrollo | Alta | Alto | Evidencia capturada previa (43 ORU+ACK) + emulador WATO; replays sobre PCAP; declarar NO_VERIFICADO lo que exige hardware |
| R2 | Falta de especificación pública HL7 de Mindray (códigos `30002/30005/30007` propietarios; versión declarada v2.3.1 no verificable) | Alta | Medio | Baseline derivada solo de evidencia propia con hashes; códigos marcados OBSERVADO en `baseline.yaml`; Apéndice A del SRS |
| R3 | Exposición de datos sensibles de paciente (PID/PV1/NTE) en capturas/derivados | Media | Alto | Anonimización irreversible **por defecto** en pipeline y alertas; `evidence_raw/` solo lectura con `evidence_inventory.csv` SHA-256; sin datos reales en este documento |
| R4 | Seguridad del entorno de pruebas (inyecciones, "ransomware simulado") | Media | Alto | Interlocks fail-closed (LAB_AUTHORIZED + marker), allowlists de host/IP, red Docker `internal: true` sin egress, sin malware real, techos por corrida (≤70 anomalías) |
| R5 | Raspberry Pi física no disponible → H2 no verificable in situ | Alta | Medio | Simulación Docker de la topología; scripts Pi listos (`deploy/pi/`); bench H2 en PC con declaración explícita NO_VERIFICADO |
| R6 | Falsos positivos por jitter de timing (R-TIME-002, ~0.3 %) | Media | Bajo | Sin tuning post-hoc (integridad estadística); documentado en RESULTS/LIMITATIONS |
| R7 | FP masivos por premisa falsa de unidades OBX (Enmienda E1) | Ocurrido | Alto | Enmienda E1 (2026-10-14): CWE+DIMLESS aceptado; replays posteriores FP=0 |
| R8 | Baseline unimodal STANDBY ⇒ alertas en RUNNING | Alta | Medio | Reglas R-OBX-* reportan "fuera de baseline" sin afirmar ataque; limitación declarada en LIMITATIONS.md |
| R9 | Reloj del WATO desfasado (+17 min 10 s observado) | Media | Bajo | Documentado; correlación con timestamp de red en evaluación |
| R10 | Desviación de cronograma (>10 %) | Baja | Alto | Semáforo bitácora; el bloque 13–17 oct cerró fases 0–9 en 5 días (desviación negativa = ahorro) |
| R11 | Percepción de "ransomware" como malware real | Media | Alto | Naming explícito "simulación compuesta"; `docs/ETHICS_AND_SAFETY.md`; sin código malicioso en repo |

## 8. Aseguramiento de calidad y gestión de configuración

### 8.1 Aseguramiento de calidad

- **Pruebas unitarias/integración:** 246 pruebas pytest (17 archivos + conftest),
  ejecutadas antes y después de cada bloque de cambios (`deploy/validacion/suite.ps1`).
- **Pruebas de sistema:** corridas E2E `run_experiment.py` (local y docker) con
  evaluación automática; 60 corridas de campaña (H1).
- **Revisión por pares:** commits en `main` con mensajes normalizados; HANDOFF
  como bitácora técnica de sesiones.
- **Criterios de aceptación:** §5.4 (todos cumplidos salvo H2-Pi).
- **Honestidad de medición:** taxonomía OBSERVADO/MEDIDO/NO_VERIFICADO en toda
  la documentación de resultados.

### 8.2 Gestión de configuración

| Control | Implementación |
|---|---|
| Repositorio | Git `main`; identidad del proyecto `Tesis G18 SIDRE`; remoto GitHub |
| Commits | Particionados por tema (docs / deploy / entrega / evidencia); mensajes en español |
| Versionado de configuración | `settings.yaml`, `baseline.yaml`, `rules.yaml` en repo; hashes de baseline hacia `evidence_raw/` |
| Reproducibilidad de corridas | `seed.txt` + semillas por fase (+1000003/+2000003) + `manifest.json` (commit, SHA-256 entradas/salidas) |
| Evidencia sellada | `analysis_output/validation/` + `SHA256SUMS.txt` (314 archivos en Fase 9) |
| Inmutabilidad de evidencia cruda | `evidence_raw/` solo lectura; verificación SHA-256 9/9 (2026-10-17) |
| Integración continua | Local: `suite.ps1` (pytest) en cada sesión; sin pipeline remoto (fuera de alcance) |
| `.gitattributes` | `*.sh`/`*.service` con `eol=lf` (requisito Linux/Pi) |

---

*Documento generado como entregable D7. Elaborado sobre la auditoría
`docs/AUDITORIA_REPO.md` y alineado con `documentos_tesis/SPMP_Tesis (1).pdf`,
`documentos_tesis/Bitacora TG.docx` y `documentos_tesis/SPMP-Plantilla.pdf`.*
