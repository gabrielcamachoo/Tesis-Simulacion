# Guion de Sustentación (15 min), Respuestas a Preguntas Duras, Demo de 2 min y Correo `CC-01` — Proyecto 2026-03-G18

Este documento complementa la Memoria **Edición Final (Noviembre de 2026)**, el [Concepto de Jurado y Director](./CONCEPTO_JURADO_Y_DIRECTOR_v5.7.md) y la [Especificación Ciega de 1 Página para Tercero](./ESPECIFICACION_TERCERO_REDTEAM.md) para la sustentación ante los jurados **Juddy Morales** e **Ivonne Valencia**.

---

## 1. Borrador listo para enviar — Aprobación formal de `CC-01` (Director)

> **Para:** Ing. Jhon Alberto Talero Patiarroyo (Director de Trabajo de Grado)  
> **CC:** Dra. Jennifer Cárdenas Mancera (Codirectora); Gabriel Camacho; David Piñeros; Santiago Ávila  
> **Asunto:** Solicitud de visto bueno formal — Solicitud de Cambio CC-01 (Proyecto de Grado 2026-03-G18)

Estimado Ing. Jhon Talero:

Cordial saludo. Con el fin de cerrar formalmente el trámite de control de cambios registrado en el PMP (§6.6) y en la Memoria (§II.2.1) del proyecto de grado **2026-03-G18**, solicitamos atentamente su visto bueno por escrito para la **Solicitud de Cambio CC-01**, cuyo propósito es alinear el título y el objetivo general con el alcance efectivamente construido y validado (preservando la no intrusividad exigida por el Decreto 4725 de 2005 del INVIMA y evitando afirmaciones fuera del alcance de red):

- **Título anterior (VPP):** *Sistema de detección de ransomware en ventiladores mecánicos con un enfoque en ciberseguridad hospitalaria*
- **Título ajustado (CC-01):** *Detección de anomalías de red compatibles con ransomware en la telemetría HL7 de una máquina de anestesia*

- **Objetivo general anterior (VPP):** *Desarrollar un controlador de hardware embebido no intrusivo, fundamentado en un modelo determinista de análisis de tráfico de red y señales, para la detección temprana de ataques de ransomware y el registro de evidencia forense en equipos de soporte respiratorio crítico.*
- **Objetivo general ajustado (CC-01):** *Desarrollar un detector, pensado para desplegarse de forma no intrusiva sobre un puerto espejo, basado en un modelo determinista de la telemetría HL7/MLLP, que identifique anomalías de red compatibles con una intrusión de ransomware en el canal de una máquina de anestesia y registre evidencia forense verificable, con miras a su despliegue en hardware embebido de bajo costo.*

Su respuesta a este correo confirmando el visto bueno nos permitirá registrar la fecha de aprobación en Memoria y PMP y adjuntar el soporte en la carpeta de entrega final.

Agradecemos de antemano su acompañamiento y revisión.

Atentamente,  
**Gabriel Alejandro Camacho Rivera · David Santiago Piñeros Rodríguez · Santiago Ávila Barbudo**  
Grupo SIDRE — Ingeniería de Sistemas, Pontificia Universidad Javeriana

---

## 2. Diapositiva clave: «Qué SÍ y qué NO demuestra este trabajo»

> **Recomendación estratégica:** Ubicar esta diapositiva inmediatamente después de los resultados (Diapositiva 10) para marcar el tono honesto de la sesión de preguntas antes de que el jurado formule sus objeciones.

| Qué SÍ está demostrado (evidencia sellada) | Qué NO está demostrado | Por qué (decisión de diseño / restricción) |
| :--- | :--- | :--- |
| **Caracterización empírica y línea base bimodal** de la Mindray WATO EX-35 (142 mensajes reales del HUSI, 33 códigos OBX, 9 unidades, 6 modos ventilatorios, cadencia de `10 s`). | **Falsos positivos en tráfico clínico nuevo no visto** (*hold-out* hospitalario). | Solo se dispuso de 2 capturas HL7 del HUSI y ambas fueron necesarias para construir/afinar la línea base (E1–E9); por eso H3 se reporta como *consistencia con la línea base* (`0/142`, IC 95 % Wilson `≤ 2,6 %`). |
| **Detección del 100 % del catálogo propio** (`16/16` escenarios, `2.010/2.010` inyecciones en PC, `0` FP) y **en vivo sobre Pi 3B** (`4.864/4.864`, recall `1,0000` / `0,9996` exacto, precisión `0,9998`, `0/208` FP legítimos bajo ataque con IC Wilson `≤ 1,8 %`). | **Generalización contra ataques desconocidos diseñados por terceros** ni detección de ransomware binario real. | Reglas, escenarios y generador son del mismo equipo (`n = 16`, límite inferior Wilson `80,6 % < 90 %`). Infectar una máquina de anestesia real es inviable por ética, costo y Decreto 4725/2005 (INVIMA). Se documentaron evasiones empíricas (`E01`, `E02`, `L01–L03`) y se dejó la especificación ciega de 1 página para un tercero. |
| **Viabilidad operativa en el hardware más limitado disponible (Pi 3B):** `9,9 %` CPU promedio, `41,0 MB` RAM estable (`+0,009 MB/min` en carga, `+0,000` en reposo), `309` pruebas (`93,8 %` cobertura núcleo), `241` archivos SHA-256. | **Cumplimiento de H2 (`≤ 500 µs`) en Raspberry Pi 3B** (`1,74 ms` FAIL) ni validación en **Raspberry Pi 4**. | Se fijó el umbral antes de medir y no se alteró post-hoc. La Pi 3B (Cortex-A53 32 bits) es el peor caso de hardware económico; aun así `1,74 ms` equivale al `0,017 %` del intervalo de `10 s` del WATO. En PC cumple incluso con parseo HL7 (`255,9–302,7 µs`). |
| **Operación pasiva y *fail-open* en red virtual Linux** y **cadena forense inmutable SHA-256** por mensaje/alerta. | **Operación pasiva sobre switch SPAN o TAP físico** y **umbrales clínicos fisiológicos** (contra mimetismo). | El switch de laboratorio carece de puerto espejo (la Pi 3B operó *in-path* como receptor MLLP) y los umbrales clínicos requieren aval médico (`clinical_approval_status: PENDING`). |

---

## 3. Guion de Sustentación (12 diapositivas · 15 minutos exactos)

| Diap. | Tiempo | Expositor sugerido | Mensaje clave y datos sellados |
| :---: | :---: | :--- | :--- |
| **1** | 0:30 | Todos / Gabriel | **Portada y alcance honesto:** Título ajustado (`CC-01`), equipo 2026-03-G18 SIDRE, alianza técnica con el Centro de Simulación del HUSI (Mindray WATO EX-35). |
| **2** | 1:15 | Gabriel | **El problema real (TI vs. TO/IoMT):** Ransomware en salud (Sophos 2024: USD 2,57 M promedio de recuperación; caso Synnovis/NHS). En Nivel 1 Purdue, la WATO EX-35 transmite HL7 v2.6/MLLP por TCP 1550 en **texto plano, sin cifrado ni autenticación**, y su firmware no se puede intervenir (Decreto 4725/2005 INVIMA). |
| **3** | 1:00 | Gabriel | **Objetivo propuesto vs. logrado (`CC-01`):** Presentar la tabla de 3 columnas (*Prometido · Entregado · Razón*). Explicar que detectar manifestaciones de red (no ransomware binario) es una decisión ética, regulatoria y económica. |
| **4** | 1:15 | Gabriel | **Caracterización empírica en el HUSI (OE-01):** 142 mensajes ORU^R01 reales (`43` STANDBY + `99` RUNNING en 6 modos ventilatorios), 33 códigos OBX, 9 unidades MDC, cadencia de `10,0 s`, límite `5.120 B`. Mapeo a MITRE ATT&CK ICS v20 (`T1692.002` y `T0814`). |
| **5** | 1:15 | Santiago | **Arquitectura Ports & Adapters y motor explicable (OE-02):** 4 capas desacopladas, **15 reglas deterministas** compartidas por 3 adaptadores (receptor, offline PCAP y captura en vivo). **309 pruebas** (`93,8 %` cobertura núcleo), **241 archivos SHA-256**. |
| **6** | 1:30 | David | **H1 (catálogo propio), evasiones documentadas y consistencia H3:** `16/16` escenarios (límite inferior Wilson `80,6 % < 90 %` → no se afirma generalización; `2.010/2.010` inyecciones muestran robustez operativa). Tabla honesta de evasiones `E01–E05` y frontera de literatura `L01–L06` (mimetismo PEEP, replay lento, Slowloris `< 15 s`, RST entre tramas). H3: **consistencia con la línea base** (`0/142`, IC Wilson `≤ 2,6 %`). |
| **7** | 1:45 | David | **Prueba física en el peor caso de hardware económico (Pi 3B, 30 min, ground truth NTP):** `4.864` inyecciones desde Kali → Recall `1,0000` (`0,9996` exacto), Precisión `0,9998`, F1 `0,9999`; **`0/208` alertas sobre emisor legítimo** (IC 95 % Wilson `≤ 1,8 %`); CPU **`9,9 %`**. Mostrar gráfica Antes/Después de memoria: de `+0,054 MB/min` (`48,2 MB`) a **`+0,009 MB/min`** (`41,0 MB`, `+0,000` en reposo). |
| **8** | 1:15 | Santiago | **H2 (latencia) — NO cumplida en el hardware más limitado posible:** Tabla comparativa PC (`170,8–302,7 µs` incluyendo camino normal y parseo HL7) vs. Pi 3B (`1706,3 ± 7,5 µs` y `1744,41 µs`) vs. umbral `500 µs` fijado antes de medir. Explicar viabilidad operativa (`1,74 ms = 0,017 %` de `10 s`) y reducción SOC offline (`19.284 → 253` notificaciones, `76,22×`). |
| **9** | 2:00 | David / Santiago | **Demo corta en vivo (2 min exactos):** Ataque `A01` → alerta JSON con `evidence_hash` SHA-256 → verificación del hash (ver §5). |
| **10** | 1:15 | Gabriel | **Diapositiva «Qué SÍ y qué NO demuestra este trabajo»** (tabla de §2). |
| **11** | 1:00 | Gabriel | **Impacto económico, social y trabajos futuros:** Nodo de `810.000 COP` (~USD 200) frente a USD 2,57 M promedio de recuperación en salud; parque biomédico heredado en Latinoamérica; ruta concreta (evaluación ciega con especificación de 1 página, Pi 4/5, SPAN físico, captura nueva HUSI y umbrales clínicos). |
| **12** | 0:30 | Todos | **Cierre y espacio para preguntas del jurado.** |

---

## 4. Respuestas ensayadas para las 5 preguntas duras del jurado

### Pregunta 1: *«¿Por qué falló la hipótesis H2 (`500 µs`) en la Raspberry Pi y por qué no probaron en la Pi 4 del SRS?»*
> **Respuesta:** «Fijamos el umbral de `500 µs` antes de medir y decidimos no moverlo tras ver el resultado porque mover metas post-hoc invalida un experimento. No compramos la Pi 4 porque el presupuesto de `810.000 COP` no se ejecutó y trabajamos con la **Raspberry Pi 3 Model B** disponible —que es el **peor caso de hardware embebido de bajo costo** (Cortex-A53 de 32 bits, 1 GB RAM). En esa placa el p95 fue de `1,74 ms` en el peor caso (con 2 alertas por mensaje), por lo que **declaramos H2 no cumplida en el hardware más limitado posible**. Sin embargo, ese resultado es útil: demuestra que incluso en hardware antiguo el sistema sostiene recall `1,0`, `9,9 %` de CPU y `41 MB` de RAM, y `1,74 ms` es el `0,017 %` del intervalo de `10 s` de la WATO. Además, en PC medimos el camino normal (`188,9 µs`) y el alcance completo con parseo HL7 (`255,9 µs` normal, `302,7 µs` peor caso), dejando listo el protocolo reproducible para medir una Pi 4 o Pi 5.»

### Pregunta 2: *«Su validación en H1 es circular: ustedes escribieron las reglas y los ataques. ¿Qué demuestra realmente un 100 %?»*
> **Respuesta:** «Totalmente de acuerdo, y por eso lo declaramos desde la primera línea de la sección de resultados: el `16/16` demuestra cobertura interna del catálogo propio y las `2.010` inyecciones demuestran robustez operativa repetible, **no generalización frente a ataques desconocidos** —más aún porque con `n = 16` escenarios el límite inferior del intervalo de Wilson al 95 % es `80,6 %` (`< 90 %`; se necesitarían `n ≥ 35` escenarios independientes). Para que el experimento sí pudiera fallar, corrimos 11 pruebas de frontera y literatura (`E01–E05` y `L01–L06`) sobre el motor congelado sin tocar las reglas, documentando evasiones reales (mimetismo de PEEP, replay lento `> 5 s`, Slowloris MLLP `< 15 s` y `RST` entre tramas). Y dejamos lista una especificación ciega de una página —sin revelar las reglas— para que un tercero independiente evalúe el detector a caja negra.»

### Pregunta 3: *«Si un atacante copia el formato HL7 y solo sube la PEEP a 28 cmH₂O (`E01`), su detector no dice nada. ¿Entonces para qué sirve?»*
> **Respuesta:** «Esa evasión está medida y documentada en `E01` (`0/3` detecciones), y delimita exactamente la frontera entre **detección de protocolo** y **detección clínica**. Nuestro motor cubre la capa de red y protocolo (suplantación de identidad, inyección de tramas malformadas, tipos de mensaje no autorizados, códigos/unidades OBX inválidos, ráfagas, silencios de telemetría y replay rápido) sin requerir intervención médica ni aprobación clínica. Detectar una PEEP peligrosa dentro de un mensaje perfectamente formado requiere **umbrales fisiológicos por modo ventilatorio avalados por anestesiólogos** —y por rigor regulatorio dejamos `clinical_approval_status: PENDING` hasta contar con esa aprobación. La arquitectura ya contempla esa capa clínica como extensión modular.»

### Pregunta 4: *«Ustedes dicen 0 falsos positivos en H3, pero probaron sobre las mismas capturas con las que ajustaron la línea base.»*
> **Respuesta:** «Por eso no presentamos H3 como tasa de falsos positivos en tráfico clínico nuevo, sino como **consistencia con la línea base** (`0` alertas sobre `142` mensajes reales, cuyo límite superior de Wilson al 95 % es `2,6 %`). Al tener solo 2 capturas HL7 del HUSI (una *Standby* y una *Running*) y haber usado ambas para derivar las enmiendas E1–E9, no podíamos separar honestamente un conjunto *hold-out* a posteriori. Lo que sí medimos en tráfico generado en vivo bajo ataque continuo en la Pi 3B fue `0` alertas sobre `208` mensajes legítimos en 30 minutos —un límite superior de Wilson al 95 % de **`1,8 %`**— tras introducir la enmienda de cadencia por sesión. Medir una captura hospitalaria completamente nueva queda como trabajo futuro prioritario.»

### Pregunta 5: *«Cambiaron el título y el objetivo general al final (y la Pi en el laboratorio estaba en la ruta del tráfico, no en un puerto espejo). ¿No es un retroceso?»*
> **Respuesta:** «Fue una decisión técnica y regulatoria documentada en `CC-01` (resumida en nuestra tabla *Prometido vs. Logrado*): el título original hablaba de un *controlador* para *ventiladores mecánicos* contra *ransomware*; en la práctica trabajamos con una **máquina de anestesia** Mindray WATO EX-35, sin infectarla con ransomware real (inviable por ética, costo y Decreto 4725/2005 del INVIMA), y diseñamos un **detector pasivo de red**, nunca un controlador *inline*. Sobre el puerto espejo: el modo pasivo y *fail-open* se validó en red virtual Linux; en la Pi física, al no contar con un switch administrable SPAN, operamos en modo de captura directa (*in-path* como receptor MLLP), lo cual declaramos explícitamente tanto en la Memoria como en el riesgo `R-02` del PMP.»

---

## 5. Guion de Demo Corta Reproducible (2 minutos exactos)

> **Objetivo:** Mostrar en vivo en 120 segundos que el sistema detecta una suplantación (`A01`), genera una alerta JSON explicable con hash criptográfico `SHA-256`, y que el hash se verifica al instante.

1. **0:00–0:20 — Verificar estado limpio y lanzar receptor/detector (Terminal 1):**
   ```powershell
   # En PC (loopback) o SSH en Raspberry Pi 3B:
   $env:LAB_AUTHORIZED='YES'
   .venv\Scripts\python.exe mllp_receiver.py --host 127.0.0.1 --port 1550
   ```
2. **0:20–0:50 — Inyectar escenario `A01` (suplantación de aplicación `MSH-3`, Terminal 2):**
   ```powershell
   $env:LAB_AUTHORIZED='YES'
   .venv\Scripts\python.exe anomaly_generator.py --host 127.0.0.1 --port 1550 --scenario A01 --count 1 --seed 202611
   ```
3. **0:50–1:30 — Mostrar la alerta explicable generada (`alerts.jsonl`) con su regla, técnica MITRE y hash `SHA-256`:**
   ```powershell
   Get-Content runs\*\alerts\alerts.jsonl -Tail 1 | ConvertFrom-Json | Format-List alert_id, rule_id, severity, mitre_technique, reason, evidence_hash
   ```
   *(Narrar en 15 s: «Aquí se ve la regla `R-ID-001`, severidad `HIGH`, mapeo `T1692.002`, el motivo legible para el operador y el `evidence_hash` SHA-256 de la trama recibida».)*
4. **1:30–2:00 — Verificar integridad criptográfica de la evidencia sellada del repositorio (`221/221` + `20/20`):**
   ```powershell
   .venv\Scripts\python.exe -c "import hashlib, pathlib; d=pathlib.Path('analysis_output/validation'); ok=sum(hashlib.sha256((d/f).read_bytes()).hexdigest()==h for h,f in (l.split(None,1) for l in (d/'SHA256SUMS.txt').read_text().splitlines() if l.strip())); print(f'SHA256SUMS verificado: {ok}/221 OK')"
   ```
   *(Si el jurado pide verificar la suite automatizada: `.venv\Scripts\python.exe -m pytest -q` → `309 passed`.)*
