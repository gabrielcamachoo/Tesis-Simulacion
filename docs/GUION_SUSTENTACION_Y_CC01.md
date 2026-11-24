# Guion de Sustentación (15 min) y Correo de Aprobación `CC-01` — Proyecto 2026-03-G18

Este documento complementa la Memoria **v5.9** y el [Concepto de Jurado y Director](./CONCEPTO_JURADO_Y_DIRECTOR_v5.7.md) con dos herramientas listas para usar antes y durante la sustentación ante los jurados **Juddy Morales** e **Ivonne Valencia**.

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

## 2. Guion de Sustentación (Estructura de 12 diapositivas · 15 minutos exactos)

| Diap. | Tiempo | Expositor sugerido | Mensaje clave y datos sellados que DEBEN decirse |
| :---: | :---: | :--- | :--- |
| **1** | 0:30 | Todos / Gabriel | **Portada y alcance honesto:** Título ajustado (`CC-01`), equipo 2026-03-G18 SIDRE, alianza técnica con el Centro de Simulación del HUSI (Mindray WATO EX-35). |
| **2** | 1:15 | Gabriel | **El problema real (TI vs. TO/IoMT):** Ransomware en salud (67 % organizaciones afectadas, caso Synnovis/NHS 2024–2025). En Nivel 1 Purdue, la WATO EX-35 transmite HL7 v2.6/MLLP por TCP 1550 en **texto plano, sin cifrado ni autenticación**. No se puede tocar el firmware (INVIMA Decreto 4725/2005). |
| **3** | 1:00 | Gabriel | **Pregunta de investigación y objetivos:** Detectar manifestaciones de red compatibles con ransomware en el canal HL7/MLLP sin modificar el equipo, preservando evidencia forense SHA-256. Mostrar el ajuste `CC-01` con madurez (de controlador *inline* BIW a sensor de red pasivo objetivo). |
| **4** | 1:15 | Gabriel | **Caracterización empírica en el HUSI (OE-01):** 3 sesiones (agosto 2026), 142 mensajes ORU^R01 reales (`43` STANDBY + `99` RUNNING en 6 modos ventilatorios), 33 códigos OBX, 9 unidades MDC, cadencia exacta de `10,0 s`, límite `5.120 B` (Enmienda E9). Mostrar los 4 grupos del Modelo de Amenazas mapeados a MITRE ATT&CK ICS v20 (`T1692.002` y `T0814`). |
| **5** | 1:30 | Santiago | **Arquitectura Ports & Adapters y FSM (OE-02):** 4 capas desacopladas (`src/mllp`, `src/hl7`, `src/detection`, `src/evidence+alerting`). Un solo motor determinista de **15 reglas explicables** (sin ML en la ruta crítica) que opera igual en 3 adaptadores: `mllp_receiver.py`, `detect_pcap.py` y `detect_live.py`. Mostrar Figura 1 (FSM) aclarando que `RUNNING → STANDBY` alerta `R-STATE-001` por no aparecer en evidencia. |
| **6** | 1:15 | Santiago | **Calidad de software y trazabilidad:** **307 pruebas automatizadas** (`pytest`, `0` fallos, portable PC y ARM), **93,8 % de cobertura en el núcleo** (`engine.py` `97,0 %`, cumpliendo `ANF-03 > 90 %`), **240 archivos sellados con SHA-256** (`220/220` en `validation/` + `20/20` en `v56_pi_20261123/`). |
| **7** | 1:30 | David | **Validación H1 (Efectividad), contra-ejemplos E01–E05 y H3 (Consistencia):** 60 corridas en PC (`2.010/2.010` TP, `0` FP oficiales, precisión `100,0 %`). Declarar abiertamente la validación circular y que el límite inferior del IC 95 % de Wilson sobre 16 escenarios (`80,6 %`) es `< 90 %` (se requieren `n ≥ 35` escenarios independientes). Mostrar los 5 contra-ejemplos de frontera (`E01–E05`): mimetismo clínico y replay lento evaden (`0/3`), `E03`/`E04` cuantifican trade-offs (`R-SEQ-001`, `R-STATE-001`), y `E05` (OBX sigiloso en RUNNING) se detecta `3/3`. H3: `0` alertas sobre los 142 mensajes reales (mismos de la línea base; tráfico nuevo = trabajo futuro). |
| **8** | 1:45 | David | **Validación física en Raspberry Pi 3 Model B con ground truth NTP (`v56_pi_20261123`):** Mostrar topología real de laboratorio (modo captura directa *in-path* + UFW) y **resultados medidos en 30 min**: `4.864` inyecciones desde Kali → **Recall `1,0000`** (`0,9996` exacto por regla: `4.862/4.864`), **Precisión `0,9998`**, **F1 `0,9999`**; **`0` alertas sobre el emisor legítimo** en `208` mensajes (E10 confirmado en vivo); **`228/228` A15 → `R-MLLP-001`** (D-04 confirmado); CPU promedio **`9,9 % ≤ 50 %`**; agregación SOC offline: `19.284 → 253` notificaciones (`76,22×` menos, `12/12` reglas). |
| **9** | 1:30 | David | **Diagnóstico y cierre de la fuga de memoria (D-02) — *Mostrar Figura 4 (Antes vs. Después)*:** En el 19-11 la RAM subía `+0,054 MB/min` hasta `48,2 MB` por retención de `SessionState`/flujos. Tras implementar `close_session()` y poda TTL, en la corrida física del 23/24-11 bajó a **`+0,009 MB/min`** (`+0,000` en reposo) y pico estable de **`41,0 MB ≤ 64 MB`**. |
| **10** | 1:15 | Santiago | **Hipótesis H2 (Latencia) — Resultado negativo honesto y desglose RD-01:** Umbral fijado antes de medir (`500 µs`): **PASS en PC** incluso con camino normal y parseo HL7 (`188,9 µs` normal motor, `255,9 µs` normal+parseo, `302,7 µs` peor caso+parseo), **FAIL en Raspberry Pi 3 Model B** (`1706,3 ± 7,5 µs` y `1744,41 µs`, `es_raspberry_pi: true`). Explicar por qué: Cortex-A53 32-bit vs. Pi 4 ARM64 del SRS y costo del camino de alerta; aun así `1,74 ms` es solo el `0,017 %` del intervalo de `10 s` del WATO. Explicar también el hallazgo `D-13` (`tcpdump --immediate-mode`). |
| **11** | 1:15 | Gabriel | **Amenazas a la validez y limitaciones (proactividad ante el jurado):** (1) Sin switch SPAN físico (pasivo validado en red virtual); (2) sin Pi 4/5 medida; (3) H3 sobre los mismos 142 mensajes; (4) evasión por mimetismo clínico (sin umbrales fisiológicos por falta de aprobación clínica); (5) agregación de alertas ante ~15–16 alertas/s. |
| **12** | 1:00 | Todos | **Conclusiones, impacto y trabajos futuros:** Aporte concreto a SIDRE y HUSI (banco reproducible + motor explicable de bajo costo). Próximos pasos: bench en Pi 4/5, prueba corta SPAN, captura *hold-out* en HUSI, agregación para SOC y capa clínica de umbrales fisiológicos. |

---

## 3. Reglas de oro durante las preguntas del jurado

1. **Nunca inflar ni maquillar un número:** si preguntan por H2 en Pi 3B, responder de inmediato *«No cumplió los 500 µs y mantuvimos intacto el umbral»*. Eso genera respeto inmediato en jurados de ingeniería.
2. **Distinguir siempre las dos latencias:** `1,74 ms` (motor aislado en peor caso con 2 alertas), `3,39 / 4,52 ms` (procesamiento interno en vivo en `detect_live.py`) y `473,8 / 1013,9 ms` (extremo a extremo Kali→Pi antes de agregar `--immediate-mode` a `tcpdump`, ya corregido en `D-13`).
3. **Tener listo el comando verificable:** si piden prueba de reproducibilidad en vivo, mostrar `pytest -q` (`307 passed`) y `sha256sum -c SHA256SUMS.txt` (`220/220` y `20/20`).
