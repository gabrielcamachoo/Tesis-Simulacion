# Concepto de Jurado Calificador y Director de Trabajo de Grado (Auditoría Integral v5.7)

**Proyecto:** *Detección de anomalías de red compatibles con ransomware en la telemetría HL7 de una máquina de anestesia* (`2026-03-G18`)  
**Programa:** Ingeniería de Sistemas — Pontificia Universidad Javeriana (Grupo SIDRE)  
**Fecha de auditoría:** 23/24 de noviembre de 2026  
**Versión auditada:** `main` (`0453c03` + corrida física `c60edc0` + sincronización documental **v5.7**)  
**Rol del evaluador:** Revisión conjunta en calidad de **Jurado Calificador y Director de Tesis** (criterio estricto de sustentación PUJ).

---

## 1. Dictamen Ejecutivo y Proyección de Calificación

El trabajo de grado exhibe una **honestidad científica inusualmente alta** (no oculta el incumplimiento de H2 en la Pi 3B, declara la validación circular de H1 y la circularidad de H3, y sella evidencia cruda con SHA-256) y una **ingeniería de software sólida** (`295` pruebas automatizadas, `93,8 %` de cobertura en el núcleo, arquitectura *Ports & Adapters* limpia y sin dependencias pesadas).

Con la integración de la corrida física de 30 minutos de David Piñeros (`commit c60edc0`, `deploy/medicion/resultados/v56_pi_20261123/`) y la sincronización documental **v5.7** realizada hoy, el proyecto cierra en hardware real cuatro defectos mayores que estaban abiertos en v5.6 (`E10/D-03`, `D-02`, `D-04`, `D-06`) y añade métricas reales de `Recall`, `Precisión` y `F1` en placa con *ground truth* NTP.

### Estimación de Calificación por Rubro (Escala PUJ 0,0 – 5,0)

| Criterio de Evaluación PUJ | Peso | Estado Pre-v5.7 (v5.6 sin corrida Pi) | Estado Actual (**v5.7**) | Techo Alcanzable (cerrando Plan de Mejora) |
| :--- | :---: | :---: | :---: | :---: |
| 1. Planteamiento del problema, alcance y estado del arte | 15 % | 4,3 | **4,5** | **4,7** (con `CC-01` aprobado) |
| 2. Rigor de ingeniería, arquitectura y calidad de código | 25 % | 4,4 | **4,6** | **4,9** (corrigiendo D-11, D-12, D-13 y `baseline.yaml`) |
| 3. Validación experimental, rigor estadístico y hardware | 35 % | 3,8 | **4,2** | **4,7 – 4,8** (con 2 hitos del Bloque 4: Pi 4/5 + SPAN o HUSI hold-out) |
| 4. Calidad documental, trazabilidad y coherencia interna | 15 % | 3,9 | **4,5** | **4,8** (corrigiendo numeración PMP/SDD + gráfica D-02) |
| 5. Cumplimiento formal y entregables administrativos | 10 % | 3,5 | **3,8** | **5,0** (`CC-01` firmado + Formato Biblioteca + ZIP limpio) |
| **NOTA PONDERADA ESTIMADA** | **100 %** | **4,02 / 5,0** | **4,36 / 5,0** | **4,78 / 5,0** *(rango Meritorio)* |

> **Veredicto del Director:** En estado v5.7 la tesis **aprueba con solidez (~4,3 – 4,4)**, pero todavía tiene puntos vulnerables que los jurados (**Juddy Morales** e **Ivonne Valencia**) atacarán sin piedad en la sustentación. Ejecutar los ajustes de **Prioridad 1 y 2** (sección 5) puede subir la calificación entre **+0,3 y +0,5 puntos** antes de la entrega final.

---

## 2. Qué Estaba Mal y YA Se Corrigió en v5.7 (Cierre Documental de Hoy)

Estos errores críticos y mayores habrían costado puntos inmediatos ante cualquier lectura cruzada entre el texto y el repositorio; **ya quedaron corregidos** en los 6 documentos `.docx`/`.pdf` y en `docs/`:

1. **Contradicción factual grave sobre `RUNNING → STANDBY` en Memoria (§V y Apéndice A):**
   - *Qué estaba mal:* La Memoria v5.6 afirmaba literalmente *"El paso de RUNNING a STANDBY se permite, pero ninguna captura lo muestra"*, contradiciendo frontalmente a `baseline.yaml:426-436` y `tests/test_enmiendas_e2_e3.py` (`test_running_a_standby_no_verificado_sigue_alertando`), donde esa transición **está prohibida y dispara `R-STATE-001`**.
   - *Justificación:* Un jurado que contraste el Apéndice A contra `baseline.yaml` concluye que el documento no refleja el sistema construido. **Corregido en Memoria v5.7.**
2. **Desactualización masiva frente a la corrida física de 30 min (`c60edc0` / `v56_pi_20261123`):**
   - *Qué estaba mal:* Los 6 documentos oficiales y el repositorio decían que no había *ground truth* en la Pi y que E10, D-02, D-04 y D-06 estaban pendientes en hardware; incluso Memoria §VIII listaba como *Trabajo Futuro* `"Liberar memoria"` y `"Ground truth en la Pi"` (tareas ya completadas). Además `README.md`, `docs/RESULTADOS_TESIS.md`, `docs/LIMITATIONS.md` y `docs/TRACEABILITY_MATRIX.csv` estaban congelados en octubre de 2026 (`251 tests`, `H2 NO_VERIFICADO en Pi`).
   - *Justificación:* Presentar documentación desincronizada con la evidencia más fuerte del proyecto destruye la trazabilidad (ISO 16326 / IEEE 830) y hace perder valor al esfuerzo físico ya ejecutado. **Sincronizado a v5.7 en todos los DOCX, PDF y Markdown.**
3. **Índices rotos, Lista de Figuras en inglés y terminología prohibida en índices:**
   - *Qué estaba mal:* En Memoria, el TOC omitía 4 subsecciones del Cap. VII, la Lista de Tablas solo listaba 4 de 17 tablas y la Lista de Figuras imprimía `"No table of figures entries found."` en inglés. En el SDD, la Lista de Figuras conservaba `"Arquitectura Bump-in-the-Wire"` (término explícitamente prohibido en §5.2). En el SRS, la Lista de Tablas aún mostraba `"RF-01: Captura Pasiva Fail-Open"` (título retirado en v5.1). En el Abstract en inglés se mezclaban comas decimales españolas (`1706,3`, `10,4%`) con puntos ingleses (`93.8%`).
   - *Justificación:* Errores editoriales visibles en las primeras 5 páginas predisponen negativamente al jurado antes de leer el aporte técnico. **Corregido y regenerado vía Word COM en v5.7.**
4. **Anexo 2 incompleto respecto a la nueva evidencia física:**
   - *Qué estaba mal:* `Anexo_2_SHA256` solo incluía los `216` hashes de `analysis_output/validation/` y omitía los `20` hashes de la corrida física `v56_pi_20261123`.
   - *Corrección:* Se añadió la sección **C.2 (`20/20` SHA-256)** para un total de **236 archivos sellados**.

---

## 3. Hallazgos de Código y Empaquetado (Parte A — Estado de Cierre Hoy)

> **Actualización de cierre en código (hoy):** Los defectos **`D-11`**, **`D-12`**, **`D-13`**, **`D-14`** y la alineación de **`baseline.yaml` (`5120 B`)** quedaron **corregidos en código y cubiertos por 9 nuevas pruebas de regresión** (`tests/test_v57_fixes_d11_d14.py`, suite total **304 pruebas**), y la carpeta `Entregable_Final_TG_2026_03_G18/` fue sincronizada a **v5.7** sin duplicados. Quedan pendientes solo los ítems que requieren firma/formato manual (`06_Formato_de_Biblioteca/` y `CC-01`) o edición gráfica opcional (M-07).

### Hallazgo M-01 [MAYOR]: Bug en `evaluate.py` (`per_rule` sobrescrito y `throughput` inflado) — Defecto `D-12`
- **Dónde está:** `evaluate.py` líneas `490` y `532–539`; visible en `deploy/medicion/resultados/v56_pi_20261123/evaluation_hardware.json` líneas `22–26` y `200–255`.
- **Por qué está mal:**
  1. El bucle `for sid, items in sorted(by_scenario.items()): res.per_rule[rule] = {...}` **sobrescribe** el diccionario en lugar de acumular cuando varios escenarios comparten `expected_rule`. En `evaluation_hardware.json`, `R-ID-001` reporta `expected: 228` (debió ser `456` = A01 + A16), `R-MLLP-001` reporta `228` (debió ser `684` = A05 + A06 + A15) y `R-TIME-002` reporta `380` (debió ser `1.900` = A12 + A13).
  2. `total_msgs = normal_count + res.alerts_total` suma **filas de alertas** (`208 + 19.284 = 19.492`), reportando `9,346 msgs/s` cuando en realidad `detect_live_summary.json` registró **`4.772` mensajes HL7** (`2,29 msgs/s`). Cada mensaje de ataque genera ~4 alertas, por lo que `throughput` está inflado `4×`.
- **Qué corregir:** Acumular (`+=`) en `res.per_rule[rule]` y renombrar/separar `alert_events_per_s` de `hl7_msgs_per_s` (leyendo el conteo real de mensajes si existe), añadiendo pruebas unitarias en `tests/test_evaluate.py`.

### Hallazgo M-02 [MAYOR]: Buffering de `1 s` en `tcpdump` infla `100×` la latencia extremo a extremo en vivo — Defecto `D-13`
- **Dónde está:** `detect_live.py` línea `629`: `cmd = ["tcpdump", "-Z", "root", "-i", args.interface, "-nn", "-s0", "-U", "-w", "-", bpf]`.
- **Por qué está mal:** En Linux `libpcap`, `-U` vacía el *buffer* de `stdout`, pero **no desactiva el timeout de 1.000 ms del ring-buffer `TPACKET_V3`**. Al inspeccionar `alerts.jsonl.gz` de `v56_pi_20261123`, todas las ráfagas de alertas se emiten exactamente cada `1,00 s` (`.20x s`), lo que causó que `evaluate.py` reportara latencias de detección **`p50 = 473,8 ms` / `p95 = 1013,9 ms`** cuando el procesamiento interno real en la Pi fue **`p50 = 3,39 ms` / `p95 = 4,52 ms`**. Un jurado preguntará por qué un sistema diseñado para microsegundos tarda más de `1 segundo` en alertar.
- **Qué corregir:** Agregar `"--immediate-mode"` al comando de `tcpdump` en `detect_live.py:629` (verificando soporte en la versión de `tcpdump` del contenedor Docker) y añadir prueba unitaria que verifique el flag.

### Hallazgo M-03 [MAYOR]: Emparejamiento de respaldo en `evaluate.py` oculta 2 pérdidas de `R-OBX-002` en `A11` — Defecto `D-14`
- **Dónde está:** `evaluate.py` líneas `243–246` y `evaluation_hardware.json` línea `151` (`"A11": {..., "detected": 228, "wrong_rule": 2}`).
- **Por qué está mal:** A las `00:00:05.391` y `00:00:05.593 UTC` en el socket `192.168.5.160:58160`, las inyecciones `ANOM-A11-2` y `ANOM-A11-3` no generaron alerta `R-OBX-002`. Sin embargo, `evaluate.py` las contó como **TP** usando alertas secundarias sobrantes (`R-NET-001` y `R-SEQ-001`) del mensaje previo `ANOM-A11-1`. Aunque en v5.7 ya transparentamos el **recall estricto por regla esperada (`0,9996`, `4.862/4.864`)**, el código debería reportar `strict_rule_recall` explícitamente como métrica de primera clase en `EvaluationResult`.
- **Qué corregir:** Exponer `strict_rule_tp` y `strict_rule_recall` (donde `matched_rule == expected_rule`) en `evaluate.py` y revisar por qué las 2 últimas tramas del socket `58160` se perdieron al cierre TCP en `detect_live.py` (posible cierre de flujo al ver `FIN` antes de vaciar `buf`).

### Hallazgo M-04 [MAYOR]: La suite `pytest` falla en la propia Raspberry Pi (`294 passed, 1 failed`) — Defecto `D-11`
- **Dónde está:** `tests/test_validation_tools.py` línea `94`: `assert rep["entorno"]["es_raspberry_pi"] is False`.
- **Por qué está mal:** Contradice `ANF-02` (portabilidad ARM) y `ANF-03` (`100 %` de pruebas pasando): al ejecutar `pytest` sobre la plataforma objetivo del proyecto, el test falla precisamente porque `D-06` funciona y devuelve `True`.
- **Qué corregir:** Cambiar la aserción en `tests/test_validation_tools.py:94` a `assert isinstance(rep["entorno"]["es_raspberry_pi"], bool)` (y validar ambos casos `True`/`False` con `monkeypatch`, como ya hace `test_bloque1_fixes_and_coverage.py`).

### Hallazgo M-05 [MEDIO]: Inconsistencia de `max_message_size_bytes` en `baseline.yaml`
- **Dónde está:** `baseline.yaml` línea `502` (`max_message_size_bytes: 65535`) frente a `src/config/settings.yaml` y Enmienda E9 (`5120`).
- **Por qué está mal:** Dos archivos de configuración oficiales declaran límites incompatibles (`65.535 B` vs `5.120 B`).
- **Qué corregir:** Alinear `baseline.yaml` y `src/evidence/baseline_builder.py` a `5120` (o documentar explícitamente allí que `65535` es el tope teórico MLLP mientras el límite operativo E9 es `5120` en `settings.yaml`).

### Hallazgo M-06 [CRÍTICO ADMINISTRATIVO]: Carpeta `06_Formato_de_Biblioteca/` vacía y `Entregable_Final_TG_2026_03_G18/` desincronizado y duplicado
- **Dónde está:** `documentos_tesis/Entregable_Final_TG_2026_03_G18/` y `documentos_tesis/Entrega_TG_G18_v5.6.zip`.
- **Por qué está mal:**
  1. `06_Formato_de_Biblioteca/` está **completamente vacía** (la biblioteca PUJ rechaza el radicado sin la Carta de Autorización firmada).
  2. Existen copias duplicadas de los PDFs en la raíz de `Entregable_Final_TG_2026_03_G18/` y dentro de las subcarpetas `01_`..`04_`, todas congeladas en **v5.6** (desactualizadas frente a v5.7).
- **Qué corregir:** Diligenciar y firmar el Formato de Biblioteca PUJ, limpiar duplicados en `Entregable_Final_TG_2026_03_G18/`, copiar todos los `.docx`/`.pdf` **v5.7** recién generados y crear un paquete limpio `Entrega_TG_G18_v5.7.zip`.

### Hallazgo M-07 [MENOR EDITORIAL]: Numeración discontinua de capítulos en PMP/SDD y ausencia de gráfica comparativa post-D-02
- **Dónde está:**
  - `PMP_Diligenciado_Final.docx`: salta del Cap. `6` al `8` (sin `7`) y del `10` al `12` (sin `11`).
  - `SDD_Diligenciado_Final.docx`: numera `1. Historial`, `2. TOC`, `3. Lista de Figuras`, `4. Lista de Tablas`, `5. Introducción`.
  - `Memoria` (Figura 3) y `DCC` (Figura 1): muestran únicamente la gráfica **pre-parche** del 19-11 (donde la memoria crece), pero NO muestran la nueva gráfica **post-parche D-02** (`deploy/medicion/resultados/v56_pi_20261123/pi_v56_rep1_fases_detector_rss_mb.svg`, curva plana en `17,1 MB`).
- **Qué corregir:**
  1. En PMP y SDD, renumerar capítulos consecutivamente (`1, 2, 3...`) o añadir una nota explícita en el Prefacio indicando que se conserva la numeración literal de las cláusulas de la plantilla PUJ/ISO 16326.
  2. Convertir `pi_v56_rep1_fases_detector_rss_mb.svg` a PNG de alta resolución e insertarlo como **Figura 4 en Memoria** (y **Figura 2 en DCC**) comparando visualmente *antes vs. después de D-02*.

---

## 4. Qué SIGUE MAL a Nivel Científico / Experimental (Lo Que Separa un 4,4 de un 4,8+)

Estos son los **cuatro frentes más duros** que el jurado va a evaluar en el fondo de la tesis. Ninguno se arregla "redactando mejor": requieren acciones externas concretas (o una defensa impecable si el tiempo no alcanza).

### Brecha C-01 [CRÍTICA]: Incumplimiento de H2 (`p95 ≤ 500 µs`) y hardware distinto al especificado en el SRS
- **Por qué baja la nota:** El SRS especifica una **Raspberry Pi 4 (ARM64)** y fija `p95 ≤ 500 µs` (`RD-01`, incluyendo parseo HL7). Se midió en una **Pi 3 Model B (`armv7l`, 32 bits)** y falló por `3,4×` (`1706,3` y `1744,4 µs`, **sin** contar el parseo HL7). No cumplir una de las tres hipótesis centrales en la única placa medida pesa fuertemente en el 35 % de validación.
- **Cómo corregir para subir +0,20 a +0,30:**
  1. **Conseguir prestada una Raspberry Pi 4 o Pi 5 en la PUJ (laboratorio SIDRE/Electrónica)** y correr `latency_bench.py --messages 1000 --runs 3` (toma 15 minutos; protocolo exacto en `docs/HANDOFF_HARDWARE_PI.md` §5 Opción A). Reportar honestamente sea PASS o FAIL.
  2. **Medir también el camino normal (sin alertas) + con parseo HL7 incluido** en `latency_bench.py`, para responder con datos exactos cuánto cuesta el parseo (`RD-01` completo) vs. el camino de alerta (`sha256` + construcción de `Alert`).

### Brecha C-02 [CRÍTICA]: H3 evaluada sobre los mismos datos de entrenamiento (circularidad) y H1 con catálogo propio
- **Por qué baja la nota:** Evaluar `0` FP sobre los mismos `142` mensajes usados para construir la línea base y las enmiendas E1–E9 viola la separación *train/test* básica de cualquier validación empírica. Aunque declararlo honestamente evita una penalización por falta de rigor ético, **no entrega evidencia de generalización**.
- **Cómo corregir para subir +0,25 a +0,35:**
  1. **Captura *hold-out* de 15 min en el Centro de Simulación del HUSI** (`5 min STANDBY + 10 min RUNNING`, alternando modos y haciendo una transición `RUNNING → STANDBY`), corriendo `detect_pcap.py` **sin tocar** `baseline.yaml` ni `rules.yaml` (`HANDOFF_HARDWARE_PI.md` §5 Opción C).
  2. **Prueba *red-team* / adversaria documentada:** pedir a un estudiante o colega externo de SIDRE que construya 2–3 trazas de evasión (incluido un ataque de mimetismo que modifique PEEP sin violar protocolo) y publicar el resultado negativo/positivo real. Eso refuta la crítica de *"experimento diseñado para no poder fallar"*.

### Brecha C-03 [CRÍTICA]: Modo pasivo (`SPAN`) y *fail-open* sin validación física en hardware
- **Por qué baja la nota:** La justificación clínica/regulatoria (INVIMA Decreto 4725/2005) descansa en que el sensor sea **pasivo y *fail-open***. En hardware real, la Pi funcionó como receptor MLLP por Wi-Fi (`wlan0`), violando simultáneamente el modo pasivo y la restricción anti-Wi-Fi del SRS §2.4.
- **Cómo corregir para subir +0,20:** Ejecutar la prueba corta de **30 minutos con un switch administrable de laboratorio PUJ (Cisco/Aruba/Mikrotik)** en modo `SPAN` sobre `eth0` cableado (`HANDOFF_HARDWARE_PI.md` §5 Opción B), apagando el contenedor del detector a mitad de transmisión y demostrando `0 %` de pérdida de ACK en el receptor independiente (**fail-open físico probado**).

### Brecha C-04 [ALTA ADMINISTRATIVA]: Solicitud de cambio `CC-01` sin aprobación escrita del Director
- **Por qué baja la nota:** El título y el objetivo general entregados difieren formalmente de la propuesta aprobada (`VPP`). Sin un correo o acta firmada por el Ing. Jhon Talero aprobando `CC-01`, el jurado puede objetar un incumplimiento formal de alcance.
- **Cómo corregir (+0,15 administrativo en 10 min):** Enviar hoy el correo formal de aprobación de `CC-01` al director, guardar el PDF de respuesta en el paquete de entrega y actualizar la línea de estado en Memoria (§II.2.1) y PMP (§6.6).

---

## 5. Hoja de Ruta Priorizada para Maximizar la Calificación

| Prioridad | Acción Concreta | Esfuerzo | Impacto Estimado en Nota |
| :---: | :--- | :---: | :---: |
| **P0 (Hoy)** | Obtener visto bueno escrito de **`CC-01`** del director + diligenciar **`06_Formato_de_Biblioteca/`** + regenerar ZIP limpio **v5.7** sin duplicados | 30 min | **+0,15 a +0,20** (evita bloqueo formal) |
| **P1 (Hoy)** | Corregir en código **`D-11`** (`test_bench_smoke`), **`D-12`** (`evaluate.py` `per_rule` y `throughput`), **`D-13`** (`--immediate-mode` en `detect_live.py`) y alinear `baseline.yaml:502`; re-correr `pytest` (295/295 en PC y Pi) | 1–2 h | **+0,10 a +0,15** (cierra grietas técnicas en código) |
| **P1 (Hoy)** | Insertar la gráfica **post-parche D-02** (`pi_v56_rep1_fases_detector_rss_mb`) en Memoria y DCC + añadir nota de numeración en PMP/SDD | 30 min | **+0,05 a +0,10** (impacto visual en sustentación) |
| **P2 (Esta semana)** | Ejecutar **Opción A** (bench H2 en **Raspberry Pi 4/5** de la PUJ) **y** **Opción B** (prueba corta **SPAN** en switch administrable PUJ con `eth0` demostrando *fail-open*) | 1–2 h en lab PUJ | **+0,25 a +0,35** (cierra las 2 críticas de hardware) |
| **P3 (Si hay acceso HUSI)** | Ejecutar **Opción C** (captura nueva *hold-out* de 15 min en el **HUSI** sin tocar `baseline.yaml`) | 1 h en HUSI | **+0,20 a +0,25** (cierra circularidad de H3 → nivel **Meritorio 4,7–4,9**) |

---

## 6. Preguntas Críticas del Jurado en Sustentación (y Cómo Responderlas)

1. **«¿Por qué su título ya no dice “controlador embebido BIW en ventiladores mecánicos” como la propuesta aprobada?»**
   - *Respuesta ganadora:* Reconocer sin rodeos que al analizar la regulación INVIMA (Decreto 4725/2005) y las capturas reales de la WATO EX-35 en el HUSI, un controlador *inline* añadía riesgo clínico inaceptable sobre un dispositivo clase IIB/III y que en el canal HL7/MLLP no se observa el binario del ransomware sino sus manifestaciones de red. Eso motivó la solicitud formal `CC-01` para alinear título y objetivo con el producto real verificable.
2. **«H2 falló en la Raspberry Pi 3B (`1,74 ms` vs `500 µs`). ¿Entonces el sistema no sirve en hardware embebido?»**
   - *Respuesta ganadora:* Separar **cumplimiento del umbral de ingeniería** (NO cumple `500 µs` en Pi 3B, reportado sin alterar el umbral) de **viabilidad operativa**: la WATO envía `1` mensaje cada `10.000 ms`, por lo que `1,74 ms` en el peor caso (con 2 alertas + SHA-256) consume el `0,017 %` del presupuesto temporal y `9,9 %` de un núcleo bajo ataque continuo de 20 minutos (`41,0 MB` de RAM estable). Adicionalmente explicar el impacto de Cortex-A53 32-bit vs. la Pi 4 ARM64 del SRS.
3. **«Sus pruebas de H3 dan `0` FP, pero son los mismos 142 mensajes con los que construyeron `baseline.yaml`. ¿No es eso *overfitting*?»**
   - *Respuesta ganadora:* Admitirlo de inmediato («Sí, exactamente por eso en el Capítulo VII §5 declaramos que ese `0` demuestra consistencia interna con la línea base y **no** es una tasa de falsos positivos en tráfico nuevo; incluso con independencia estadística el IC95 de Wilson llega a `2,6 %`»). Mostrar qué se sí probó en vivo en hardware: `0` alertas sobre `208` mensajes legítimos bajo ataque continuo de Kali (`v56_pi_20261123`), y explicar el protocolo *hold-out* listo en `HANDOFF_HARDWARE_PI.md`.
4. **«¿Qué pasa si un atacante sofisticado envía un mensaje HL7 válido desde la IP del WATO cambiando solo el PEEP de 6 a 25 cmH₂O?»**
   - *Respuesta ganadora:* Responder con precisión quirúrgica: **el detector actual no lo detectaría**, porque valida anomalías de protocolo y no umbrales fisiológicos (`clinical_approval_status: PENDING`). Citar a Hady et al. [20] y Mahler et al. [21] para explicar que la defensa natural contra mimetismo es la capa de coherencia fisiológica validada por clínicos (trabajo futuro directo con la Dra. Jennifer Cárdenas en el HUSI).
5. **«¿Por qué en `evaluation_hardware.json` la latencia p95 es de `1.013,9 ms` si en `detect_live_summary.json` dice `4,52 ms`?»**
   - *Respuesta ganadora:* Demostrar dominio técnico profundo: `4,52 ms` es el tiempo de procesamiento interno paquete→alerta en Python en la Pi 3B, mientras que `1.013,9 ms` incluye el timeout de `1.000 ms` del ring-buffer de `libpcap` en `tcpdump` (invocado con `-U` sin `--immediate-mode`, defecto `D-13`). Identificar esta causa raíz ante el jurado suma puntos enormes de rigor técnico.
