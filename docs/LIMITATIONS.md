# Limitaciones y Amenazas a la Validez (Edición Final)

**Última actualización:** 23/24-11-2026 (`main` Edición Final) · **Regla:** todo lo marcado `NO_VERIFICADO` no se afirma como resultado; se declara como decisión de diseño o limitación explícita. Complementa `docs/THREAT_MODEL.md` §6 y Memoria Capítulo VII §7.

## 1. Evidencia clínica disponible

- **2 de 5 capturas contienen HL7** (`43` y `99` ORU+ACK; `142` mensajes totales de una sola máquina Mindray WATO EX-35 y una sola versión de firmware en el Centro de Simulación del HUSI). Las otras 3 capturas son tráfico no HL7 (ARP/otro).
- La transición **`RUNNING → STANDBY`** y las **alarmas fisiológicas activas** no aparecen en `evidence_raw/`. Por decisión explícita de la Enmienda E2 (`baseline.yaml`), `RUNNING → STANDBY` no figura en `state_transitions_observed` y genera alerta `R-STATE-001` hasta que se capture y verifique clínicamente.
- El supuesto de que el formato HL7 del WATO no cambia entre versiones de firmware es `NO_VERIFICADO`: tras cada actualización de firmware debe revalidarse la línea base.

## 2. Fidelidad del laboratorio y topología física

- **No hay WATO real en el lazo experimental:** el emulador reproduce estructura, modos y periodicidad observados, pero no la pila TCP/IP ni el reloj del equipo real (desfase observado `+17 min 10 s`).
- **Sin switch administrable con SPAN ni TAP físico:** el switch disponible (Linksys SE3005 v2) no soporta *port mirroring* y no se compró hardware del presupuesto (`810.000 COP` no ejecutados). El modo pasivo y *fail-open* se validaron únicamente en red virtual Linux; en la Raspberry Pi 3B se operó en **modo de captura directa** (la Pi recibe el tráfico como receptor MLLP y lo captura en `wlan0` con UFW).
- **Interfaz Wi-Fi en laboratorio:** el SRS prohíbe interfaces inalámbricas en el despliegue objetivo; en el laboratorio la Pi usó `wlan0`, mitigado con reglas estrictas de UFW (solo TCP `1550` desde emisor/Kali y SSH desde administración).

## 3. Baseline, falsos positivos y evasión

- **Mismos datos para construir y evaluar H3:** los `0` FP sobre los `142` mensajes reales (`43` STANDBY + `99` RUNNING) muestran consistencia con la línea base bimodal v1.1 (tras las enmiendas E1–E9), pero **no miden la tasa de falsos positivos en tráfico clínico nuevo no visto** (con `n = 142`, el IC95 de Wilson llega hasta `2,6 %`).
- **Evasión por mimetismo y ausencia de umbrales clínicos (`clinical_approval_status: PENDING`):** un atacante informado que copie `MSH-3`, utilice códigos OBX/unidades autorizados, respete la cadencia de `10 s` y altere únicamente un valor numérico (ej. PEEP) evade las 15 reglas actuales (confirmado empíricamente en `E01` y `E02` de `analysis_output/validation/adversarial_eval_v59.json`: `0/3` detecciones cada uno).
- **Compromisos de diseño de reglas:** `R-STATE-001` alerta la transición clínica normal `RUNNING → STANDBY` (confirmado en `E04`: `3/3`, política *fail-safe* por no figurar en `evidence_raw/`); `R-SEQ-001` alertaría si un reinicio legítimo de la WATO reinicia el contador `MSH-10` (confirmado en `E03`: `3/3`); `R-NET-001` es evadible por suplantación de IP en capa 2 sin controles de switch (`DAI`/`802.1X`); `R-TIME-001` no depende del desfase de `+17 min` frente al servidor porque compara `MSH-7` solo contra el `MSH-7` previo de la propia WATO (pero sería sensible a retrocesos manuales del reloj de la máquina).
- **MSH-4 vacío:** en la WATO EX-35 `MSH-4` llega vacío, limitando la capacidad discriminativa de `R-ID-002`.

## 4. Validación circular y evaluación estadística

- **Validación circular en H1:** el mismo equipo escribió las 15 reglas, los 16 escenarios y el generador `anomaly_generator.py`. Un ADR de `100 %` (`16/16` en PC, límite inferior Wilson **`80,6 % < 90 %`** por `n = 16`, `2.010/2.010` inyecciones; y `4.864/4.864` en Pi 3B) valida cobertura del catálogo propio, no generalización frente a ataques diseñados por terceros. Las pruebas de frontera `E01–E05` (`adversarial_eval_v59.json`) y los vectores de literatura `L01–L06` (`literature_boundary_v60.json`) delimitan empíricamente evasiones reales (`E01`, `E02`, `L01 < 15 s`, `L02 < 5120 B`, `L03` RST entre tramas), pero no sustituyen una evaluación ciega por terceros (especificación de 1 página lista en `docs/ESPECIFICACION_TERCERO_REDTEAM.md`).
- **Intervalos de confianza de Wilson al 95 %:** sobre `16/16` escenarios `[80,6 %, 100,0 %]` (se requerirían `n ≥ 35` escenarios independientes); sobre `0/208` mensajes legítimos bajo ataque en Pi 3B **`[0,0 %, 1,8 %]`**; sobre `0/142` mensajes de consistencia con la línea base en `evidence_raw/` **`[0,0 %, 2,6 %]`** (`0/43` STANDBY `≤ 8,2 %`, `0/99` RUNNING `≤ 3,7 %`).
- **Detalles del evaluador cerrados en v5.8:**
  - En `v56_pi_20261123`, `2` de `228` inyecciones `A11` (`00:00:05.391/.593 UTC`) fueron emparejadas por respaldo de `evaluate.py` (`wrong_rule: 2`) con alertas secundarias `R-NET-001`/`R-SEQ-001`; `evaluate.py` reporta ahora explícitamente `strict_rule_recall` (`0,9996`, `4.862/4.864`) junto al recall global (`1,0000`, cierre `D-14`).
  - `D-12` (`per_rule` acumulado con `+=` y separación de `msgs_per_s` vs. `events_per_s`) y `D-13` (`--immediate-mode` en `tcpdump`) quedaron cerrados en código.

## 5. Plataforma hardware y rendimiento (H2)

- **Hardware inferior al especificado:** el SRS especifica **Raspberry Pi 4 (Cortex-A72, ARM64)**, pero se midió en **Raspberry Pi 3 Model B (Cortex-A53 a 1,2 GHz, 1 GB RAM, Linux 32 bits `armv7l`)**.
- **H2 NO CUMPLE en Raspberry Pi 3 Model B:** con el umbral de `500 µs` fijado antes de medir, el p95 fue **`1706,3 ± 7,5 µs`** (3 repeticiones, 19-11-2026) y **`1744,41 µs`** (corrida v5.6, 24-11-2026). En PC (v5.9) se añadió el desglose completo con `latency_bench.py`: camino normal solo motor `188,90 µs`, normal con parseo HL7 (`RD-01` completo) `255,91 µs`, peor caso con parseo `302,74 µs` (todos PASS en PC; pendiente repetir en placa embebida). El desempeño en Pi 4/5 queda `NO_VERIFICADO`.
- **Latencia de captura vs. latencia del motor en vivo:** en la corrida física `v56_pi_20261123`, el motor procesó cada mensaje en `p50 = 3,39 ms` / `p95 = 4,52 ms`, pero la latencia extremo a extremo medida por `evaluate.py` fue `p50 = 473,8 ms` / `p95 = 1013,9 ms` debido al buffering de `1 s` de `libpcap` (`tcpdump -U` sin `--immediate-mode`, cerrado en código en `D-13`, pendiente re-medición física).
- **Fuente de alimentación:** avisos de bajo voltaje únicamente en el arranque (`0x50000` histórico); sin throttling activo durante las mediciones (bits 0–3 en `0`, `dmesg` limpio en la ventana).
- **Volumen de alertas sin agregación:** ~15–16 alertas/s bajo ataque continuo (defecto D-10 abierto; la agregación offline por `(IP, regla, minuto UTC)` sobre las `19.284` alertas de la Pi 3B reduce el volumen a `253` notificaciones —`76,22×` menos— preservando las `12/12` reglas).

## 6. Estado de cierres en hardware (`v56_pi_20261123`)

- **Cerrados y confirmados en vivo sobre Pi 3B (23/24-11-2026):**
  - **E10 / D-03:** `0` alertas sobre el emisor legítimo `192.168.5.114` en la ventana de 30 min (`208` mensajes `NORMAL`).
  - **D-02:** pendiente de memoria `detector_rss_mb` reducida a `+0,009 MB/min` en CARGA (`+0,000 MB/min` en REPOSO2) y `lab_rss_mb` máx. `41,0 MB ≤ 64 MB`.
  - **D-04:** `A15 → R-MLLP-001` disparado `228/228` en vivo (`15/15` escenarios).
  - **D-06:** `latency_bench.py` detecta automáticamente `es_raspberry_pi: true` y `Raspberry Pi 3 Model B Rev 1.2`.
  - **Ground truth NTP en hardware:** Recall `1,0000` (`0,9996` exacto por regla), Precisión `0,9998`, F1 `0,9999`.
- **Pendiente administrativo y Bloque 4:** visto bueno escrito de `CC-01` (director), bench en Pi 4/5, prueba corta en switch con SPAN y captura nueva independiente en el HUSI.

## 7. Mapeo MITRE ATT&CK, ética y gobernanza

- Matriz **MITRE ATT&CK for ICS v20** (`13-10-2026`): 14 reglas en `T1692.002` y `R-TIME-002` en `T0814`; `T0831` no se reclama por no existir efecto sobre control físico.
- Anonimización con SHA-256 truncado a 8 hex; revisión formal de cumplimiento de Ley 1581/2012 y Decreto 1377/2013: `NO_VERIFICADO`.
- Suite `pytest` en ARM: el defecto `D-11` (`test_bench_smoke`) quedó **cerrado en código** (**`309 passed`**, portable x86_64 y ARM), al igual que `D-12` (`per_rule`/`throughput`), `D-13` (`--immediate-mode` en `tcpdump`) y `D-14` (`strict_rule_recall`).
