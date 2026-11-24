# Resultados de la Tesis — Compilado para Defensa (Edición Final)

**Proyecto:** Detección de anomalías de red compatibles con ransomware en la telemetría HL7 de una máquina de anestesia Mindray WATO EX-35 (Tesis 2026-03-G18, SIDRE, Pontificia Universidad Javeriana)  
**Última actualización:** 23/24-11-2026 (`main` Edición Final)  
**Fuentes selladas:** `analysis_output/validation/SHA256SUMS.txt` (`221/221` OK) y `deploy/medicion/resultados/v56_pi_20261123/SHA256SUMS.txt` (`20/20` OK) — **241 archivos verificados**

> Taxonomía usada: **MEDIDO** = dato de corrida sellada con SHA-256; **OBSERVADO** = evidencia real del WATO EX-35; **NO_VERIFICADO** = pendiente de hardware externo, captura nueva o aprobación clínica.

---

## 0. Resumen ejecutivo (para la sustentación)

| Hipótesis / Criterio | Enunciado | Estado (Edición Final) | Evidencia sellada |
|---|---|---|---|
| **H1 — Efectividad (catálogo propio)** | ADR ≥ 90 % sobre escenarios MITRE ATT&CK for ICS (A01–A16) | **16/16 en catálogo propio; límite inferior Wilson `80,6 % < 90 %` (`n = 16`, no se afirma generalización); evasiones documentadas en `E01–E02` y `L01–L03`** | **60 corridas PC:** `16/16` escenarios (Wilson 95 % `[80,6 %, 100 %]`), `2.010/2.010` inyecciones (`0` FP, precisión `100,0 %`). **Pi 3B (`v56_pi_20261123`):** `4.864` inyecciones (`15/15`), Recall `1,0000` (`0,9996` estricto), Precisión `0,9998`, F1 `0,9999`. **Frontera y literatura (`E01–E05`, `L01–L06`):** `adversarial_eval_v59.json` y `literature_boundary_v60.json`. Especificación ciega de 1 pág. para tercero: `docs/ESPECIFICACION_TERCERO_REDTEAM.md`. |
| **H2 — Latencia por mensaje** | p95 de evaluación determinista ≤ 500 µs (fijado antes de medir) | **PASS en PC (normal + parseo HL7) / NO CUMPLE en el hardware más limitado posible (Pi 3B)** | **PC Windows:** normal motor `188,90 µs`, normal + parseo `255,91 µs`, peor caso motor `233,71 µs` (`170,82 µs` Linux), peor caso + parseo `302,74 µs`. **Raspberry Pi 3 Model B (peor caso HW económico):** `1706,3 ± 7,5 µs` y **`1744,41 µs`** → **NO CUMPLE** (umbral intacto). Pi 4 del SRS: `NO_VERIFICADO`. |
| **H3 — Consistencia con la línea base** | Consistencia sin alertas sobre las capturas reales del WATO EX-35 | **Consistente con línea base (`0/142`, IC 95 % Wilson `≤ 2,6 %`) / Tráfico nuevo `NO_VERIFICADO`** | `0/43` STANDBY (`≤ 8,2 %`) y `0/99` RUNNING (`≤ 3,7 %`) sobre las capturas de ajuste de baseline bimodal v1.1 + E1–E9. En vivo en Pi 3B bajo ataque continuo (`v56_pi_20261123`, E10): **`0/208` alertas** sobre emisor legítimo (IC 95 % Wilson **`≤ 1,8 %`**). |

| Indicador de calidad y hardware (Edición Final) | Resultado medido |
|---|---|
| Suite automatizada (`pytest`) | **309 passed** (`0` fallos, `0` omitidas; portable PC y ARM; incluye `E01–E05`, `L01–L06` e IC Wilson) |
| Cobertura de código (`pytest-cov`) | **93,8 % en el núcleo** (`src/mllp` `91,4 %`, `src/hl7` `93,2 %`, `src/detection` `96,9 %`, `engine.py` `97,0 %` — **CUMPLE ANF-03 > 90 %**); `78,1 %` en `src/` |
| Recursos en Pi 3B post-parches (`v56_pi_20261123`, 30 min) | CPU promedio en CARGA: **`9,9 %`** (≤ 50 %); RAM máx. 3 procesos: **`41,0 MB`** (≤ 64 MB); pendiente RSS detector en CARGA: **`+0,009 MB/min`** (`REPOSO2 = +0,000 MB/min`) |
| Detección en vivo `A15 → R-MLLP-001` | **`228/228`** en vivo sobre Pi 3B (`15/15` escenarios activos) |
| Agregación offline de alertas SOC sobre Pi 3B | **`19.284` alertas crudas → `253` notificaciones** por `(IP, regla, minuto UTC)` (**`76,22×` menos**, `12/12` reglas preservadas) |
| Integridad criptográfica (`RF-04`) | `analysis_output/validation/SHA256SUMS.txt`: **`221/221` OK**; `deploy/medicion/resultados/v56_pi_20261123/SHA256SUMS.txt`: **`20/20` OK** (**`241`** totales) |

---

## 1. Campaña H1 Re-ejecutada (23-11-2026, commit `0453c03`, 60 corridas)

- **Subcampaña principal (15 escenarios, `--exclude A14`, 30 corridas, semillas `100001–100030`):** `1.920 / 1.920` TP, `0` FP, `0` FN (`analysis_output/validation/main_bloque1_20261123_200400/`).
- **Subcampaña A14 (silencio, 30 corridas, semillas `100001–100030`):** `90 / 90` TP, `0` FP, `0` FN (`analysis_output/validation/a14_bloque1_20261123_200828/`).
- **Total global H1:** `2.010 / 2.010` TP (`16 / 16` escenarios), ADR `100,0 %`, **precisión oficial `100,0 %` (`0` FP tras cierre de D-05)**, intervalo de Wilson al 95 % sobre los 16 escenarios: **`[80,6 %, 100 %]`**.
- **Salvedad metodológica obligatoria:** Validación circular (reglas, escenarios y generador escritos por el mismo equipo); demuestra cumplimiento sobre el catálogo propio, no sobre ataques desconocidos o diseñados por terceros.

---

## 2. Corrida Física en Vivo en la Raspberry Pi 3 Model B (`v56_pi_20261123`, 23/24-11-2026)

Montaje en red aislada con UFW activo (`wlan0`, Pi `192.168.5.134` como receptor MLLP + `pi-mllp-detector`, PC Windows `192.168.5.114` emisor benigno `wato-benign` 1 msg/10 s, Kali `192.168.5.160` atacante en bucle con `--all --exclude A14 --count 3` y registro de `ground_truth.jsonl` sincronizado por NTP).

| Métrica física medida en placa | Valor `v56_pi_20261123` | Criterio / Observación |
|---|---|---|
| Fases (UTC) | `REPOSO1` (~7,5 min) · `CARGA` (~21,4 min, 76 iter.) · `REPOSO2` (~5 min) | `pi_v56_rep1_fases.csv` corrige 67 filas donde Kali aún no iniciaba |
| Inyecciones en `ground_truth` | **4.864** (`15/15` escenarios, excl. A14) | `A01–A11, A15–A16`: 228 c/u; `A12`: 1.520; `A13`: 380 |
| Recall / Precisión / F1 (`evaluate.py`) | **1,0000 / 0,9998 / 0,9999** (TP `4.864`, FP `1`, FN `0`) | Recall estricto por regla esperada: **`0,9996`** (`4.862/4.864`; `A11` tuvo `2` emparejamientos por respaldo) |
| Alertas sobre emisor legítimo (`192.168.5.114`) en ventana | **0** de 208 mensajes benignos | **Confirma E10 en vivo** (antes `354/366`). El único FP ocurrió a las `00:11:11` (`R-TIME-002` silencio) tras apagar el emisor |
| `A15 → R-MLLP-001` en vivo | **228 / 228** | **Confirma D-04 en vivo** (`5120 B` en `detect_live.py`) |
| CPU promedio / p95 / máx. en CARGA (`lab_cpu_pct`) | **9,9 % / 15,4 % / 20,6 %** | ≤ 50 %: **CUMPLE** |
| RAM máxima 3 procesos (`lab_rss_mb`) | **41,0 MB** (detector `17,1 MB`, receptor `18,8 MB`, tcpdump `5,1 MB`) | ≤ 64 MB: **CUMPLE** |
| Pendiente RAM detector (`CARGA` / `REPOSO2`) | **`+0,009 MB/min` / `+0,000 MB/min`** | **Confirma D-02 en vivo** (antes `+0,045` a `+0,055 MB/min`) |
| Latencia de procesamiento en vivo (`detect_live_summary.json`) | p50 **`3,39 ms`**, p95 **`4,52 ms`**, máx. `44,73 ms` | Procesamiento interno paquete→alerta en Pi 3B |
| Latencia extremo a extremo (`evaluate.py` Kali→Pi) | p50 **`473,8 ms`**, p95 **`1013,9 ms`** | Dominada por buffer de `1 s` de `libpcap` (`tcpdump -U` sin `--immediate-mode`) |
| Bench H2 (`latency_pi_v56.json`, 3×1000, peor caso) | p50 `1610,42 µs`, **p95 `1744,41 µs`**, p99 `1850,84 µs` | **`FAIL`** vs `500 µs`. **`es_raspberry_pi: true`** (**confirma D-06 en vivo**) |
| Throttling / temperatura | `0x50000` antes y después; `dmesg` sin eventos nuevos; máx. `47,2 °C` | Corrida **VÁLIDA** |

---

## 3. H2 — Comparativa histórica de latencia (`latency_bench.py`)

| Plataforma / Corrida | Fecha | Mensajes | p50 (µs) | p95 (µs) | p99 (µs) | Veredicto vs 500 µs |
|---|---|---:|---:|---:|---:|---|
| PC desarrollo (Fase 9) | 14-10-2026 | 3.000 | 113,20 | 177,52 | 325,00 | PASS (referencia PC) |
| PC Linux (`main` 1a8ff5d) | 19-11-2026 | 3.000 | 127,27 | 170,82 | 232,23 | PASS (referencia PC) |
| PC Windows (`main` v5.6, D-06, peor caso motor) | 23-11-2026 | 3.000 | 133,10 | 233,71 | 348,23 | PASS (referencia PC) |
| PC Windows (v5.9, **camino normal motor**, 0 alertas) | 23-11-2026 | 3.000 | 65,40 | **188,90** | 288,26 | PASS (referencia PC) |
| PC Windows (v5.9, **normal + parseo HL7**, RD-01 completo) | 23-11-2026 | 3.000 | 147,35 | **255,91** | 401,20 | PASS (referencia PC) |
| PC Windows (v5.9, **peor caso + parseo HL7**, 2 alertas/msg) | 23-11-2026 | 3.000 | 117,50 | **302,74** | 453,31 | PASS (referencia PC) |
| **Raspberry Pi 3 Model B** (3 rep. pre-parche, peor caso motor) | 19-11-2026 | 9.000 | 1570,8–1577,6 | **1706,3 ± 7,5** | 1801,1–1846,0 | **FAIL** |
| **Raspberry Pi 3 Model B** (`v56_pi_20261123`, D-06, peor caso motor) | 24-11-2026 | 3.000 | 1610,42 | **1744,41** | 1850,84 | **FAIL** |

---

## 4. H3 — Consistencia sobre evidencia clínica real (`evidence_raw/`)

- **STANDBY (`LECTURACONACK25AGOSTO.pcapng`):** `43/43` ORU^R01 clasificados `NORMAL` (`0` alertas).
- **RUNNING (`LECTURAACK27AGOSTO.pcapng`):** `99/99` ORU^R01 (`13` STANDBY + `86` RUNNING en 6 modos ventilatorios) clasificados `NORMAL` (`0` alertas) con baseline bimodal v1.1 + E1–E9 (`detect_pcap.py` y `detect_live.py` idénticos).
- **Salvedad:** son las mismas capturas usadas para construir y afinar la línea base (enmiendas E1–E9). No constituyen una medición de tasa de falsos positivos en tráfico clínico nuevo no visto.

---

## 5. Limitaciones obligatorias para la defensa

1. **H2 no se cumple en Raspberry Pi 3 Model B** (`1706,3 ± 7,5 µs` y `1744,41 µs` vs. `500 µs`). La **Raspberry Pi 4** especificada en el SRS no fue medida.
2. **Sin SPAN físico ni TAP de red:** el modo pasivo y *fail-open* solo se validaron en red virtual Linux; en la Pi 3B se operó en modo de captura directa por Wi-Fi (`wlan0`) con UFW.
3. **Validación circular en H1 y mismos datos en H3:** faltan escenarios de terceros y una captura clínica nueva (hold-out) en el HUSI.
4. **Sin umbrales clínicos ni defensa contra mimetismo:** un mensaje bien formado con cadencia, identidad y códigos válidos que altere solo un valor fisiológico (ej. PEEP) no dispara alerta.
5. **Volumen de alertas sin agregación:** ~15–16 alertas/s bajo ataque continuo (requiere agregación por regla/sesión/ventana antes de producción SIEM).
6. **Aprobación clínica `PENDING` y trámite administrativo `CC-01`** pendiente de visto bueno escrito del director.
