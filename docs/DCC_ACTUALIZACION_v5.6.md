# Actualización del Documento de Control de Calidad (DCC v5.6 — 23-11-2026)

Sincronizado con el cierre del **Bloque 1 y Bloque 2** en la rama `main` (commit `0453c03`, `295` pruebas automatizadas, `336/336` archivos verificados en `analysis_output/validation/SHA256SUMS.txt`).

---

## Tabla 4 Actualizada: Cobertura de código con `pytest-cov` (commit `0453c03`, 23-11-2026)

| Módulo | Sentencias | Sin cubrir | Cobertura | Comparación vs v5.5 |
| :--- | ---: | ---: | ---: | :---: |
| `src/mllp` | 467 | 40 | **91,4 %** | +5,4 pp (antes 86,0 %) |
| `src/hl7` | 352 | 24 | **93,2 %** | -0,1 pp (antes 93,3 %) |
| `src/detection` | 419 | 13 | **96,9 %** | +6,1 pp (antes 90,8 %) |
| `src/detection/engine.py` | 232 | 7 | **97,0 %** | +2,1 pp (antes 94,9 %) |
| **Núcleo (`mllp + hl7 + detection`)** | **1.238** | **77** | **93,8 %** | **+4,2 pp — CUMPLE ANF-03 (> 90 %)** |
| `src` (todo el paquete) | 2.550 | 559 | **78,1 %** | +3,2 pp (antes 74,9 %) |

- **Suite completa (`pytest -q`):** **295 pruebas aprobadas**, 0 fallos, 0 omitidas (`53,75 s`).

---

## Re-ejecución de Campaña H1 (23-11-2026, commit `0453c03`, 60 corridas, semillas `100001`–`100030`)

| Subcampaña | Directorio sellado en `analysis_output/validation/` | Corridas | TP / Iny. | ADR | FP oficiales | Precisión |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| 15 escenarios (`exclude A14`) | `main_bloque1_20261123_200400/` | 30 | 1.920 / 1.920 | 100,0 % | **0** | **100,0 %** |
| Escenario `A14` (silencio) | `a14_bloque1_20261123_200828/` | 30 | 90 / 90 | 100,0 % | **0** | **100,0 %** |
| **Total Global H1** | `SHA256SUMS.txt` (`336/336` OK) | **60** | **2.010 / 2.010** | **100,0 %** | **0** | **100,0 %** |

---

## Repetición de los PCAPs reales de la Pi del 19-11-2026 (`77.201` paquetes, `02:23`–`03:37 UTC`)

Evidencia guardada y sellada en `analysis_output/validation/pi_replay_bloque1_20261123/memdiag_bloque1_main.json`:

| Métrica sobre tráfico real de la Pi | `main` v5.5 (`1a8ff5d`) | `main` v5.6 (`0453c03`) | Defecto cerrado |
| :--- | :---: | :---: | :---: |
| Alertas `R-TIME-002` sobre emisor legítimo (`192.168.5.114`) | 354 | **0** | **D-03 (E10)** |
| Crecimiento `tracemalloc` (`02:23` → `03:37 UTC`) | +2,93 MB | **+0,01 MB** (`7,58 → 7,59 MB`) | **D-02** |
| Sesiones retenidas / flujos abiertos al cierre | 1.345 / 636 | **0 / 0** (`1` hash global) | **D-02** |
| Alertas `R-MLLP-001` en 224 campañas (incl. 672 `A15`) | 1.344 (0 de A15) | **2.016** (**672/672 A15**) | **D-04 (E9 vivo)** |
| Alertas totales sobre Kali (`192.168.5.160`) | 58.972 | 56.511 (descarte en framing A15) | **D-04** |

---

## Tabla 8 Actualizada: Registro de Defectos y Observaciones

| ID | Hallazgo | Estado en v5.6 (`23-11-2026`) |
| :---: | :--- | :--- |
| **D-01** | 43 FP en STANDBY y 256 en RUNNING sobre capturas reales | **Cerrado** (Enmiendas E1–E9 y línea base bimodal v1.1). |
| **D-02** | Fuga de memoria bajo ataque (`SessionState`, flujos TCP sin cierre, `global_content_hashes`, `EvidenceWriter.session_metadata`) | **Cerrado en código (`b9eb69c`).** En repetición de los PCAPs reales de la Pi (`74 min`), el crecimiento bajó de `+2,93 MB` a `+0,01 MB` (`0` sesiones/flujos retenidos). Pendiente repetir estrés de `30 min` en la placa física. |
| **D-03** | `R-TIME-002` marca mensajes legítimos bajo ataque (354/366 en la Pi) | **Cerrado en código (`6614a28`, PR #10 / E10).** En repetición de los PCAPs reales de la Pi baja de `354` a `0` alertas sobre el emisor legítimo. Pendiente confirmar en vivo en la placa física. |
| **D-04** | `detect_live.py` no aplicaba límite de `5.120 B` (`A15` sin `R-MLLP-001`) | **Cerrado en código (`b9eb69c`).** En repetición de las 224 campañas reales de la Pi dispara `R-MLLP-001` en las `672` inyecciones `A15` (`15/15` escenarios). Pendiente confirmar en vivo en la placa física. |
| **D-05** | `evaluate.py` contaba como FP alertas tempranas de `A14` y mensajes `SEED` | **Cerrado en código (`308880d`).** Re-ejecución H1 de 60 corridas (`100001`–`100030`) arroja **0 FP oficiales** y **100,0 % de precisión**. |
| **D-06** | `latency_bench.py` guardaba fijo `«Medido en PC»` y `es_raspberry_pi: false` | **Cerrado en código (`fc982ed`).** Detecta automáticamente `platform.machine()` y `/proc/device-tree/model`. |
| **D-07** | Salida de `detect_live.py` fuera del repositorio por `.gitignore` | **Cerrado** (`2237e3c` en `analisis/hardware-20261120` y `pi_replay_bloque1_20261123/` sellado). |
| **D-08** | `settings_lab.yaml` sellado modificado en rama externa | **No afecta a `main`** (`336/336` verificados en `SHA256SUMS.txt`). |
| **D-09** | H2 no cumple en Raspberry Pi 3 Model B (`p95 = 1706,3 ± 7,5 µs` vs `500 µs`) | **Abierto (resultado negativo reportado).** Pendiente medir en Raspberry Pi 4 o 5 física (Bloque 4). |
| **D-10** | Volumen de alertas bajo ataque (~16,4 alertas/s sin agregación) | **Abierto** (agregación queda como trabajo futuro). |

---

## Ítems Honestamente Pendientes (Requieren Terceros / Hardware Físico)

1. **Aprobación formal de `CC-01`:** requiere visto bueno por correo o firma del director (**Ing. Jhon Talero**).
2. **Prueba en vivo de 30 min en Pi física post-parches + ground truth NTP de Kali:** para confirmar en hardware (no solo en repetición de PCAPs) la pendiente plana de RSS, `0` FP legítimos y recall/precisión reales en placa.
3. **Bloque 4 — Hardware / Hospital:**
   - Benchmark H2 en **Raspberry Pi 4 o 5** física (`latency_bench.py`).
   - Prueba física en **switch administrable con puerto espejo (SPAN)** en laboratorio de redes PUJ.
   - **Captura nueva** en el Centro de Simulación Clínica del **HUSI** (WATO EX-35 en STANDBY y RUNNING) para medir H3 sobre tráfico no visto sin modificar `baseline.yaml`.
