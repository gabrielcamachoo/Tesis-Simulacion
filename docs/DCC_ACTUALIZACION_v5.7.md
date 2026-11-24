# Actualización del Documento de Control de Calidad (DCC v1.5 — Edición Final, 23/24-11-2026)

Sincronizado con el cierre de **Bloque 1–2** (`commit 0453c03`), **la corrida física de confirmación en hardware** sobre la Raspberry Pi 3 Model B (`commit c60edc0`, `deploy/medicion/resultados/v56_pi_20261123/`, `20/20` archivos verificados en su `SHA256SUMS.txt` local) y la **Edición Final** (`309 passed`, `adversarial_eval_v59.json`, `literature_boundary_v60.json`, `latency_v59_*.json`, **`221/221` en `analysis_output/validation/SHA256SUMS.txt` — 241 archivos verificados**).

> El documento institucional completo actualizado en versión **1.5 (Edición Final)** se encuentra en [`documentos_tesis/Documento_Control_Calidad_G18.pdf`](../documentos_tesis/Documento_Control_Calidad_G18.pdf) (y editable `.docx`). Concentra la trazabilidad granular de versiones internas (`v5.0–v5.9`), commits y defectos (`D-01` a `D-14`) para mantener limpia la Memoria de Grado.

---

## 1. Confirmación Física en Vivo en la Raspberry Pi 3 Model B (`v56_pi_20261123`)

Corrida ejecutada el **23/24-11-2026** sobre `main` (`c360eea`, con código `0453c03` desplegado: E10 + D-02 + D-04 + D-05 + D-06), topología de captura directa (`192.168.5.114` emisor WATO STANDBY 1 msg/10 s → `192.168.5.134:1550` Pi 3B con UFW activo; atacante Kali `192.168.5.160` con `--all --exclude A14 --count 3`, semillas `200001+`, relojes NTP sincronizados entre Pi y Kali).

| Criterio | Pre-parche (`19-11-2026`, `1a8ff5d`) | Post-parche en vivo (`23/24-11-2026`, `v56_pi_20261123`) | Estado en Hardware |
| :--- | :---: | :---: | :---: |
| **E10 / D-03:** alertas sobre emisor legítimo (`192.168.5.114`) durante la ventana de 30 min | `354 / 366` (`96,7 %`) | **`0 / 208`** (`0,0 %` en ventana)* | **CERRADO EN VIVO** |
| **D-02:** pendiente `detector_rss_mb` en CARGA | `+0,045` a `+0,055 MB/min` | **`+0,009 MB/min`** (`REPOSO2 = +0,000 MB/min`) | **CERRADO EN VIVO** |
| **Memoria total lab (`lab_rss_mb` máx. ≤ 64 MB)** | `48,2 MB` (creciente) | **`41,0 MB`** (estable en REPOSO2) | **CUMPLE** |
| **CPU promedio lab en CARGA (`lab_cpu_pct` ≤ 50 %)** | `10,4–10,5 %` | **`9,9 %`** (p95 `15,4 %`, máx. `20,6 %`) | **CUMPLE** |
| **D-04:** `A15 → R-MLLP-001` en vivo (`5120 B`) | `0 / 672` (`14/15` esc.) | **`228 / 228`** (`15/15` escenarios) | **CERRADO EN VIVO** |
| **D-06:** auto-detección plataforma en `latency_bench.py` | `es_raspberry_pi: false` | **`es_raspberry_pi: true`** (`Raspberry Pi 3 Model B Rev 1.2`) | **CERRADO EN VIVO** |
| **Recall / Precisión / F1 en hardware (`evaluate.py`, 4.864 iny.)** | `NO_VERIFICADO` (sin GT) | **Recall `1,0000`** (`0,9996` exacto por regla†) · **Precisión `0,9998`** · **F1 `0,9999`** | **CUMPLE (≥ 0,90)** |
| **H2 latencia p95 (`latency_bench.py`, 3×1000 vs ≤ 500 µs)** | `1706,3 ± 7,5 µs` (FAIL) | **`1744,41 µs`** (p50 `1610,42 µs`, p99 `1850,84 µs`) | **FAIL (Pi 3B)** |
| **Validez eléctrica / térmica** | `0x50000`, `47,2 °C` | `0x50000` pre/post, `dmesg` sin eventos nuevos, máx. `47,2 °C` | **VÁLIDA** |

> \* El único FP reportado por `evaluate.py` (`ALERT-018600-1795479071865`, `R-TIME-002` por silencio `15,2 s > 15,0 s` a las `00:11:11 UTC`) ocurrió **15 segundos después de detener el emisor benigno al finalizar la corrida**, validando incidentalmente el vigilante de silencio E3 en hardware real. Se conserva íntegro en el registro sin editarlo.  
> † De las `4.864` inyecciones (`76` iteraciones × `64`), `4.862` dispararon exactamente su regla esperada (`99,96 %`) y `2` inyecciones `A11` (`00:00:05.391` y `.593 UTC`, puerto `58160`) fueron emparejadas por respaldo de `evaluate.py` con alertas secundarias `R-NET-001`/`R-SEQ-001` (`wrong_rule: 2`).

---

## 2. Hallazgos Detectados en Auditoría v5.7 y Cerrados en Código (Trazabilidad Completa)

| ID | Hallazgo | Evidencia / Ubicación | Estado en `main` v5.7 |
| :---: | :--- | :--- | :--- |
| **D-11** | `test_bench_smoke` fallaba al correr `pytest` en ARM/Raspberry Pi (`294 passed, 1 failed`) | `tests/test_validation_tools.py:94` exigía `es_raspberry_pi is False` | **Cerrado en código:** valida `isinstance(..., bool)` y coherencia con `detect_hardware_environment()`. Probado con mock ARM en `tests/test_v57_fixes_d11_d14.py`. |
| **D-12** | `evaluate.py` sobrescribía `per_rule[rule]` en vez de acumular (`R-ID-001`, `R-MLLP-001`, `R-TIME-002`) y calculaba `throughput` sobre filas de alertas (`19.492`) en vez de mensajes HL7 (`4.772`) | `evaluate.py:406-440, 498-515, 567-578` | **Cerrado en código:** `per_rule` acumula (`+=`) `expected`, `detected`, `missed` y `wrong_rule`; `throughput` usa `received_messages` (`source: "hl7"`) y reporta aparte `events_total` y `events_per_s`. Verificado sobre los `4.864` eventos reales de `v56_pi_20261123`. |
| **D-13** | Latencia extremo a extremo en vivo (`p50 = 473,8 ms`, `p95 = 1013,9 ms`) dominada por buffer de `1 s` de `libpcap` en `tcpdump` (sin `--immediate-mode`), pese a que el motor tarda `3,39 / 4,52 ms` | `detect_live.py:565-577` (`build_tcpdump_cmd`) y `_close_flow` | **Cerrado en código:** agregado `--immediate-mode` junto a `-U` en `build_tcpdump_cmd()` y drenado de segmentos pendientes contiguos en `_close_flow()`. Pendiente re-medición en hardware en próxima corrida. |
| **D-14** | `evaluate.py` emparejó por respaldo (`wrong_rule`) 2 inyecciones `A11` con alertas secundarias del mismo socket | `evaluate.py:79-80, 500-506, 605-607`; `evaluation_hardware.json:151` | **Cerrado en código y documentado:** expuestos `strict_rule_tp` y `strict_rule_recall` en `EvaluationResult` y en `format_report` (sobre `v56_pi_20261123`: `4.862/4.864 = 0,9996` vs. recall global `1,0000`). |
| **E9-cfg** | `baseline.yaml:502` y `baseline_builder.py:616` conservaban `max_message_size_bytes: 65535` frente a `5120` en `settings.yaml` | `baseline.yaml:502`, `src/evidence/baseline_builder.py:616` | **Cerrado en código:** alineados ambos archivos a `5120` B (Enmienda E9), con prueba automatizada en `tests/test_v57_fixes_d11_d14.py`. |

---

## 3. Ítems Pendientes (Requieren Hardware Externo / Hospital / Director)

1. **Aprobación formal por escrito de `CC-01`:** visto bueno del director (**Ing. Jhon Talero**) sobre el ajuste de título y objetivo general.
2. **Bloque 4 — Validaciones físicas externas:**
   - Benchmark H2 en **Raspberry Pi 4 o 5** física (plataforma especificada en el SRS).
   - Prueba corta en **switch administrable con SPAN** (laboratorio de redes PUJ) para demostrar modo pasivo y *fail-open* físico.
   - **Captura nueva independiente (hold-out)** en el Centro de Simulación Clínica del **HUSI** (sin modificar `baseline.yaml`) para medir H3 sobre tráfico no visto.
3. **Formato de Biblioteca PUJ:** diligenciar la carta de autorización de publicación (`06_Formato_de_Biblioteca/`, actualmente vacía en la carpeta de entregables).
