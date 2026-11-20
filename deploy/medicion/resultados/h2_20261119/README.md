# H2 en la Raspberry Pi — 3 repeticiones (19-11-2026)

Los umbrales y el criterio de validez se fijaron **antes de medir**, en los
commits `b89e8c3` y `42f721f` (`deploy/medicion/README.md`, sección "H2 en la
Pi"). Los datos son de después.

- **Pi:** Raspberry Pi 3 Model B Rev 1.2, Cortex-A53 a 1,2 GHz, 1 GB, Linux 6.18 armv7l (`pi_host.txt`). El SRS especifica una **Pi 4**.
- **Carga:** emisor WATO del PC (`192.168.5.114`, 1 mensaje cada 10 s) todo el tiempo. En `CARGA` se suma la campaña de Kali (`192.168.5.160`, A01–A16 sin A14) en bucle: 74, 73 y 75 campañas.
- **Detección:** 58.972 alertas de Kali en `alerts.jsonl` de la Pi durante las 3 repeticiones, 14.109 de ellas R-NET-001.
- **Latencia:** `latency_bench.py --messages 1000 --runs 3` en la Pi al cerrar cada repetición, con el medidor ya detenido.

## Ventanas (UTC, 20-11-2026)

| Rep | REPOSO1 | CARGA | REPOSO2 | Muestras (R1 / C / R2) |
|---|---|---|---|---|
| 1 | 02:02:50–02:08:04 | 02:08:04–02:28:08 | 02:28:08–02:33:10 | 297 / 1140 / 301 |
| 2 | 02:35:08–02:35:37 | 02:35:37–02:56:08 | 02:56:08–03:01:23 | 30 / 1165 / 296 |
| 3 | 03:02:35–03:07:46 | 03:07:46–03:28:08 | 03:28:08–03:33:10 | 295 / 1156 / 298 |

## Validez

En las 3 repeticiones, `throttled` = `0x50000` en todas las muestras: las
banderas actuales estuvieron siempre en 0. El último `Undervoltage detected` en
`dmesg` es de las 20:52:22 hora local (01:52:22 UTC), durante el arranque y antes
de la rep1. **Las 3 repeticiones son válidas** según el criterio fijado. Las
caídas de voltaje del arranque se declaran como limitación de la fuente.

## Resultado contra los umbrales

| Métrica | Umbral | Rep1 | Rep2 | Rep3 | Media ± desviación | Resultado |
|---|---|---|---|---|---|---|
| Latencia p95 (bench, 3000 mensajes por rep) | ≤ 500 µs | 1714,0 µs | 1705,8 µs | 1699,1 µs | **1706,3 ± 7,5 µs** | ❌ **NO cumple** |
| CPU de receptor + detector + tcpdump en CARGA (promedio, 100 % = 1 núcleo) | ≤ 50 % | 10,4 % | 10,5 % | 10,5 % | 10,4 ± 0,05 % (máx 36,6 %) | ✅ cumple |
| RAM de receptor + detector + tcpdump (máximo) | ≤ 64 MB | 42,1 MB | 45,1 MB | 48,2 MB | máx 48,2 MB | ✅ cumple |

La latencia p95 en PC (referencia de desarrollo) fue de 177,52 µs. En reposo,
la CPU de los tres procesos fue de 0,3 % en todas las repeticiones.

## Crecimiento de la RAM

| | Rep1 | Rep2 | Rep3 |
|---|---|---|---|
| RSS del detector al inicio → al final | 15,9 → 17,1 MB | 17,1 → 18,2 MB | 18,2 → 19,1 MB |
| Pendiente en CARGA | +0,054 MB/min | +0,055 MB/min | +0,045 MB/min |
| Pendiente en REPOSO | 0 | 0 | 0 |

La RAM **crece de forma sostenida mientras hay ataque** y no se libera en
reposo. El receptor sigue el mismo patrón (17,9 → 24,1 MB). Los tres procesos
juntos suben unos 3 MB por cada 20 min de ataque. Hoy cumplen el umbral (máximo
de 48,2 MB), pero a este ritmo llegarían a 64 MB tras unas 5 cargas más (~1,7 h
de ataque continuo). No se revisó la causa en el código.

## Otros

- Temperatura máxima: 47,2 °C.
- CPU total de la Pi en CARGA: 5,3 % de promedio.
- Latencia del detector en vivo (`detect_live_summary.json`, acumulada en las 3 repeticiones): p50 3,36 ms, p95 4,49 ms. Mide el pipeline en vivo y no se compara directamente con el bench.
- PC simwato (control): CPU ~0 % y RAM 12,4 MB en todas las fases.

## Archivos

| Archivo | Qué es |
|---|---|
| `pi_h2_rep{1,2,3}.csv` | Medidor de la Pi, 1 muestra/s, con fase y `throttled` |
| `pc_h2_rep{1,2,3}.csv` | Medidor del contenedor del emisor en el PC |
| `pi_resumen.md`, `pc_resumen.md` | `analyze_resources.py`: por fase, entre repeticiones y H2 (cumple / pendiente / throttled) |
| `latency_h2_rep{1,2,3}.json` | Salida de `latency_bench.py` en la Pi. **Ojo:** el campo `nota_h2` ("Medido en PC") y `es_raspberry_pi: false` son textos o detecciones fijos del script. Las corridas sí fueron en la Pi: lo confirman `entorno.platform` (`rpi-v7-armv7l`) y `pi_host.txt` |
| `pi_host.txt` | Modelo de placa, kernel y frecuencia de CPU durante el bench |
| `*.svg` | Por repetición: CPU de los tres procesos, RSS del detector, RSS de los tres y temperatura (Pi); CPU del emisor (PC) |

Regenerar: `python analyze_resources.py deploy/medicion/resultados/h2_20261119/pi_h2_rep*.csv --out <salida>.md --plot lab_cpu_pct`
