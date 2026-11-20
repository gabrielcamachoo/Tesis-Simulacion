# Repetición 1 — consumo de recursos durante los ataques (19-11-2026)

Hardware real. Protocolo en `deploy/medicion/README.md`.

- **Pi:** Raspberry Pi 3 Model B, `192.168.5.134`, por Wi-Fi. Corre `mllp-receiver.service` y el contenedor `pi-mllp-detector` (`detect_live.py` en `wlan0`, `EXTRA_ALLOWED_IPS` vacío, es decir, campaña externa).
- **PC simwato:** `192.168.5.114`, contenedor `simwato-wato-benign-1`. Emisor STANDBY cada 10 s hacia la Pi.
- **Kali:** VM en adaptador puente, con IP propia `192.168.5.160`.
- **Ataque:**
  - F2: campaña A01–A16 sin A14 (`attacker all --exclude-a14`);
  - F2b: estrés A12 ×20, A13 ×5 y A15 ×5.
- **Detección en la Pi:** 434 alertas de `192.168.5.160`, incluida R-NET-001.

## Archivos

| Archivo | Qué es |
|---|---|
| `pi_rep1.csv` | Medición cruda de la Pi (`resource_sampler.py`, 1 muestra/s), recortada a la ventana del PC (hasta 22:10:06 UTC) |
| `pc_rep1.csv` | Medición cruda del PC (`medir_simwato.ps1`, ~1 muestra cada 2 s) |
| `pi_rep1_fases.csv`, `pc_rep1_fases.csv` | Las mismas filas con la fase corregida según la hora real del ataque (ver abajo) |
| `pi_resumen.md`, `pc_resumen.md` | Salida de `analyze_resources.py` sobre los `*_fases.csv`: promedio / p95 / máximo por fase |
| `pi_rep1_fases_*.svg` | CPU total, CPU del receptor, CPU del detector y temperatura de la Pi en el tiempo, con el fondo por fase |
| `pc_rep1_fases_cpu_pct.svg` | CPU del contenedor del emisor en el tiempo |

## Fases (UTC)

| Fase | Ventana | Qué pasaba |
|---|---|---|
| F1 | 21:57:52 – 21:59:30 | Solo el emisor WATO |
| F2 | 21:59:30 – 22:00:02 | Campaña desde Kali (primera y última alerta de `192.168.5.160`) |
| pausa | 22:00:02 – 22:04:30 y 22:04:38 – 22:04:54 | Sin ataque, a la espera del siguiente paso |
| F2b | 22:04:30 – 22:04:38 | Estrés A12/A13/A15 |
| F3 | 22:04:54 – 22:10:06 | Recuperación, solo el emisor WATO |

**Corrección de fases.** La campaña empezó unos 30 s antes de que el operador
marcara F2, así que la columna `fase` de los CSV crudos no cuadra con el ataque.
Los `*_fases.csv` reasignan la fase según la hora de las alertas de Kali en
`alerts.jsonl` de la Pi, que usa el mismo reloj que el medidor de la Pi. Los
relojes de la Pi y del PC coincidían al segundo (`date -u`). Esta repetición no
tuvo F0 (reposo).

## Resultados — Raspberry Pi (promedio / máximo)

| Métrica | F1 benigno | F2 campaña | F2b estrés | F3 recuperación |
|---|---|---|---|---|
| CPU total, 4 núcleos | 1.7 % / 3.8 % | 4.7 % / 25.9 % | 4.8 % / 7.6 % | 1.8 % / 21.3 % |
| CPU receptor (100 % = 1 núcleo) | 0.1 % / 1.9 % | 4.0 % / 11.4 % | 6.4 % / 11.6 % | 0.1 % / 1.9 % |
| CPU detector (100 % = 1 núcleo) | 0.1 % / 1.9 % | 3.3 % / 9.4 % | 4.5 % / 11.6 % | 0.2 % / 4.7 % |
| RAM usada (de 920 MB) | 280 MB | 272 MB / 298 MB | 279 MB | 278 MB |
| RSS receptor / detector / tcpdump | 18.0 / 15.9 / 5.0 MB | 18.2 / 16.1 / 5.0 MB | 18.2 / 16.1 / 5.0 MB | 18.3 / 16.2 / 5.0 MB |
| Temperatura | 42.7 °C | 43.3 °C / 45.1 °C | 43.0 °C | 42.8 °C |

## Resultados — PC simwato (control)

CPU del contenedor de ~0 % (máximo 0.1 %) y RAM de ~12 MB en **todas** las fases.
Kali ataca a la Pi, no al PC, así que el emisor no se ve afectado.

## Lectura

- Durante el ataque **sube la CPU** del receptor y del detector de la Pi: de
  ~0 % a 4–6 % en promedio, con picos de ~11 % de un núcleo. Es una carga baja
  para la Pi 3.
- La **RAM no crece**: los tres procesos suman menos de 40 MB en todas las fases.
- La **temperatura** sube como mucho 2 °C, lejos del umbral de throttling (~80 °C).
- En **F3** todo vuelve al nivel de F1.
- Los picos de ~21 % de CPU total en `pausa` y F3 no son del laboratorio: en
  esas muestras el receptor y el detector están en ~0 %. Por eso la conclusión
  se basa en la CPU **por proceso**.

## Limitaciones

- Es **1 de 3** repeticiones planeadas.
- Las fases de ataque fueron cortas (F2 31 s, F2b 8 s), así que hay pocas
  muestras: 31 y 8 en la Pi, 16 y 4 en el PC.
- `cpu_percent` por proceso con muestras de 1 s tiene una resolución de ~1 %.
