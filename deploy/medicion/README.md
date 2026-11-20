# Medición de recursos durante los ataques (Pi y simwato)

Pregunta: **¿sube el consumo de CPU, RAM y temperatura de la Pi y del PC
simwato mientras Kali ataca?** Se mide una serie de tiempo en cada máquina y se
compara por fase.

| Máquina | Qué se mide | Herramienta |
|---|---|---|
| Raspberry Pi `192.168.5.134` | CPU y RAM totales, temperatura, y por proceso: receptor (`mllp_receiver.py`), detector (`detect_live.py`) y `tcpdump` | `resource_sampler.py` (1 muestra/s) |
| PC Windows `192.168.5.114` | CPU y RAM del contenedor `simwato-wato-benign-1` | `deploy/medicion/medir_simwato.ps1` (~1 muestra cada 2 s) |

En esta topología Kali ataca a la Pi, no al PC: el simwato funciona como
**control** y su consumo debería quedar plano.

## Fases (una repetición ≈ 17 min)

| Fase | Duración | Qué corre |
|---|---|---|
| `F0` reposo | 2 min | Receptor y detector sin tráfico (emisor WATO detenido). Mide el piso, incluido el propio medidor |
| `F1` benigno | 5 min | Emisor WATO → Pi |
| `F2` ataque | ~3–5 min | Campaña A01–A16 sin A14 desde Kali |
| `F2b` estrés | ~1–2 min | A12 (ráfaga ×20), A13 (reconexiones ×5), A15 (mensajes de 32 KiB ×5) |
| `F3` recuperación | 5 min | Solo el emisor WATO |

Se hacen **3 repeticiones** (`rep1`, `rep2`, `rep3`).

La fase se marca escribiéndola en un archivo; cada medidor la lee en cada
muestra. No hace falta sincronizar relojes. Igual, revísalos antes de empezar
con `date -u` en Linux y `(Get-Date).ToUniversalTime()` en Windows.

## Preparación (una vez)

Todo en la rama `feat/medicion-recursos`. Pi y Kali con `git fetch origin && git checkout feat/medicion-recursos`.

- **Pi:** receptor activo (`systemctl is-active mllp-receiver`) y detector arriba:
  `sudo docker compose -f deploy/docker/raspberry/docker-compose.yml up -d`
- **PC:** Docker Desktop abierto y el emisor creado:
  `docker compose -f deploy/docker/simwato/docker-compose.yml up -d --build`
- **Kali:** en adaptador puente, con IP `192.168.5.x` (ver `deploy/docker/PRUEBA_LAB.md`).

## Una repetición, paso a paso

Cambia `rep1` por `rep2` y `rep3` en las siguientes repeticiones.

**1. F0 — reposo.** Detén el emisor en el PC:

```powershell
docker compose -f deploy/docker/simwato/docker-compose.yml stop wato-benign
```

En la Pi, terminal 1 (queda midiendo toda la repetición):

```bash
cd ~/Tesis-Simulacion
echo F0 | sudo tee /tmp/fase
sudo .venv/bin/python resource_sampler.py --out runs/recursos/pi_rep1.csv
```

En el PC (otra ventana de PowerShell, dentro del repo; también queda midiendo):

```powershell
Set-Content $env:TEMP\fase.txt F0
powershell -ExecutionPolicy Bypass -File deploy\medicion\medir_simwato.ps1 -Out runs\recursos\pc_rep1.csv
```

Mientras el emisor está detenido, el PC registra avisos "No se pudo leer…" y no escribe filas. Es normal.
Espera **2 min**.

**2. F1 — benigno.** Marca la fase en las dos máquinas y arranca el emisor:

```bash
echo F1 | sudo tee /tmp/fase                       # Pi, terminal 2
```
```powershell
Set-Content $env:TEMP\fase.txt F1                  # PC
docker compose -f deploy/docker/simwato/docker-compose.yml start wato-benign
```

Espera **5 min**.

**3. F2 — ataque.** Marca `F2` en la Pi y en el PC (mismos comandos con `F2`) y en Kali:

```bash
sudo TARGET_IP=192.168.5.134 docker compose -f deploy/docker/simatacante/docker-compose.yml run --rm attacker all --exclude-a14
```

**4. F2b — estrés.** Cuando termine la campaña, marca `F2b` en la Pi y en el PC y en Kali:

```bash
G="sudo env LAB_AUTHORIZED=YES python3 anomaly_generator.py --host 192.168.5.134 --port 1550 --config src/config/settings.yaml"
bash -c "$G --scenario A12 --count 20 && $G --scenario A13 --count 5 && $G --scenario A15 --count 5"
```

**5. F3 — recuperación.** Marca `F3` en la Pi y en el PC. Espera **5 min**.

**6. Cerrar.** `Ctrl+C` en los dos medidores; cada uno avisa cuántas muestras escribió.

## Análisis

Junta los CSV en una máquina (quedan en `runs/recursos/`, que no se sube a Git) y corre:

```bash
python analyze_resources.py runs/recursos/pi_rep*.csv --out runs/recursos/pi_resumen.md
python analyze_resources.py runs/recursos/pc_rep*.csv --out runs/recursos/pc_resumen.md --plot cpu_pct
```

Salida:

- una tabla por repetición y otra con **todas juntas**: para cada fase y columna, `promedio / p95 / máximo`;
- una gráfica SVG por CSV (`*_cpu_total_pct.svg` en la Pi, `*_cpu_pct.svg` en el PC), con el fondo coloreado por fase. Con `--plot` se grafica otra columna, por ejemplo `--plot receptor_cpu_pct` o `--plot temp_c`.

### Cómo leerlo

- **¿Sube con el ataque?** Compara `F2` y `F2b` contra `F1`. Lo que interesa en la Pi:
  - `cpu_total_pct`: la CPU es de 4 núcleos y el porcentaje es el promedio de todos;
  - `receptor_cpu_pct` y `detector_cpu_pct`: por proceso, 100 % = un núcleo completo;
  - `mem_used_mb`: la Pi tiene 920 MB;
  - `temp_c`: la Pi 3 empieza a bajar la frecuencia cerca de 80 °C.
- **¿Se recupera?** `F3` debería volver al nivel de `F1`.
- **Costo del medidor:** `F0` incluye el propio medidor. Ese es el piso.
- **Simwato:** si `cpu_pct` sube en `F2`, no es porque lo ataquen. Puede ser que la Pi tarde más en devolver los ACK.

Solo la tabla resumen va a la documentación de la tesis, con aprobación del equipo. Los CSV crudos se quedan en `runs/`.

## H2 en la Pi: umbrales fijados antes de medir

Se fijaron el **19-11-2026, antes de la primera repetición H2**. El commit que
agrega esta sección es anterior a todos los datos H2, así que los umbrales no se
ajustaron a los resultados.

| Métrica | Umbral | Origen |
|---|---|---|
| Latencia de evaluación por mensaje | p95 ≤ 500 µs | SRS RD-01 / RNF-001 (`latency_bench.py`, ≥ 1000 mensajes × ≥ 3 corridas, en la Pi) |
| RAM de receptor + detector + tcpdump (`lab_rss_mb`) | máximo ≤ 64 MB en cada fase | SRS §2.1.6 ("el demonio analizador no debe exceder 64 MB"). Se aplica a la suma de los tres procesos, que es más estricto |
| CPU de receptor + detector + tcpdump (`lab_cpu_pct`) | promedio ≤ 50 % de un núcleo en cada fase (≤ 12.5 % de la CPU total) | El SRS no fija umbral de CPU. Lo decidió el equipo el 19-11-2026, antes de medir |
| Validez de la repetición | Ningún `Undervoltage detected` en `dmesg` dentro de la ventana de la repetición y banderas **actuales** de `throttled` (bits 0–3) en 0 en todas las muestras | Se repite si falla. Criterio ajustado el 19-11-2026, **antes de medir**: con la fuente disponible, la Pi registra caídas de voltaje solo durante el arranque (`dmesg` 20:51:48 y 20:52:22, luego estable), así que las banderas "ocurrió" (`0x50000`) quedan puestas desde el boot. Se declara como limitación |
| Crecimiento de RAM | La pendiente de `detector_rss_mb` en `CARGA` no debe ser sostenidamente positiva | Se revisa la pendiente en MB/min y la gráfica `--plot detector_rss_mb` |

**Repetición H2 (30 min):**

| Fase | Duración | Qué corre |
|---|---|---|
| `REPOSO1` | 5 min | Solo el emisor WATO hacia la Pi (operación normal) |
| `CARGA` | 20 min | WATO más la campaña de Kali (A01–A16 sin A14) en bucle |
| `REPOSO2` | 5 min | Solo el emisor WATO |

Son 3 repeticiones (`h2_rep1..3`). Antes de cada una se revisa
`vcgencmd get_throttled` (bits 0–3 en 0) y se anota la hora para revisar `dmesg` al final. Al
terminar cada repetición, con el medidor ya detenido, se corre en la Pi
`LAB_AUTHORIZED=YES .venv/bin/python latency_bench.py --messages 1000 --runs 3`.

`analyze_resources.py` calcula para cada CSV de la Pi la tabla de cumple / no
cumple, la pendiente de la RAM y los valores de `throttled`. Con varios CSV
agrega una tabla entre repeticiones (media ± desviación y máximo).

Hardware usado: **Raspberry Pi 3 Model B (1 GB)**. El SRS pide una Pi 4, así
que se declara como diferencia de plataforma. La Pi 3 es más lenta, de modo que
si cumple aquí, el resultado es conservador.

## Resultados

| Repetición | Fecha | Carpeta |
|---|---|---|
| rep1 | 19-11-2026 | [`resultados/rep1_20261119/`](resultados/rep1_20261119/README.md) |

Nota: si `resource_sampler.py` se lanza en segundo plano (`nohup … &`), Ctrl+C
no le llega; se detiene con `sudo pkill -f resource_sampler.py`. Las filas ya
escritas no se pierden.
