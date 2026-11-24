# HANDOFF DE HARDWARE — Sincronización Raspberry Pi y Validación Física (v5.6 → v5.7)

> **Actualización 23/24-11-2026 (`commit c60edc0`):** **Pasos 0, 1, 2 y 4 (actualización documental v5.7) COMPLETADOS** en `deploy/medicion/resultados/v56_pi_20261123/` (`20/20` SHA-256 OK). En la Raspberry Pi 3 Model B quedaron confirmados en vivo **E10** (`0` FP en `192.168.5.114` durante la ventana de 30 min), **D-02** (`+0,009 MB/min` en CARGA, `+0,000` en REPOSO2, máx. `41,0 MB`), **D-04** (`228/228 A15 → R-MLLP-001`), **D-06** (`es_raspberry_pi: true`) y **Recall/Precisión/F1 en hardware** (`1,0000 / 0,9998 / 0,9999` sobre `4.864` inyecciones; `0,9996` regla exacta). **Permanecen pendientes únicamente el Paso 3 (Bloque 4: Pi 4/5, switch SPAN y/o captura nueva HUSI) y el Paso 5 (aprobación escrita de `CC-01`).**

> **Fecha base:** 23 de noviembre de 2026  
> **Rama de referencia en código:** `main` (`0453c03` + `c60edc0` + cierre documental v5.7)  
> **Propósito:** Guía ejecutable paso a paso para alinear la Raspberry Pi física (y el laboratorio PUJ/HUSI) con el código y los documentos, producir la evidencia física pendiente y elevar la evaluación del trabajo de grado.

---

## 1. Qué ya está cerrado en `main` y qué falta probar en hardware

| Ítem | Estado en `main` (`0453c03`) | Qué falta en hardware físico |
|---|---|---|
| **E10 / D-03** (`R-TIME-002` por sesión) | Cerrado en código (`PR #10`, `6614a28`); replay PCAPs Pi baja alertas sobre emisor legítimo de `354 → 0` | Confirmar `0` FP sobre `192.168.5.114` en una corrida nueva en vivo de 30 min en la Pi |
| **D-02** (fuga de memoria) | Cerrado en código (`b9eb69c`); replay 74 min PCAPs Pi baja `tracemalloc` de `+2,93 MB → +0,01 MB` (`0` sesiones/flujos al cierre) | Confirmar pendiente RSS plana (`≈ 0 MB/min`, pico `≤ 64 MB`) con `resource_sampler.py` en la Pi |
| **D-04** (`5120 B` en `detect_live.py`) | Cerrado en código (`b9eb69c`); replay 224 campañas dispara `R-MLLP-001` en `672/672` A15 (`15/15` escenarios) | Confirmar `A15 → R-MLLP-001` en vivo sobre la Pi |
| **D-05** (`evaluate.py` A14/SEED) | Cerrado en código (`308880d`); 60 corridas H1 re-ejecutadas: `2010/2010 TP`, **`0` FP**, `100,0 %` precisión | Usar `evaluate.py` contra `ground_truth_pi.jsonl` generado en Kali durante la corrida de 30 min |
| **D-06** (`latency_bench.py` auto-ARM) | Cerrado en código (`fc982ed`); detecta `platform.machine()` y `/proc/device-tree/model` | Correr `latency_bench.py` en la Pi (y en Pi 4/5 si está disponible) y confirmar `es_raspberry_pi: true` |
| **Suite y cobertura** (`ANF-03`) | **295/295 pruebas**, **93,8 %** en núcleo (`mllp+hl7+detection`), `78,1 %` en `src/` | Re-ejecutar `pytest` en la Pi tras `git pull` para confirmar paridad ARM |
| **Evidencia sellada** (`RF-04`) | `SHA256SUMS.txt`: **216/216 OK** | Re-sellar tras incorporar los nuevos resultados físicos |
| **Hitos físicos Bloque 4** | Pendientes de laboratorio | Ejecutar al menos **1 o 2**: (A) bench en **Pi 4/5**, (B) prueba corta **SPAN** en switch PUJ, (C) captura nueva de 15 min en **HUSI** |
| **Trámite `CC-01`** | Pendiente visto bueno formal del director | Obtener aprobación escrita del Ing. Jhon Talero y actualizar Memoria p. 14 y PMP p. 9 |

> **Regla de integridad científica:** Nunca modificar umbrales (`500 µs`, `64 MB`, `50 % CPU`) después de medir, nunca sobrescribir `evidence_raw/` y nunca reportar un dato que no haya sido medido y sellado con SHA-256.

---

## 2. Paso 0 — Actualizar la Raspberry Pi, el PC emisor y Kali a `main` v5.6

### 2.1 En la Raspberry Pi (`192.168.5.134`)

```bash
ssh pi@192.168.5.134
cd ~/Tesis-Simulacion

# 1. Traer main actualizado (asegúrese primero de haber hecho git push de main desde el PC)
git fetch origin
git checkout main
git pull --ff-only origin main
git log -1 --oneline   # debe contener commit 0453c03 o posterior

# 2. Verificar suite automatizada y sello de evidencia en la Pi
.venv/bin/python -m pytest -q
# Esperado: 295 passed

(cd analysis_output/validation && sha256sum -c SHA256SUMS.txt | tail -n 5)
# Esperado: 216 archivos OK, 0 FAILED

# 3. Reconstruir el contenedor del detector en vivo (para incluir E10 + D-02 + D-04)
sudo docker compose -f deploy/docker/raspberry/docker-compose.yml down
sudo docker compose -f deploy/docker/raspberry/docker-compose.yml up -d --build

# 4. Reiniciar el servicio del receptor MLLP (para incluir close_session() y limpieza de session_metadata)
sudo systemctl restart mllp-receiver
sudo systemctl status mllp-receiver --no-pager

# 5. Confirmar que el detector en vivo y UFW están activos
sudo docker ps --filter name=pi-mllp-detector
sudo ufw status numbered
```

> **Nota sobre la rama `feat/medicion-recursos` (defecto D-08):** Si en algún momento se integra `feat/medicion-recursos` hacia `main`, revertir primero `analysis_output/validation/settings_lab.yaml` (`git checkout main -- analysis_output/validation/settings_lab.yaml`) para no romper `SHA256SUMS.txt`.

### 2.2 En el PC emisor Windows (`192.168.5.114`) y en Kali (`192.168.5.160`)

```powershell
# PC Windows (192.168.5.114)
cd C:\Users\OsoGa\OneDrive\Documentos\Tesis\Tesis-Simulacion
docker compose -f deploy/docker/simwato/docker-compose.yml up -d --build
```

```bash
# Kali Linux (192.168.5.160)
cd ~/Tesis-Simulacion
git fetch origin && git checkout main && git pull --ff-only origin main
# Verificar que existe el marcador obligatorio
ls -l LAB_ONLY.marker /LAB_ONLY.marker
```

---

## 3. Paso 1 — Sincronización NTP y chequeo eléctrico/térmico previo

Para poder calcular **recall, precisión y F1 reales en hardware** cruzando `alerts.jsonl` (Pi) contra `ground_truth_pi.jsonl` (Kali), los relojes UTC de las tres máquinas deben estar sincronizados (diferencia `< 50 ms`).

```bash
# En la Raspberry Pi y en Kali:
timedatectl status
# Si NTP no está sincronizado:
sudo timedatectl set-ntp true
date -u +"%Y-%m-%dT%H:%M:%S.%3NZ"
```

```powershell
# En el PC Windows:
w32tm /resync
(Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
```

### Chequeo de validez eléctrica en la Raspberry Pi (obligatorio antes de medir)

```bash
# 1. Revisar banderas actuales de throttling (los bits 0–3 deben ser 0; ej. 0x0 o 0x50000 solo de arranque)
vcgencmd get_throttled
vcgencmd measure_temp
vcgencmd measure_clock arm

# 2. Guardar marca temporal y estado de dmesg ANTES de iniciar la corrida
date -u > /tmp/inicio_corrida_v56.txt
dmesg -T | grep -i -E "voltage|throttl" | tail -n 10 | tee /tmp/dmesg_pre_v56.txt
```

---

## 4. Paso 2 — Corrida física de confirmación de 30 minutos (cierre en vivo de E10, D-02, D-04 y ground truth)

Esta corrida replica el protocolo de 30 minutos (`REPOSO1` 5 min → `CARGA` 20 min → `REPOSO2` 5 min) con **dos mejoras clave**:
1. Corre sobre **`main` v5.6 (`0453c03`+)** con E10, D-02, D-04 y D-06 integrados.
2. Kali registra **`ground_truth_pi.jsonl`** en disco en cada iteración para poder ejecutar `evaluate.py` al final.

### 4.1 Limpiar carpeta de salida limpia para esta corrida en la Pi

```bash
# En la Raspberry Pi:
RUN_TAG="v56_pi_$(date -u +%Y%m%d_%H%M%S)"
mkdir -p "runs/${RUN_TAG}"
echo "RUN_TAG=${RUN_TAG}"

# Reiniciar contenedor del detector para que el alerts.jsonl de esta corrida arranque vacío
sudo docker compose -f deploy/docker/raspberry/docker-compose.yml restart pi-mllp-detector
```

### 4.2 Fase `REPOSO1` (5 minutos — solo tráfico benigno del WATO)

```bash
# Pi — Terminal 1 (queda corriendo los 30 minutos completos):
cd ~/Tesis-Simulacion
echo REPOSO1 | sudo tee /tmp/fase
sudo .venv/bin/python resource_sampler.py --out "runs/${RUN_TAG}/pi_v56_rep1.csv"
```

```powershell
# PC Windows — Terminal 1 (control simwato, queda corriendo los 30 min):
Set-Content $env:TEMP\fase.txt REPOSO1
docker compose -f deploy/docker/simwato/docker-compose.yml start wato-benign
powershell -ExecutionPolicy Bypass -File deploy\medicion\medir_simwato.ps1 -Out "runs\pc_v56_rep1.csv"
```

Esperar **5 minutos exactos** (verificando que `192.168.5.114` envía 1 mensaje cada 10 s y no hay alertas).

### 4.3 Fase `CARGA` (20 minutos — WATO benigno + Kali atacando con ground truth)

```bash
# Pi — Terminal 2:
echo CARGA | sudo tee /tmp/fase
```

```powershell
# PC Windows — Terminal 2:
Set-Content $env:TEMP\fase.txt CARGA
```

```bash
# Kali Linux (192.168.5.160) — ejecutar bucle de 20 min guardando ground_truth acumulado:
cd ~/Tesis-Simulacion
mkdir -p runs/kali_v56
GT_FILE="runs/kali_v56/ground_truth_pi.jsonl"
: > "$GT_FILE"

END_TS=$(( $(date +%s) + 1200 ))   # 20 minutos = 1200 s
ITER=1
while [ $(date +%s) -lt $END_TS ]; do
  SEED=$(( 200000 + ITER ))
  echo "=== [$(date -u +%H:%M:%S)] Iteración ${ITER} (seed=${SEED}) ==="
  sudo env LAB_AUTHORIZED=YES .venv/bin/python anomaly_generator.py \
    --all --exclude A14 \
    --seed "${SEED}" \
    --count 3 \
    --host 192.168.5.134 \
    --port 1550 \
    --config src/config/settings.yaml \
    --ground-truth "runs/kali_v56/gt_iter_${ITER}.jsonl"
  cat "runs/kali_v56/gt_iter_${ITER}.jsonl" >> "$GT_FILE"
  ITER=$(( ITER + 1 ))
done
echo "Total inyecciones registradas en ground truth: $(wc -l < "$GT_FILE")"
```

### 4.4 Fase `REPOSO2` (5 minutos — recuperación tras el ataque)

```bash
# Pi — Terminal 2 (cuando termine el bucle de Kali):
echo REPOSO2 | sudo tee /tmp/fase
```

```powershell
# PC Windows — Terminal 2:
Set-Content $env:TEMP\fase.txt REPOSO2
```

Esperar **5 minutos exactos** (esto permite que `prune_idle_flows()` y `prune_stale_state()` con TTL = 120 s completen al menos 2 ciclos de limpieza), y luego detener `resource_sampler.py` y `medir_simwato.ps1` con `Ctrl+C`.

### 4.5 Verificación post-corrida en la Raspberry Pi

```bash
# 1. Comprobar que no hubo throttling durante los 30 min
vcgencmd get_throttled
dmesg -T | grep -i -E "voltage|throttl" | tail -n 10 | tee "runs/${RUN_TAG}/dmesg_post.txt"

# 2. Correr latency_bench.py con el medidor detenido (verifica D-06 en vivo)
LAB_AUTHORIZED=YES .venv/bin/python latency_bench.py \
  --messages 1000 --runs 3 \
  --out "runs/${RUN_TAG}/latency_pi_v56.json"

# Verificar que D-06 detectó automáticamente la Raspberry Pi:
grep -E "es_raspberry_pi|modelo_placa|host_declarado|p95_us|verdict" "runs/${RUN_TAG}/latency_pi_v56.json"

# 3. Analizar CPU, RAM y pendiente de memoria (cierre D-02 en vivo)
.venv/bin/python analyze_resources.py "runs/${RUN_TAG}/pi_v56_rep1.csv" \
  --out "runs/${RUN_TAG}/pi_v56_resumen.md" --plot detector_rss_mb
cat "runs/${RUN_TAG}/pi_v56_resumen.md"

# 4. Copiar la salida del detector en vivo (runs/docker-pi) a la carpeta de esta corrida
cp -r runs/docker-pi/* "runs/${RUN_TAG}/"

# 5. Verificar en vivo: (a) 0 alertas sobre el emisor legítimo 192.168.5.114 (E10),
#    (b) R-MLLP-001 disparado en A15 (D-04)
.venv/bin/python - <<'PY'
import json, collections, pathlib, glob
alerts_files = sorted(glob.glob("runs/v56_pi_*/**/alerts.jsonl", recursive=True))
af = pathlib.Path(alerts_files[-1])
by_ip = collections.Counter()
by_rule = collections.Counter()
for line in af.read_text(encoding="utf-8").splitlines():
    if not line.strip(): continue
    a = json.loads(line)
    by_ip[a.get("source_ip", "?")] += 1
    by_rule[a.get("rule_id", "?")] += 1
print("Archivo:", af)
print("Alertas por IP:", dict(by_ip))
print("Alertas sobre emisor legítimo 192.168.5.114:", by_ip.get("192.168.5.114", 0))
print("Alertas R-MLLP-001:", by_rule.get("R-MLLP-001", 0))
print("Top reglas:", by_rule.most_common(10))
PY
```

### 4.6 Calcular Recall, Precisión y F1 reales en hardware (copiando `ground_truth_pi.jsonl` desde Kali)

```bash
# Desde la Pi (o desde el PC), traer ground_truth_pi.jsonl de Kali:
scp kali@192.168.5.160:~/Tesis-Simulacion/runs/kali_v56/ground_truth_pi.jsonl "runs/${RUN_TAG}/ground_truth.jsonl"

# Ejecutar evaluate.py sobre la carpeta de la corrida:
.venv/bin/python evaluate.py \
  --alerts "runs/${RUN_TAG}/alerts/alerts.jsonl" \
  --ground-truth "runs/${RUN_TAG}/ground_truth.jsonl" \
  --out "runs/${RUN_TAG}/evaluation_hardware.json"
```

**Criterios de éxito de la corrida de 30 min:**
- `by_ip["192.168.5.114"] == 0` (**E10 confirmado en vivo**).
- Pendiente de `detector_rss_mb` en `CARGA` plana (`≈ 0 MB/min`) y `lab_rss_mb_max ≤ 64 MB` (**D-02 confirmado en vivo**).
- `R-MLLP-001` presente en cada inyección `A15` (**D-04 confirmado en vivo**).
- `latency_pi_v56.json` con `"es_raspberry_pi": true` y `"modelo_placa"` lleno (**D-06 confirmado en vivo**).
- `evaluation_hardware.json` con `recall ≥ 0.90` medido directamente sobre tráfico real de la red del laboratorio.

---

## 5. Paso 3 — Bloque 4: Hitos físicos de laboratorio (ejecutar al menos 1 o 2)

Ejecutar **al menos uno** de estos tres hitos (idealmente A + B o A + C) cierra las brechas físicas principales señaladas en la evaluación y sube la nota proyectada a **4.5–4.6 / 5.0**.

### Opción A — Benchmark de latencia H2 en Raspberry Pi 4 o Pi 5 (PUJ / laboratorio SIDRE) ⭐ *Más rápida (~15 min)*

El SRS especifica una **Raspberry Pi 4 (Cortex-A72, ARM64)**, pero solo se midió en Pi 3 Model B (`1706,3 µs`). Conseguir una Pi 4 o Pi 5 prestada en la PUJ permite verificar H2 en la plataforma real especificada:

```bash
# En la Raspberry Pi 4 / 5:
git clone <URL_REPO> ~/Tesis-Simulacion
cd ~/Tesis-Simulacion
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
touch /tmp/LAB_ONLY.marker   # o crear LAB_ONLY.marker en la raíz si aplica

# Verificar arquitectura (confirmar ARM64 / aarch64) y frecuencia sin throttling
uname -a
cat /proc/device-tree/model; echo
vcgencmd get_throttled

# Correr 3 repeticiones oficiales (3 × 1000 mensajes cada una)
mkdir -p runs/h2_pi4
for r in 1 2 3; do
  LAB_AUTHORIZED=YES .venv/bin/python latency_bench.py \
    --messages 1000 --runs 3 \
    --out "runs/h2_pi4/latency_pi4_rep${r}.json"
done

# Verificar veredicto (PASS si p95 <= 500 µs; reportar honestamente sea PASS o FAIL)
grep -E "modelo_placa|es_raspberry_pi|p95_us|verdict" runs/h2_pi4/latency_pi4_rep*.json
```

### Opción B — Prueba corta en Modo Pasivo con Switch Administrable (SPAN / Port Mirroring) en la PUJ (~30 min)

Valida **RF-01** en hardware sin que la Pi sea el receptor MLLP:

1. **Cableado físico en un switch administrable de laboratorio PUJ (ej. Cisco Catalyst / Aruba / Mikrotik):**
   - Puerto `Gi0/1`: PC emisor WATO (`192.168.5.114`).
   - Puerto `Gi0/2`: PC receptor MLLP independiente (o VM separada corriendo `mllp_receiver.py` en puerto `1550`) + Kali (`192.168.5.160`).
   - Puerto `Gi0/3`: Raspberry Pi conectada por **Ethernet cableado (`eth0`)**, **sin** `mllp-receiver` corriendo en la Pi.
2. **Configuración SPAN en el switch (ejemplo Cisco IOS):**
   ```text
   configure terminal
   monitor session 1 source interface Gi0/1 both
   monitor session 1 destination interface Gi0/3
   end
   show monitor session 1
   ```
3. **Ejecución pasiva en la Raspberry Pi (`eth0` en modo promiscuo):**
   ```bash
   # Detener mllp-receiver en la Pi para garantizar modo 100 % pasivo:
   sudo systemctl stop mllp-receiver
   sudo ip link set eth0 up promisc on

   # Arrancar detect_live.py escuchando eth0 (SPAN):
   CAPTURE_INTERFACE=eth0 WATO_IP=192.168.5.114 \
     sudo -E docker compose -f deploy/docker/raspberry/docker-compose.yml up -d --force-recreate
   ```
4. **Prueba de 10 minutos:**
   - 5 min solo tráfico benigno WATO → Receptor independiente: confirmar `0` alertas en la Pi y `0` pérdida de ACK aunque se apague el contenedor de la Pi (**fail-open físico demostrado**).
   - 1 campaña completa A01–A16 (sin A14) desde Kali hacia el receptor independiente con `--ground-truth`: confirmar captura pasiva y detección por `detect_live.py` sobre el puerto espejo.
5. Guardar PCAP, `alerts.jsonl`, `detect_live_summary.json`, `ground_truth.jsonl` y captura de `show monitor session 1`.

### Opción C — Captura clínica nueva de 15 minutos en el HUSI (WATO EX-35 real para H3 verdadero) (~20 min)

Actualmente H3 (`0` FP) se midió sobre las mismas capturas usadas para construir `baseline.yaml` v1.1. Una captura nueva independiente (**hold-out**) sin tocar `baseline.yaml` ni `rules.yaml` cierra la objeción de circularidad de H3:

1. En el Centro de Simulación del HUSI (sin pacientes, pulmón de prueba):
   - Capturar **5 min en `STANDBY`** y **10 min en `RUNNING`** (preferiblemente alternando al menos 2 modos ventilatorios y, si es posible, una transición `RUNNING → STANDBY` para verificar el estado `NO_VERIFICADO` de `RF-03`).
   - Comando de captura: `sudo tcpdump -i eth0 -w evidence_raw/husi_holdout_202611XX.pcap tcp port 1550`
2. **NO modificar** `src/config/baseline.yaml` ni `src/config/rules.yaml`.
3. Ejecutar el detector offline sobre la captura nueva:
   ```bash
   .venv/bin/python detect_pcap.py \
     --pcap evidence_raw/husi_holdout_202611XX.pcap \
     --outdir analysis_output/validation/h3_holdout_202611XX \
     --label HUSI_HOLDOUT
   ```
4. Reportar el número real de mensajes analizados y la tasa real de falsos positivos (con intervalo de Wilson al 95 %), sin ocultar ningún falso positivo que aparezca.

---

## 6. Paso 4 — Empaquetado, sellado SHA-256 y actualización documental final

Cuando termine las pruebas en hardware:

1. **Guardar resultados en el repositorio** (fuera de `runs/`, que está en `.gitignore`):
   - Corrida de 30 min en Pi: `deploy/medicion/resultados/v56_pi_<YYYYMMDD>/` (CSV, `pi_v56_resumen.md`, SVGs, `latency_pi_v56.json`, `detect_live_summary.json`, `evaluation_hardware.json`, `SHA256SUMS.txt` local).
   - Si corrió Pi 4/5, SPAN o HUSI hold-out: guardar sus JSON/resúmenes en `analysis_output/validation/<nombre_experimento>/`.
2. **Re-sellar `analysis_output/validation/SHA256SUMS.txt`** incluyendo únicamente los archivos versionados en Git (`git ls-files analysis_output/validation/`):
   ```bash
   cd analysis_output/validation
   git ls-files . | grep -v '^SHA256SUMS.txt$' | LC_ALL=C sort | xargs sha256sum > SHA256SUMS.txt
   sha256sum -c SHA256SUMS.txt | tail -n 5
   ```
3. **Qué secciones actualizar en los documentos (v5.6 → v5.7) con los datos reales obtenidos:**
   - `Memoria_TG_Diligenciada_Final.docx`: Resumen/Abstract, Capítulo VII (secciones 4, 5, 6 y Amenazas a la Validez), Capítulo VIII (Conclusiones/Trabajos Futuros) y Anexo 2 (nuevo conteo de archivos en `SHA256SUMS.txt`).
   - `SRS_Diligenciado_Final.docx`: Sección 2.1.6 (pendiente RSS real en Pi), Tabla 16 (`RD-01`, `RD-03`, `RD-04`) y tablas de sello (`RF-04`).
   - `SDD_Diligenciado_Final.docx`: Secciones 6.2, 6.3 y 7.3.
   - `PMP_Diligenciado_Final.docx`: Tabla 6 y Sección 12.3.
   - `Documento_Control_Calidad_G18.docx` y `Anexo_2_SHA256.docx`: Tablas 5, 6, 7, 8, Figura 1 nueva (curva plana post-D-02) y manifiesto actualizado.

---

## 7. Paso 5 — Cierre administrativo obligatorio: aprobación de `CC-01`

Actualmente `CC-01` (ajuste de título y objetivo general a detector pasivo/en vivo de anomalías de protocolo) figura honestamente como **pendiente del visto bueno del director** en:
- `Memoria_TG_Diligenciada_Final.docx` (Sección II.1 / alcance)
- `PMP_Diligenciado_Final.docx` (Sección 6 / control de cambios)

**Acción inmediata:** Enviar correo al **Ing. Jhon Alberto Talero Patiarroyo** solicitando su aprobación formal por escrito de la Solicitud de Cambio `CC-01` (adjuntando el texto exacto del nuevo título y objetivo general que ya figuran en la portada de Memoria, SRS, SDD y PMP v5.6).  
Una vez recibido su correo/acta de aprobación, registrar fecha y medio de aprobación en Memoria y PMP y archivar el soporte en la carpeta de entrega.
