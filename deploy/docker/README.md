# Docker por máquina — prueba final con la Pi en modo pasivo

Cada bloque se ejecuta **en su propia máquina física**. No se levanta un único
Compose para todo: cada equipo construye y corre su contenedor con
`network_mode: host`.

## Roles

| Máquina | IP | Carpeta | Qué hace |
|---|---|---|---|
| Estación receptora ("simWATO") | `192.168.5.114` | `simwato/` | Corre `mllp_receiver.py` en `0.0.0.0:1550`: hace de estación central que recibe el HL7 y responde ACK |
| Emisor WATO (benigno) | otra máquina, p. ej. `192.168.5.115` | `simemisor/` | Corre `wato_emulator.py` **sin parar** (`--count 0`) y sin rendirse si el receptor se cae (`--max-reconnects 0`) |
| Kali (atacante) | p. ej. `192.168.5.50` | `simatacante/` | Corre `anomaly_generator.py`: tráfico MLLP sintético A01–A16, sin malware |
| Raspberry Pi (detector pasivo) | `192.168.5.134` | `raspberry/` | Escucha el **puerto espejo** del switch con `detect_live.py`; no abre ni reenvía conexiones |

```text
 Emisor WATO ──MLLP──┐
 (192.168.5.115)     ├──► switch ──► Estación 192.168.5.114:1550
 Kali ───────MLLP────┘       │
 (192.168.5.50)              └── puerto espejo ──► Raspberry Pi (captura)
```

**El emisor benigno tiene que ir en una máquina distinta de la estación.** Si
corre en la misma, manda a `127.0.0.1`, el tráfico no pasa por el switch y la
Pi no lo ve. Puede ir en el equipo de Kali (ver §3).

## Requisitos (todas las máquinas)

```bash
git clone https://github.com/gabrielcamachoo/Tesis-Simulacion.git
cd Tesis-Simulacion
docker info && docker compose version
sudo touch /LAB_ONLY.marker
```

En el switch, configure el puerto de la Pi como **mirror/SPAN** del puerto de
la estación. Sin eso la Pi no ve nada.

## 1. Raspberry Pi — detector pasivo en vivo

```bash
cd ~/Tesis-Simulacion
CAPTURE_INTERFACE=eth0 \
EXTRA_ALLOWED_IPS=192.168.5.115 \
  docker compose -f deploy/docker/raspberry/docker-compose.yml up -d --build
docker logs -f pi-mllp-detector
```

- `EXTRA_ALLOWED_IPS`: IP del emisor WATO benigno. Se autoriza **solo para esta
  corrida**; `baseline.yaml` no cambia.
- Cada 30 s aparece una línea `[live] paquetes=… mensajes=… anomalías=… por_regla=… por_ip=…`.
  Si `paquetes` no sube, el puerto espejo no está llegando a la Pi.
- Salidas en `runs/docker-pi/live_<fecha>/`:
  - `alerts/alerts.jsonl`: alertas y mensajes normales.
  - `detect_live_summary.json`: contadores por regla y por IP (se reescribe cada 30 s y al detener).
  - `pcap/`: captura cruda rotada cada hora, con `SHA256SUMS.txt`.

Detener (escribe el resumen final):

```bash
docker compose -f deploy/docker/raspberry/docker-compose.yml down
```

## 2. Estación receptora ("simWATO") — `192.168.5.114`

```bash
docker compose -f deploy/docker/simwato/docker-compose.yml up -d --build wato
docker compose -f deploy/docker/simwato/docker-compose.yml logs -f wato
```

## 3. Emisor WATO benigno — otra máquina

```bash
WATO_RECEIVER_HOST=192.168.5.114 \
  docker compose -f deploy/docker/simemisor/docker-compose.yml up -d --build
docker logs -f simemisor-wato
```

Opciones (variables de entorno):

| Variable | Default | Uso |
|---|---|---|
| `WATO_STATE` | `STANDBY` | `RUNNING` para ventilación |
| `WATO_VENT_MODE` | `VCV` | En RUNNING: `VCV`, `SIMVVC_PLUS_PS`, `PCV`, `SIMVPC_PLUS_PS`, `PS`, `MANUAL` o `CYCLE` (alterna los 6) |
| `WATO_INTERVAL` | `10.0` | Segundos entre mensajes (el WATO real manda cada 10 s) |
| `BIND_IP` | `0.0.0.0` | IP de origen del emisor |

**Si el emisor va en el mismo equipo de Kali**, dele una IP propia para que
la Pi distinga el tráfico benigno del ataque:

```bash
sudo ip addr add 192.168.5.115/24 dev eth0
BIND_IP=192.168.5.115 WATO_RECEIVER_HOST=192.168.5.114 \
  docker compose -f deploy/docker/simemisor/docker-compose.yml up -d --build
```

El emisor no se detiene: si el ataque satura la estación (máx. 5 conexiones),
reintenta cada 2 s y sigue cuando la estación se libera.

## 4. Kali — atacante

```bash
docker compose -f deploy/docker/simatacante/docker-compose.yml build
# Validar sin enviar tráfico:
docker compose -f deploy/docker/simatacante/docker-compose.yml run --rm attacker dry-run
# Campaña A01–A16 (A14 dura ~2 min; --exclude-a14 para omitirla):
WATO_IP=192.168.5.114 docker compose -f deploy/docker/simatacante/docker-compose.yml run --rm attacker all
# Solo los escenarios del ransomware simulado (A01/A05/A06/A13/A14/A16):
WATO_IP=192.168.5.114 docker compose -f deploy/docker/simatacante/docker-compose.yml run --rm attacker ransomware
```

El ground truth queda en `runs/docker-attacker/<corrida>/ground_truth.jsonl`.

## Orden de la prueba

1. Pi (§1) y estación (§2).
2. Emisor benigno (§3). Esperar 1–2 minutos: en la Pi deben subir `mensajes` y
   `normales` con `anomalías=0`.
3. Ataque desde Kali (§4).
4. Dejar el emisor 1–2 minutos más: debe seguir enviando (ver `docker logs`).
5. Opcional: detener el emisor; a los ~15 s la Pi debe dar **R-TIME-002 por
   silencio** (canal caído).
6. Detener la Pi y llevar `runs/docker-pi/live_*` y el ground truth de Kali a
   una sola máquina para evaluar:

```bash
LAB_AUTHORIZED=YES python evaluate.py \
  --ground-truth runs/docker-attacker/<corrida>/ground_truth.jsonl \
  --alerts runs/docker-pi/live_<fecha>/alerts/alerts.jsonl \
  --out runs/docker-pi/live_<fecha>/evaluation.json
```

## Dos campañas y cómo leer los resultados

| Campaña | `EXTRA_ALLOWED_IPS` en la Pi | Qué demuestra |
|---|---|---|
| **A. Atacante externo** | solo el emisor (`192.168.5.115`) | Kali no está autorizado: **todo** lo suyo dispara R-NET-001, además de la regla de contenido de cada escenario |
| **B. Atacante interno** | emisor y Kali (`192.168.5.115,192.168.5.50`) | Kali parece un equipo autorizado: lo detectan **solo** las reglas de contenido (MLLP, HL7, OBX, secuencia, tiempo, identidad) |

Repórtelas por separado. En la campaña A, un 100 % de detección no prueba las
reglas de contenido, porque R-NET-001 marca hasta un mensaje normal enviado
desde la IP de Kali. Use `alertas_por_ip_y_regla` del resumen.

Comportamientos esperados (no son fallas):

- **R-TIME-002 en el emisor benigno durante el ataque.** La cadencia es global
  del canal: si Kali inyecta un mensaje entre dos del WATO, el siguiente mensaje
  legítimo llega "demasiado pronto" respecto al inyectado. En la red real solo
  el WATO transmite, así que es un síntoma de la inyección, pero `evaluate.py`
  lo cuenta como FP del emisor.
- **R-SEQ-001 después de que la estación se cae.** El emisor reenvía el mensaje
  que no recibió ACK con el mismo MSH-10, como lo hace HL7. La Pi ve dos veces
  el mismo número de control.
- **R-TIME-002 por silencio al final**, si se apaga el emisor (paso 5).

## Resultados de la simulación (18-11-2026)

Antes de llevarlo a las máquinas, el flujo completo se probó en una red virtual
(un bridge como switch, la estación en el host, emisor y Kali en namespaces de
red separados y `detect_live.py` capturando el bridge con tcpdump real):

| Prueba | Resultado |
|---|---|
| Benigno STANDBY solo, 60 s | 0 anomalías |
| Benigno RUNNING alternando los 6 modos, 12 mensajes | 12/12 NORMAL |
| Campaña A (externo), A01–A16 sin A14, 2 por escenario | 51/51 inyecciones detectadas (recall 1.0); Kali además marcado 51 veces por R-NET-001 |
| Campaña B (interno), mismo ataque con Kali autorizado | 51/51 detectadas **solo por reglas de contenido** (recall 1.0, F1 0.97). A05 y A06 por R-MLLP-001 (framing visto desde la red) |
| Falsos positivos de `evaluate.py` en la campaña B | 3, todos explicados: 1 R-TIME-002 en un mensaje de Kali justo después de uno del WATO, 1 R-TIME-002 en el emisor benigno durante el ataque y 1 por silencio al apagar el emisor (paso 5). Fuera del ataque, el emisor benigno no tuvo ninguna alerta |
| Emisor durante el ataque | 15/15 mensajes con ACK, 0 reintentos, siguió vivo |
| Estación caída 15 s | El emisor reintentó 6 veces y siguió; 0 errores |
| Emisor apagado | 1 alerta R-TIME-002 por silencio a los 15 s |
| Pcap de evidencia | Rotados con `SHA256SUMS.txt` |

Falta repetirlo en las máquinas reales y medir la latencia H2 en la Pi
(`python latency_bench.py` dentro del contenedor o en la Pi).
