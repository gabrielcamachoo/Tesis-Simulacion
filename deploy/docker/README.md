# Docker por máquina — topología del laboratorio (Pi como receptor)

Cada bloque se ejecuta **en su propia máquina**. No se levanta un único Compose
para todo.

## Por qué esta topología

El switch del laboratorio (Linksys SE3005 v2) **no es administrable**: no tiene
port mirroring/SPAN. La Pi (Raspberry Pi 3 Model B) está por Wi-Fi (`wlan0`) y
solo ve el tráfico dirigido a ella. Por eso la Pi **es el receptor MLLP** (el
`mllp-receiver.service` de `deploy/pi/`) y `detect_live.py` captura en la misma
Pi el tráfico que le llega.

> **Limitación.** En esta topología la Pi **no es un tap pasivo**: recibe las
> conexiones y responde ACK. El modo pasivo real (Pi en un puerto espejo, sin
> abrir conexiones) solo está validado en simulación (red virtual, ver
> [Resultados](#resultados-de-la-simulación-en-red-virtual-18-11-2026)) y queda
> como trabajo futuro con un switch administrable (p. ej. Netgear GS305E o
> TP-Link TL-SG105E, mirror del puerto del WATO en dirección *Both* hacia la Pi
> cableada en `eth0`). `detect_live.py` es el mismo en los dos casos; solo cambia
> la interfaz.

## Roles

| Máquina | IP | Carpeta | Qué hace |
|---|---|---|---|
| PC Windows "WATO" (emisor benigno) | `192.168.5.114` | `simwato/` | `wato_emulator.py` en Docker, envía a la Pi `192.168.5.134:1550` |
| Kali (VM VirtualBox en **adaptador puente**) | propia `192.168.5.x` | `simatacante/` | `anomaly_generator.py`: tráfico MLLP sintético A01–A16 hacia la Pi, sin malware |
| Raspberry Pi (receptor + detector) | `192.168.5.134` | `deploy/pi/` + `raspberry/` | `mllp-receiver.service` recibe en `:1550`; el contenedor `pi-mllp-detector` corre `detect_live.py` sobre `wlan0` |

```text
 PC Windows 192.168.5.114 ── benigno (WATO) ──┐
                                              ├──► Pi 192.168.5.134:1550  (mllp-receiver.service)
 Kali 192.168.5.x (puente) ── ataques ────────┘        └─ detect_live.py captura wlan0
```

**IP de origen del benigno.** Docker Desktop en Windows hace NAT de salida: el
contenedor sale con `172.18.x.x`, pero la Pi lo ve como `192.168.5.114` (con otro
puerto de origen). Es lo que queremos, porque `.114` está en el baseline.
Verificado el 18-11-2026 con `tcpdump -i wlan0` en la Pi: un contenedor
`172.18.0.4:42392` llegó como `192.168.5.114:39356 > 192.168.5.134:1550`.

## Requisitos (todas las máquinas)

```bash
git clone https://github.com/gabrielcamachoo/Tesis-Simulacion.git
cd Tesis-Simulacion
docker info && docker compose version
sudo touch /LAB_ONLY.marker      # en Linux (Pi y Kali)
```

## 0. Kali en adaptador puente (VirtualBox)

Con Kali en NAT (`10.0.2.15`) todo lo que manda sale con la IP del PC y la Pi no
lo puede distinguir del WATO. Hay que darle IP propia:

1. Apagar la VM de Kali.
2. VirtualBox → Kali → **Configuración → Red → Adaptador 1**.
3. *Conectado a:* **Adaptador puente**. *Nombre:* la tarjeta del PC que tiene
   `192.168.5.114` (en el PC del lab es `Killer E2600 Gigabit Ethernet Controller`).
4. Aceptar y encender Kali.
5. En Kali: `ip -br addr`. Debe salir una IP `192.168.5.x` (no `10.0.2.15`).
   Si no la toma, `sudo dhclient -r eth0 && sudo dhclient eth0`.
6. Anotar esa IP: es `KALI_IP` en los pasos siguientes.

## 1. Raspberry Pi — receptor + detector en vivo

El receptor ya corre como servicio (`deploy/pi/03_instalar_servicio.sh`):

```bash
systemctl is-active mllp-receiver      # active
```

Si se usa firewall (`deploy/pi/02_red_aislada.sh`), Kali debe estar permitido o
su handshake se descarta y el detector solo ve SYN sueltos:

```bash
ADMIN_IP=<IP desde la que haces SSH> KALI_IP=<IP de Kali> bash deploy/pi/02_red_aislada.sh
```

Detector en vivo:

```bash
cd ~/Tesis-Simulacion
docker compose -f deploy/docker/raspberry/docker-compose.yml up -d --build
docker logs -f pi-mllp-detector
```

- `CAPTURE_INTERFACE`: `wlan0` por defecto (la Pi está por Wi-Fi). Si se cablea, `CAPTURE_INTERFACE=eth0`.
- `EXTRA_ALLOWED_IPS`: **vacío** por defecto (campaña externa). En la campaña
  interna se pasa la IP de Kali: `EXTRA_ALLOWED_IPS=<IP de Kali>`. Solo vale para
  esa corrida; no modifica `baseline.yaml`. No hace falta poner `.114`: ya está en
  el baseline.
- Cada 30 s aparece una línea `[live] paquetes=… mensajes=… anomalías=… por_regla=… por_ip=…`.
  Si `paquetes` no sube, no está llegando tráfico al `1550` de la Pi.
- Salidas en `runs/docker-pi/live_<fecha>/`:
  - `alerts/alerts.jsonl`: alertas y mensajes normales.
  - `detect_live_summary.json`: contadores por regla y por IP (se reescribe cada 30 s y al detener).
  - `pcap/`: captura cruda rotada cada hora, con `SHA256SUMS.txt`.

Detener (escribe el resumen final):

```bash
docker compose -f deploy/docker/raspberry/docker-compose.yml down
```

## 2. PC Windows — emisor benigno WATO

```bash
docker compose -f deploy/docker/simwato/docker-compose.yml up -d --build
docker compose -f deploy/docker/simwato/docker-compose.yml logs -f wato-benign
```

Opciones (variables de entorno):

| Variable | Default | Uso |
|---|---|---|
| `WATO_RECEIVER_HOST` | `192.168.5.134` | Receptor MLLP (la Pi) |
| `WATO_STATE` | `STANDBY` | `RUNNING` para ventilación |
| `WATO_VENT_MODE` | `VCV` | En RUNNING: `VCV`, `SIMVVC_PLUS_PS`, `PCV`, `SIMVPC_PLUS_PS`, `PS`, `MANUAL` o `CYCLE` (alterna los 6) |
| `WATO_INTERVAL` | `10.0` | Segundos entre mensajes (el WATO real manda cada 10 s) |
| `WATO_BIND_HOST` | `0.0.0.0` | Interfaz dentro del contenedor |

El emisor no se detiene (`--count 0`, `--max-reconnects 0`): si el receptor se
satura o se cae, reintenta y sigue cuando vuelve.

Receptor local opcional, solo para pruebas en el mismo PC (no participa en la
prueba con la Pi; se publica únicamente en `127.0.0.1`):

```bash
WATO_RECEIVER_HOST=wato docker compose -f deploy/docker/simwato/docker-compose.yml --profile receptor-local up -d --build
```

## 3. Kali — atacante

```bash
docker compose -f deploy/docker/simatacante/docker-compose.yml build
# Validar sin enviar tráfico:
docker compose -f deploy/docker/simatacante/docker-compose.yml run --rm attacker dry-run
# Campaña A01–A16 (A14 dura ~2 min; --exclude-a14 para omitirla):
TARGET_IP=192.168.5.134 docker compose -f deploy/docker/simatacante/docker-compose.yml run --rm attacker all
# Solo los escenarios del ransomware simulado (A01/A05/A06/A13/A14/A16):
TARGET_IP=192.168.5.134 docker compose -f deploy/docker/simatacante/docker-compose.yml run --rm attacker ransomware
```

`TARGET_IP` es el destino (default `192.168.5.134`). `WATO_IP` se sigue
aceptando por compatibilidad. El compose usa `network_mode: host`, así que con
Kali en puente los ataques salen con la IP propia de Kali.

El ground truth queda en `runs/docker-attacker/<corrida>/ground_truth.jsonl`.

## Orden de la prueba

1. Kali en puente (§0) y anotar su IP.
2. Pi (§1): receptor activo y detector en vivo, con `EXTRA_ALLOWED_IPS` vacío.
3. PC (§2): emisor benigno.
4. Esperar 1–2 minutos. En `docker logs pi-mllp-detector` deben subir `paquetes`
   y `mensajes`, `por_ip` solo con `192.168.5.114` y **0 anomalías**.
5. **Campaña externa:** ataque desde Kali (§3). En la Pi deben aparecer las
   alertas de contenido de cada escenario **y R-NET-001** con la IP de Kali en
   `por_ip`.
6. **Campaña interna:** detener el detector, levantarlo con
   `EXTRA_ALLOWED_IPS=<IP de Kali>` y repetir el ataque. Ya no debe salir
   R-NET-001 por Kali; lo detectan solo las reglas de contenido.
7. Opcional: detener `wato-benign` en el PC. A los ~15 s la Pi debe dar
   **R-TIME-002 por silencio**.
8. Detener la Pi y llevar `runs/docker-pi/live_*` y el ground truth de Kali a
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
| **A. Atacante externo** | vacío | Kali no está autorizado: **todo** lo suyo puede disparar R-NET-001, además de la regla de contenido de cada escenario |
| **B. Atacante interno** | IP de Kali | Kali parece un equipo autorizado: lo detectan **solo** las reglas de contenido (MLLP, HL7, OBX, secuencia, tiempo, identidad) |

Repórtelas por separado. En la campaña A, un 100 % de detección no prueba las
reglas de contenido, porque R-NET-001 marca hasta un mensaje normal enviado
desde la IP de Kali. Use `alertas_por_ip_y_regla` del resumen.

Comportamientos esperados (no son fallas):

- **R-TIME-002 en el emisor benigno durante el ataque.** La cadencia es global
  del canal: si Kali inyecta un mensaje entre dos del WATO, el siguiente mensaje
  legítimo llega "demasiado pronto" respecto al inyectado. En la red real solo
  el WATO transmite, así que es un síntoma de la inyección, pero `evaluate.py`
  lo cuenta como FP del emisor.
- **R-SEQ-001 después de que el receptor se cae.** El emisor reenvía el mensaje
  que no recibió ACK con el mismo MSH-10, como lo hace HL7. La Pi ve dos veces
  el mismo número de control.
- **R-TIME-002 por silencio al final**, si se apaga el emisor (paso 7).

## Simulación de esta topología en red virtual (18-11-2026)

Misma idea que la siguiente sección, pero con la Pi como receptor: namespaces
`pi` (`.134`: `mllp_receiver.py` + `detect_live.py` sobre su propia interfaz),
`pc` (`.114`: emisor STANDBY cada 10 s) y `kali` (`.50`), unidos por un bridge.
Campañas A01–A16 sin A14, `--count 3` (64 inyecciones). **Simulación, no hardware
real.**

| Prueba | Resultado |
|---|---|
| Benigno solo, 60 s | 7 mensajes, 0 anomalías |
| Campaña externa (`EXTRA_ALLOWED_IPS` vacío) | 64/64 detectadas (recall 1.0, F1 0.985); R-NET-001 ×63, todas sobre `192.168.5.50` |
| Campaña interna (`EXTRA_ALLOWED_IPS=192.168.5.50`) | 64/64 detectadas sin ninguna R-NET-001 (recall 1.0, F1 0.985) |
| Falsos positivos (cada campaña) | 2, ambos R-TIME-002 del emisor `.114` durante el ataque (efecto de cadencia descrito arriba) |
| Emisor apagado | 1 R-TIME-002 por silencio (vigilante E3) |
| Emisor en toda la corrida | 0 timeouts de ACK, 0 reconexiones, 0 errores |

## Resultados de la simulación en red virtual (18-11-2026)

> Estos números salieron de una **simulación en red virtual** (Linux, namespaces
> de red + un bridge `br-lab` como switch con todo el tráfico visible), con la
> topología **pasiva por espejo**: la estación `.114` en el host, emisor y Kali
> en namespaces separados y `detect_live.py` capturando el bridge con tcpdump
> real. **No son del hardware real** y no corresponden a la topología de la Pi
> como receptor descrita arriba.

| Prueba | Resultado |
|---|---|
| Benigno STANDBY solo, 60 s | 0 anomalías |
| Benigno RUNNING alternando los 6 modos, 12 mensajes | 12/12 NORMAL |
| Campaña A (externo), A01–A16 sin A14, 2 por escenario | 51/51 inyecciones detectadas (recall 1.0); Kali además marcado 51 veces por R-NET-001 |
| Campaña B (interno), mismo ataque con Kali autorizado | 51/51 detectadas **solo por reglas de contenido** (recall 1.0, F1 0.97). A05 y A06 por R-MLLP-001 (framing visto desde la red) |
| Falsos positivos de `evaluate.py` en la campaña B | 3, todos explicados: 1 R-TIME-002 en un mensaje de Kali justo después de uno del WATO, 1 R-TIME-002 en el emisor benigno durante el ataque y 1 por silencio al apagar el emisor. Fuera del ataque, el emisor benigno no tuvo ninguna alerta |
| Emisor durante el ataque | 15/15 mensajes con ACK, 0 reintentos, siguió vivo |
| Estación caída 15 s | El emisor reintentó 6 veces y siguió; 0 errores |
| Emisor apagado | 1 alerta R-TIME-002 por silencio a los 15 s |
| Pcap de evidencia | Rotados con `SHA256SUMS.txt` |

Falta correr la prueba en las máquinas reales con esta topología y medir la
latencia H2 en la Pi (`python latency_bench.py` dentro del contenedor o en la Pi).
