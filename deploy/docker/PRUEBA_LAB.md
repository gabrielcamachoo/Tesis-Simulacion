# Prueba del laboratorio — comandos por máquina

Topología (opción A): la Raspberry Pi es el receptor MLLP y detecta lo que le
llega. Detalle y limitaciones en `deploy/docker/README.md`.

```text
 PC Windows "WATO" 192.168.5.114 ── benigno ──┐
                                              ├──► Pi 192.168.5.134:1550  (receptor + detect_live en wlan0)
 Kali (VM en puente) 192.168.5.x ── ataques ──┘
```

| Máquina | IP | Qué corre |
|---|---|---|
| Raspberry Pi | `192.168.5.134` | `mllp-receiver.service` + contenedor `pi-mllp-detector` |
| PC Windows (simwato) | `192.168.5.114` | Contenedor `wato-benign` (emisor WATO) |
| Kali | `192.168.5.x` propia | Generador de ataques A01–A16 |

Orden: **Kali (puente) → Pi → PC → Kali (ataque)**.

---

## 1. Kali — adaptador puente y limpieza

En VirtualBox (PC Windows), con Kali **apagada**:
**Configuración → Red → Adaptador 1 → Conectado a: Adaptador puente →
Nombre: Killer E2600 Gigabit Ethernet Controller** (la tarjeta del PC con `192.168.5.114`).

Encender Kali y, en `~/Tesis-Simulacion`:

```bash
# Bajar contenedores anteriores
docker ps -a
docker compose -f deploy/docker/simatacante/docker-compose.yml down --remove-orphans

# Comprobar IP propia (NO 10.0.2.15) y que llega a la Pi
ip -br addr                      # eth0 -> 192.168.5.x  (anotar: KALI_IP)
sudo dhclient -r eth0 && sudo dhclient eth0   # solo si no tomó 192.168.5.x
nc -vz 192.168.5.134 1550        # open

# Código y imagen
git fetch origin && git checkout fix/topologia-lab
docker compose -f deploy/docker/simatacante/docker-compose.yml build
docker compose -f deploy/docker/simatacante/docker-compose.yml run --rm attacker dry-run   # no envía nada
```

---

## 2. Raspberry Pi — detector en vivo

```bash
ssh tesis@192.168.5.134
cd ~/Tesis-Simulacion
git fetch origin && git checkout fix/topologia-lab
systemctl is-active mllp-receiver          # active

docker compose -f deploy/docker/raspberry/docker-compose.yml down
docker compose -f deploy/docker/raspberry/docker-compose.yml up -d --build
docker logs -f pi-mllp-detector
```

Debe decir `Captura en vivo: interfaz=wlan0`. Cada 30 s sale una línea
`[live] paquetes=… mensajes=… anomalías=… por_regla=… por_ip=…`.

Opcional, en otra terminal SSH (tráfico crudo):

```bash
sudo tcpdump -i wlan0 -nn 'tcp port 1550'
```

---

## 3. PC Windows (simwato) — emisor benigno WATO

PowerShell, dentro del repo:

```powershell
git fetch origin; git checkout fix/topologia-lab
# Bajar lo anterior (incluye el receptor local viejo si estaba arriba)
docker compose -f deploy/docker/simwato/docker-compose.yml --profile receptor-local down
# Levantar el emisor hacia la Pi
docker compose -f deploy/docker/simwato/docker-compose.yml up -d --build
docker compose -f deploy/docker/simwato/docker-compose.yml logs -f wato-benign
```

**Qué se ve:** en el PC, un mensaje con ACK cada 10 s. En la Pi, tras 1–2 min,
`mensajes` sube y `anomalías=0`; en tcpdump `192.168.5.114 > 192.168.5.134.1550`.

---

## 4. Kali — ataque (campaña externa)

Con la Pi y el PC ya arriba.

Ataque corto (un escenario, 3 mensajes):

```bash
LAB_AUTHORIZED=YES python3 anomaly_generator.py --scenario A01 --count 3 \
  --host 192.168.5.134 --port 1550 --config src/config/settings.yaml
```

Campaña completa sin A14:

```bash
TARGET_IP=192.168.5.134 docker compose -f deploy/docker/simatacante/docker-compose.yml run --rm attacker all --exclude-a14
```

**Qué se ve en la Pi:** `anomalías` sube, `por_regla` incluye **R-NET-001** y la
regla del escenario, `por_ip` muestra la **IP de Kali**. En tcpdump,
`<KALI_IP> > 192.168.5.134.1550`.

### Ataques disponibles (A01–A16)

Un escenario suelto se lanza cambiando `--scenario` (y `--count`, máx. el techo de la tabla):

```bash
LAB_AUTHORIZED=YES python3 anomaly_generator.py --scenario A05 --count 3 \
  --host 192.168.5.134 --port 1550 --config src/config/settings.yaml
```

| ID | Qué manda Kali | Regla que debe salir en la Pi | Techo `--count` |
|---|---|---|---|
| A01 | Remitente lógico (MSH-3/MSH-4) desconocido | R-ID-001 | 10 |
| A02 | Número de control (MSH-10) repetido | R-SEQ-001 | 10 |
| A03 | Reenvío de un mensaje previo con número de control nuevo | R-SEQ-002 | 10 |
| A04 | Fecha (MSH-7) que retrocede | R-TIME-001 | 10 |
| A05 | Trama MLLP sin cierre (`0x1C 0x0D`) | R-MLLP-001 | 5 |
| A06 | Bytes basura antes del inicio (`0x0B`) | R-MLLP-001 | 5 |
| A07 | Mensaje sin segmento MSH | R-HL7-001 | 5 |
| A08 | Segmentos en orden inválido | R-HL7-003 | 5 |
| A09 | Tipo de mensaje fuera del baseline (ADT, ORM) | R-HL7-002 | 10 |
| A10 | OBX con tipo de dato inesperado | R-OBX-003 | 10 |
| A11 | OBX con unidad no permitida | R-OBX-002 | 10 |
| A12 | Ráfaga de mensajes (≤20 en 5 s) | R-TIME-002 | 20 |
| A13 | Reconexiones repetidas | R-TIME-002 | 5 |
| A14 | Silencio de 45 s y luego mensaje (tarda; se omite con `--exclude-a14`) | R-TIME-002 | 3 |
| A15 | Mensaje gigante (~32 KiB) | R-MLLP-001 | 5 |
| A16 | Cambio de identidad lógica a mitad de sesión | R-ID-001 | 5 |

- En la **campaña externa** cada mensaje de Kali además dispara **R-NET-001** (IP no autorizada).
- Modo **ransomware** (solo A01, A05, A06, A13, A14, A16):
  `TARGET_IP=192.168.5.134 docker compose -f deploy/docker/simatacante/docker-compose.yml run --rm attacker ransomware`
- El ground truth de cada corrida queda en `runs/` (Python) o `runs/docker-attacker/` (Docker).
- Detalle completo (STRIDE, MITRE, techos): `docs/ATTACK_SCENARIOS.md`.

---

## 5. Campaña interna (Kali autorizada)

En la Pi:

```bash
docker compose -f deploy/docker/raspberry/docker-compose.yml down
EXTRA_ALLOWED_IPS=<KALI_IP> docker compose -f deploy/docker/raspberry/docker-compose.yml up -d
docker logs -f pi-mllp-detector      # "IPs autorizadas extra (solo esta corrida): <KALI_IP>"
```

Repetir el ataque del paso 4. **Qué se ve:** ya **no** sale R-NET-001; solo
reglas de contenido (R-MLLP, R-HL7, R-OBX, R-SEQ, R-TIME, R-ID).

---

## 6. Silencio del WATO

En el PC:

```powershell
docker compose -f deploy/docker/simwato/docker-compose.yml stop wato-benign
```

**Qué se ve en la Pi:** ~15 s después, **R-TIME-002** por silencio.

---

## 7. Cierre y resumen (Pi)

```bash
docker compose -f deploy/docker/raspberry/docker-compose.yml down
ls runs/docker-pi/
cat runs/docker-pi/live_<fecha>/detect_live_summary.json
```

Un `live_<fecha>` por cada `up` (externa e interna). Cada uno trae
`alerts/alerts.jsonl`, `detect_live_summary.json` y `pcap/` con `SHA256SUMS.txt`.

---

## Dónde cambiar las IPs

Todas se pasan como **variable de entorno** al lanzar el comando; el valor
por defecto está en el archivo indicado (editarlo solo si la IP cambia de forma permanente).

| Qué | Máquina | Variable | Default | Archivo (línea) |
|---|---|---|---|---|
| A quién le manda el emisor WATO (IP de la Pi) | PC | `WATO_RECEIVER_HOST` | `192.168.5.134` | `deploy/docker/simwato/docker-compose.yml` (~49) |
| Estado del WATO (`STANDBY` / `RUNNING`) | PC | `WATO_STATE` | `STANDBY` | `deploy/docker/simwato/docker-compose.yml` (~55) |
| Interfaz de captura de la Pi | Pi | `CAPTURE_INTERFACE` | `wlan0` (`eth0` si se cablea) | `deploy/docker/raspberry/docker-compose.yml` (~15) |
| IP de Kali autorizada **solo** en campaña interna | Pi | `EXTRA_ALLOWED_IPS` | vacío | `deploy/docker/raspberry/docker-compose.yml` (~22) |
| Destino de los ataques (IP de la Pi) | Kali | `TARGET_IP` (acepta `WATO_IP`) | `192.168.5.134` | `deploy/docker/simatacante/docker-compose.yml` (~10) |
| Firewall de la Pi: emisor WATO permitido | Pi | `WATO_SIM_IP` | `192.168.5.114` | `deploy/pi/02_red_aislada.sh` (~18) |
| Firewall de la Pi: Kali permitida | Pi | `KALI_IP` | vacío | `deploy/pi/02_red_aislada.sh` (~20) |
| Firewall de la Pi: SSH de administración | Pi | `ADMIN_IP` | vacío | `deploy/pi/02_red_aislada.sh` (~19) |

Cómo pasarlas:

```powershell
# PC Windows (PowerShell)
$env:WATO_RECEIVER_HOST = "192.168.5.134"
docker compose -f deploy/docker/simwato/docker-compose.yml up -d --build
```

```bash
# Pi / Kali (bash): la variable va delante del comando
EXTRA_ALLOWED_IPS=192.168.5.50 docker compose -f deploy/docker/raspberry/docker-compose.yml up -d
TARGET_IP=192.168.5.134 docker compose -f deploy/docker/simatacante/docker-compose.yml run --rm attacker all

# Firewall de la Pi (solo si se activa UFW; hoy está inactivo).
# Por SSH, ADMIN_IP es obligatorio o el script se detiene para no cortar la sesión.
ADMIN_IP=192.168.5.114 KALI_IP=<KALI_IP> bash deploy/pi/02_red_aislada.sh
```

La IP del WATO (`192.168.5.114`) **no** se agrega en la Pi: ya está en las IPs
permitidas del baseline (`baseline.yaml`, `allowed_ips`). No editar ese archivo.
