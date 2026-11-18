# Docker por máquina

Estos comandos se ejecutan **por separado en cada equipo físico**. No se debe
levantar un único Compose para los tres roles: cada máquina construye y ejecuta
su propio contenedor con `network_mode: host`.

La topología operativa usa tres equipos físicos:

```text
simatacante (Kali)  --ataques MLLP:1550-->  simWATO 192.168.5.114
                                                ^
                                             tráfico observado
                                                |
                                    Raspberry Pi 192.168.5.134
                                      captura + alertas MLLP
```

La Raspberry Pi no abre ni reenvía conexiones al WATO. El atacante solamente
abre conexiones TCP hacia el WATO en el puerto 1550.

## Requisitos previos

En **cada equipo**:

```bash
git clone https://github.com/gabrielcamachoo/Tesis-Simulacion.git
cd Tesis-Simulacion
```

Se requiere Docker Engine y el plugin Docker Compose. Verifique:

```bash
docker info
docker compose version
```

En la Pi, la interfaz debe recibir una copia del tráfico mediante SPAN/port
mirroring del switch. Sin port mirroring, la captura pasiva no verá los
paquetes entre Kali y WATO.

## 1. Raspberry Pi — `192.168.5.134`

Conecte la interfaz de captura al puerto configurado como mirror/SPAN. Cambie
`eth0` si la interfaz tiene otro nombre:

```bash
cd /home/pi/wato
sudo touch /LAB_ONLY.marker
docker build -t tesis-pi-detector \
  -f deploy/docker/raspberry/Dockerfile .
CAPTURE_INTERFACE=eth0 WATO_IP=192.168.5.114 \
  docker compose -f deploy/docker/raspberry/docker-compose.yml up -d --build
```

Ver captura y alertas:

```bash
docker logs -f pi-mllp-detector
find runs/docker-pi -maxdepth 3 -type f -print
```

Detener:

```bash
docker compose -f deploy/docker/raspberry/docker-compose.yml down
```

Los PCAP y alertas quedan en `runs/docker-pi`.

## 2. simWATO — `192.168.5.114`

El contenedor del simWATO escucha en `0.0.0.0:1550`. Construir e iniciar:

```bash
cd /ruta/Tesis-Simulacion
sudo touch /LAB_ONLY.marker
docker compose -f deploy/docker/simwato/docker-compose.yml up -d --build wato
docker logs -f simwato-wato-1
```

En otra terminal del simWATO, generar tráfico benigno local contra su receptor:

```bash
docker compose -f deploy/docker/simwato/docker-compose.yml \
  --profile benign run --rm wato-benign
```

Detener:

```bash
docker compose -f deploy/docker/simwato/docker-compose.yml down
```

## 3. simAtacante — Kali

Kali **no escucha** en el puerto 1550. El contenedor abre conexiones salientes
hacia `192.168.5.114:1550`.

Construir la imagen:

```bash
cd /ruta/Tesis-Simulacion
docker compose -f deploy/docker/simatacante/docker-compose.yml build
```

Validar sin enviar tráfico:

```bash
docker compose -f deploy/docker/simatacante/docker-compose.yml \
  run --rm attacker dry-run
```

Campaña completa A01-A16:

```bash
WATO_IP=192.168.5.114 MLLP_PORT=1550 \
  docker compose -f deploy/docker/simatacante/docker-compose.yml \
  run --rm attacker all
```

Campaña ransomware A01/A05/A06/A13/A14/A16:

```bash
WATO_IP=192.168.5.114 MLLP_PORT=1550 \
  docker compose -f deploy/docker/simatacante/docker-compose.yml \
  run --rm attacker ransomware
```

Para excluir A14 y evitar sus silencios de 45 segundos:

```bash
docker compose -f deploy/docker/simatacante/docker-compose.yml \
  run --rm attacker all --exclude-a14
```

Las evidencias del atacante quedan en `runs/docker-attacker`.

## Orden recomendado

1. Iniciar el contenedor de captura en la Raspberry Pi.
2. Iniciar el receptor simulado en simWATO.
3. Ejecutar tráfico benigno desde simWATO.
4. Ejecutar la campaña desde Kali.
5. Revisar `runs/docker-pi` en la Raspberry Pi.
