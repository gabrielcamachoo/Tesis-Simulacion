# Docker por máquina

La topología operativa usa tres equipos físicos:

```text
simatacante 192.168.5.1??  --ataques MLLP-->  simwato 192.168.5.114
                                                        ^
                                                     tráfico observado
                                                        |
                                                    Raspberry Pi 192.168.5.134
                                                  captura + alertas MLLP
```

La Raspberry Pi no abre ni reenvía conexiones al WATO. El atacante solamente
abre conexiones TCP hacia el WATO en el puerto 1550.

## Requisitos previos

En la Pi, el puerto y la interfaz deben tener acceso al tráfico que se desea
observar. Configure SPAN/port mirroring en el switch hacia la interfaz
`eth0`, o TCP redirection/tcpdump del host. La forma exacta depende del switch.

No hay Docker Compose para dos máquinas simulando el mismo host físico:
cada carpeta corresponde a una máquina real.

## Raspberry Pi 192.168.5.134

```bash
cd /home/pi/wato
sudo touch /LAB_ONLY.marker
CAPTURE_INTERFACE=eth0 WATO_IP=192.168.5.114 \
  docker compose -f deploy/docker/raspberry/docker-compose.yml up -d
docker logs -f pi-mllp-detector
```

Los PCAP y alertas quedan en `/lab_output` dentro del contenedor, montado en
`/home/pi/wato/runs/docker-pi`.

## simWATO 192.168.5.114

Iniciar el receptor simulado del dispositivo WATO:

```bash
docker compose -f deploy/docker/simwato/docker-compose.yml up -d wato
```

Iniciar opcionalmente tráfico benigno desde ese mismo equipo:

```bash
docker compose -f deploy/docker/simwato/docker-compose.yml --profile benign run --rm wato-benign
```

## simAtacante Kali

Validar sin enviar tráfico:

```bash
docker compose -f deploy/docker/simatacante/docker-compose.yml run --rm attacker dry-run
```

Campaña completa A01-A16:

```bash
docker compose -f deploy/docker/simatacante/docker-compose.yml run --rm attacker all
```

Campaña ransomware A01/A05/A06/A13/A14/A16:

```bash
docker compose -f deploy/docker/simatacante/docker-compose.yml run --rm attacker ransomware
```
