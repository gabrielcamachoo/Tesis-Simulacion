# Despliegue en Raspberry Pi (flujo Windows -> Pi física)

Este flujo es **remoto** y sin Docker:

- PC Windows con emulador WATO (IP variable por prueba; ejemplo validado `192.168.5.114`)
- Raspberry Pi con receptor/detector (IP configurable; ejemplo validado `192.168.5.134`)
- Transporte `TCP/MLLP` puerto `1550`

```text
Windows (wato_emulator.py / deploy/wato/wato.ps1)
        -> Raspberry Pi (mllp_receiver.py + detector) :1550
```

## Qué script usar en la Pi

| Script | Propósito |
|---|---|
| `01_instalar.sh` | prepara `.venv` y dependencias |
| `03_instalar_servicio.sh` | instala `mllp-receiver.service` con usuario/ruta reales |
| `07_preparar_prueba_remota.sh` | automatiza baseline allowlist + UFW exacto + systemd + verificaciones |
| `04_detector_online.sh` | ejecución manual foreground del receptor (si no usas systemd) |

`deploy/pi/pi_detector_docker.ps1` **no aplica** para este flujo con Pi física.

## Ejecución recomendada (Pi)

```bash
cd /home/tesis/Tesis-Simulacion
git fetch origin
git switch PruebasRaspi
git pull --ff-only origin PruebasRaspi

sudo bash deploy/pi/07_preparar_prueba_remota.sh \
  --wato-ip 192.168.5.114 \
  --iface eth0 \
  --service-user tesis \
  --repo-path /home/tesis/Tesis-Simulacion \
  --pi-ip 192.168.5.134
```

Opcional para no perder SSH al endurecer reglas:

```bash
sudo bash deploy/pi/07_preparar_prueba_remota.sh \
  --wato-ip 192.168.5.114 \
  --admin-ip <IP_ADMIN_SSH>
```

## Ejecución en Windows

Desde PowerShell (en el repo local del PC):

```powershell
.\deploy\wato\probar_pi.ps1 `
  -PiHost 192.168.5.134 `
  -Port 1550 `
  -Count 10 `
  -Interval 10 `
  -State STANDBY
```

Solo conectividad:

```powershell
.\deploy\wato\probar_pi.ps1 -PiHost 192.168.5.134 -ConnectivityOnly
```

## Alta/baja de IP del PC de prueba

1. `baseline.yaml` -> `network_parameters.allowed_ips` (IPv4 exacta, sin CIDR)
2. Regla UFW exacta al puerto 1550 para esa IP

Alta manual rápida:

```bash
sudo ufw allow in on eth0 from <IP_PC> to any port 1550 proto tcp
```

Baja de IP vieja:

```bash
# baseline.yaml -> eliminar solo la IP exacta en network_parameters.allowed_ips
sudo ufw status numbered
sudo ufw delete <NUMERO_REGLA>
```

Guía detallada completa: `docs/RASPBERRY_PI_SETUP.md`.
