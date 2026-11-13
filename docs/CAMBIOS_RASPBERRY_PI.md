# Diferencias de la rama `PruebasRaspi` respecto a `main`

Esta rama adapta el despliegue para ejecutar el detector en una Raspberry Pi
física y recibir tráfico del simulador WATO ubicado en otro equipo de la red
aislada.

## Topología y direcciones usadas

| Componente | Dirección |
|---|---|
| Simulador WATO remoto | `192.168.5.114` |
| Raspberry Pi, receptor/detector | `192.168.5.134` |
| Puerto MLLP | `1550/tcp` |

El flujo es:

```text
192.168.5.114  ── TCP/MLLP ──>  192.168.5.134:1550
```

## Cambios realizados

### Allowlist de IPs

Se agregó `192.168.5.114` a:

```yaml
baseline.yaml
network_parameters:
  allowed_ips:
```

La allowlist debe contener IPs exactas, sin CIDR. Las IPs autorizadas se
mantienen en `baseline.yaml`, en `network_parameters.allowed_ips`.

### Firewall de la Raspberry Pi

`deploy/pi/02_red_aislada.sh` ahora:

- Permite el tráfico entrante al puerto `1550/tcp` únicamente desde
  `192.168.5.114`.
- Usa la interfaz indicada por `LAB_IFACE`; si no se define, utiliza `eth0`.
- Mantiene bloqueadas las conexiones entrantes y salientes por defecto.
- Recomienda agregar una regla SSH específica antes de activar UFW, solo para
  una IP de administración conocida.

La regla aplicada es equivalente a:

```bash
sudo ufw allow in on eth0 from 192.168.5.114 to any port 1550 proto tcp
```

### Detector en línea

Antes escuchaba únicamente en `127.0.0.1:1550`. Ahora escucha en
`0.0.0.0:1550` para aceptar conexiones del simulador WATO remoto.

El cambio se aplica en:

- `deploy/pi/04_detector_online.sh`
- `deploy/pi/mllp-receiver.service`
- `docs/RASPBERRY_PI_SETUP.md`
- `deploy/pi/README.md`

### Servicio systemd

El servicio `mllp-receiver` ahora:

- Escucha en `0.0.0.0:1550`.
- Se ejecuta con el usuario `tesis` en lugar de `pi`.

El script `deploy/pi/03_instalar_servicio.sh` reemplaza automáticamente
`/home/pi/wato` por la ruta real del repositorio al instalar la unidad.

### Generación de configuración de despliegue

`deploy/receptor/make_deploy_settings.py` corrige la ruta raíz del repositorio:

```python
ROOT = pathlib.Path(__file__).resolve().parents[2]
```

Esto permite localizar correctamente `src/config/settings.yaml` y
`LAB_ONLY.marker` desde `deploy/receptor/`.

### Documentación y operación

La documentación de Raspberry Pi ahora describe el modo remoto:

1. El receptor se ejecuta en la Raspberry Pi.
2. El tráfico benigno se envía desde el equipo WATO
   (`192.168.5.114`).
3. La Raspberry Pi física no ejecuta `wato_emulator.py`.
4. `deploy/pi/pi_detector_docker.ps1` no se utiliza en este escenario físico.

Desde el equipo remoto se puede enviar tráfico con:

```powershell
.\deploy\wato\wato.ps1 `
  -TargetHost 192.168.5.134 `
  -Port 1550 `
  -Count 10 `
  -Interval 10 `
  -State STANDBY
```

En la Raspberry Pi, el detector en línea se inicia con:

```bash
./deploy/pi/04_detector_online.sh
```

La alternativa persistente es instalar el servicio:

```bash
./deploy/pi/03_instalar_servicio.sh
journalctl -u mllp-receiver -f
```
