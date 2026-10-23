# Guía operativa Raspberry Pi (flujo WATO remoto desde Windows)

## 1) Topología y alcance real

Flujo soportado para esta fase:

```text
PC Windows (WATO emulado, IP variable)
    -> Raspberry Pi física (receptor/detector)
    -> TCP/MLLP puerto 1550
```

Valores de la prueba validada:

- Pi: `192.168.5.134`
- PC Windows WATO: `192.168.5.114` (esta IP puede cambiar entre pruebas)
- Puerto: `1550/tcp`

> Importante:
> - `wato_emulator.py` y `deploy/wato/wato.ps1` se ejecutan **solo en Windows**.
> - En la Pi se ejecuta el receptor/detector (`mllp_receiver.py`).
> - `deploy/pi/pi_detector_docker.ps1` **no aplica** para este flujo.

---

## 2) Pasos en la Raspberry Pi (manual y verificable)

### 2.1 Actualizar repo y validar contexto

```bash
cd /home/tesis/Tesis-Simulacion
git fetch origin
git switch PruebasRaspi
git pull --ff-only origin PruebasRaspi

ip -4 addr
```

Si deseas validación estricta del lab, confirma que la interfaz de pruebas tenga la IP esperada (ejemplo `192.168.5.134`).

### 2.2 Preparar marcador y entorno (sin ejecutar el simulador)

```bash
cd /home/tesis/Tesis-Simulacion

test -d .venv && echo ".venv OK" || echo "Falta .venv"
test -f LAB_ONLY.marker && echo "LAB_ONLY.marker (repo) OK" || echo "Falta LAB_ONLY.marker en repo"

sudo touch /LAB_ONLY.marker
```

Si falta `.venv`:

```bash
sudo apt-get update
sudo apt-get install -y python3 python3-venv python3-pip
python3 -m venv .venv
.venv/bin/pip install --upgrade pip
.venv/bin/pip install -r requirements.txt
```

### 2.3 Configurar allowlist (baseline) para IP nueva del PC

Editar `baseline.yaml` en `network_parameters.allowed_ips`:

- agregar **solo** IPv4 exacta (ej. `192.168.5.120`)
- **no** usar CIDR (`/24`, `/32`, etc.)
- no eliminar IPs vigentes necesarias

Verificación rápida:

```bash
grep -nA15 '^network_parameters:' baseline.yaml
```

Para retirar una IP vieja del baseline (sin borrar otras entradas):

```bash
.venv/bin/python - <<'PY'
import yaml
from pathlib import Path
ip = "192.168.5.114"  # reemplazar por la IP a retirar
p = Path("baseline.yaml")
d = yaml.safe_load(p.read_text(encoding="utf-8"))
allowed = d["network_parameters"]["allowed_ips"]
if ip in allowed:
    allowed.remove(ip)
    p.write_text(yaml.safe_dump(d, allow_unicode=True, sort_keys=False), encoding="utf-8")
    print(f"IP retirada: {ip}")
else:
    print(f"IP no estaba presente: {ip}")
PY
```

### 2.4 Configurar UFW con regla exacta

Permitir únicamente la IP del PC WATO al puerto 1550:

```bash
sudo ufw allow in on eth0 from <IP_PC_WATO> to any port 1550 proto tcp
sudo ufw --force enable
sudo ufw reload
sudo ufw status numbered
```

Si administras por SSH y endureces reglas, agrega explícitamente tu IP de administración:

```bash
sudo ufw allow in on eth0 from <IP_ADMIN_SSH> to any port 22 proto tcp
```

Para retirar IP vieja:

```bash
sudo ufw status numbered
sudo ufw delete <NUMERO_REGLA>
```

### 2.5 Instalar/activar servicio systemd con usuario real

No asumir `pi`. En este equipo validado el usuario es `tesis`.

```bash
cd /home/tesis/Tesis-Simulacion
SERVICE_USER=tesis bash deploy/pi/03_instalar_servicio.sh
```

Verificaciones:

```bash
sudo systemctl status mllp-receiver --no-pager
sudo ss -ltnp | grep ':1550'
sudo journalctl -u mllp-receiver -n 80 --no-pager
```

El socket debe quedar escuchando en `0.0.0.0:1550`, no solo `127.0.0.1`.

### 2.6 Automatización recomendada en un solo comando (Pi)

```bash
sudo bash deploy/pi/07_preparar_prueba_remota.sh \
  --wato-ip 192.168.5.114 \
  --iface eth0 \
  --service-user tesis \
  --repo-path /home/tesis/Tesis-Simulacion \
  --pi-ip 192.168.5.134
```

Opciones clave del script:

- `--wato-ip` (requerido): IP exacta del PC emulador
- `--admin-ip`: opcional para habilitar SSH restringido sin abrir global
- `--skip-baseline-update`: no toca `baseline.yaml`

---

## 3) Pasos en Windows (emulador WATO)

### 3.1 Verificar conectividad y estado mínimo

```powershell
cd C:\ruta\Tesis-Simulacion

Test-NetConnection 192.168.5.134 -Port 1550
```

Debe devolver `TcpTestSucceeded : True`.

### 3.2 Ejecutar validación + prueba

```powershell
.\deploy\wato\probar_pi.ps1 `
  -PiHost 192.168.5.134 `
  -Port 1550 `
  -Count 10 `
  -Interval 10 `
  -State STANDBY
```

El script valida antes de correr:

- `.venv\Scripts\python.exe`
- `LAB_ONLY.marker`
- ausencia de marcadores `<<<<<<<`, `=======`, `>>>>>>>` en `wato_emulator.py`

Modo solo conectividad:

```powershell
.\deploy\wato\probar_pi.ps1 -PiHost 192.168.5.134 -ConnectivityOnly
```

---

## 4) Resultado de prueba validada (referencia)

Prueba ya ejecutada exitosamente:

- 10 mensajes `STANDBY` cada 10 segundos
- 10 ACK `AA` validados
- 0 timeouts
- 0 errores
- En Pi: `SESSION_START` (origen `192.168.5.114`), `10 MSG_RECV`, `10 ACK_SENT`, `SESSION_END`

### Nota sobre `R-TIME-002` al final

Después del cierre normal puede aparecer `R-TIME-002` por silencio posterior del canal. En esta campaña, ese evento posterior al `SESSION_END` se interpreta como comportamiento esperado del watchdog al no recibir más tráfico, no como fallo de entrega de los 10 mensajes.

Si se desea evitar confusión en operación:

- cerrar/rotar la sesión al terminar la campaña, o
- interpretar `R-TIME-002` solo cuando no exista un `SESSION_END` normal previo.

---

## 5) Evidencia y revisión posterior

En Pi:

```bash
find evidence_output -maxdepth 3 -type f -print
find runs -maxdepth 3 -type f -print 2>/dev/null
sudo journalctl -u mllp-receiver -n 120 --no-pager
```

Comprobación de reglas/red:

```bash
grep -nA20 '^network_parameters:' baseline.yaml
sudo ufw status numbered
sudo ss -ltnp | grep ':1550'
```
