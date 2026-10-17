# Despliegue en Raspberry Pi — Banco de pruebas HL7/MLLP

**Proyecto:** detector determinista de anomalías para comunicaciones HL7/MLLP (Tesis G18 SIDRE)
**Fecha:** 2026-10-14 · **Estado:** ⬜ Fase 6 — guía de instalación escrita; **ejecución en la Pi
pendiente** (ver `docs/LAB_ARCHITECTURE.md` §6). H2 (latencia ≤ 500 µs) solo se verifica en la Pi
(`docs/VALIDATION_PROTOCOL.md` §3.3).

## 1. Alcance

Este documento describe cómo instalar y operar el laboratorio sobre la Raspberry Pi objetivo,
con los mismos interlocks de seguridad que en el host Windows:

- Autorización explícita (`LAB_AUTHORIZED=YES` + marcador `LAB_ONLY.marker`).
- Solo redes de laboratorio aisladas: sin IP pública, sin salida a Internet en runtime
  (`block_public_ips: true` en `src/config/settings.yaml`).
- `evidence_raw/` de solo lectura (los SHA-256 de `evidence_inventory.csv` deben seguir
  coincidiendo).
- Ningún componente inline en el equipo clínico real: el Pi reemplaza al host de laboratorio,
  no al WATO.

## 2. Hardware y software

| Ítem | Requisito | Fuente |
|------|-----------|--------|
| Placa | Raspberry Pi 4 (8 GB) o Jetson Nano; bajo consumo (< 5 W), hardware ARM | SRS, requisito de hardware ARM |
| Sistema | Raspberry Pi OS 64 bits (Bookworm o superior) | decisión de despliegue |
| Python | 3.11+ (`python3-venv`); el lector de PCAP es Python puro, sin dependencias de sistema | `README.md` §Requisitos |
| Dependencias | `PyYAML>=6.0` (runtime), `pytest>=8.0` (pruebas) | `requirements.txt` |
| Red | interfaz de laboratorio aislada (sin Internet, sin IP pública); puerto **1550/tcp** | `docs/LAB_ARCHITECTURE.md` §4 |

## 3. Aislamiento de red

1. Conectar la Pi únicamente a la red de laboratorio (switch/AP aislado; nada de ISP).
2. Configurar IP fija de lab (ej. `192.168.23.x`) y firewall de salida por defecto:

```bash
sudo apt install -y ufw
sudo ufw default deny outgoing
sudo ufw default deny incoming
sudo ufw allow in on eth0 to any port 1550 proto tcp   # solo si hay emulador remoto
sudo ufw enable
```

3. El receptor escucha por defecto en `127.0.0.1` (loopback). Usar `--host 0.0.0.0` solo
   dentro de una red Docker internal o de laboratorio estrictamente aislada, y **nunca**
   con IP pública (lo bloquea además `block_public_ips`).
4. Cualquier IP emisora nueva debe agregarse a la allowlist exacta (sin CIDR) en
   `baseline.yaml` → `network_parameters.allowed_ips` — de lo contrario la regla
   `R-NET-001` alerta IP no autorizada (comportamiento esperado, no un bug).

## 4. Instalación

La instalación inicial puede hacerse por red local o transferencia por USB; en runtime la Pi
no requiere Internet.

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip git

# Transferir el repo (desde el host Windows, ufw permite el tráfico de lab):
#   rsync -av --exclude .venv --exclude .git <ruta-repo>/ pi@<ip-pi>:/home/pi/wato/
cd /home/pi/wato   # nombre de la clonación usada

python3 -m venv .venv
.venv/bin/pip install -r requirements.txt

# Verificación: la suite completa debe pasar (misma cifra que en el host)
.venv/bin/python -m pytest tests -q
```

## 5. Guardas de seguridad (obligatorias antes de arrancar)

```bash
# 1) Marcador de laboratorio en la ruta por defecto de settings (lab_marker_path)
sudo touch /LAB_ONLY.marker

# 2) Autorización explícita (por sesión...)
export LAB_AUTHORIZED=YES
# ...o de forma persistiente en la unidad systemd (§6)

# 3) Revisar allowlist y límites
#    - baseline.yaml -> network_parameters.allowed_ips  (agregar la IP de lab del Pi/emulador)
#    - src/config/settings.yaml -> laboratory.safety     (≤70 anomalías/corrida, ≤5 msg/s,
#                                                         ≤32 KiB, cooldown ≥30 s)
```

Notas:

- `SafetyGuard` exige **estrictamente** el archivo en `lab_marker_path`; no existe fallback al
  marcador del repositorio (excepto la comodidad de desarrollo en `anomaly_generator.main()`).
- La anonimización de datos clínicos (PID/PV1/NTE) está activada por defecto en todo artefacto
  derivado (`README.md` §Reglas).

## 6. Operación

### 6.1 Modo local (loopback, más simple)

```bash
export LAB_AUTHORIZED=YES

# Terminal 1 — receptor (escribe runs/ y alertas)
.venv/bin/python mllp_receiver.py --host 127.0.0.1 --port 1550 --verbose
# (escribe en evidence_output/ por defecto; el orquestador usa runs/<timestamp>)

# Terminal 2 — tráfico benigno (STANDBY sintético)
.venv/bin/python wato_emulator.py --host 127.0.0.1 --count 10 --interval 6.0

# O bien, corrida completa automatizada (benigno → A01–A16 → benigno → evaluación)
.venv/bin/python run_experiment.py --mode local --exclude A14
```

### 6.2 Servicio persistente con systemd

```ini
# /etc/systemd/system/mllp-receiver.service
[Unit]
Description=Receptor MLLP de laboratorio (HL7/MLLP WATO)
After=network-online.target

[Service]
WorkingDirectory=/home/pi/wato
Environment=LAB_AUTHORIZED=YES
ExecStart=/home/pi/wato/.venv/bin/python mllp_receiver.py --host 127.0.0.1 --port 1550
Restart=on-failure
User=pi

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now mllp-receiver
journalctl -u mllp-receiver -f
```

### 6.3 Modo Docker en la Pi (opcional)

La topología `docker-compose.yml` (red internal `172.30.0.0/24`, IPs fijas) también aplica en
ARM64 instalando Docker Engine desde la guía oficial de Docker para Raspberry Pi OS, y
quitando antes el `--mode docker` del host Windows si compite por el mismo proyecto compose:

```bash
docker compose up -d mllp-receiver
docker compose --profile benign run --rm wato-emulator
docker compose --profile anomalies run --rm anomaly-generator
```

### 6.4 Salidas

| Ruta | Contenido |
|------|-----------|
| `runs/<timestamp>/` | corrida completa: `ground_truth.jsonl`, `alerts/`, `hl7/`, `logs/`, `raw/`, `evaluation.*`, snapshot `settings_lab.yaml` |
| `evidence_output/` | evidencia del receptor cuando se corre sin orquestador |
| `baseline.yaml`, `config/rules.yaml` | insumos versionados; no editar en la Pi (regenerar en el repo) |

`runs/` y `evidence_output/` son regenerables; **nunca** se modifica `evidence_raw/`.

## 7. Evaluación y respaldo

- `evaluate.py` es Python puro: puede correr en la propia Pi
  (`.venv/bin/python -c "from evaluate import run_from_dir; print(run_from_dir('runs/<ts>'))"`).
- Para análisis en el host Windows, copiar solo las corridas (no `evidence_raw/`):

```powershell
scp -r pi@<ip-pi>:/home/pi/wato/runs/<timestamp> .\runs\
```

- Verificar integridad de la evidencia original tras cada transferencia: los SHA-256 de
  `evidence_raw/evidence_inventory.csv` deben seguir coincidiendo (lectura con `utf-8-sig`).

## 8. Medición de latencia (H2)

La hipótesis H2 (p95 lectura→alerta ≤ 500 µs por mensaje) se mide **en la Pi**, con
`perf_counter` por mensaje, siguiendo `docs/VALIDATION_PROTOCOL.md` §3.3. Si la medición se hace en
un PC, debe declararse y H2 queda sin verificar ("sin Pi no hay H2").

## 9. Checklist de despliegue

| Paso | Estado |
|------|--------|
| Sistema 64 bits + Python 3.11 + venv + `requirements.txt` | ⬜ pendiente |
| Suite `pytest -q` en la Pi (misma cifra que host) | ⬜ pendiente |
| `/LAB_ONLY.marker` + `LAB_AUTHORIZED=YES` (systemd) | ⬜ pendiente |
| Firewall aislado (sin egress) + IP de lab fija | ⬜ pendiente |
| Allowlist `baseline.yaml` con IPs del lab | ⬜ pendiente |
| Corrida local end-to-end (`run_experiment.py --mode local`) | 🟡 **simulada en docker** (topología idéntica, `docs/SIMULACION_RANSOMWARE.md` §4); física ⬜ |
| Evidencia respaldada (scp) + hashes verificados | ⬜ pendiente |
| Medición H2 en la Pi (`docs/VALIDATION_PROTOCOL.md` §3.3) | ⬜ pendiente (en PC p95=248 µs, no extrapolable) |

> **Nota 2026-10-14:** se ejecutó la campaña A01–A16 (sin A14) con el
> `docker-compose.yml` del repo (misma topología que usará la Pi):
> recall=1.0, precision=0.985 (1 FP jitter), sellada en
> `analysis_output/validation/pi_sim_20261014_175742/`. Ver también
> `docs/SIMULACION_RANSOMWARE.md` (campaña ransomware + metodología Pi).

## 10. Problemas comunes

| Síntoma | Causa / solución |
|---------|------------------|
| `SafetyGuard` rechaza arranque | falta `LAB_AUTHORIZED=YES` o el archivo `/LAB_ONLY.marker` |
| Alerta `R-NET-001` con tráfico propio | la IP emisora no está en `baseline.yaml` `allowed_ips` (allowlist exacta, sin CIDR) |
| `R-HL7-002` con ORU | `message_types_allowed` debe incluir `ORU^R01^ORU_R01` (settings actual) |
| Rechazo por IP pública | `block_public_ips: true` — behavior correcto; usar solo red de lab |
| El emulador no recibe ACK | el receptor está con `--no-ack` (modo pasivo); quitarlo para ACK `AA` |

Ver también: `docs/ETHICS_AND_SAFETY.md` (límites cuantitativos), `docs/LAB_ARCHITECTURE.md`
(interlocks §5), `README.md` (comandos), `docs/VALIDATION_PROTOCOL.md` (protocolo de medición).
