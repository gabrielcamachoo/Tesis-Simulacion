#!/usr/bin/env python3
"""
resource_sampler.py - Serie de tiempo de CPU/RAM/temperatura (Pi o Linux).

Cada --interval segundos escribe una fila CSV con el uso total del equipo y el
de los procesos del laboratorio (receptor, detector, tcpdump), más la fase
actual del experimento, que se lee de --phase-file en cada muestra. El operador
cambia de fase escribiendo en ese archivo (p. ej. `echo F2 | sudo tee /tmp/fase`),
así no hace falta sincronizar relojes entre máquinas.

Uso (en la Pi, fuera del contenedor):
  sudo .venv/bin/python resource_sampler.py --out runs/recursos/pi_rep1.csv
  Ctrl+C para terminar.
"""

import argparse
import csv
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import psutil

# Grupo -> texto que debe aparecer en la línea de comandos del proceso.
GROUPS = {"receptor": "mllp_receiver.py", "detector": "detect_live.py", "tcpdump": "tcpdump"}


def read_temp_c():
    """Temperatura de la CPU en °C, o '' si el equipo no la expone."""
    try:
        temps = psutil.sensors_temperatures()
    except (AttributeError, OSError):
        return ""
    for entries in temps.values():
        if entries:
            return round(entries[0].current, 1)
    return ""


def read_throttled():
    """Banderas de `vcgencmd get_throttled` ("0x0" = nada desde el arranque); '' sin vcgencmd."""
    try:
        out = subprocess.run(["vcgencmd", "get_throttled"], capture_output=True,
                             text=True, timeout=2).stdout
    except (OSError, subprocess.SubprocessError):
        return ""
    return out.strip().partition("=")[2]


def read_phase(path):
    try:
        return Path(path).read_text(encoding="utf-8").strip() or "sin_fase"
    except OSError:
        return "sin_fase"


def group_of(proc):
    """Grupo del proceso según su línea de comandos; None si no es del lab."""
    try:
        cmd = " ".join(proc.cmdline())
    except (psutil.Error, OSError):
        return None
    if "resource_sampler" in cmd:  # no medirse a sí mismo (ni al sudo que lo lanza)
        return None
    for name, token in GROUPS.items():
        if token in cmd:
            return name
    return None


def sample(tracked, phase_file):
    """Una fila. `tracked` guarda los Process ya vistos para que cpu_percent mida deltas."""
    for proc in psutil.process_iter():
        if proc.pid not in tracked:
            g = group_of(proc)
            if g:
                proc.cpu_percent(None)  # primer llamado: arranca el contador
                tracked[proc.pid] = (proc, g)
    mem = psutil.virtual_memory()
    row = {
        "ts_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "fase": read_phase(phase_file),
        "cpu_total_pct": psutil.cpu_percent(None),
        "mem_used_mb": round(mem.used / 2**20, 1),
        "mem_pct": mem.percent,
        "temp_c": read_temp_c(),
        "throttled": read_throttled(),
    }
    for g in GROUPS:
        row.update({f"{g}_cpu_pct": 0.0, f"{g}_rss_mb": 0.0, f"{g}_n": 0})
    for pid, (proc, g) in list(tracked.items()):
        try:
            with proc.oneshot():
                row[f"{g}_cpu_pct"] = round(row[f"{g}_cpu_pct"] + proc.cpu_percent(None), 1)
                row[f"{g}_rss_mb"] = round(row[f"{g}_rss_mb"] + proc.memory_info().rss / 2**20, 1)
            row[f"{g}_n"] += 1
        except psutil.Error:
            del tracked[pid]  # el proceso terminó
    return row


def run(out, interval, duration, phase_file):
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    tracked = {}
    psutil.cpu_percent(None)
    sample(tracked, phase_file)  # calienta los contadores; esta fila no se guarda
    t_end = time.monotonic() + duration if duration > 0 else None
    rows = 0
    with out.open("w", newline="", encoding="utf-8") as fh:
        writer = None
        try:
            while t_end is None or time.monotonic() < t_end:
                time.sleep(interval)
                row = sample(tracked, phase_file)
                if writer is None:
                    writer = csv.DictWriter(fh, fieldnames=list(row))
                    writer.writeheader()
                writer.writerow(row)
                fh.flush()  # que un corte no pierda las filas ya medidas
                rows += 1
        except KeyboardInterrupt:
            pass
    return rows


def main():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    p.add_argument("--out", required=True, help="CSV de salida")
    p.add_argument("--interval", type=float, default=1.0, help="Segundos entre muestras")
    p.add_argument("--duration", type=float, default=0, help="Segundos totales (0 = hasta Ctrl+C)")
    p.add_argument("--phase-file", default="/tmp/fase", help="Archivo con la fase actual")
    a = p.parse_args()
    print(f"Midiendo cada {a.interval}s -> {a.out} (fase desde {a.phase_file}; Ctrl+C para terminar)")
    n = run(a.out, a.interval, a.duration, a.phase_file)
    print(f"{n} muestras escritas en {a.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
