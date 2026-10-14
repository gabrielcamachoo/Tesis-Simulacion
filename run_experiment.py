#!/usr/bin/env python3
"""
run_experiment.py - Orquestador de corridas experimentales del laboratorio.

Fases de cada corrida (runs/<timestamp>/):
  1. FASE BENIGNA 1 : emulador WATO (STANDBY)         -> mensajes normales (TN)
  2. FASE ANÓMALA   : generador A01-A16                -> ground_truth.jsonl
  3. FASE BENIGNA 2 : emulador WATO (post-anomalías)  -> TN adicionales
  4. EVALUACIÓN     : evaluate.run_from_dir           -> evaluation.json/txt

Modos:
  --mode local   procesos en el host (loopback; para desarrollo/CI)
  --mode docker  docker compose con red interna aislada (metodología tesis)
  --mode auto    docker si está disponible, si no local (default)

Uso:
  LAB_AUTHORIZED=YES python run_experiment.py --mode auto
  LAB_AUTHORIZED=YES python run_experiment.py --mode local --benign-count 4
  LAB_AUTHORIZED=YES python run_experiment.py --mode docker --exclude A14

Requiere: LAB_AUTHORIZED=YES y LAB_ONLY.marker (creado en la raíz del repo).
"""

import argparse
import os
import random
import socket
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PY = sys.executable


def parse_args():
    p = argparse.ArgumentParser(
        description="Orquestador de experimentos del laboratorio HL7/MLLP")
    p.add_argument("--mode", choices=["auto", "local", "docker"], default="auto",
                   help="Modo de ejecución (default: auto)")
    p.add_argument("--benign-count", type=int, default=6,
                   help="Mensajes benignos por fase (default 6)")
    p.add_argument("--interval", type=float, default=6.0,
                   help="Intervalo benigno en s, debe estar en [5, 15.015] (default 6)")
    p.add_argument("--anomaly-count", type=int, default=3,
                   help="Inyecciones por escenario, tope safety_limit (default 3)")
    p.add_argument("--exclude", default="",
                   help="Escenarios a excluir, separados por coma (ej: A14)")
    p.add_argument("--window", type=float, default=5.0,
                   help="Ventana de matching inyección-alerta en s (default 5)")
    p.add_argument("--seed", type=int, default=None,
                   help="Semilla PRNG por corrida (protocolo §2.3); "
                        "si se omite se genera y registra en runs/<ts>/seed.txt")
    return p.parse_args()


def die(msg: str, code: int = 1):
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(code)


def lab_env(extra: dict = None) -> dict:
    env = os.environ.copy()
    env["LAB_AUTHORIZED"] = "YES"
    if extra:
        env.update(extra)
    return env


def write_lab_config(run_dir: Path) -> Path:
    """Copia de settings.yaml con lab_marker_path apuntando al marcador
    del repo (en Windows /LAB_ONLY.marker no es escribible en la raíz)."""
    src = ROOT / "src" / "config" / "settings.yaml"
    text = src.read_text(encoding="utf-8")
    marker = ROOT / "LAB_ONLY.marker"
    if not marker.exists():
        die(f"falta {marker}")
    text = text.replace('lab_marker_path: "/LAB_ONLY.marker"',
                        f'lab_marker_path: "{marker.as_posix()}"')
    cfg = run_dir / "settings_lab.yaml"
    cfg.write_text(text, encoding="utf-8")
    return cfg


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_port(host: str, port: int, timeout: float = 20.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        try:
            with socket.create_connection((host, port), timeout=1):
                return
        except OSError:
            time.sleep(0.2)
    die(f"el receptor no abrió {host}:{port} en {timeout}s")


def wait_healthy(service: str, timeout: float = 90.0):
    """Espera a que el servicio compose quede 'healthy'.

    En modo docker NO se usa wait_port: con redes internal:true el publish
    de puertos no se materializa en Docker Desktop WSL2 (verificado
    2026-10-14), y las fases corren dentro de la red compose igualmente."""
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        r = subprocess.run(["docker", "compose", "ps", "-q", service],
                           capture_output=True, text=True, cwd=ROOT)
        cid = r.stdout.strip()
        if cid:
            h = subprocess.run(
                ["docker", "inspect", "-f",
                 "{{if .State.Health}}{{.State.Health.Status}}{{end}}", cid],
                capture_output=True, text=True)
            if h.stdout.strip() == "healthy":
                return
        time.sleep(1)
    die(f"el servicio '{service}' no quedó healthy en {timeout}s")


def run_cmd(cmd, label: str, env: dict = None):
    print(f"\n=== {label} ===\n$ {' '.join(str(c) for c in cmd)}", flush=True)
    r = subprocess.run([str(c) for c in cmd], cwd=ROOT, env=env)
    if r.returncode != 0:
        die(f"fase '{label}' terminó con código {r.returncode}")
    return r


def docker_available() -> bool:
    try:
        r = subprocess.run(["docker", "compose", "version"],
                           capture_output=True, timeout=15)
        return r.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def preflight_budget(args) -> None:
    """Fail-fast: verifica que las inyecciones planeadas caben en
    max_anomalies_per_run ANTES de levantar el receptor. Reproduce la
    misma lógica de conteo que anomaly_generator.run_scenario."""
    import yaml
    from anomaly_generator import SCENARIOS

    cfg = yaml.safe_load(
        (ROOT / "src" / "config" / "settings.yaml").read_text(encoding="utf-8"))
    budget = int(cfg.get("anomaly_generator", {})
                 .get("safety_limits", {})
                 .get("max_anomalies_per_run", 70))
    excluded = {s.strip() for s in args.exclude.split(",") if s.strip()}

    total = 0
    detail = []
    for sid, sc in SCENARIOS.items():
        if not sc.enabled or sid in excluded:
            continue
        if sid == "A12":  # ráfaga: una sola llamada
            n = min(int(sc.params.get("max_burst_messages", 20)), sc.safety_limit)
        elif sid == "A13":  # reconexiones: una sola llamada
            n = min(int(sc.params.get("max_reconnects", 5)), sc.safety_limit)
        else:
            n = min(args.anomaly_count, sc.safety_limit)
        total += n
        detail.append(f"{sid}={n}")

    if total > budget:
        die(f"presupuesto excedido: {total} inyecciones "
            f"({' '.join(detail)}) > max_anomalies_per_run={budget}. "
            f"Reduce --anomaly-count o excluye escenarios (ej: --exclude A14); "
            f"presupuesto en src/config/settings.yaml", 4)
    print(f"Preflight: {total} inyecciones planeadas "
          f"(presupuesto {budget}): {' '.join(detail)}", flush=True)


# ---------------------------------------------------------------------------
# Modo local (procesos en el host)
# ---------------------------------------------------------------------------
def run_local(args, run_dir: Path, port: int):
    cfg = write_lab_config(run_dir)
    env = lab_env()

    receiver = subprocess.Popen(
        [PY, "mllp_receiver.py", "--host", "127.0.0.1", "--port", str(port),
         "--config", str(cfg), "--outdir", str(run_dir)],
        cwd=ROOT, env=env)
    try:
        wait_port("127.0.0.1", port)

        run_cmd([PY, "wato_emulator.py", "--host", "127.0.0.1", "--port", port,
                 "--state", "STANDBY", "--count", args.benign_count,
                 "--interval", args.interval, "--ack-timeout", "5",
                 "--seed", str(args.phase_seeds["benign1"])],
                "FASE BENIGNA 1", env)

        gen_cmd = [PY, "anomaly_generator.py", "--all",
                   "--count", args.anomaly_count,
                   "--host", "127.0.0.1", "--port", port,
                   "--config", cfg,
                   "--ground-truth", run_dir / "ground_truth.jsonl",
                   "--seed", str(args.phase_seeds["anomalies"])]
        if args.exclude:
            gen_cmd += ["--exclude", args.exclude]
        run_cmd(gen_cmd, "FASE ANÓMALA", env)

        run_cmd([PY, "wato_emulator.py", "--host", "127.0.0.1", "--port", port,
                 "--state", "STANDBY", "--count", args.benign_count,
                 "--interval", args.interval, "--ack-timeout", "5",
                 "--seed", str(args.phase_seeds["benign2"])],
                "FASE BENIGNA 2", env)

        # Dar tiempo a que el servidor procese cierres (A05) y vacíe buffers
        time.sleep(2.0)
    finally:
        receiver.terminate()
        try:
            receiver.wait(timeout=10)
        except subprocess.TimeoutExpired:
            receiver.kill()
            receiver.wait(timeout=5)


# ---------------------------------------------------------------------------
# Modo docker (red interna aislada, metodología de la tesis)
# ---------------------------------------------------------------------------
def run_docker(args, run_dir: Path):
    # Evidencia en named volume lab_output (/lab_output) — el bind del repo
    # está sobre OneDrive y el E2E docker de 2026-10-13 estancó el I/O.
    outdir = f"/lab_output/{run_dir.name}"
    env = lab_env({"LAB_OUTDIR": outdir})

    run_cmd(["docker", "compose", "up", "-d", "--build", "mllp-receiver"],
            " Levantar receptor (docker)", env)
    try:
        wait_healthy("mllp-receiver", timeout=90)

        run_cmd(["docker", "compose", "--profile", "benign", "run", "--rm",
                 "wato-emulator", "python", "wato_emulator.py",
                 "--host", "mllp-receiver", "--port", "1550",
                 "--state", "STANDBY", "--count", args.benign_count,
                 "--interval", args.interval, "--ack-timeout", "5",
                 "--seed", str(args.phase_seeds["benign1"])],
                "FASE BENIGNA 1 (docker)", env)

        gen_cmd = ["docker", "compose", "--profile", "anomalies", "run", "--rm",
                   "anomaly-generator", "python", "anomaly_generator.py",
                   "--all", "--count", args.anomaly_count,
                   "--host", "mllp-receiver", "--port", "1550",
                   "--ground-truth", f"{outdir}/ground_truth.jsonl",
                   "--seed", str(args.phase_seeds["anomalies"])]
        if args.exclude:
            gen_cmd += ["--exclude", args.exclude]
        run_cmd(gen_cmd, "FASE ANÓMALA (docker)", env)

        run_cmd(["docker", "compose", "--profile", "benign", "run", "--rm",
                 "wato-emulator", "python", "wato_emulator.py",
                 "--host", "mllp-receiver", "--port", "1550",
                 "--state", "STANDBY", "--count", args.benign_count,
                 "--interval", args.interval, "--ack-timeout", "5",
                 "--seed", str(args.phase_seeds["benign2"])],
                "FASE BENIGNA 2 (docker)", env)

        time.sleep(2.0)

        # Copiar resultados del named volume al host para la evaluación
        run_cmd(["docker", "compose", "cp",
                 f"mllp-receiver:{outdir}/.", str(run_dir)],
                "Copiar resultados (volume -> host)", env)
    finally:
        print("\n=== docker compose down ===", flush=True)
        subprocess.run(["docker", "compose", "down"], cwd=ROOT, env=env)


# ---------------------------------------------------------------------------
def main() -> int:
    args = parse_args()

    if os.environ.get("LAB_AUTHORIZED", "").strip().upper() != "YES":
        die("define LAB_AUTHORIZED=YES primero (entorno de laboratorio)", 3)
    if not (ROOT / "LAB_ONLY.marker").exists():
        die("falta LAB_ONLY.marker en la raíz del repo", 3)

    preflight_budget(args)

    mode = args.mode
    if mode == "auto":
        mode = "docker" if docker_available() else "local"
        if mode == "local":
            print("AVISO: Docker no disponible; usando modo local (loopback). "
                  "La metodología de la tesis usa --mode docker.", file=sys.stderr)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = ROOT / "runs" / ts
    run_dir.mkdir(parents=True, exist_ok=True)

    # §2.3: semilla PRNG por corrida, registrada antes de medir. Derivados
    # distintos por fase para que los MCID benignos no colisionen entre fases
    # (una semilla idéntica haría repetir el ctrl_id inicial -> FP R-SEQ-001).
    seed_base = args.seed if args.seed is not None else \
        random.SystemRandom().randrange(1, 2**31)
    args.phase_seeds = {
        "benign1": seed_base,
        "anomalies": seed_base + 1_000_003,
        "benign2": seed_base + 2_000_003,
    }
    (run_dir / "seed.txt").write_text(
        f"seed_base={seed_base}\n"
        f"seed_benign1={args.phase_seeds['benign1']}\n"
        f"seed_anomalies={args.phase_seeds['anomalies']}\n"
        f"seed_benign2={args.phase_seeds['benign2']}\n"
        f"mode={args.mode}\nexclude={args.exclude}\n"
        f"anomaly_count={args.anomaly_count}\nbenign_count={args.benign_count}\n"
        f"interval={args.interval}\n"
        f"nota=derivados +1000003/+2000003 entre fases para evitar "
        f"MCID idénticos (R-SEQ-001); orden de escenarios en "
        f"scenario_order.txt\n",
        encoding="utf-8")

    print(f"Modo: {mode} | Corrida: {run_dir.relative_to(ROOT)}")
    print(f"Semilla: {seed_base} "
          f"(anomalies=+1000003, benign2=+2000003, registrada en seed.txt)")

    if mode == "local":
        run_local(args, run_dir, free_port())
    else:
        run_docker(args, run_dir)

    # ---- Evaluación (siempre en el host) ----
    from evaluate import run_from_dir
    try:
        res = run_from_dir(run_dir, window_s=args.window)
    except FileNotFoundError as e:
        die(f"salidas incompletas: {e}")

    print(f"\nCorrida completa: {run_dir.relative_to(ROOT)}")
    print(f"  ground_truth.jsonl, alerts/alerts.jsonl, "
          f"evaluation.json, evaluation.txt")
    detection_rate = res.tp / res.injections_total if res.injections_total else 0.0
    print(f"  recall={detection_rate:.3f} precision={res.precision:.3f} "
          f"fp={res.fp} fn={res.fn}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
