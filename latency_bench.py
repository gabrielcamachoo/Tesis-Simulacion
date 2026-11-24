#!/usr/bin/env python3
"""
latency_bench.py - Bench de latencia del motor de detección (hipótesis H2).

Protocolo de validación §3.3:
  - Marca time.perf_counter() interna del motor: entrada de mensaje parseado
    -> DetectionResult (DetectionResult.processing_time_ms). El parseo HL7
    queda FUERA de la medición, igual que en la definición de la hipótesis.
  - >= 1000 mensajes por corrida, >= 3 corridas.
  - Se reportan p50/p95/p99/máx en µs y se comparan con 500 µs.
  - Si se mide en PC (no en la Raspberry Pi objetivo), queda DECLARADO: la H2
    para la Pi queda NO VERIFICADO (protocolo §6: "sin Pi no hay H2").

Carga de trabajo (peor caso por mensaje): mensajes benignos sintéticos
procesados en ráfaga sin sleep, de modo que R-TIME-002 (frecuencia fuera de
baseline) y R-SEQ-002 (contenido repetido dentro de la ventana de replay)
disparan alerta en cada mensaje después del primero. Se mide así el costo
completo del camino de alerta (hash de evidencia + construcción de Alert) sin
red ni I/O de evidencia, que es el camino más costoso del motor.

Uso:
  LAB_AUTHORIZED=YES python latency_bench.py --messages 1000 --runs 3
"""

import argparse
import json
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent

from src.config.settings import load_settings
from src.detection.baseline import load_baseline
from src.detection.rules import RuleSet
from src.detection.engine import DetectionEngine
from src.hl7.parser import parse_hl7_message
from src.mllp.framing import frame_hl7_message
from anomaly_generator import base_hl7_message, now_hl7_timestamp
from evaluate import percentile

THRESHOLD_US = 500.0
SESSION_ID = "latency-bench:127.0.0.1:0"


def detect_hardware_environment(device_tree_model_path: Path = Path("/proc/device-tree/model")) -> dict:
    """Detecta automáticamente si el benchmark corre en ARM/Raspberry Pi (Defecto D-06)."""
    machine = (platform.machine() or "").strip()
    machine_l = machine.lower()
    sys_l = (platform.system() or "").lower()
    model = ""
    try:
        if device_tree_model_path.exists():
            model = device_tree_model_path.read_text(encoding="utf-8", errors="ignore").replace("\x00", "").strip()
    except OSError:
        model = ""

    is_arm = any(tok in machine_l for tok in ("arm", "aarch64"))
    is_pi = ("raspberry pi" in model.lower()) or (sys_l == "linux" and is_arm)
    if is_pi:
        label = model if model else f"ARM Linux ({machine})"
        host_declarado = f"Raspberry Pi ({label}) {platform.node()}"
    else:
        host_declarado = f"PC {platform.node()}"

    return {
        "host_declarado": host_declarado,
        "platform": platform.platform(),
        "machine": machine or "no-declarado",
        "modelo_placa": model or None,
        "processor": platform.processor() or machine or "no-declarado",
        "python": platform.python_version(),
        "cargas_paralelas": "ninguna (bench exclusivo, protocolo §2.4)",
        "es_raspberry_pi": is_pi,
    }


def build_engine(config: Path, baseline_path: Path, rules_path: Path):
    settings = load_settings(str(config))
    baseline = load_baseline(str(baseline_path))
    rules = RuleSet(str(rules_path))
    return DetectionEngine(settings, baseline, rules)


def bench_run(engine, n_messages: int, run_idx: int,
              mode: str = "worst_case", include_parse: bool = False):
    """Procesa n_messages con el motor ya construido y colecta latencias (ms).
    mode='worst_case': ráfaga sin avance temporal -> R-TIME-002 + R-SEQ-002 en cada msg.
    mode='normal_path': avance de capture_time (+10 s) y MSH-7 monotónico -> 0 alertas.
    include_parse=True: mide parse_hl7_message() + engine.process_message() (RD-01 completo).
    """
    import time
    from datetime import timedelta

    lat_ms = []
    alerts_total = 0
    base_dt = datetime(2026, 11, 23, 12, 0, 0, tzinfo=timezone.utc)
    base_ts_epoch = base_dt.timestamp()
    fixed_ts = now_hl7_timestamp()
    for i in range(n_messages):
        control_id = f"LB{run_idx:02d}{i:08d}"
        if mode == "normal_path":
            msg_dt = base_dt + timedelta(seconds=10 * i)
            ts_str = msg_dt.strftime("%Y%m%d%H%M%S") + "+0000"
            cap_t = base_ts_epoch + 10.0 * i
        else:
            ts_str = fixed_ts
            cap_t = None
        text = base_hl7_message(control_id=control_id, timestamp=ts_str)
        frame = frame_hl7_message(text)
        raw_bytes = frame[1:-2]
        if include_parse:
            t0 = time.perf_counter()
            parsed = parse_hl7_message(text)
            if parsed is None:
                raise RuntimeError(f"parse falló para mensaje {i}")
            result = engine.process_message(
                session_id=SESSION_ID, source_ip="127.0.0.1",
                source_port=40000 + (i % 20000),
                parsed_message=parsed, raw_bytes=raw_bytes, mllp_frame=frame,
                capture_time=cap_t)
            lat_ms.append((time.perf_counter() - t0) * 1000.0)
        else:
            parsed = parse_hl7_message(text)
            if parsed is None:
                raise RuntimeError(f"parse falló para mensaje {i}")
            result = engine.process_message(
                session_id=SESSION_ID, source_ip="127.0.0.1",
                source_port=40000 + (i % 20000),
                parsed_message=parsed, raw_bytes=raw_bytes, mllp_frame=frame,
                capture_time=cap_t)
            lat_ms.append(result.processing_time_ms)
        alerts_total += len(result.alerts)
    return lat_ms, alerts_total


def run_bench(messages: int, runs: int, seed: int,
              config: Path, baseline_path: Path, rules_path: Path,
              mode: str = "worst_case", include_parse: bool = False) -> dict:
    per_run = []
    all_ms = []
    for r in range(runs):
        engine = build_engine(config, baseline_path, rules_path)
        lat_ms, alerts = bench_run(
            engine, messages, r, mode=mode, include_parse=include_parse
        )
        all_ms.extend(lat_ms)
        per_run.append({
            "run": r + 1,
            "messages": len(lat_ms),
            "alerts_emitidas": alerts,
            "p50_us": round(percentile(lat_ms, 50) * 1000, 2),
            "p95_us": round(percentile(lat_ms, 95) * 1000, 2),
            "p99_us": round(percentile(lat_ms, 99) * 1000, 2),
            "max_us": round(max(lat_ms) * 1000, 2),
            "min_us": round(min(lat_ms) * 1000, 2),
        })
        print(f"corrida {r + 1}/{runs} [{mode}, parse={include_parse}]: n={len(lat_ms)} "
              f"p50={per_run[-1]['p50_us']}µs p95={per_run[-1]['p95_us']}µs "
              f"p99={per_run[-1]['p99_us']}µs max={per_run[-1]['max_us']}µs "
              f"alertas={alerts}", flush=True)

    agg = {
        "n_total": len(all_ms),
        "p50_us": round(percentile(all_ms, 50) * 1000, 2),
        "p95_us": round(percentile(all_ms, 95) * 1000, 2),
        "p99_us": round(percentile(all_ms, 99) * 1000, 2),
        "max_us": round(max(all_ms) * 1000, 2),
        "min_us": round(min(all_ms) * 1000, 2),
    }
    verdict_p95 = "PASS" if agg["p95_us"] <= THRESHOLD_US else "FAIL"
    entorno = detect_hardware_environment()
    if entorno["es_raspberry_pi"]:
        nota_h2 = (
            f"Medido en hardware Raspberry Pi ({entorno['modelo_placa'] or entorno['machine']}): "
            f"p95 = {agg['p95_us']}µs vs umbral {THRESHOLD_US}µs -> {verdict_p95}."
        )
    else:
        nota_h2 = (
            "Medido en PC: si p95 <= 500µs, H2 sigue NO VERIFICADO "
            "para la Raspberry Pi hasta ejecutar este bench allí "
            "(protocolo §3.3/§6)."
        )
    med_desc = (
        "time.perf_counter() de parse_hl7_message() + engine.process_message() (RD-01 completo)"
        if include_parse else
        "time.perf_counter() interno del motor (DetectionResult.processing_time_ms); parseo HL7 excluido"
    )
    camino_desc = (
        "camino normal sin alertas: cadencia exacta de 10 s (capture_time +10 s), MSH-7 monotónico y MCID único"
        if mode == "normal_path" else
        "peor caso por mensaje: ráfaga sin sleep -> R-TIME-002 + R-SEQ-002 en cada mensaje posterior al primero (incluye hash de evidencia y construcción de Alert); sin red ni I/O"
    )
    return {
        "tool": "latency_bench.py",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "hipotesis": "H2",
        "modo": mode,
        "include_parse": include_parse,
        "medicion": med_desc,
        "entorno": entorno,
        "carga": {
            "mensajes_por_corrida": messages,
            "corridas": runs,
            "seed_base": seed,
            "camino_medido": camino_desc,
        },
        "per_run": per_run,
        "aggregate": agg,
        "threshold_us": THRESHOLD_US,
        "verdict_p95_vs_threshold": verdict_p95,
        "nota_h2": nota_h2,
    }


def parse_args():
    p = argparse.ArgumentParser(description="Bench de latencia del motor (H2)")
    p.add_argument("--messages", type=int, default=1000,
                   help="Mensajes por corrida (protocolo: >= 1000)")
    p.add_argument("--runs", type=int, default=3,
                   help="Corridas (protocolo: >= 3)")
    p.add_argument("--seed", type=int, default=20261014,
                   help="Semilla declarada (registro §2.3)")
    p.add_argument("--mode", choices=["worst_case", "normal_path"], default="worst_case",
                   help="Camino medido: worst_case (2 alertas/msg) o normal_path (0 alertas/msg)")
    p.add_argument("--include-parse", action="store_true",
                   help="Incluir parse_hl7_message() en la medición (RD-01 completo)")
    p.add_argument("--config", default="",
                   help="settings YAML (default: config de laboratorio "
                        "generada junto al JSON de salida)")
    p.add_argument("--baseline", default=str(ROOT / "baseline.yaml"))
    p.add_argument("--rules", default=str(ROOT / "config/rules.yaml"))
    p.add_argument("--out", default="",
                   help="Destino JSON (default: "
                        "analysis_output/validation/latency_<ts>.json)")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    out = Path(args.out) if args.out else (
        ROOT / "analysis_output" / "validation" /
        f"latency_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    if not out.is_absolute():
        out = ROOT / out
    out.parent.mkdir(parents=True, exist_ok=True)

    if args.config:
        config = Path(args.config)
    else:
        from run_experiment import write_lab_config
        config = write_lab_config(out.parent)

    print(f"Bench latencia H2 [{args.mode}, parse={args.include_parse}]: "
          f"{args.messages} msg x {args.runs} corridas "
          f"(threshold {THRESHOLD_US}µs p95)", flush=True)
    report = run_bench(args.messages, args.runs, args.seed,
                       config, Path(args.baseline), Path(args.rules),
                       mode=args.mode, include_parse=args.include_parse)
    out.write_text(json.dumps(report, indent=2, ensure_ascii=False),
                   encoding="utf-8")
    agg = report["aggregate"]
    print(f"\nAGREGADO n={agg['n_total']}: p50={agg['p50_us']}µs "
          f"p95={agg['p95_us']}µs p99={agg['p99_us']}µs "
          f"max={agg['max_us']}µs -> {report['verdict_p95_vs_threshold']}")
    print(f"Escrito: {out.relative_to(ROOT)}")
    print(f"NOTA: {report['nota_h2']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
