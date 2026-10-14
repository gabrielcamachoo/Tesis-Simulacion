#!/usr/bin/env python3
"""
run_matrix.py - Campaña de validación H1: N corridas + agregación ADR/IC95 Wilson.

Protocolo §3.1: >= 30 corridas por escenario con semillas distintas (o todas
las posibles si el techo lo limita; se declara N real por escenario).

Ejecuta run_experiment.py N veces con semillas derivadas (seed_base + i),
colecta evaluation.json de cada corrida y agrega TP/FN por escenario,
calculando ADR con IC 95% de Wilson. Escribe:

  analysis_output/validation/<tag>_<ts>/validation_summary.json
  analysis_output/validation/<tag>_<ts>/validation_summary.md   (tabla RESULTS)
  analysis_output/validation/<tag>_<ts>/runs/<seed>/evaluation.json (crudos)

Uso:
  LAB_AUTHORIZED=YES python run_matrix.py --runs 30 --mode docker --exclude A14
  LAB_AUTHORIZED=YES python run_matrix.py --runs 2 --mode local --exclude A14   # smoke
  # Solo A14 (corrida dedicada, ~135 s c/u):
  LAB_AUTHORIZED=YES python run_matrix.py --runs 30 --mode local --tag a14 \
      --exclude A01,A02,A03,A04,A05,A06,A07,A08,A09,A10,A11,A12,A13,A15,A16
"""

import argparse
import json
import math
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PY = sys.executable


def wilson_ci(k: int, n: int, z: float = 1.96):
    """IC 95% de Wilson para proporción k/n. Devuelve (lo, hi) como fracción."""
    if n == 0:
        return (0.0, 1.0)
    p = k / n
    z2 = z * z
    denom = 1 + z2 / n
    centre = (p + z2 / (2 * n)) / denom
    margin = (z / denom) * math.sqrt(p * (1 - p) / n + z2 / (4 * n * n))
    lo = max(0.0, centre - margin)
    hi = min(1.0, centre + margin)
    return (lo, hi)


def run_once(i: int, args, seed: int) -> Path:
    """Ejecuta una corrida y devuelve el run_dir."""
    cmd = [PY, "run_experiment.py", "--mode", args.mode,
           "--benign-count", str(args.benign_count),
           "--anomaly-count", str(args.anomaly_count),
           "--interval", str(args.interval),
           "--seed", str(seed)]
    if args.exclude:
        cmd += ["--exclude", args.exclude]
    env = os.environ.copy()
    env["LAB_AUTHORIZED"] = "YES"
    print(f"\n[{i}/{args.runs}] seed={seed} modo={args.mode}", flush=True)
    t0 = time.monotonic()
    r = subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True,
                       text=True, encoding="utf-8", errors="replace")
    elapsed = round(time.monotonic() - t0, 1)
    if r.returncode != 0:
        print(r.stdout[-2000:], file=sys.stderr)
        print(r.stderr[-2000:], file=sys.stderr)
        raise SystemExit(f"corrida {i} (seed={seed}) falló con código {r.returncode}")
    m = re.search(r"Corrida completa:\s*(runs[\\/][\d_]+)", r.stdout)
    if not m:
        print(r.stdout[-2000:], file=sys.stderr)
        raise SystemExit(f"corrida {i}: no se pudo parsear el run_dir")
    run_dir = ROOT / m.group(1).replace("\\", "/")
    ev = json.loads((run_dir / "evaluation.json").read_text(encoding="utf-8"))
    print(f"  -> {run_dir.name} ({elapsed}s): recall={ev['recall']:.3f} "
          f"fp={ev['fp']} fn={ev['fn']} inyecciones={ev['injections_total']}",
          flush=True)
    return run_dir


def aggregate(run_dirs):
    """Agrega evaluation.json de varias corridas → tabla por escenario + global."""
    per = {}
    g = {"tp": 0, "fp": 0, "fn": 0, "tn": 0, "injections": 0,
         "alerts": 0, "normal": 0}
    for rd in run_dirs:
        ev = json.loads((rd / "evaluation.json").read_text(encoding="utf-8"))
        g["tp"] += ev["tp"]
        g["fp"] += ev["fp"]
        g["fn"] += ev["fn"]
        g["tn"] += ev["tn"]
        g["injections"] += ev["injections_total"]
        g["alerts"] += ev["alerts_total"]
        g["normal"] += ev["normal_messages"]
        for sid, s in ev.get("per_scenario", {}).items():
            d = per.setdefault(sid, {
                "name": s.get("name", ""),
                "expected_rule": s.get("expected_rule", ""),
                "mitre_ics": s.get("mitre_ics", ""),
                "injected": 0, "detected": 0, "missed": 0, "runs": 0,
            })
            d["injected"] += s.get("injected", 0)
            d["detected"] += s.get("detected", 0)
            d["missed"] += s.get("missed", 0)
            d["runs"] += 1

    for sid, d in per.items():
        n = d["injected"]
        k = d["detected"]
        d["adr"] = (k / n) if n else 0.0
        lo, hi = wilson_ci(k, n)
        d["wilson_lo"] = round(lo, 4)
        d["wilson_hi"] = round(hi, 4)
        d["adr_pct"] = round(d["adr"] * 100, 1)
        d["meets_90"] = d["adr"] >= 0.90

    gtot = g["tp"] + g["fn"]
    g["adr"] = (g["tp"] / gtot) if gtot else 0.0
    glo, ghi = wilson_ci(g["tp"], gtot)
    g["wilson_lo"] = round(glo, 4)
    g["wilson_hi"] = round(ghi, 4)
    g["adr_pct"] = round(g["adr"] * 100, 1)
    g["precision"] = (g["tp"] / (g["tp"] + g["fp"])) if (g["tp"] + g["fp"]) else 0.0
    coverage = sum(1 for d in per.values() if d["meets_90"])
    return {"per_scenario": per, "global": g, "coverage_90": coverage,
            "n_escenarios": len(per)}


def render_markdown(agg, meta):
    g = agg["global"]
    lines = [
        "# Resultados campaña H1 (run_matrix)",
        "",
        f"- Fecha (UTC): {meta['timestamp_utc']}",
        f"- Commit: {meta['commit']}",
        f"- Modo: {meta['mode']} | Corridas: {meta['runs']} | "
        f"seed_base: {meta['seed_base']}",
        f"- Parámetros: benign={meta['benign_count']} "
        f"anomaly={meta['anomaly_count']} interval={meta['interval']}s "
        f"exclude={meta['exclude'] or '(ninguno)'}",
        f"- Host: PC (declarado) | Python: {meta['python']}",
        f"- Cobertura ADR≥90%: {agg['coverage_90']}/{agg['n_escenarios']} escenarios",
        "",
        "## H1 — Efectividad por escenario (ADR ≥ 90%)",
        "",
        "| Escenario | N corridas | Inyectados | TP | FN | ADR % | IC95 % (Wilson) | ≥90% |",
        "|-----------|-----------|-----------|----|----|-------|------------------|------|",
    ]
    for sid in sorted(agg["per_scenario"]):
        d = agg["per_scenario"][sid]
        ci = f"[{d['wilson_lo']*100:.1f}, {d['wilson_hi']*100:.1f}]"
        mark = "✅" if d["meets_90"] else "❌"
        lines.append(
            f"| {sid} | {d['runs']} | {d['injected']} | {d['detected']} | "
            f"{d['missed']} | {d['adr_pct']:.1f} | {ci} | {mark} |")
    ci_g = f"[{g['wilson_lo']*100:.1f}, {g['wilson_hi']*100:.1f}]"
    lines += [
        f"| **GLOBAL** | {meta['runs']} | {g['injections']} | {g['tp']} | "
        f"{g['fn']} | {g['adr_pct']:.1f} | {ci_g} | "
        f"{'✅' if g['adr'] >= 0.90 else '❌'} |",
        "",
        f"**Precisión global:** {g['precision']*100:.1f}% | "
        f"**FP totales:** {g['fp']} | **TN (mensajes benignos):** {g['normal']} | "
        f"**Alertas totales:** {g['alerts']}",
        "",
        "> Nota: FP sobre corpus de inyecciones sintéticas (mensajes benignos "
        "intercalados). El FP sobre evidencia real (STANDBY/RUNNING) se mide "
        "aparte con replay_evidence.py (H3).",
    ]
    return "\n".join(lines) + "\n"


def parse_args():
    p = argparse.ArgumentParser(description="Campaña H1: N corridas + ADR/IC95 Wilson")
    p.add_argument("--runs", type=int, default=30,
                   help="Corridas (protocolo: >= 30 por escenario; default 30)")
    p.add_argument("--mode", choices=["local", "docker"], default="docker",
                   help="Modo de run_experiment (metodología: docker)")
    p.add_argument("--exclude", default="A14",
                   help="Escenarios a excluir (default A14: lento; correr aparte)")
    p.add_argument("--benign-count", type=int, default=6)
    p.add_argument("--anomaly-count", type=int, default=3)
    p.add_argument("--interval", type=float, default=6.0)
    p.add_argument("--seed-base", type=int, default=100000,
                   help="Semilla base; corrida i usa seed_base+i (default 100000)")
    p.add_argument("--tag", default="main",
                   help="Etiqueta del directorio de salida (main, a14, ...)")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    if os.environ.get("LAB_AUTHORIZED", "").strip().upper() != "YES":
        print("ERROR: define LAB_AUTHORIZED=YES", file=sys.stderr)
        return 3
    if not (ROOT / "LAB_ONLY.marker").exists():
        print("ERROR: falta LAB_ONLY.marker", file=sys.stderr)
        return 3

    commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT,
                            capture_output=True, text=True).stdout.strip()
    ts_dir = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    out_root = (ROOT / "analysis_output" / "validation" /
                f"{args.tag}_{ts_dir}")
    (out_root / "runs").mkdir(parents=True, exist_ok=True)

    print(f"Campaña H1: {args.runs} corridas modo={args.mode} "
          f"exclude={args.exclude or '(ninguno)'}", flush=True)
    print(f"Salida: {out_root.relative_to(ROOT)}", flush=True)

    run_dirs = []
    for i in range(1, args.runs + 1):
        seed = args.seed_base + i
        rd = run_once(i, args, seed)
        # Copiar evaluation.json crudo al dir de la campaña
        dst = out_root / "runs" / f"seed_{seed}"
        dst.mkdir(parents=True, exist_ok=True)
        (dst / "evaluation.json").write_bytes(
            (rd / "evaluation.json").read_bytes())
        (dst / "source_run").write_text(str(rd.relative_to(ROOT)), encoding="utf-8")
        run_dirs.append(rd)

    agg = aggregate(run_dirs)
    meta = {
        "tool": "run_matrix.py",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "commit": commit,
        "mode": args.mode,
        "runs": args.runs,
        "seed_base": args.seed_base,
        "seeds": [args.seed_base + i for i in range(1, args.runs + 1)],
        "exclude": args.exclude,
        "benign_count": args.benign_count,
        "anomaly_count": args.anomaly_count,
        "interval": args.interval,
        "python": sys.version.split()[0],
        "host_declarado": "PC",
    }
    summary = {**meta, **agg}
    (out_root / "validation_summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    md = render_markdown(agg, meta)
    (out_root / "validation_summary.md").write_text(md, encoding="utf-8")

    g = agg["global"]
    print(f"\n=== CAMPAÑA COMPLETA ({args.runs} corridas) ===")
    print(f"ADR global: {g['adr_pct']:.1f}% "
          f"(IC95 [{g['wilson_lo']*100:.1f}, {g['wilson_hi']*100:.1f}]) "
          f"precision={g['precision']*100:.1f}% fp={g['fp']} fn={g['fn']}")
    print(f"Cobertura ADR>=90%: {agg['coverage_90']}/{agg['n_escenarios']} escenarios")
    print(f"Resumen: {out_root.relative_to(ROOT)}/validation_summary.md")
    return 0


if __name__ == "__main__":
    sys.exit(main())
