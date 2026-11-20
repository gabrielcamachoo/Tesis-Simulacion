#!/usr/bin/env python3
"""
analyze_resources.py - Resume por fase los CSV de resource_sampler.py (Pi) y
de deploy/medicion/medir_simwato.ps1 (PC).

Para cada fase (F0, F1, F2, ...) y cada columna numérica saca promedio, p95,
máximo y desviación estándar. Escribe una tabla Markdown y, por cada CSV, una
gráfica SVG de la columna --plot con el fondo coloreado por fase.

En los CSV de la Pi agrega además (H2):
  - lab_cpu_pct / lab_rss_mb: suma de receptor + detector + tcpdump;
  - comparación contra los umbrales UMBRALES (cumple / NO cumple) por fase;
  - pendiente de la RAM (MB/min) por fase, para ver si crece de forma constante;
  - valores de `throttled` vistos (distinto de 0x0 = repetir la repetición);
  - con varios CSV, tabla entre repeticiones (media, desviación, máximo).

Uso:
  python analyze_resources.py runs/recursos/pi_rep*.csv --out runs/recursos/pi_resumen.md
  python analyze_resources.py runs/recursos/pc_rep*.csv --out runs/recursos/pc_resumen.md --plot cpu_pct
"""

import argparse
import csv
import statistics
import sys
from datetime import datetime
from pathlib import Path

from src.evidence.baseline_builder import percentile

LAB = ("receptor", "detector", "tcpdump")
# Umbrales de H2 fijados ANTES de medir (deploy/medicion/README.md, sección H2).
# columna -> (estadístico comparado, límite). 100 % de CPU = un núcleo.
UMBRALES = {"lab_cpu_pct": ("promedio", 50.0),   # decisión del equipo, 19-11-2026
            "lab_rss_mb": ("máximo", 64.0)}      # SRS §2.1.6: analizador ≤ 64 MB
STAT = {"promedio": 0, "p95": 1, "máximo": 2}

COLORS = ["#dbeafe", "#fee2e2", "#fef3c7", "#dcfce7", "#ede9fe", "#fce7f3"]


def load(path):
    with open(path, newline="", encoding="utf-8-sig") as fh:
        rows = list(csv.DictReader(fh))
    for r in rows:
        if all(f"{g}_cpu_pct" in r for g in LAB):
            for m in ("cpu_pct", "rss_mb"):
                r[f"lab_{m}"] = round(sum(float(r[f"{g}_{m}"] or 0) for g in LAB), 1)
    return rows


def numeric_columns(rows):
    cols = []
    for c in rows[0]:
        if c in ("ts_utc", "fase", "throttled") or c.endswith("_n"):
            continue
        try:
            [float(r[c]) for r in rows if r[c] != ""]
            cols.append(c)
        except ValueError:
            pass
    return cols


def summarize(rows):
    """{fase: {col: (promedio, p95, max, desviación)}} en el orden en que aparecen las fases."""
    cols = numeric_columns(rows)
    out = {}
    for fase in dict.fromkeys(r["fase"] for r in rows):
        sel = [r for r in rows if r["fase"] == fase]
        out[fase] = {"n": len(sel)}
        for c in cols:
            v = sorted(float(r[c]) for r in sel if r[c] != "")
            if v:
                sd = statistics.stdev(v) if len(v) > 1 else 0.0
                out[fase][c] = (sum(v) / len(v), percentile(v, 95), v[-1], sd)
    return out


def to_markdown(title, summary):
    cols = [c for c in next(iter(summary.values())) if c != "n"]
    lines = [f"### {title}", "", "| Fase | Muestras | " + " | ".join(cols) + " |",
             "|---|---|" + "---|" * len(cols)]
    for fase, s in summary.items():
        cells = [f"{s[c][0]:.1f} / {s[c][1]:.1f} / {s[c][2]:.1f} / {s[c][3]:.1f}" if c in s else ""
                 for c in cols]
        lines.append(f"| {fase} | {s['n']} | " + " | ".join(cells) + " |")
    lines += ["", "Cada celda: promedio / p95 / máximo / desviación.", ""]
    return "\n".join(lines)


def between_reps(summaries):
    """{fase: {col: (media de los promedios, desviación entre repeticiones, máximo de máximos)}}."""
    out = {}
    for s in summaries:
        for fase, cols in s.items():
            for c, v in cols.items():
                if c != "n":
                    out.setdefault(fase, {}).setdefault(c, []).append(v)
    return {f: {c: (statistics.mean(x[0] for x in v),
                    statistics.stdev(x[0] for x in v) if len(v) > 1 else 0.0,
                    max(x[2] for x in v)) for c, v in cols.items()}
            for f, cols in out.items()}


def reps_markdown(summaries):
    b = between_reps(summaries)
    cols = list(next(iter(b.values())))
    lines = [f"### Entre repeticiones ({len(summaries)})", "",
             "| Fase | " + " | ".join(cols) + " |", "|---|" + "---|" * len(cols)]
    for fase, s in b.items():
        lines.append(f"| {fase} | " + " | ".join(
            f"{s[c][0]:.1f} +/- {s[c][1]:.1f} (máx {s[c][2]:.1f})" if c in s else "" for c in cols) + " |")
    lines += ["", "Cada celda: media de los promedios por repetición +/- desviación entre "
              "repeticiones (máximo de todas).", ""]
    return "\n".join(lines)


def slope_per_min(rows, col):
    """Pendiente por mínimos cuadrados de `col` en MB (o la unidad de col) por minuto."""
    t0 = datetime.fromisoformat(rows[0]["ts_utc"])
    xs = [(datetime.fromisoformat(r["ts_utc"]) - t0).total_seconds() / 60 for r in rows]
    ys = [float(r[col]) for r in rows]
    mx, my = statistics.mean(xs), statistics.mean(ys)
    den = sum((x - mx) ** 2 for x in xs)
    return sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / den if den else 0.0


def h2_markdown(title, rows, summary):
    """Umbrales, pendiente de la RAM y throttled de un CSV de la Pi."""
    lines = [f"#### H2 — {title}", ""]
    thr = sorted({r.get("throttled", "") for r in rows} - {""})
    if thr:
        # Criterio (README, sección H2): las banderas ACTUALES (bits 0-3) en 0 en todas las muestras
        # y sin bandera nueva; las "ocurrió" (bits 16-19) heredadas del arranque se declaran.
        ok = all(int(t, 16) & 0xF == 0 for t in thr) and len(thr) == 1
        lines += [f"- throttled: {', '.join(thr)} → " + ("válida (revisar también dmesg en la ventana)"
                                                       if ok else "**REPETIR esta repetición**"), ""]
    lines += ["| Fase | " + " | ".join(f"{c} {st} <= {lim:g}" for c, (st, lim) in UMBRALES.items())
              + " | Pendiente RAM detector (MB/min) |", "|---|" + "---|" * (len(UMBRALES) + 1)]
    for fase, s in summary.items():
        cells = []
        for c, (st, lim) in UMBRALES.items():
            v = s[c][STAT[st]]
            cells.append(f"{v:.1f} {'cumple' if v <= lim else '**NO cumple**'}")
        sel = [r for r in rows if r["fase"] == fase]
        cells.append(f"{slope_per_min(sel, 'detector_rss_mb'):+.3f}" if len(sel) > 1 else "")
        lines.append(f"| {fase} | " + " | ".join(cells) + " |")
    return "\n".join(lines + [""])


def to_svg(rows, col, title):
    """Línea de `col` en el tiempo (una muestra = un paso) con bandas por fase."""
    w, h, pad = 900, 300, 40
    vals = [float(r[col]) if r[col] != "" else 0.0 for r in rows]
    top = max(max(vals), 1.0) * 1.1
    x = lambda i: pad + i * (w - 2 * pad) / max(len(vals) - 1, 1)
    y = lambda v: h - pad - v * (h - 2 * pad) / top
    fases = list(dict.fromkeys(r["fase"] for r in rows))
    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" font-family="sans-serif" font-size="12">',
             f'<rect width="{w}" height="{h}" fill="white"/>']
    start = 0
    for i in range(1, len(rows) + 1):
        if i == len(rows) or rows[i]["fase"] != rows[start]["fase"]:
            fase = rows[start]["fase"]
            color = COLORS[fases.index(fase) % len(COLORS)]
            parts.append(f'<rect x="{x(start):.1f}" y="{pad}" width="{max(x(i - 1) - x(start), 1):.1f}" '
                         f'height="{h - 2 * pad}" fill="{color}"/>')
            parts.append(f'<text x="{x(start) + 3:.1f}" y="{pad + 14}">{fase}</text>')
            start = i
    pts = " ".join(f"{x(i):.1f},{y(v):.1f}" for i, v in enumerate(vals))
    parts += [f'<polyline points="{pts}" fill="none" stroke="#1d4ed8" stroke-width="1.5"/>',
              f'<text x="{pad}" y="20" font-size="14">{title} — {col} (máx {max(vals):.1f})</text>',
              f'<text x="{pad}" y="{h - 12}">{rows[0]["ts_utc"]} → {rows[-1]["ts_utc"]}</text>',
              "</svg>"]
    return "\n".join(parts)


def main():
    p = argparse.ArgumentParser(description="Resumen por fase de los CSV de recursos")
    p.add_argument("csv", nargs="+", help="CSV de resource_sampler.py o medir_simwato.ps1")
    p.add_argument("--out", required=True, help="Markdown de salida (las SVG van al lado)")
    p.add_argument("--plot", default="cpu_total_pct", help="Columna a graficar")
    a = p.parse_args()

    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    md, todas, sums = [], [], []
    for f in a.csv:
        rows = load(f)
        if not rows:
            print(f"AVISO: {f} está vacío, se omite", file=sys.stderr)
            continue
        todas += rows
        s = summarize(rows)
        sums.append(s)
        md.append(to_markdown(Path(f).name, s))
        if "lab_cpu_pct" in rows[0]:
            md.append(h2_markdown(Path(f).name, rows, s))
        if a.plot in rows[0]:
            svg = out.with_name(Path(f).stem + f"_{a.plot}.svg")
            svg.write_text(to_svg(rows, a.plot, Path(f).stem), encoding="utf-8")
    if not todas:
        print("ERROR: no hay muestras", file=sys.stderr)
        return 1
    if len(a.csv) > 1:
        md.append(reps_markdown(sums))
        md.append(to_markdown("Todas las repeticiones juntas", summarize(todas)))
    out.write_text("\n".join(md), encoding="utf-8")
    print(out.read_text(encoding="utf-8"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
