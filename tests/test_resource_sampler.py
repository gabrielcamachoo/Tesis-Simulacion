"""Pruebas del medidor de recursos por fase y de su analizador."""

import csv
import subprocess
import sys

import analyze_resources
import resource_sampler


def test_sampler_escribe_filas_con_fase_y_proceso_del_lab(tmp_path):
    fase = tmp_path / "fase"
    fase.write_text("F1\n", encoding="utf-8")
    # Proceso falso cuya línea de comandos contiene "mllp_receiver.py".
    fake = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(10)", "mllp_receiver.py"])
    try:
        out = tmp_path / "pi.csv"
        n = resource_sampler.run(out, interval=0.3, duration=1.5, phase_file=fase)
    finally:
        fake.kill()
    rows = list(csv.DictReader(out.open(encoding="utf-8")))
    assert n == len(rows) >= 3
    assert {"ts_utc", "fase", "cpu_total_pct", "mem_used_mb", "receptor_cpu_pct",
            "detector_rss_mb", "tcpdump_n"} <= set(rows[0])
    assert all(r["fase"] == "F1" for r in rows)
    assert int(rows[-1]["receptor_n"]) >= 1
    assert float(rows[-1]["receptor_rss_mb"]) > 0


def test_sampler_sin_archivo_de_fase(tmp_path):
    out = tmp_path / "x.csv"
    resource_sampler.run(out, interval=0.2, duration=0.5, phase_file=tmp_path / "no_existe")
    rows = list(csv.DictReader(out.open(encoding="utf-8")))
    assert rows and rows[0]["fase"] == "sin_fase"


def test_analizador_resume_por_fase_y_grafica(tmp_path, monkeypatch):
    f = tmp_path / "pc_rep1.csv"
    datos = [("F1", 1.0), ("F1", 3.0), ("F2", 50.0), ("F2", 70.0), ("F3", 2.0)]
    with f.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["ts_utc", "fase", "cpu_pct", "mem_mb"])
        for i, (fase, cpu) in enumerate(datos):
            w.writerow([f"2026-11-19T10:00:0{i}+00:00", fase, cpu, 20 + i])

    s = analyze_resources.summarize(analyze_resources.load(f))
    assert list(s) == ["F1", "F2", "F3"]
    assert s["F1"]["cpu_pct"][0] == 2.0      # promedio
    assert s["F2"]["cpu_pct"][2] == 70.0     # máximo
    assert s["F2"]["n"] == 2

    out = tmp_path / "resumen.md"
    monkeypatch.setattr(sys, "argv", ["x", str(f), "--out", str(out), "--plot", "cpu_pct"])
    assert analyze_resources.main() == 0
    assert "| F2 | 2 |" in out.read_text(encoding="utf-8")
    assert (tmp_path / "pc_rep1_cpu_pct.svg").read_text(encoding="utf-8").startswith("<svg")
