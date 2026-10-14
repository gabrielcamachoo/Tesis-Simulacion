#!/usr/bin/env python3
"""
Test de integración end-to-end:
  receptor MLLP (en proceso) + emulador benigno + generador de anomalías + evaluador.

Flujo:
  1. Levanta MLLPServer en puerto efímero con settings/baseline reales.
  2. Emulador benigno STANDBY (intervalo 6 s ∈ [5, 15.015] = sin alerta).
  3. Genera escenarios A01-A13, A15, A16 (A14 excluido: hueco >15 s, lento).
  4. Cierra, evalúa ground_truth vs alerts y verifica métricas.

Duración aprox. 20-30 s.
"""

import json
import os
import sys
import threading
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.config.settings import load_settings
from src.detection.baseline import load_baseline
from src.detection.rules import RuleSet
from src.detection.engine import DetectionEngine
from src.evidence.writer import EvidenceWriter
from src.alerting.json_logger import AlertLogger
from src.mllp.server import run_server
from anomaly_generator import SCENARIOS, AnomalyGenerator, SafetyGuard
from wato_emulator import WATOEmulator, EmulatorConfig, EmulatorState
from evaluate import load_ground_truth, load_alerts, evaluate


def _write_lab_config(tmp_path: Path) -> Path:
    src = ROOT / "src" / "config" / "settings.yaml"
    text = src.read_text(encoding="utf-8")
    marker = tmp_path / "LAB_ONLY.marker"
    marker.write_text("lab")
    text = text.replace('lab_marker_path: "/LAB_ONLY.marker"',
                        f'lab_marker_path: "{marker.as_posix()}"')
    cfg = tmp_path / "settings_lab.yaml"
    cfg.write_text(text, encoding="utf-8")
    return cfg


def start_lab(tmp_path: Path) -> dict:
    """Levanta el receptor completo. Devuelve componentes y puerto."""
    os.environ["LAB_AUTHORIZED"] = "YES"
    cfg = _write_lab_config(tmp_path)

    settings = load_settings(str(cfg))
    settings.network.bind_host = "127.0.0.1"
    settings.network.bind_port = 0  # puerto efímero
    outdir = tmp_path / "evidence"
    settings.evidence.output_dir = str(outdir)

    baseline = load_baseline(str(ROOT / "baseline.yaml"))
    rules = RuleSet(str(ROOT / "config" / "rules.yaml"))

    evidence_writer = EvidenceWriter(str(outdir), settings)
    engine = DetectionEngine(settings, baseline, rules)
    alert_logger = AlertLogger(settings, evidence_writer)

    server = run_server(settings, evidence_writer, engine, alert_logger,
                        send_ack=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.3)
    port = server.server_address[1]
    return {
        "server": server, "port": port, "settings": settings,
        "engine": engine, "alert_logger": alert_logger,
        "outdir": outdir, "tmp": tmp_path, "thread": thread,
    }


def stop_lab(lab: dict):
    lab["alert_logger"].close()
    lab["server"].shutdown()
    lab["server"].server_close()
    lab["thread"].join(timeout=5)


def run_benign(lab: dict, count: int, interval: float) -> WATOEmulator:
    emu_cfg = EmulatorConfig(
        receiver_host="127.0.0.1",
        receiver_port=lab["port"],
        state=EmulatorState.STANDBY,
        interval_seconds=interval,
        max_messages=count,
        require_ack=True,
        ack_timeout=3.0,
        max_reconnects=2,
    )
    emu = WATOEmulator(emu_cfg)
    emu.run()
    return emu


def test_benign_emulator_produces_no_alerts(tmp_path):
    """Emulador benigno aislado: solo NORMAL, cero alertas ANOMALO."""
    lab = start_lab(tmp_path)
    try:
        emu = run_benign(lab, count=2, interval=6.0)
        assert emu.stats["messages_sent"] == 2, emu.stats
        assert emu.stats["acks_received"] == 2, emu.stats
        time.sleep(0.5)

        alerts_file = lab["outdir"] / "alerts" / "alerts.jsonl"
        rows = []
        if alerts_file.exists():
            rows = [json.loads(l) for l in
                    alerts_file.read_text(encoding="utf-8").splitlines()
                    if l.strip()]
        anom = [a for a in rows if a.get("label") == "ANOMALO"]
        normal = [a for a in rows if a.get("label") == "NORMAL"]
        assert not anom, (
            f"emulador benigno generó alertas: "
            f"{[(a['rule_id'], a['reason']) for a in anom]}")
        assert len(normal) == 2, f"esperaba 2 NORMAL, hay {len(normal)}"
    finally:
        stop_lab(lab)


def test_end_to_end_detection(tmp_path):
    """Flujo completo benigno + anómalo + evaluación."""
    lab = start_lab(tmp_path)
    try:
        # ---- Fase 1: tráfico benigno (emulador) ----
        emu = run_benign(lab, count=2, interval=6.0)
        assert emu.stats["messages_sent"] == 2, emu.stats
        assert emu.stats["acks_received"] == 2, emu.stats

        # ---- Fase 2: anomalías ----
        gt_path = tmp_path / "ground_truth.jsonl"
        guard = SafetyGuard(lab["settings"])
        assert guard.check("127.0.0.1", lab["port"]), guard.errors

        gen = AnomalyGenerator(lab["settings"], "127.0.0.1", lab["port"], gt_path)

        # A14 excluido: requiere hueco >15 s (demasiado lento para el test)
        selected = [s for sid, s in SCENARIOS.items() if sid != "A14"]

        total = 0
        try:
            for s in selected:
                total += gen.run_scenario(s, count=1)
        finally:
            summary = gen.summary()
            gen.close()  # cierra sesión principal

        assert total > 0, "ninguna inyección exitosa"
        print(f"\nInyecciones={total} por escenario={summary}")

        # Tiempo para que el servidor procese cierres de sesión (A05)
        time.sleep(1.5)

        # ---- Recopilar salidas ----
        alerts_file = lab["outdir"] / "alerts" / "alerts.jsonl"
        assert gt_path.exists(), "falta ground_truth.jsonl"
        assert alerts_file.exists(), "falta alerts.jsonl"

        injections = load_ground_truth(gt_path)
        alerts, normal_count = load_alerts(alerts_file)

        assert len(injections) == total
        assert normal_count >= 2, (
            f"mensajes benignos sin alerta (TN)={normal_count}, esperado >= 2")

        # ---- Evaluación ----
        res = evaluate(injections, alerts, normal_count, window_s=5.0)
        print("\n" + res.__dict__.__repr__()[:2000])

        detection_rate = res.tp / res.injections_total if res.injections_total else 0
        assert detection_rate >= 0.90, (
            f"recall {detection_rate:.2f} < 0.90; TP={res.tp} FN={res.fn} "
            f"perdidas={res.missed_injections}")

        assert res.fp <= 2, f"FP={res.fp} demasiado: {res.unmatched_alerts}"

        zero = [sid for sid, sc in res.per_scenario.items() if sc["detected"] == 0]
        assert not zero, f"escenarios sin detectar: {zero}"
    finally:
        stop_lab(lab)
