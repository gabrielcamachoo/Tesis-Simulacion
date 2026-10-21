#!/usr/bin/env python3
"""
Pruebas de la enmienda E6 (evaluación por conexión de origen).
Rama pruebas-santi (2026-10-20).

Hallazgo: evaluate.py contaba como "correlacionada" (no FP) cualquier alerta
dentro de 5 s de CUALQUIER inyección, aunque viniera de otra conexión. En la
campaña (semilla 100001) el primer mensaje benigno de la fase 2 alertaba
R-TIME-002 "Interval too short: 0.33s" y quedaba oculto. Además, las alertas
del vigilante de silencio (E3) durante A14 caían ~30 s ANTES del registro de
la inyección (que se escribe al terminar el silencio) y se contaban como FP.

E6: el generador registra la conexión de origen (source) y el inicio de la
anomalía (started_utc); el evaluador solo correlaciona alertas de la misma
conexión y desde el inicio de la anomalía. Ground truth antiguo (sin esos
campos) se evalúa igual que antes.
"""

import json
import socket
import sys
import threading
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from evaluate import (AlertRecord, Injection, evaluate, match_injections,
                      partition_unmatched)

GEN = "127.0.0.1:40001"     # conexión del generador
BENIGN = "127.0.0.1:50002"  # conexión del emulador benigno


def _inj(ts, source=GEN, started="", rule="R-ID-001", iid="INJ-00001", sid="A01"):
    return Injection(injection_id=iid, scenario_id=sid, scenario_name="x",
                     expected_rule=rule, timestamp_utc=ts, source=source,
                     started_utc=started)


def _al(ts, source, rule="R-TIME-002", aid="ALERT-1"):
    return AlertRecord(alert_id=aid, rule_id=rule, timestamp_utc=ts,
                       source=source)


T0 = "2026-10-20T18:21:15.900000+00:00"
T0_PLUS_03 = "2026-10-20T18:21:16.240000+00:00"


class TestEvaluadorPorOrigen:

    def test_alerta_benigna_en_ventana_es_fp(self):
        """Caso medido en la campaña: alerta del emulador 0.34 s después de
        la última inyección -> FP (antes: correlacionada)."""
        injs = [_inj(T0)]
        alerts = [_al(T0, GEN, rule="R-ID-001", aid="A-gen"),
                  _al(T0_PLUS_03, BENIGN, aid="A-benign")]
        res = evaluate(injs, alerts, normal_count=11)
        assert res.tp == 1
        assert res.fp == 1
        assert res.unmatched_alerts == ["A-benign"]
        assert res.fp_other_source_in_window == 1
        assert res.correlated_alerts == 0

    def test_alerta_extra_misma_conexion_sigue_correlacionada(self):
        injs = [_inj(T0)]
        alerts = [_al(T0, GEN, rule="R-ID-001", aid="A-gen"),
                  _al(T0_PLUS_03, GEN, aid="A-gen-extra")]
        res = evaluate(injs, alerts, normal_count=11)
        assert (res.tp, res.fp, res.correlated_alerts) == (1, 0, 1)

    def test_alerta_de_otra_conexion_no_hace_match(self):
        """Una inyección no puede 'detectarse' con la alerta de otra conexión."""
        injs = [_inj(T0)]
        n, _, unmatched = match_injections(injs, [_al(T0_PLUS_03, BENIGN,
                                                      rule="R-ID-001")])
        assert n == 0
        assert len(unmatched) == 1

    def test_ground_truth_antiguo_sin_origen_igual_que_antes(self):
        injs = [_inj(T0, source="")]
        alerts = [_al(T0, GEN, rule="R-ID-001", aid="A-gen"),
                  _al(T0_PLUS_03, BENIGN, aid="A-benign")]
        res = evaluate(injs, alerts, normal_count=11)
        assert (res.tp, res.fp, res.correlated_alerts) == (1, 0, 1)

    def test_silencio_a14_durante_el_hueco_es_correlacionado(self):
        """Valores reales de la campaña: silencio desde 18:18:56, vigilante
        alerta a las 18:19:12, el mensaje que cierra el hueco a las 18:19:41."""
        inj = _inj("2026-10-20T18:19:41.000000+00:00", rule="R-TIME-002",
                   started="2026-10-20T18:18:56.000000+00:00", sid="A14")
        silence = _al("2026-10-20T18:19:12.489000+00:00", GEN, aid="A-sil")
        closing = _al("2026-10-20T18:19:41.001000+00:00", GEN, aid="A-close")
        res = evaluate([inj], [silence, closing], normal_count=11)
        assert res.tp == 1
        assert res.fp == 0
        assert res.correlated_alerts == 1

    def test_silencio_sin_started_utc_sigue_siendo_fp(self):
        """Sin el inicio registrado (ground truth antiguo) el silencio queda
        fuera de ventana, como antes de E6."""
        inj = _inj("2026-10-20T18:19:41.000000+00:00", rule="R-TIME-002", sid="A14")
        silence = _al("2026-10-20T18:19:12.489000+00:00", GEN, aid="A-sil")
        res = evaluate([inj], [silence], normal_count=11)
        assert res.fp == 1


# --------------------------------------------------------------------------
# Generador: registra la conexión real usada
# --------------------------------------------------------------------------

@pytest.fixture
def sink():
    """Servidor TCP local que acepta y descarta (sin red externa)."""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    peers = []
    stop = threading.Event()

    def loop():
        srv.settimeout(0.2)
        while not stop.is_set():
            try:
                c, addr = srv.accept()
            except OSError:
                continue
            peers.append(f"{addr[0]}:{addr[1]}")
            c.settimeout(0.2)
            try:
                while c.recv(65536):
                    pass
            except OSError:
                pass
    t = threading.Thread(target=loop, daemon=True)
    t.start()
    yield srv.getsockname()[1], peers
    stop.set()
    srv.close()


@pytest.fixture
def generator(tmp_path, monkeypatch, sink):
    monkeypatch.setenv("LAB_AUTHORIZED", "YES")
    marker = ROOT / "LAB_ONLY.marker"
    created = not marker.exists()
    if created:
        marker.write_text("LAB ONLY\n", encoding="utf-8")
    try:
        from run_experiment import write_lab_config
        from src.config.settings import load_settings
        from anomaly_generator import AnomalyGenerator
        port, peers = sink
        gt = tmp_path / "gt.jsonl"
        gen = AnomalyGenerator(load_settings(str(write_lab_config(tmp_path))),
                               "127.0.0.1", port, gt)
        yield gen, gt, peers
        gen._close()
    finally:
        if created:
            marker.unlink()


class TestGeneradorRegistraOrigen:

    def _gt(self, path):
        return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l]

    def test_origen_es_la_conexion_local(self, generator):
        from anomaly_generator import SCENARIOS
        gen, gt, peers = generator
        rec = gen.inject(SCENARIOS["A01"], 1)
        assert rec is not None
        local = gen._sock.getsockname()
        assert rec.source == f"{local[0]}:{local[1]}"
        assert self._gt(gt)[-1]["source"] == rec.source
        assert rec.started_utc == rec.timestamp_utc

    def test_conexion_dedicada_a05_registra_su_propio_origen(self, generator):
        from anomaly_generator import SCENARIOS
        gen, gt, peers = generator
        a01 = gen.inject(SCENARIOS["A01"], 1)
        a05 = gen.inject(SCENARIOS["A05"], 1)
        assert a05 is not None and a05.source
        assert a05.source != a01.source
        # El receptor vio exactamente esa conexión
        import time
        deadline = time.monotonic() + 3
        while a05.source not in peers and time.monotonic() < deadline:
            time.sleep(0.05)
        assert a05.source in peers
