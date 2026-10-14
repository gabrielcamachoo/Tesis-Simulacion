#!/usr/bin/env python3
"""
tests/test_validation_tools.py - Herramientas de la Fase 9 (validación):
semillas deterministas, bench de latencia H2 y replay de evidencia H3.
"""

import os
from pathlib import Path

import pytest

from anomaly_generator import SCENARIOS, select_scenarios

ROOT = Path(__file__).resolve().parents[1]
PCAP_STANDBY = ROOT / "evidence_raw" / "pcap" / "LECTURACONACK25AGOSTO.pcapng"
PCAP_RUNNING = ROOT / "evidence_raw" / "pcap" / "LECTURAACK27AGOSTO.pcapng"


class TestSelectScenarios:
    def test_misma_semilla_mismo_orden(self):
        a = [s.id for s in select_scenarios(seed=42)]
        b = [s.id for s in select_scenarios(seed=42)]
        assert a == b
        assert len(a) == len(SCENARIOS)

    def test_sementas_distintas_alternan_orden(self):
        orders = {tuple(s.id for s in select_scenarios(seed=k))
                  for k in (1, 2, 3, 4, 5)}
        assert len(orders) > 1

    def test_sin_semilla_conserva_orden_original(self):
        assert [s.id for s in select_scenarios()] == list(SCENARIOS.keys())

    def test_exclude(self):
        ids = [s.id for s in select_scenarios({"A14"})]
        assert "A14" not in ids
        assert len(ids) == len(SCENARIOS) - 1

    def test_exclude_con_semilla(self):
        ids = [s.id for s in select_scenarios({"A14"}, seed=7)]
        assert "A14" not in ids
        assert len(ids) == len(SCENARIOS) - 1


@pytest.mark.skipif(not PCAP_STANDBY.exists(),
                    reason="evidencia de la tesis requerida")
class TestReplayExtraction:
    def test_standby_extrae_43_oru_un_flujo(self):
        from replay_evidence import extract_oru_flows, flatten
        flows = extract_oru_flows(PCAP_STANDBY)
        assert len(flows) == 1
        assert len(flatten(flows)) == 43

    def test_running_extrae_99_oru_un_flujo(self):
        from replay_evidence import extract_oru_flows, flatten
        flows = extract_oru_flows(PCAP_RUNNING)
        assert len(flows) == 1
        assert len(flatten(flows)) == 99

    def test_intervalos_standby_aprox_10s(self):
        from replay_evidence import extract_oru_flows, flatten, interval_stats
        stats = interval_stats(flatten(extract_oru_flows(PCAP_STANDBY)))
        assert stats["n"] == 42
        assert 9.0 <= stats["avg_s"] <= 11.0

    def test_mensajes_son_oru_anonimizados(self):
        from replay_evidence import extract_oru_flows, flatten
        flat = flatten(extract_oru_flows(PCAP_STANDBY))
        for content, _ts in flat:
            assert content.startswith(b"MSH|")
            assert b"ORU^R01" in content


class TestLatencyBenchSmoke:
    def test_bench_smoke(self, tmp_path, monkeypatch):
        from latency_bench import ROOT as BENCH_ROOT, run_bench
        from run_experiment import write_lab_config

        monkeypatch.setenv("LAB_AUTHORIZED", "YES")
        cfg = write_lab_config(tmp_path)
        rep = run_bench(150, 1, 7, cfg,
                        BENCH_ROOT / "baseline.yaml",
                        BENCH_ROOT / "config/rules.yaml")
        run = rep["per_run"][0]
        assert run["messages"] == 150
        assert rep["aggregate"]["n_total"] == 150
        assert run["p95_us"] > 0
        assert run["max_us"] >= run["p50_us"]
        # Camino de peor caso: R-TIME-002 + R-SEQ-002 en cada mensaje
        # posterior al primero (>= 149 alertas sobre 150 mensajes).
        assert run["alerts_emitidas"] >= 149
        assert rep["threshold_us"] == 500.0
        assert rep["verdict_p95_vs_threshold"] in ("PASS", "FAIL")
        assert rep["entorno"]["es_raspberry_pi"] is False
