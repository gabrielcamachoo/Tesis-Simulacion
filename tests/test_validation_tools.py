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


class TestRunMatrix:
    def test_wilson_ci_perfecto(self):
        from run_matrix import wilson_ci
        lo, hi = wilson_ci(30, 30)
        assert 0.85 < lo < 1.0
        assert hi == 1.0

    def test_wilson_ci_cero(self):
        from run_matrix import wilson_ci
        lo, hi = wilson_ci(0, 30)
        assert lo == 0.0
        assert 0.0 < hi < 0.2

    def test_wilson_ci_n_cero(self):
        from run_matrix import wilson_ci
        assert wilson_ci(0, 0) == (0.0, 1.0)

    def test_wilson_ci_parcial(self):
        from run_matrix import wilson_ci
        lo, hi = wilson_ci(27, 30)  # 90%
        assert 0.70 < lo < 0.95 < hi < 1.0

    def test_aggregate_suma_y_adr(self, tmp_path):
        from run_matrix import aggregate
        ev1 = {"tp": 5, "fp": 0, "fn": 1, "tn": 2, "injections_total": 6,
               "alerts_total": 5, "normal_messages": 2,
               "per_scenario": {"A01": {"name": "x", "expected_rule": "R-ID-001",
                                        "mitre_ics": "T1", "injected": 3,
                                        "detected": 3, "missed": 0},
                                "A02": {"name": "y", "expected_rule": "R-SEQ-001",
                                        "mitre_ics": "T1", "injected": 3,
                                        "detected": 2, "missed": 1}}}
        ev2 = dict(ev1)
        (tmp_path / "a").mkdir()
        (tmp_path / "b").mkdir()
        import json
        (tmp_path / "a" / "evaluation.json").write_text(json.dumps(ev1))
        (tmp_path / "b" / "evaluation.json").write_text(json.dumps(ev2))
        agg = aggregate([tmp_path / "a", tmp_path / "b"])
        assert agg["global"]["tp"] == 10
        assert agg["global"]["fn"] == 2
        assert agg["global"]["injections"] == 12
        assert abs(agg["global"]["adr"] - 10 / 12) < 1e-9
        a01 = agg["per_scenario"]["A01"]
        assert a01["injected"] == 6 and a01["detected"] == 6
        assert a01["adr"] == 1.0 and a01["meets_90"] is True
        a02 = agg["per_scenario"]["A02"]
        assert a02["injected"] == 6 and a02["detected"] == 4
        assert a02["adr"] < 0.90 and a02["meets_90"] is False
