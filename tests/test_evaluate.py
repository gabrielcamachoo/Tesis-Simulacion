#!/usr/bin/env python3
"""
Tests del evaluador: matching, métricas, percentiles y reporte.
Funciones puras sobre datos en memoria (sin archivos reales de corrida).
"""

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from evaluate import (
    Injection, AlertRecord, load_ground_truth, load_alerts,
    match_injections, compute_metrics, percentile, evaluate,
    format_report, run_from_dir, parse_expected_counts,
    compute_throughput, compute_message_loss, count_received_messages,
)


def inj(iid, sid, rule, ts, ctrl="1"):
    return Injection(injection_id=iid, scenario_id=sid, scenario_name=f"sc_{sid}",
                     expected_rule=rule, timestamp_utc=ts, control_id=ctrl)


def alt(aid, rule, ts, label="ANOMALO"):
    return AlertRecord(alert_id=aid, rule_id=rule, timestamp_utc=ts, label=label)


class TestMatching:
    def test_perfect_match(self):
        ins = [inj("INJ-1", "A02", "R-SEQ-001", "2026-10-13T10:00:00+00:00")]
        als = [alt("AL-1", "R-SEQ-001", "2026-10-13T10:00:01+00:00")]
        n, lats, unmatched = match_injections(ins, als, 5.0)
        assert n == 1
        assert len(unmatched) == 0
        assert lats and 900 <= lats[0] <= 1100  # ~1000 ms
        assert ins[0].matched_alert_id == "AL-1"

    def test_no_match_when_too_late(self):
        ins = [inj("INJ-1", "A02", "R-SEQ-001", "2026-10-13T10:00:00+00:00")]
        als = [alt("AL-1", "R-SEQ-001", "2026-10-13T10:01:00+00:00")]
        n, lats, unmatched = match_injections(ins, als, 5.0)
        assert n == 0
        assert len(unmatched) == 1

    def test_alert_before_injection_not_matched(self):
        ins = [inj("INJ-1", "A02", "R-SEQ-001", "2026-10-13T10:00:00+00:00")]
        als = [alt("AL-1", "R-SEQ-001", "2026-10-13T09:59:50+00:00")]
        n, _, unmatched = match_injections(ins, als, 5.0)
        assert n == 0
        assert len(unmatched) == 1

    def test_one_alert_matches_one_injection_only(self):
        ins = [inj("INJ-1", "A02", "R-SEQ-001", "2026-10-13T10:00:00+00:00"),
               inj("INJ-2", "A02", "R-SEQ-001", "2026-10-13T10:00:01+00:00")]
        als = [alt("AL-1", "R-SEQ-001", "2026-10-13T10:00:02+00:00")]
        n, _, unmatched = match_injections(ins, als, 5.0)
        assert n == 1
        assert len(unmatched) == 0

    def test_expected_rule_preferred(self):
        ins = [inj("INJ-1", "A01", "R-ID-001", "2026-10-13T10:00:00+00:00")]
        als = [alt("AL-OTHER", "R-TIME-002", "2026-10-13T10:00:00.500+00:00"),
               alt("AL-EXP", "R-ID-001", "2026-10-13T10:00:00.900+00:00")]
        n, lats, unmatched = match_injections(ins, als, 5.0)
        assert n == 1
        assert ins[0].matched_rule == "R-ID-001"
        assert len(unmatched) == 1  # la otra alerta queda como FP

    def test_wrong_rule_still_counts_as_detection(self):
        ins = [inj("INJ-1", "A01", "R-ID-001", "2026-10-13T10:00:00+00:00")]
        als = [alt("AL-1", "R-HL7-001", "2026-10-13T10:00:01+00:00")]
        n, _, unmatched = match_injections(ins, als, 5.0)
        assert n == 1
        assert ins[0].matched_rule == "R-HL7-001"
        assert ins[0].matched_rule != ins[0].expected_rule


class TestMetrics:
    def test_perfect_scores(self):
        m = compute_metrics(tp=10, fp=0, tn=100, fn=0)
        assert m["recall"] == 1.0
        assert m["precision"] == 1.0
        assert m["f1_score"] == 1.0
        assert m["fpr"] == 0.0

    def test_zero_division_safe(self):
        m = compute_metrics(tp=0, fp=0, tn=0, fn=0)
        assert m["recall"] == 0.0
        assert m["precision"] == 0.0
        assert m["f1_score"] == 0.0
        assert m["fpr"] == 0.0

    def test_partial_detection(self):
        m = compute_metrics(tp=8, fp=2, tn=98, fn=2)
        assert m["recall"] == 0.8
        assert m["precision"] == 0.8
        assert m["f1_score"] == 0.8
        assert m["fpr"] == round(2 / 100, 4)

    def test_all_missed(self):
        m = compute_metrics(tp=0, fp=1, tn=99, fn=10)
        assert m["recall"] == 0.0
        assert m["precision"] == 0.0


class TestPercentile:
    def test_median_odd(self):
        assert percentile([1, 3, 5], 50) == 3

    def test_median_even_interpolates(self):
        assert percentile([1, 2, 3, 4], 50) == 2.5

    def test_p99_high_value(self):
        vals = list(range(1, 101))
        assert percentile(vals, 99) == pytest.approx(99.01, abs=0.1)

    def test_empty(self):
        assert percentile([], 50) == 0.0

    def test_max(self):
        assert percentile([5, 1, 9], 100) == 9


class TestEvaluate:
    def test_all_detected_no_fp(self):
        ins = [inj(f"INJ-{i}", "A02", "R-SEQ-001",
                   f"2026-10-13T10:00:0{i}+00:00") for i in range(5)]
        als = [alt(f"AL-{i}", "R-SEQ-001",
                   f"2026-10-13T10:00:0{i}.200+00:00") for i in range(5)]
        res = evaluate(ins, als, normal_count=50)
        assert res.tp == 5
        assert res.fn == 0
        assert res.fp == 0
        assert res.tn == 50
        assert res.recall == 1.0
        assert res.precision == 1.0
        assert res.f1_score == 1.0
        assert res.fpr == 0.0

    def test_missed_injection_increases_fn(self):
        ins = [inj("INJ-1", "A05", "R-MLLP-001", "2026-10-13T10:00:00+00:00"),
               inj("INJ-2", "A05", "R-MLLP-001", "2026-10-13T10:00:05+00:00")]
        als = [alt("AL-1", "R-MLLP-001", "2026-10-13T10:00:01+00:00")]
        res = evaluate(ins, als, normal_count=10)
        assert res.tp == 1
        assert res.fn == 1
        assert res.recall == 0.5

    def test_spurious_alert_is_fp(self):
        ins = [inj("INJ-1", "A02", "R-SEQ-001", "2026-10-13T10:00:00+00:00")]
        als = [alt("AL-1", "R-SEQ-001", "2026-10-13T10:00:01+00:00"),
               alt("AL-2", "R-ID-001", "2026-10-13T11:00:00+00:00")]
        res = evaluate(ins, als, normal_count=10)
        assert res.fp == 1
        assert res.unmatched_alerts == ["AL-2"]

    def test_per_scenario_breakdown(self):
        ins = [inj("INJ-1", "A01", "R-ID-001", "2026-10-13T10:00:00+00:00"),
               inj("INJ-2", "A01", "R-ID-001", "2026-10-13T10:00:02+00:00"),
               inj("INJ-3", "A12", "R-TIME-002", "2026-10-13T10:00:04+00:00")]
        als = [alt("AL-1", "R-ID-001", "2026-10-13T10:00:01+00:00"),
               alt("AL-2", "R-ID-001", "2026-10-13T10:00:03+00:00")]
        res = evaluate(ins, als, normal_count=5)
        assert res.per_scenario["A01"]["detected"] == 2
        assert res.per_scenario["A01"]["detection_rate"] == 1.0
        assert res.per_scenario["A12"]["detected"] == 0
        assert res.per_scenario["A12"]["detection_rate"] == 0.0

    def test_latency_percentiles_present(self):
        ins = [inj(f"INJ-{i}", "A02", "R-SEQ-001",
                   f"2026-10-13T10:00:{i:02d}+00:00") for i in range(10)]
        als = [alt(f"AL-{i}", "R-SEQ-001",
                   f"2026-10-13T10:00:{i:02d}.100+00:00") for i in range(10)]
        res = evaluate(ins, als, normal_count=10)
        assert "p50" in res.latency_ms
        assert "p99" in res.latency_ms
        assert 90 <= res.latency_ms["p50"] <= 110

    def test_warnings_generated(self):
        res = evaluate([], [], normal_count=0)
        assert any("alertas" in w.lower() for w in res.warnings)

    def test_report_contains_metrics(self):
        ins = [inj("INJ-1", "A02", "R-SEQ-001", "2026-10-13T10:00:00+00:00")]
        als = [alt("AL-1", "R-SEQ-001", "2026-10-13T10:00:01+00:00")]
        res = evaluate(ins, als, normal_count=3)
        txt = format_report(res)
        assert "TP=" in txt
        assert "Recall" in txt
        assert "A02" in txt


class TestFileIO:
    def test_load_ground_truth(self, tmp_path):
        p = tmp_path / "gt.jsonl"
        p.write_text(json.dumps({
            "injection_id": "INJ-1", "scenario_id": "A02",
            "scenario_name": "duplicate_control_id",
            "expected_rule": "R-SEQ-001",
            "timestamp_utc": "2026-10-13T10:00:00+00:00",
            "monotonic_ns": 123, "control_id": "1",
            "bytes_sent": 971, "target": "receiver:1550",
            "mitre_ics": "T0857", "threat": "Replay",
        }) + "\n", encoding="utf-8")
        items = load_ground_truth(p)
        assert len(items) == 1
        assert items[0].scenario_id == "A02"
        assert items[0].expected_rule == "R-SEQ-001"

    def test_load_alerts_separates_normal(self, tmp_path):
        p = tmp_path / "alerts.jsonl"
        rows = [
            {"alert_id": "A1", "rule_id": "R-ID-001",
             "timestamp_utc": "2026-10-13T10:00:00+00:00", "label": "ANOMALO"},
            {"alert_id": "N1", "rule_id": "NORMAL",
             "timestamp_utc": "2026-10-13T10:00:01+00:00", "label": "NORMAL"},
        ]
        p.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
        alerts, normal, timestamps = load_alerts(p)
        assert len(alerts) == 1
        assert normal == 1
        assert len(timestamps) == 2  # NORMAL + ANOMALO

    def test_parse_expected_counts(self, tmp_path):
        run = tmp_path / "run1"
        run.mkdir()
        (run / "seed.txt").write_text(
            "seed_base=100001\nbenign_count=4\nanomaly_count=2\ninterval=6\n",
            encoding="utf-8")
        (run / "ground_truth.jsonl").write_text(
            '{"injection_id":"INJ-1"}\n{"injection_id":"INJ-2"}\n',
            encoding="utf-8")
        counts = parse_expected_counts(run)
        # benign*2 (dos fases benignas del protocolo) + inyecciones GT
        assert counts == {"benign": 8, "injections": 2, "expected_total": 10}

    def test_parse_expected_counts_fallback_anomaly(self, tmp_path):
        run = tmp_path / "run1"
        run.mkdir()
        (run / "seed.txt").write_text(
            "seed_base=100001\nbenign_count=4\nanomaly_count=2\n",
            encoding="utf-8")
        counts = parse_expected_counts(run)
        assert counts["expected_total"] == 8 + 2

    def test_parse_expected_counts_missing(self, tmp_path):
        assert parse_expected_counts(tmp_path) is None

    def test_count_received_messages(self, tmp_path):
        run = tmp_path / "run1"
        (run / "hl7").mkdir(parents=True)
        (run / "hl7" / "messages_a.hl7").write_text(
            "### 2026-10-14 10:00:00 | msg 1 | 100 bytes\nMSH|...\n"
            "### 2026-10-14 10:00:01 | msg 2 | 100 bytes\nMSH|...\n",
            encoding="utf-8")
        (run / "hl7" / "messages_b.hl7").write_text(
            "### 2026-10-14 10:00:02 | msg 1 | 100 bytes\nMSH|...\n",
            encoding="utf-8")
        assert count_received_messages(run) == 3

    def test_count_received_messages_missing(self, tmp_path):
        assert count_received_messages(tmp_path) is None

    def test_compute_throughput(self):
        from datetime import datetime
        ts = [datetime(2026, 10, 13, 10, 0, 0),
              datetime(2026, 10, 13, 10, 0, 10)]
        tp = compute_throughput(ts, total_msgs=5)
        assert tp["msgs_per_s"] == pytest.approx(0.5, abs=0.01)
        assert tp["window_s"] == 10.0
        assert tp["total_msgs"] == 5

    def test_compute_throughput_empty(self):
        assert compute_throughput([], 5)["msgs_per_s"] == 0.0
        assert compute_throughput([], 5)["window_s"] == 0.0

    def test_compute_message_loss_calculable(self):
        loss = compute_message_loss({"expected_total": 10}, received=9,
                                    normal_count=6, alerts_total=2)
        assert loss["calculable"] == 1
        assert loss["expected"] == 10
        assert loss["received"] == 9
        assert loss["lost"] == 1
        assert loss["loss_rate"] == pytest.approx(0.1, abs=0.001)
        assert loss["source"] == "hl7"

    def test_compute_message_loss_no_lost(self):
        loss = compute_message_loss({"expected_total": 10}, received=12,
                                    normal_count=3, alerts_total=2)
        assert loss["lost"] == 0
        assert loss["loss_rate"] == 0.0

    def test_compute_message_loss_fallback_estimado(self):
        loss = compute_message_loss({"expected_total": 10}, received=None,
                                    normal_count=6, alerts_total=2)
        assert loss["received"] == 8
        assert loss["lost"] == 2
        assert loss["source"] == "estimado"

    def test_compute_message_loss_not_calculable(self):
        loss = compute_message_loss(None, received=7,
                                    normal_count=6, alerts_total=2)
        assert loss["calculable"] == 0
        assert loss["received"] == 7
        assert "lost" not in loss

    def test_evaluate_includes_throughput_and_loss(self):
        from datetime import datetime
        ins = [inj("INJ-1", "A02", "R-SEQ-001", "2026-10-13T10:00:00+00:00")]
        als = [alt("AL-1", "R-SEQ-001", "2026-10-13T10:00:01+00:00")]
        ts = [datetime(2026, 10, 13, 10, 0, 0),
              datetime(2026, 10, 13, 10, 0, 10)]
        res = evaluate(ins, als, normal_count=5, timestamps=ts,
                       expected_counts={"expected_total": 10},
                       received_messages=10)
        assert res.throughput["msgs_per_s"] > 0
        assert res.message_loss["calculable"] == 1
        assert res.message_loss["expected"] == 10
        assert res.message_loss["received"] == 10
        assert res.message_loss["lost"] == 0

    def test_run_from_dir_end_to_end(self, tmp_path):
        run = tmp_path / "run1"
        run.mkdir()
        gt_rows = [{
            "injection_id": "INJ-1", "scenario_id": "A02",
            "scenario_name": "duplicate_control_id",
            "expected_rule": "R-SEQ-001",
            "timestamp_utc": "2026-10-13T10:00:00+00:00",
            "monotonic_ns": 1, "control_id": "1",
            "bytes_sent": 100, "target": "receiver:1550",
            "mitre_ics": "T0857", "threat": "Replay",
        }]
        (run / "ground_truth.jsonl").write_text(
            "\n".join(json.dumps(r) for r in gt_rows) + "\n", encoding="utf-8")
        al_rows = [
            {"alert_id": "AL-1", "rule_id": "R-SEQ-001",
             "timestamp_utc": "2026-10-13T10:00:00.300+00:00", "label": "ANOMALO"},
            {"alert_id": "N-1", "rule_id": "NORMAL",
             "timestamp_utc": "2026-10-13T10:00:05+00:00", "label": "NORMAL"},
        ]
        (run / "alerts.jsonl").write_text(
            "\n".join(json.dumps(r) for r in al_rows) + "\n", encoding="utf-8")

        res = run_from_dir(run)
        assert res.tp == 1
        assert res.tn == 1
        assert (run / "evaluation.json").exists()
        assert (run / "evaluation.txt").exists()

    def test_run_from_dir_missing_files(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            run_from_dir(tmp_path / "no_existe")
