"""Pruebas de regresión v5.7 para cierres D-11, D-12, D-13, D-14 y baseline.yaml."""
from datetime import datetime, timezone
from pathlib import Path
import gzip
import json
import yaml
import pytest

import evaluate
import detect_live
import latency_bench


ROOT = Path(__file__).resolve().parent.parent


class TestD11ArmBenchPortability:
    """D-11: latency_bench y su prueba smoke deben pasar tanto en x86_64 como en ARM/Pi."""

    def test_detect_platform_returns_bool_flag(self):
        info = latency_bench.detect_hardware_environment()
        assert isinstance(info["es_raspberry_pi"], bool)

    def test_run_bench_respects_mocked_arm_platform(self, tmp_path, monkeypatch):
        from run_experiment import write_lab_config

        monkeypatch.setenv("LAB_AUTHORIZED", "YES")
        monkeypatch.setattr(
            latency_bench,
            "detect_hardware_environment",
            lambda: {
                "host_declarado": "Raspberry Pi (Raspberry Pi 3 Model B Rev 1.2) test-pi",
                "platform": "Linux-armv7l",
                "machine": "armv7l",
                "modelo_placa": "Raspberry Pi 3 Model B Rev 1.2",
                "es_raspberry_pi": True,
            },
        )
        cfg = write_lab_config(tmp_path)
        rep = latency_bench.run_bench(
            50, 1, 7, cfg, ROOT / "baseline.yaml", ROOT / "config/rules.yaml"
        )
        assert rep["entorno"]["es_raspberry_pi"] is True
        assert "Raspberry Pi 3 Model B" in rep["entorno"]["modelo_placa"]


class TestD12AndD14EvaluateFixes:
    """D-12 (acumulación per_rule y throughput HL7 vs eventos) y D-14 (strict_rule_recall)."""

    def _inj(self, iid, sid, rule, ts, src="10.0.0.2:40000"):
        return evaluate.Injection(
            injection_id=iid,
            scenario_id=sid,
            scenario_name=f"sc_{sid}",
            expected_rule=rule,
            timestamp_utc=ts,
            source=src,
        )

    def _alt(self, aid, rule, ts, src="10.0.0.2:40000"):
        return evaluate.AlertRecord(
            alert_id=aid,
            rule_id=rule,
            timestamp_utc=ts,
            source=src,
        )

    def test_per_rule_accumulates_across_shared_scenarios(self):
        # A01 y A16 comparten R-ID-001; A05, A06 y A15 comparten R-MLLP-001
        injs = [
            self._inj("1", "A01", "R-ID-001", "2026-11-23T10:00:00+00:00"),
            self._inj("2", "A01", "R-ID-001", "2026-11-23T10:00:01+00:00"),
            self._inj("3", "A16", "R-ID-001", "2026-11-23T10:00:02+00:00"),
            self._inj("4", "A05", "R-MLLP-001", "2026-11-23T10:00:03+00:00"),
            self._inj("5", "A06", "R-MLLP-001", "2026-11-23T10:00:04+00:00"),
            self._inj("6", "A15", "R-MLLP-001", "2026-11-23T10:00:05+00:00"),
        ]
        als = [
            self._alt("AL-1", "R-ID-001", "2026-11-23T10:00:00.100+00:00"),
            self._alt("AL-2", "R-ID-001", "2026-11-23T10:00:01.100+00:00"),
            self._alt("AL-3", "R-ID-001", "2026-11-23T10:00:02.100+00:00"),
            self._alt("AL-4", "R-MLLP-001", "2026-11-23T10:00:03.100+00:00"),
            self._alt("AL-5", "R-MLLP-001", "2026-11-23T10:00:04.100+00:00"),
            self._alt("AL-6", "R-MLLP-001", "2026-11-23T10:00:05.100+00:00"),
        ]
        res = evaluate.evaluate(injs, als, normal_count=4)
        assert res.per_rule["R-ID-001"]["expected"] == 3
        assert res.per_rule["R-ID-001"]["detected"] == 3
        assert res.per_rule["R-MLLP-001"]["expected"] == 3
        assert res.per_rule["R-MLLP-001"]["detected"] == 3
        assert sum(v["expected"] for v in res.per_rule.values()) == len(injs)

    def test_strict_rule_recall_distinguishes_fallback_matches(self):
        injs = [
            self._inj("1", "A11", "R-OBX-002", "2026-11-23T10:00:00+00:00"),
            self._inj("2", "A11", "R-OBX-002", "2026-11-23T10:00:00.200+00:00"),
        ]
        # Solo hay 1 R-OBX-002 y 1 alerta secundaria R-NET-001 en ventana de ambas inyecciones
        als = [
            self._alt("AL-1", "R-OBX-002", "2026-11-23T10:00:00.250+00:00"),
            self._alt("AL-2", "R-NET-001", "2026-11-23T10:00:00.251+00:00"),
        ]
        res = evaluate.evaluate(injs, als, normal_count=2)
        assert res.tp == 2
        assert res.recall == 1.0
        assert res.strict_rule_tp == 1
        assert res.strict_rule_recall == 0.5
        assert res.per_rule["R-OBX-002"]["wrong_rule"] == 1
        txt = evaluate.format_report(res)
        assert "estricto por regla esperada: 0.5000" in txt

    def test_throughput_separates_hl7_msgs_from_alert_events(self):
        t0 = datetime(2026, 11, 23, 10, 0, 0, tzinfo=timezone.utc)
        t1 = datetime(2026, 11, 23, 10, 0, 10, tzinfo=timezone.utc)
        injs = [self._inj("1", "A01", "R-ID-001", t0.isoformat())]
        # 1 mensaje de ataque dispara 4 alertas + 6 normales = 10 filas de eventos,
        # pero solo 7 mensajes HL7 reales recibidos.
        als = [
            self._alt(f"AL-{k}", r, t0.isoformat())
            for k, r in enumerate(["R-ID-001", "R-NET-001", "R-SEQ-001", "R-TIME-002"])
        ]
        res = evaluate.evaluate(
            injs, als, normal_count=6, timestamps=[t0, t1], received_messages=7
        )
        assert res.throughput["source"] == "hl7"
        assert res.throughput["total_msgs"] == 7
        assert res.throughput["msgs_per_s"] == pytest.approx(0.7, abs=0.01)
        assert res.throughput["events_total"] == 10
        assert res.throughput["events_per_s"] == pytest.approx(1.0, abs=0.01)

    @pytest.mark.skipif(
        not (ROOT / "deploy/medicion/resultados/v56_pi_20261123/alerts.jsonl.gz").exists(),
        reason="evidencia fisica v56_pi_20261123 no presente",
    )
    def test_v56_pi_hardware_re_evaluation_consistency(self):
        base = ROOT / "deploy/medicion/resultados/v56_pi_20261123"
        with gzip.open(base / "ground_truth.jsonl.gz", "rt", encoding="utf-8") as f:
            injs = [
                evaluate.Injection(
                    injection_id=d.get("injection_id", ""),
                    scenario_id=d.get("scenario_id", ""),
                    scenario_name=d.get("scenario_name", ""),
                    expected_rule=d.get("expected_rule", ""),
                    timestamp_utc=d.get("timestamp_utc", ""),
                    source=d.get("source", ""),
                    started_utc=d.get("started_utc", ""),
                )
                for d in (json.loads(l) for l in f if l.strip())
            ]
        als = []
        normals = 0
        with gzip.open(base / "alerts.jsonl.gz", "rt", encoding="utf-8") as f:
            for l in f:
                if not l.strip():
                    continue
                d = json.loads(l)
                if d.get("label") == "NORMAL" or d.get("rule_id") == "NORMAL":
                    normals += 1
                    continue
                als.append(
                    evaluate.AlertRecord(
                        alert_id=d.get("alert_id", ""),
                        rule_id=d.get("rule_id", ""),
                        timestamp_utc=d.get("timestamp_utc", ""),
                        source=d.get("source", ""),
                        message_control_id=d.get("message_control_id", ""),
                        experimental_state=d.get("experimental_state", ""),
                        reason=d.get("reason", ""),
                    )
                )
        res = evaluate.evaluate(injs, als, normal_count=normals)
        assert res.injections_total == 4864
        assert sum(v["expected"] for v in res.per_rule.values()) == 4864
        assert res.per_rule["R-ID-001"]["expected"] == 456
        assert res.per_rule["R-MLLP-001"]["expected"] == 684
        assert res.per_rule["R-TIME-002"]["expected"] == 1900
        assert res.strict_rule_tp == 4862
        assert res.strict_rule_recall == 0.9996


class TestD13TcpdumpImmediateMode:
    """D-13: tcpdump debe incluir --immediate-mode para evitar buffer de 1000 ms en libpcap."""

    def test_build_tcpdump_cmd_includes_immediate_mode(self):
        cmd = detect_live.build_tcpdump_cmd("eth0", 1550)
        assert "--immediate-mode" in cmd
        assert "-U" in cmd
        assert cmd[0] == "tcpdump"
        assert cmd[-1] == "tcp port 1550"

    def test_build_tcpdump_cmd_custom_bpf(self):
        cmd = detect_live.build_tcpdump_cmd("wlan0", 1550, bpf="host 192.168.5.114")
        assert "--immediate-mode" in cmd
        assert cmd[-1] == "host 192.168.5.114"


class TestBaselineAlignmentE9:
    """Alineación de baseline.yaml con Enmienda E9 (5120 B)."""

    def test_baseline_yaml_max_message_size_matches_e9(self):
        data = yaml.safe_load((ROOT / "baseline.yaml").read_text(encoding="utf-8"))
        settings = yaml.safe_load((ROOT / "src/config/settings.yaml").read_text(encoding="utf-8"))
        assert data["mllp_parameters"]["max_message_size_bytes"] == 5120
        assert settings["wato_observed_standby"]["mllp"]["max_message_size"] == 5120


class TestV59LatencyModesAndAdversarial:
    """Pruebas de regresión v5.9: camino normal + parseo HL7 en latency_bench y suite E01-E05."""

    def test_latency_bench_normal_path_zero_alerts_and_parse(self, tmp_path, monkeypatch):
        from run_experiment import write_lab_config

        monkeypatch.setenv("LAB_AUTHORIZED", "YES")
        cfg = write_lab_config(tmp_path)
        rep = latency_bench.run_bench(
            30, 1, 7, cfg, ROOT / "baseline.yaml", ROOT / "config/rules.yaml",
            mode="normal_path", include_parse=True,
        )
        assert rep["modo"] == "normal_path"
        assert rep["include_parse"] is True
        assert rep["per_run"][0]["alerts_emitidas"] == 0
        assert rep["aggregate"]["p95_us"] > 0

    def test_adversarial_suite_evasions_and_tradeoffs(self, tmp_path, monkeypatch):
        import adversarial_eval
        from run_experiment import write_lab_config

        monkeypatch.setenv("LAB_AUTHORIZED", "YES")
        cfg = write_lab_config(tmp_path)
        rep = adversarial_eval.run_adversarial_suite(cfg, count=2)
        by_id = {s["id"]: s for s in rep["escenarios"]}
        assert by_id["E01"]["evadidos"] == 2
        assert by_id["E02"]["evadidos"] == 2
        assert by_id["E03"]["detectados"] == 2 and "R-SEQ-001" in by_id["E03"]["reglas_disparadas"]
        assert by_id["E04"]["detectados"] == 2 and "R-STATE-001" in by_id["E04"]["reglas_disparadas"]
        assert by_id["E05"]["detectados"] == 2 and "R-OBX-001" in by_id["E05"]["reglas_disparadas"]

    @pytest.mark.skipif(
        not (ROOT / "deploy/medicion/resultados/v56_pi_20261123/alerts.jsonl.gz").exists(),
        reason="evidencia fisica v56_pi_20261123 no presente",
    )
    def test_pi_soc_alert_aggregation(self):
        import adversarial_eval

        ag = adversarial_eval.analyze_pi_alert_aggregation(
            ROOT / "deploy/medicion/resultados/v56_pi_20261123/alerts.jsonl.gz"
        )
        assert ag["disponible"] is True
        assert ag["alertas_crudas"] == 19284
        assert ag["notificaciones_agregadas_por_ip_regla_minuto"] == 253
        assert ag["factor_reduccion"] > 70.0

