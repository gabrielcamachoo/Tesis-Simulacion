#!/usr/bin/env python3
"""
Pruebas unitarias e integración ligera para los cierres del Bloque 1:
- D-02: Liberación de SessionState, poda por TTL de flujos/hashes, cota en
  global_control_ids y liberación de EvidenceWriter.session_metadata.
- D-04: Validación del límite de 5120 B (Enmienda E9) en detect_live.py (A15 -> R-MLLP-001).
- D-05: Emparejamiento en evaluate.py de alertas tempranas del vigilante de
  silencio (A14) y mensajes de preparación SEED del generador.
- D-06: Detección automática de plataforma ARM/Raspberry Pi en latency_bench.py.
- Cobertura del núcleo (ANF-03 > 90 %): bordes de src/mllp, src/hl7 y src/detection.
"""

import json
import os
import socket
import struct
import sys
import threading
import time
from pathlib import Path
from unittest import mock

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import detect_live as dl
import evaluate as ev
import latency_bench as lb
from anomaly_generator import base_hl7_message, now_hl7_timestamp
from run_experiment import write_lab_config
from src.alerting.json_logger import AlertLogger
from src.config.settings import load_settings
from src.detection.baseline import Baseline, load_baseline
from src.detection.engine import DetectionEngine
from src.detection.rules import RuleSet, create_rules_yaml
from src.evidence.writer import EvidenceWriter
from src.hl7.parser import parse_hl7_message
from src.mllp.ack import (
    ACK_ACCEPT,
    HL7Ack,
    build_ack,
    build_ack_from_bytes,
    build_emulator_ack,
    parse_msh_for_ack,
)
from src.mllp.framing import (
    EOM,
    SB,
    MLLPFramer,
    MLLPIterator,
    count_frames,
    frame_hl7_message,
    validate_mllp_frame,
)
from src.mllp.server import run_server


def _build_eth_ipv4_tcp(src_ip: str, sport: int, dst_ip: str, dport: int,
                        seq: int, flags: int, payload: bytes = b"") -> bytes:
    """Construye trama Ethernet + IPv4 + TCP válida para alimentar LiveDetector."""
    eth = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"
    total_len = 20 + 20 + len(payload)
    ip_hdr = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, total_len, 1, 0, 64, 6, 0,
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip),
    )
    tcp_hdr = struct.pack(
        "!HHLLBBHHH",
        sport, dport, seq & 0xFFFFFFFF, 0, (5 << 4), flags, 65535, 0, 0,
    )
    return eth + ip_hdr + tcp_hdr + payload


def _make_engine(tmp_path: Path):
    os.environ["LAB_AUTHORIZED"] = "YES"
    cfg = write_lab_config(tmp_path)
    settings = load_settings(str(cfg))
    baseline = load_baseline(str(ROOT / "baseline.yaml"))
    rules = RuleSet(str(ROOT / "config" / "rules.yaml"))
    return DetectionEngine(settings, baseline, rules), settings


# ============================================================================
# D-02: Fuga de memoria (SessionState, hashes, control IDs, metadata, flujos)
# ============================================================================

class TestMemoryLeakFixD02:
    def test_engine_close_session_and_prune_stale_state(self, tmp_path):
        engine, _ = _make_engine(tmp_path)
        ts_str = now_hl7_timestamp()
        t0 = 1_700_000_000.0

        for idx in range(5):
            txt = base_hl7_message(f"MCID-MEM-{idx}", ts_str)
            parsed = parse_hl7_message(txt)
            frame = frame_hl7_message(txt.encode("utf-8"))
            engine.process_message(
                session_id=f"sess-{idx}", source_ip="127.0.0.1", source_port=40000 + idx,
                parsed_message=parsed, raw_bytes=frame[1:-2], mllp_frame=frame,
                capture_time=t0 + idx * 10.0,
            )

        assert len(engine.sessions) == 5
        assert engine.get_session_stats("sess-0")["messages"] == 1
        assert engine.get_session_stats("inexistente") is None

        # Cerrar sesiones cerradas libera SessionState inmediatamente
        assert engine.close_session("sess-0") is True
        assert engine.close_session("sess-0") is False
        assert "sess-0" not in engine.sessions

        # Poda por TTL elimina sesiones viejas y hashes vencidos fuera de replay_window_s
        pruned = engine.prune_stale_state(now=t0 + 500.0, session_ttl_s=60.0)
        assert pruned["sessions_pruned"] == 4
        assert pruned["hashes_pruned"] >= 1
        assert len(engine.sessions) == 0
        assert len(engine.global_content_hashes) == 0

    def test_engine_bounds_global_control_ids(self, tmp_path):
        engine, _ = _make_engine(tmp_path)
        engine.max_global_control_ids = 5
        ts_str = now_hl7_timestamp()
        t0 = 1_700_000_000.0

        for idx in range(12):
            txt = base_hl7_message(f"BOUNDED-{idx}", ts_str)
            parsed = parse_hl7_message(txt)
            frame = frame_hl7_message(txt.encode("utf-8"))
            engine.process_message(
                session_id="bounded", source_ip="127.0.0.1", source_port=41000,
                parsed_message=parsed, raw_bytes=frame[1:-2], mllp_frame=frame,
                capture_time=t0 + idx * 10.0,
            )

        assert len(engine.global_control_ids) <= 5
        assert "BOUNDED-11" in engine.global_control_ids
        assert "BOUNDED-0" not in engine.global_control_ids

    def test_evidence_writer_releases_session_metadata_on_close(self, tmp_path):
        _, settings = _make_engine(tmp_path)
        ev_dir = tmp_path / "ev"
        writer = EvidenceWriter(str(ev_dir), settings)
        sid = "127.0.0.1:45000:1"
        writer.open_session(sid, "127.0.0.1", 45000, "127.0.0.1", 1550)
        assert sid in writer.session_metadata

        writer.close_session(sid)
        assert sid not in writer.session_metadata
        meta_files = list((ev_dir / "logs").glob("meta_*.json"))
        assert len(meta_files) == 1

    def test_mllp_server_releases_engine_session_on_tcp_close(self, tmp_path):
        engine, settings = _make_engine(tmp_path)
        settings.network.bind_host = "127.0.0.1"
        settings.network.bind_port = 0
        settings.evidence.output_dir = str(tmp_path / "srv_ev")
        writer = EvidenceWriter(settings.evidence.output_dir, settings)
        alert_logger = AlertLogger(settings, writer)
        server = run_server(settings, writer, engine, alert_logger, send_ack=True)
        port = server.server_address[1]
        th = threading.Thread(target=server.serve_forever, daemon=True)
        th.start()
        try:
            msg = base_hl7_message("SRV-CLOSE-1", now_hl7_timestamp())
            with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
                s.sendall(frame_hl7_message(msg.encode("utf-8")))
                s.settimeout(2)
                s.recv(4096)
                stats = server.get_session_stats()
                assert stats["active_sessions"] >= 1
            # Esperar a que finish() cierre la sesión
            deadline = time.monotonic() + 3.0
            while engine.sessions and time.monotonic() < deadline:
                time.sleep(0.05)
            assert len(engine.sessions) == 0
            assert len(writer.session_metadata) == 0
        finally:
            server.shutdown()
            server.server_close()
            alert_logger.close()

    def test_detect_live_closes_and_prunes_flows_and_engine_sessions(self, tmp_path, monkeypatch):
        monkeypatch.setenv("LAB_AUTHORIZED", "YES")
        cfg = write_lab_config(tmp_path)
        det = dl.LiveDetector(
            tmp_path / "live", cfg, ROOT / "baseline.yaml", ROOT / "config" / "rules.yaml",
            label="memtest", port=1550, extra_allowed_ips=["192.168.5.114"],
        )
        try:
            t0 = 1_700_000_000.0
            msg1 = frame_hl7_message(base_hl7_message("LIVE-1", now_hl7_timestamp()).encode("utf-8"))
            # Flujo 1: se abre, manda mensaje y cierra con FIN -> libera SessionState
            det.feed_packet(t0, _build_eth_ipv4_tcp("192.168.5.114", 50001, "192.168.5.134", 1550, 100, dl.TCP_SYN))
            det.feed_packet(t0 + 0.1, _build_eth_ipv4_tcp("192.168.5.114", 50001, "192.168.5.134", 1550, 101, dl.TCP_ACK, msg1))
            assert len(det.engine.sessions) == 1
            det.feed_packet(t0 + 0.2, _build_eth_ipv4_tcp("192.168.5.114", 50001, "192.168.5.134", 1550, 101 + len(msg1), dl.TCP_FIN | dl.TCP_ACK))
            assert len(det.flows) == 0
            assert len(det.engine.sessions) == 0

            # Flujo 2: queda abierto sin FIN ni RST -> poda por TTL lo libera
            msg2 = frame_hl7_message(base_hl7_message("LIVE-2", now_hl7_timestamp()).encode("utf-8"))
            det.feed_packet(t0 + 10.0, _build_eth_ipv4_tcp("192.168.5.114", 50002, "192.168.5.134", 1550, 200, dl.TCP_SYN))
            det.feed_packet(t0 + 10.1, _build_eth_ipv4_tcp("192.168.5.114", 50002, "192.168.5.134", 1550, 201, dl.TCP_ACK, msg2))
            assert len(det.flows) == 1
            assert len(det.engine.sessions) == 1

            pruned = det.prune_idle_flows(now=t0 + 200.0, flow_ttl_s=60.0)
            assert pruned == 1
            assert len(det.flows) == 0
            assert len(det.engine.sessions) == 0
        finally:
            det.close()


# ============================================================================
# D-04: Límite de 5120 B (Enmienda E9) en detect_live.py para A15
# ============================================================================

class TestDetectLiveMaxSizeD04:
    def test_a15_oversized_fragmented_triggers_r_mllp_001_in_live_mode(self, tmp_path, monkeypatch):
        monkeypatch.setenv("LAB_AUTHORIZED", "YES")
        cfg = write_lab_config(tmp_path)
        det = dl.LiveDetector(
            tmp_path / "live_a15", cfg, ROOT / "baseline.yaml", ROOT / "config" / "rules.yaml",
            label="a15test", port=1550, extra_allowed_ips=["192.168.5.160"],
        )
        try:
            assert det.max_message_size == 5120
            ts_str = now_hl7_timestamp()
            msh = (
                f"MSH|^~\\&|MINDRAY_WATOPRO-SERIES^000F14002D3586ec^EUI-64||||{ts_str}||"
                f"ORU^R01^ORU_R01|A15-LIVE-1|P|2.6|||NE|AL||UNICODE UTF-8|||"
                f"IHE_PCD_001^IHE PCD^1.3.6.1.4.1.19376.1.6.1.1.1^ISO"
            )
            big_hl7 = msh + "\rNTE|1||" + ("X" * 12000) + "\r"
            payload = frame_hl7_message(big_hl7.encode("utf-8"))
            assert len(payload) > 5120

            t0 = 1_700_000_000.0
            seq = 1000
            det.feed_packet(t0, _build_eth_ipv4_tcp("192.168.5.160", 51000, "192.168.5.134", 1550, seq, dl.TCP_SYN))
            seq += 1
            # Fragmentar en segmentos TCP de 1400 B (como en red real Ethernet)
            for i in range(0, len(payload), 1400):
                chunk = payload[i : i + 1400]
                det.feed_packet(
                    t0 + 0.001 * (i // 1400 + 1),
                    _build_eth_ipv4_tcp("192.168.5.160", 51000, "192.168.5.134", 1550, seq, dl.TCP_ACK, chunk),
                )
                seq += len(chunk)

            summary = det.summary(final=True)
            assert summary["alertas_por_regla"].get("R-MLLP-001", 0) == 1
            assert summary["mensajes"] == 0  # descartado en framing como en MLLPFramer
        finally:
            det.close()


# ============================================================================
# D-05: Emparejamiento en evaluate.py (A14 vigilancia temprana + SEED)
# ============================================================================

class TestEvaluateMatchingD05:
    def test_a14_early_silence_watchdog_matches_even_from_wato_source(self):
        # Silencio A14 empieza a 10:00:00 y termina a 10:00:45 (conexión del generador :50002)
        a14 = ev.Injection(
            injection_id="INJ-A14-1", scenario_id="A14", scenario_name="periodic_silence",
            expected_rule="R-TIME-002",
            started_utc="2026-11-23T10:00:00+00:00",
            timestamp_utc="2026-11-23T10:00:45+00:00",
            source="127.0.0.1:50002",
        )
        # Vigilante E3 avisa a 10:00:15 con source del emulador WATO (:40001)
        al_early = ev.AlertRecord(
            alert_id="AL-SILENCE-1", rule_id="R-TIME-002",
            timestamp_utc="2026-11-23T10:00:15+00:00",
            source="127.0.0.1:40001",
            experimental_state="SILENCE",
            reason="R-TIME-002: Silence: no message for 15.1s > 15.000s",
        )
        # Y al cerrar el silencio llega una segunda R-TIME-002 del generador (:50002)
        al_end = ev.AlertRecord(
            alert_id="AL-END-1", rule_id="R-TIME-002",
            timestamp_utc="2026-11-23T10:00:45.100+00:00",
            source="127.0.0.1:50002",
            reason="R-TIME-002: Interval too long: 45.0s > 15.000s",
        )
        res = ev.evaluate([a14], [al_early, al_end], normal_count=10)
        assert res.tp == 1
        assert res.fn == 0
        assert res.fp == 0
        assert res.precision == 1.0
        assert res.correlated_alerts == 1

    def test_generator_seed_setup_alerts_are_not_counted_as_fp(self):
        inj_a03 = ev.Injection(
            injection_id="INJ-A03-1", scenario_id="A03", scenario_name="replay_synthetic_message",
            expected_rule="R-SEQ-002",
            timestamp_utc="2026-11-23T10:01:00+00:00",
            started_utc="2026-11-23T10:01:00+00:00",
            source="127.0.0.1:50010",
        )
        al_seed = ev.AlertRecord(
            alert_id="AL-SEED-1", rule_id="R-TIME-002",
            timestamp_utc="2026-11-23T10:00:59.500+00:00",
            source="127.0.0.1:50010",
            message_control_id="SEED-1",
        )
        al_dup_seed = ev.AlertRecord(
            alert_id="AL-SEED-2", rule_id="R-TIME-002",
            timestamp_utc="2026-11-23T10:00:58.000+00:00",
            source="127.0.0.1:50010",
            message_control_id="DUP-SEED-0001",
        )
        al_real = ev.AlertRecord(
            alert_id="AL-A03-1", rule_id="R-SEQ-002",
            timestamp_utc="2026-11-23T10:01:00.050+00:00",
            source="127.0.0.1:50010",
            message_control_id="REPLAY-1",
        )
        # Alerta espuria real sobre tráfico benigno sí debe seguir contando como FP
        al_benign_fp = ev.AlertRecord(
            alert_id="AL-BENIGN-FP", rule_id="R-OBX-001",
            timestamp_utc="2026-11-23T10:05:00+00:00",
            source="127.0.0.1:40001",
            message_control_id="WATO-99",
        )
        res = ev.evaluate([inj_a03], [al_seed, al_dup_seed, al_real, al_benign_fp], normal_count=20)
        assert res.tp == 1
        assert res.setup_alerts == 2
        assert res.fp == 1
        assert res.unmatched_alerts == ["AL-BENIGN-FP"]


# ============================================================================
# D-06: Detección de hardware ARM / Raspberry Pi en latency_bench.py
# ============================================================================

class TestLatencyBenchPlatformD06:
    def test_detects_raspberry_pi_from_device_tree_model(self, tmp_path):
        dt = tmp_path / "model"
        dt.write_bytes(b"Raspberry Pi 4 Model B Rev 1.4\x00")
        with mock.patch("platform.machine", return_value="aarch64"), \
             mock.patch("platform.system", return_value="Linux"):
            env = lb.detect_hardware_environment(device_tree_model_path=dt)
        assert env["es_raspberry_pi"] is True
        assert env["machine"] == "aarch64"
        assert env["modelo_placa"] == "Raspberry Pi 4 Model B Rev 1.4"
        assert "Raspberry Pi" in env["host_declarado"]

    def test_detects_arm_linux_without_device_tree(self, tmp_path):
        missing = tmp_path / "no_model"
        with mock.patch("platform.machine", return_value="armv7l"), \
             mock.patch("platform.system", return_value="Linux"):
            env = lb.detect_hardware_environment(device_tree_model_path=missing)
        assert env["es_raspberry_pi"] is True
        assert env["machine"] == "armv7l"

    def test_detects_pc_on_x86_64(self, tmp_path):
        missing = tmp_path / "no_model"
        with mock.patch("platform.machine", return_value="AMD64"), \
             mock.patch("platform.system", return_value="Windows"):
            env = lb.detect_hardware_environment(device_tree_model_path=missing)
        assert env["es_raspberry_pi"] is False
        assert env["host_declarado"].startswith("PC ")


# ============================================================================
# ANF-03 (> 90 % cobertura núcleo): bordes de src/mllp y src/detection
# ============================================================================

class TestCoreCoverageBoost:
    def test_ack_helpers_and_error_paths(self):
        ack = HL7Ack(ack_code=ACK_ACCEPT, message_control_id="77", text_message="OK", error_condition="0")
        assert ack.to_hl7() == "MSA|AA|77|OK|0\r"
        assert parse_msh_for_ack("PID|1|2\r") == {}

        with pytest.raises(ValueError):
            build_ack("PID|1|2\r")

        msg = base_hl7_message("ACK-99", now_hl7_timestamp())
        resp = build_ack(msg, text_message="Accepted", error_condition="0")
        assert bytes(resp) == resp.mllp_framed
        assert "Accepted|0" in resp.msa_segment

        emu_ack = build_emulator_ack(msg)
        assert b"WATO_EMULATOR" in emu_ack

        from_bytes = build_ack_from_bytes(msg.encode("utf-8"))
        assert from_bytes.startswith(SB) and from_bytes.endswith(EOM)

    def test_framing_edge_cases_and_iterator(self):
        framer = MLLPFramer(max_message_size=64, max_buffer_size=128)
        assert framer.feed(b"").frames == []

        # Restart at nested SB before EOM
        r1 = framer.feed(SB + b"PARCIAL" + SB + b"MSH|1" + EOM)
        assert len(r1.frames) == 1
        assert len(r1.frames[0]) == 5
        assert bytes(r1.frames[0]) == SB + b"MSH|1" + EOM

        # Buffer overflow trimming
        framer2 = MLLPFramer(max_message_size=200, max_buffer_size=32)
        framer2.feed(SB + b"A" * 20)
        framer2.feed(b"B" * 25)
        stats = framer2.get_stats()
        assert stats["bytes_discarded"] > 0

        # validate_mllp_frame empty
        ok, err = validate_mllp_frame(b"")
        assert not ok and err == "empty_frame"

        # MLLPIterator y count_frames con basura final y trama incompleta
        raw = b"JUNK" + SB + b"MSH|1" + EOM + b"TAIL"
        assert len(list(MLLPIterator(raw))) == 1
        assert count_frames(SB + b"MSH|1" + EOM + SB + b"INCOMPLETE") == 1
        assert len(list(MLLPIterator(SB + b"NO_EOM"))) == 0

    def test_baseline_and_ruleset_helpers(self, tmp_path):
        bl = load_baseline(str(ROOT / "baseline.yaml"))
        sample_obx = bl.obx_identifiers_observed[0]
        assert bl.is_obx_code_allowed(sample_obx) is True
        assert bl.is_obx_code_allowed("99999999") is False
        assert bl.is_obx_type_allowed("CWE") is True
        assert bl.is_obx_unit_allowed("262656^MDC_DIM_DIMLESS^MDC") is True
        assert bl.is_transition_allowed("", "SESION_ESTABLECIDA_STANDBY") is True
        assert bl.get_obx_detail(sample_obx) is not None

        empty_bl = Baseline()
        assert empty_bl.is_obx_code_allowed("ANY") is True
        assert empty_bl.is_obx_type_allowed("ANY") is True
        assert empty_bl.is_obx_unit_allowed("ANY") is True

        with pytest.raises(FileNotFoundError):
            load_baseline(str(tmp_path / "missing.yaml"))
        empty_file = tmp_path / "empty.yaml"
        empty_file.write_text("", encoding="utf-8")
        with pytest.raises(ValueError):
            load_baseline(str(empty_file))

        # RuleSet simple format & create_rules_yaml
        simple_yaml = tmp_path / "simple_rules.yaml"
        simple_yaml.write_text("enabled_rules:\n  - R-ID-001\n  - R-MLLP-001\n", encoding="utf-8")
        rs_simple = RuleSet()
        rs_simple.enabled.clear()
        rs_simple.load_from_yaml(str(simple_yaml))
        assert rs_simple.is_enabled("R-ID-001")
        assert len(rs_simple.list_all()) == 15

        out_rules = tmp_path / "exported_rules.yaml"
        create_rules_yaml(str(out_rules))
        assert out_rules.exists()
