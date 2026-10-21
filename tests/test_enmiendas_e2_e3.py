#!/usr/bin/env python3
"""
Pruebas de las enmiendas E2 (FSM de estados) y E3 (vigilante de silencio).

Rama pruebas-santi (2026-10-19). Todas las pruebas de E2 usan mensajes REALES
del WATO tomados de evidence_raw/ (solo lectura), no plantillas sintéticas:

- E2: R-STATE-001 nunca disparaba porque _infer_state buscaba 'STANDBY' en el
  componente numérico de OBX-5 (202836). Verificado sobre la evidencia:
  LECTURACONACK25AGOSTO = 43 STANDBY; LECTURAACK27AGOSTO = 13 STANDBY +
  86 RUNNING con una sola transición STANDBY->RUNNING; 184352^MDC_VENT_MODE
  presente en 86/86 RUNNING y 0/56 STANDBY.
- E3: un silencio sin mensaje posterior nunca alertaba (60 s -> 0 alertas).
"""

import sys
import types
import time as _time
from collections import Counter
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

STANDBY_PCAP = ROOT / "evidence_raw" / "pcap" / "LECTURACONACK25AGOSTO.pcapng"
RUNNING_PCAP = ROOT / "evidence_raw" / "pcap" / "LECTURAACK27AGOSTO.pcapng"

STANDBY_STATE = "SESION_ESTABLECIDA_STANDBY"
RUNNING_STATE = "SESION_ESTABLECIDA_RUNNING"


@pytest.fixture
def lab_engine(tmp_path, monkeypatch):
    """Motor con settings de laboratorio, baseline y reglas reales del repo,
    y un reloj controlable (no depende del reloj de pared)."""
    monkeypatch.setenv("LAB_AUTHORIZED", "YES")
    marker = ROOT / "LAB_ONLY.marker"
    created = False
    if not marker.exists():
        marker.write_text("LAB ONLY\n", encoding="utf-8")
        created = True
    try:
        from run_experiment import write_lab_config
        import src.detection.engine as eng
        from src.config.settings import load_settings
        from src.detection.baseline import load_baseline
        from src.detection.rules import RuleSet

        clock = {"now": 1_000_000.0}
        monkeypatch.setattr(eng, "time", types.SimpleNamespace(
            time=lambda: clock["now"], perf_counter=_time.perf_counter))
        cfg = write_lab_config(tmp_path)
        engine = eng.DetectionEngine(
            load_settings(str(cfg)),
            load_baseline(str(ROOT / "baseline.yaml")),
            RuleSet(str(ROOT / "config" / "rules.yaml")))
        yield engine, clock
    finally:
        if created:
            marker.unlink()


def _real_messages(pcap: Path):
    """[(texto HL7, ts captura)] en orden de llegada, del flujo real."""
    import detect_pcap as dp
    out = []
    for fl in dp.extract_flows(pcap):
        out += [(c.decode("utf-8"), ts) for c, ts in fl["messages"]]
    return out


def _process(engine, text, session="s1", ip="192.168.23.250", port=2070):
    from src.hl7.parser import parse_hl7_message
    from src.mllp.framing import frame_hl7_message
    raw = text.encode("utf-8")
    return engine.process_message(session, ip, port, parse_hl7_message(text),
                                  raw, frame_hl7_message(raw))


def _rules(result):
    return [a.rule_id for a in result.alerts]


# --------------------------------------------------------------------------
# E2 - inferencia de estado y R-STATE-001
# --------------------------------------------------------------------------

class TestE2InferenciaEstado:

    def test_standby_real_reconocido(self, lab_engine):
        engine, _ = lab_engine
        from src.hl7.parser import parse_hl7_message
        text, _ = _real_messages(STANDBY_PCAP)[0]
        assert engine._infer_state(parse_hl7_message(text)) == STANDBY_STATE

    def test_running_real_reconocido(self, lab_engine):
        engine, _ = lab_engine
        from src.hl7.parser import parse_hl7_message
        text, _ = _real_messages(RUNNING_PCAP)[-1]
        assert engine._infer_state(parse_hl7_message(text)) == RUNNING_STATE

    def test_corpus_standby_sin_alertas_de_estado(self, lab_engine):
        engine, clock = lab_engine
        states, state_alerts = Counter(), 0
        for text, ts in _real_messages(STANDBY_PCAP):
            clock["now"] = ts
            r = _process(engine, text)
            states[r.session_state.current_state] += 1
            state_alerts += _rules(r).count("R-STATE-001")
        assert states == Counter({STANDBY_STATE: 43})
        assert state_alerts == 0

    def test_corpus_running_13_standby_86_running_sin_alertas_de_estado(self, lab_engine):
        engine, clock = lab_engine
        states, seq, state_alerts = Counter(), [], 0
        for text, ts in _real_messages(RUNNING_PCAP):
            clock["now"] = ts
            r = _process(engine, text, port=2048)
            st = r.session_state.current_state
            states[st] += 1
            seq.append(st)
            state_alerts += _rules(r).count("R-STATE-001")
        assert states == Counter({STANDBY_STATE: 13, RUNNING_STATE: 86})
        transitions = [(a, b) for a, b in zip(seq, seq[1:]) if a != b]
        assert transitions == [(STANDBY_STATE, RUNNING_STATE)]
        assert state_alerts == 0


class TestE2Coherencia:

    def _spoofed_running(self):
        """STANDBY real con OBX-5 cambiado a RUNNING (sin datos de ventilación)."""
        text, _ = _real_messages(STANDBY_PCAP)[0]
        assert "202836^MDC_EVT_STAT_STANDBY^MDC" in text
        return text.replace("202836^MDC_EVT_STAT_STANDBY^MDC",
                            "202902^MDC_EVT_STAT_RUNNING^MDC")

    def test_running_falso_sin_modo_ventilacion_alerta(self, lab_engine):
        engine, clock = lab_engine
        r = _process(engine, self._spoofed_running())
        state_alerts = [a for a in r.alerts if a.rule_id == "R-STATE-001"]
        assert len(state_alerts) == 1
        assert "184352" in state_alerts[0].reason

    def test_running_falso_alerta_en_cada_mensaje(self, lab_engine):
        """Tras STANDBY legítimo, 3 mensajes RUNNING falsos -> 3 alertas
        de coherencia (la transición STANDBY->RUNNING en sí es OBSERVADA)."""
        engine, clock = lab_engine
        standby = _real_messages(STANDBY_PCAP)
        for text, ts in standby[:3]:
            clock["now"] = ts
            assert "R-STATE-001" not in _rules(_process(engine, text))
        t = standby[2][1]
        spoof = self._spoofed_running()
        count = 0
        for i in range(3):
            clock["now"] = t + 10.0 * (i + 1)
            count += _rules(_process(engine, spoof.replace("|1|P|2.6", f"|{900 + i}|P|2.6"))).count("R-STATE-001")
        assert count == 3

    def test_running_a_standby_no_verificado_sigue_alertando(self, lab_engine):
        """RUNNING->STANDBY no se ha observado: debe seguir alertando."""
        engine, clock = lab_engine
        running_text, ts = _real_messages(RUNNING_PCAP)[-1]
        standby_text, _ = _real_messages(STANDBY_PCAP)[0]
        clock["now"] = ts
        assert "R-STATE-001" not in _rules(_process(engine, running_text, port=2048))
        clock["now"] = ts + 10.0
        assert "R-STATE-001" in _rules(_process(engine, standby_text, port=2048))

    def test_mensaje_sin_obx_de_estado_no_cambia_el_estado(self, lab_engine):
        engine, clock = lab_engine
        standby = _real_messages(STANDBY_PCAP)
        clock["now"] = standby[0][1]
        _process(engine, standby[0][0])
        # Mismo mensaje sin el OBX 202886: no aporta estado
        lines = [l for l in standby[1][0].split("\r") if "202886" not in l]
        clock["now"] = standby[1][1]
        r = _process(engine, "\r".join(lines))
        assert "R-STATE-001" not in _rules(r)
        assert r.session_state.current_state == STANDBY_STATE


# --------------------------------------------------------------------------
# E3 - vigilante de silencio
# --------------------------------------------------------------------------

class TestE3Silencio:

    def test_no_se_arma_antes_del_primer_mensaje(self, lab_engine):
        engine, clock = lab_engine
        assert engine.check_silence(now=clock["now"] + 3600) is None

    def test_alerta_una_vez_al_superar_15s(self, lab_engine):
        engine, clock = lab_engine
        text, _ = _real_messages(STANDBY_PCAP)[0]
        t0 = clock["now"]
        _process(engine, text)
        assert engine.check_silence(now=t0 + 14.9) is None
        alert = engine.check_silence(now=t0 + 15.5)
        assert alert is not None
        assert alert.rule_id == "R-TIME-002"
        assert "Silence" in alert.reason
        # Una sola alerta por episodio
        assert engine.check_silence(now=t0 + 20.0) is None
        assert engine.check_silence(now=t0 + 60.0) is None

    def test_nuevo_mensaje_rearma_el_vigilante(self, lab_engine):
        engine, clock = lab_engine
        msgs = _real_messages(STANDBY_PCAP)
        t0 = clock["now"]
        _process(engine, msgs[0][0])
        assert engine.check_silence(now=t0 + 16) is not None
        clock["now"] = t0 + 30
        _process(engine, msgs[1][0])
        assert engine.check_silence(now=t0 + 44) is None
        assert engine.check_silence(now=t0 + 46) is not None

    def test_cadencia_real_10s_nunca_alerta(self, lab_engine):
        """43 mensajes reales a su cadencia real: el vigilante no alerta."""
        engine, clock = lab_engine
        msgs = _real_messages(STANDBY_PCAP)
        for (text, ts), nxt in zip(msgs, msgs[1:] + [(None, msgs[-1][1] + 10)]):
            clock["now"] = ts
            _process(engine, text)
            t = ts
            while t < nxt[1]:
                t += 1.0
                assert engine.check_silence(now=t) is None

    def test_respeta_regla_deshabilitada(self, lab_engine):
        engine, clock = lab_engine
        text, _ = _real_messages(STANDBY_PCAP)[0]
        _process(engine, text)
        engine.rules.disable("R-TIME-002")
        assert engine.check_silence(now=clock["now"] + 60) is None
