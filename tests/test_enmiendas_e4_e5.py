#!/usr/bin/env python3
"""
Pruebas de las enmiendas E4 (motivo de R-OBX-002/003) y E5 (hora de captura
en el análisis offline). Rama pruebas-santi (2026-10-20).

Todas usan mensajes REALES del WATO tomados de evidence_raw/ (solo lectura).

- E4: las alertas R-OBX-002 y R-OBX-003 mostraban el texto de R-OBX-001
  ("Unauthorized OBX code: 184352") porque todas usaban errors[0].
- E5: detect_pcap procesaba a velocidad de CPU con el reloj de pared, así
  que R-TIME-002 se disparaba por el propio modo offline (STANDBY real:
  1 NORMAL + 42 R-TIME-002). Ahora el motor recibe la hora del paquete y el
  resultado es 43 NORMAL. El receptor en vivo no cambia (now=None).
"""

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

STANDBY_PCAP = ROOT / "evidence_raw" / "pcap" / "LECTURACONACK25AGOSTO.pcapng"
RUNNING_PCAP = ROOT / "evidence_raw" / "pcap" / "LECTURAACK27AGOSTO.pcapng"


@pytest.fixture
def lab(tmp_path, monkeypatch):
    """Config de laboratorio + rutas reales de baseline y reglas."""
    monkeypatch.setenv("LAB_AUTHORIZED", "YES")
    marker = ROOT / "LAB_ONLY.marker"
    created = False
    if not marker.exists():
        marker.write_text("LAB ONLY\n", encoding="utf-8")
        created = True
    try:
        from run_experiment import write_lab_config
        cfg = write_lab_config(tmp_path)
        yield cfg, ROOT / "baseline.yaml", ROOT / "config" / "rules.yaml"
    finally:
        if created:
            marker.unlink()


@pytest.fixture
def engine(lab):
    from src.detection.engine import DetectionEngine
    from src.config.settings import load_settings
    from src.detection.baseline import load_baseline
    from src.detection.rules import RuleSet
    cfg, baseline, rules = lab
    return DetectionEngine(load_settings(str(cfg)), load_baseline(str(baseline)),
                           RuleSet(str(rules)))


def _real_messages(pcap: Path):
    import detect_pcap as dp
    out = []
    for fl in dp.extract_flows(pcap):
        out += [(c.decode("utf-8"), ts) for c, ts in fl["messages"]]
    return out


def _process(engine, text, now=None, port=2070):
    """now = hora del mensaje; se pasa como capture_time (API del main
    2026-10-20, equivalente a la E5 original)."""
    from src.hl7.parser import parse_hl7_message
    from src.mllp.framing import frame_hl7_message
    raw = text.encode("utf-8")
    return engine.process_message("s1", "192.168.23.250", port,
                                  parse_hl7_message(text), raw,
                                  frame_hl7_message(raw), capture_time=now)


# --------------------------------------------------------------------------
# E4 - cada alerta R-OBX lleva el motivo de su propia regla
# --------------------------------------------------------------------------

class TestE4MotivoOBX:

    def _tres_violaciones(self):
        """RUNNING real con tres OBX alterados, uno por regla. Con la baseline
        bimodal el RUNNING real ya no viola nada, así que el caso de varias
        violaciones en el mismo mensaje se arma a propósito."""
        need = ("|NM|20016^MDC_VENT_RESP_RATE_SETTING^99MNDRY|",
                "|264928^MDC_DIM_RESP_PER_MIN^MDC|",
                "|NM|151586^MDC_VENT_RESP_RATE^MDC|")
        # primer ORU RUNNING real con medición de frecuencia numérica (no MANUAL)
        text, ts = next((t, ts) for t, ts in _real_messages(RUNNING_PCAP)
                        if all(n in t for n in need))
        assert "|NM|20016^MDC_VENT_RESP_RATE_SETTING^99MNDRY|" in text
        assert "|264928^MDC_DIM_RESP_PER_MIN^MDC|" in text
        assert "|NM|151586^MDC_VENT_RESP_RATE^MDC|" in text
        text = text.replace("|NM|20016^MDC_VENT_RESP_RATE_SETTING^99MNDRY|",
                            "|NM|99999^FAKE_CODE^99MNDRY|", 1)
        text = text.replace("|264928^MDC_DIM_RESP_PER_MIN^MDC|", "|mg/dL|")
        text = text.replace("|NM|151586^MDC_VENT_RESP_RATE^MDC|",
                            "|ST|151586^MDC_VENT_RESP_RATE^MDC|", 1)
        return text, ts

    def test_motivo_propio_con_varias_violaciones(self, engine):
        text, ts = self._tres_violaciones()
        r = _process(engine, text, now=ts, port=2048)
        by_rule = {a.rule_id: a.reason for a in r.alerts}
        assert {"R-OBX-001", "R-OBX-002", "R-OBX-003"} <= set(by_rule)
        for rule_id in ("R-OBX-001", "R-OBX-002", "R-OBX-003"):
            assert by_rule[rule_id].startswith(rule_id), by_rule[rule_id]
        assert "unit" in by_rule["R-OBX-002"].lower()
        assert "value type" in by_rule["R-OBX-003"].lower()

    def test_running_real_sin_violaciones_obx(self, engine):
        """Baseline bimodal (main 2026-10-20): los 99 ORU reales del 27-08
        no generan ninguna alerta R-OBX."""
        for text, ts in _real_messages(RUNNING_PCAP):
            r = _process(engine, text, now=ts, port=2048)
            assert not [a for a in r.alerts if a.rule_id.startswith("R-OBX")]


# --------------------------------------------------------------------------
# E5 - hora del mensaje explícita en el motor
# --------------------------------------------------------------------------

class TestE5MotorConHora:

    def test_cadencia_10s_con_hora_explicita_no_alerta(self, engine):
        """Dos mensajes reales a 10 s según 'now': sin R-TIME-002 aunque
        el reloj de pared no avance entre llamadas."""
        msgs = _real_messages(STANDBY_PCAP)
        t = msgs[0][1]
        _process(engine, msgs[0][0], now=t)
        r = _process(engine, msgs[1][0], now=t + 10.0)
        assert "R-TIME-002" not in [a.rule_id for a in r.alerts]

    def test_intervalo_corto_con_hora_explicita_alerta(self, engine):
        msgs = _real_messages(STANDBY_PCAP)
        t = msgs[0][1]
        _process(engine, msgs[0][0], now=t)
        r = _process(engine, msgs[1][0], now=t + 2.0)
        alerts = [a for a in r.alerts if a.rule_id == "R-TIME-002"]
        assert len(alerts) == 1
        assert "too short" in alerts[0].reason

    def test_sin_hora_usa_reloj_de_pared(self, engine, monkeypatch):
        """now=None (receptor en vivo) conserva el comportamiento original."""
        import types
        import time as _time
        import src.detection.engine as eng
        clock = {"now": 5_000_000.0}
        monkeypatch.setattr(eng, "time", types.SimpleNamespace(
            time=lambda: clock["now"], perf_counter=_time.perf_counter))
        msgs = _real_messages(STANDBY_PCAP)
        _process(engine, msgs[0][0])
        clock["now"] += 10.0
        r = _process(engine, msgs[1][0])
        assert "R-TIME-002" not in [a.rule_id for a in r.alerts]
        assert r.session_state.last_message_time == clock["now"]


# --------------------------------------------------------------------------
# E5 - detect_pcap sobre las capturas reales
# --------------------------------------------------------------------------

class TestE5DetectPcap:

    def test_standby_real_43_normales(self, lab, tmp_path):
        from detect_pcap import run_detect
        cfg, baseline, rules = lab
        m = run_detect(STANDBY_PCAP, tmp_path / "sb", cfg, baseline, rules,
                       label="STANDBY")
        assert m["n_mensajes"] == 43
        assert m["eventos_normales"] == 43
        assert m["alertas_por_regla"] == {}

    def test_running_real_sin_alertas_de_tiempo(self, lab, tmp_path):
        from detect_pcap import run_detect
        cfg, baseline, rules = lab
        m = run_detect(RUNNING_PCAP, tmp_path / "run", cfg, baseline, rules,
                       label="RUNNING")
        assert m["n_mensajes"] == 99
        # Con la baseline bimodal del main 2026-10-20: 99 NORMAL
        assert m["alertas_por_regla"] == {}
        assert m["eventos_normales"] == 99

    def test_resultado_no_depende_de_realtime(self, lab, tmp_path):
        from detect_pcap import run_detect
        cfg, baseline, rules = lab
        a = run_detect(STANDBY_PCAP, tmp_path / "a", cfg, baseline, rules)
        b = run_detect(STANDBY_PCAP, tmp_path / "b", cfg, baseline, rules,
                       realtime=True, max_sleep=0.0)
        assert a["alertas_por_regla"] == b["alertas_por_regla"]
        assert a["eventos_normales"] == b["eventos_normales"]


class TestE5OrdenDeEntrega:

    def _flow(self, idx, ts_list):
        return {"flow_idx": idx, "src_ip": "192.168.23.250",
                "src_port": 2000 + idx,
                "messages": [(f"m{idx}-{i}".encode(), t)
                             for i, t in enumerate(ts_list)]}

    def test_retransmision_no_genera_tiempo_negativo(self):
        """Patrón de la captura con Nessus: el segmento 91 se retransmite
        y llega después que 92. TCP entrega 91 y luego 92: la hora de
        entrega de 92 no puede ser anterior a la de 91."""
        from detect_pcap import delivery_order
        out = delivery_order([self._flow(0, [890.0, 916.2, 910.4, 920.4])])
        times = [t for t, _, _ in out]
        assert times == [890.0, 916.2, 916.2, 920.4]
        assert [c for _, _, c in out] == [b"m0-0", b"m0-1", b"m0-2", b"m0-3"]

    def test_flujos_se_intercalan_por_hora(self):
        from detect_pcap import delivery_order
        out = delivery_order([self._flow(0, [0.0, 20.0]),
                              self._flow(1, [10.0, 30.0])])
        assert [c for _, _, c in out] == [b"m0-0", b"m1-0", b"m0-1", b"m1-1"]
