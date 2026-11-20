#!/usr/bin/env python3
"""
Propuesta E10: R-TIME-002 atribuye un intervalo corto a la sesión que lo causó.

Problema (campaña H1, 7 FP; red virtual con la Pi, 2 FP): la regla medía la
cadencia de forma global, así que un mensaje del atacante seguido del mensaje
legítimo dejaba un intervalo corto y la alerta caía sobre el legítimo.
Usa mensajes REALES del WATO (evidence_raw/, solo lectura).
"""
from tests.test_enmiendas_e2_e3 import lab_engine, _real_messages, _process, STANDBY_PCAP  # noqa: F401


def _rtime(result):
    return [a for a in result.alerts if a.rule_id == "R-TIME-002"]


def test_legitimo_tras_mensaje_de_otra_sesion_no_alerta(lab_engine):
    engine, clock = lab_engine
    msgs = [m for m, _ in _real_messages(STANDBY_PCAP)]
    t0 = clock["now"]
    _process(engine, msgs[0], session="wato", port=2070)
    clock["now"] = t0 + 8.0          # intruso desde otra sesión, intervalo normal
    _process(engine, msgs[1], session="kali", ip="192.168.5.50", port=40000)
    clock["now"] = t0 + 10.0         # el WATO sigue con su cadencia de 10 s
    r = _process(engine, msgs[2], session="wato", port=2070)
    assert _rtime(r) == []


def test_rafaga_en_la_misma_sesion_sigue_alertando(lab_engine):
    engine, clock = lab_engine
    msgs = [m for m, _ in _real_messages(STANDBY_PCAP)]
    t0 = clock["now"]
    _process(engine, msgs[0], session="kali", ip="192.168.5.50", port=40000)
    clock["now"] = t0 + 0.2
    r = _process(engine, msgs[1], session="kali", ip="192.168.5.50", port=40000)
    assert len(_rtime(r)) == 1


def test_conexion_nueva_sin_historial_sigue_alertando(lab_engine):
    engine, clock = lab_engine
    msgs = [m for m, _ in _real_messages(STANDBY_PCAP)]
    t0 = clock["now"]
    _process(engine, msgs[0], session="wato", port=2070)
    clock["now"] = t0 + 0.5          # A13: reconexión inmediata, sesión nueva
    r = _process(engine, msgs[1], session="r1", ip="192.168.5.50", port=40001)
    assert len(_rtime(r)) == 1


def test_legitimo_con_cadencia_propia_corta_sigue_alertando(lab_engine):
    engine, clock = lab_engine
    msgs = [m for m, _ in _real_messages(STANDBY_PCAP)]
    t0 = clock["now"]
    _process(engine, msgs[0], session="wato", port=2070)
    clock["now"] = t0 + 1.0
    _process(engine, msgs[1], session="kali", ip="192.168.5.50", port=40000)
    clock["now"] = t0 + 2.0          # la propia sesión del WATO va demasiado rápido
    r = _process(engine, msgs[2], session="wato", port=2070)
    assert len(_rtime(r)) == 1
