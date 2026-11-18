#!/usr/bin/env python3
"""
Cierre de código (rama final, 2026-11-18): emulador WATO.

1. Los 6 modos ventilatorios generan mensajes RUNNING distintos y llevan la
   marca NTE de tráfico sintético. El merge del 21-10 (commit 43471e3) había
   dejado los 6 modos con el mismo mensaje de 3264 B sin que ninguna prueba
   lo detectara; esta prueba lo vigila.
2. --max-reconnects 0 = el emisor benigno no se rinde nunca. Antes, con 3
   reintentos de 2 s, el emisor se apagaba en cuanto un ataque de saturación
   (A11/A12) ocupaba el receptor (máx. 5 conexiones).
3. Con un límite > 0 se conserva el comportamiento anterior.
4. Integración: el emisor arranca sin receptor, sigue reintentando y entrega
   sus mensajes cuando el receptor aparece.
"""

import os
import random
import socket
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from wato_emulator import EmulatorConfig, EmulatorState, WATOEmulator  # noqa: E402

MODES = ["VCV", "SIMVVC_PLUS_PS", "PCV", "SIMVPC_PLUS_PS", "PS", "MANUAL"]


def _running_message(mode: str) -> str:
    random.seed(1)
    emu = WATOEmulator(EmulatorConfig(state=EmulatorState.RUNNING, vent_mode=mode))
    return emu._build_message()


def test_seis_modos_generan_mensajes_distintos():
    msgs = {m: _running_message(m) for m in MODES}
    # Cada modo produce su propio conjunto de OBX: no puede haber dos iguales
    # en tamaño y número de OBX a la vez.
    firmas = {(len(v), v.count("OBX|")) for v in msgs.values()}
    assert len(firmas) == len(MODES), {m: (len(v), v.count("OBX|")) for m, v in msgs.items()}
    # El modo ventilatorio (OBX 184352) cambia con --vent-mode
    def linea_modo(msg):
        return next(s for s in msg.split("\r") if "184352" in s)
    assert len({linea_modo(m) for m in msgs.values()}) == len(MODES)


def test_trafico_sintetico_marcado_con_nte():
    for mode in MODES:
        assert "NTE|" in _running_message(mode), mode
    random.seed(1)
    standby = WATOEmulator(EmulatorConfig(state=EmulatorState.STANDBY))._build_message()
    assert standby.startswith("MSH|")


class _EmuSinReceptor(WATOEmulator):
    """Emulador cuyo _connect siempre falla; se detiene tras N intentos."""

    def __init__(self, cfg, parar_en):
        super().__init__(cfg)
        self.intentos = 0
        self.parar_en = parar_en

    def _connect(self):
        self.intentos += 1
        if self.intentos >= self.parar_en:
            self.running = False
        return False


def test_reconexion_sin_limite_no_se_rinde():
    cfg = EmulatorConfig(receiver_host="127.0.0.1", receiver_port=1,
                         max_reconnects=0, reconnect_delay=0.0)
    emu = _EmuSinReceptor(cfg, parar_en=40)
    emu.run()
    # Solo se detuvo porque la prueba lo apagó en el intento 40
    assert emu.intentos == 40
    assert emu.stats["reconnects"] == 40


def test_reconexion_con_limite_conserva_comportamiento():
    cfg = EmulatorConfig(receiver_host="127.0.0.1", receiver_port=1,
                         max_reconnects=3, reconnect_delay=0.0)
    emu = _EmuSinReceptor(cfg, parar_en=1000)
    emu.run()
    assert emu.intentos == 3


def _puerto_libre() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def test_emisor_espera_al_receptor_y_entrega(tmp_path):
    """El emisor arranca sin receptor; el receptor aparece 1.5 s después."""
    import test_integration as ti
    from src.config.settings import load_settings
    from src.detection.baseline import load_baseline
    from src.detection.rules import RuleSet
    from src.detection.engine import DetectionEngine
    from src.evidence.writer import EvidenceWriter
    from src.alerting.json_logger import AlertLogger
    from src.mllp.server import run_server

    os.environ["LAB_AUTHORIZED"] = "YES"
    port = _puerto_libre()
    lab = {}

    def levantar_receptor():
        cfg = ti._write_lab_config(tmp_path)
        settings = load_settings(str(cfg))
        settings.network.bind_host = "127.0.0.1"
        settings.network.bind_port = port
        outdir = tmp_path / "evidence"
        settings.evidence.output_dir = str(outdir)
        writer = EvidenceWriter(str(outdir), settings)
        engine = DetectionEngine(settings, load_baseline(str(ROOT / "baseline.yaml")),
                                 RuleSet(str(ROOT / "config" / "rules.yaml")))
        logger = AlertLogger(settings, writer)
        server = run_server(settings, writer, engine, logger, send_ack=True)
        th = threading.Thread(target=server.serve_forever, daemon=True)
        th.start()
        lab.update(server=server, thread=th, alert_logger=logger)

    threading.Timer(1.5, levantar_receptor).start()
    emu = WATOEmulator(EmulatorConfig(
        receiver_host="127.0.0.1", receiver_port=port,
        state=EmulatorState.STANDBY, interval_seconds=0.2, max_messages=3,
        require_ack=True, ack_timeout=3.0,
        max_reconnects=0, reconnect_delay=0.25))
    t0 = time.monotonic()
    emu.run()
    try:
        assert emu.stats["reconnects"] >= 3          # reintentó mientras no había receptor
        assert emu.stats["messages_sent"] == 3        # y luego entregó todo
        assert emu.stats["acks_received"] == 3
        assert time.monotonic() - t0 < 20
    finally:
        if lab:
            ti.stop_lab(lab)
