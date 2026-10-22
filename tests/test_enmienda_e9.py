#!/usr/bin/env python3
"""
Pruebas de la Enmienda E9 y saneamiento de deudas técnicas (2026-10-20):
1. max_message_size elevado a 5120 B en settings.yaml (>= 1000 B de margen
   sobre los 6 modos ventilatorios de RUNNING, incluido SIMV-VC+PS con NTE).
2. A15 (oversized_message) sigue siendo rechazado como message_too_large.
3. Bloque baseline_builder de settings.yaml sincronizado con baseline.yaml v1.1.
4. Los 6 subpaquetes de src/ cuentan con __init__.py explícito y exportan __all__.
5. Sin código muerto en src/mllp/framing.py::_try_extract_frame.
6. run_experiment.py soporta --state RUNNING y --vent-mode CYCLE.
"""

import ast
import sys
from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def test_max_message_size_5120_da_margen_a_todos_los_modos_running():
    """Enmienda E9: max_message_size=5120 deja >=1000 B de margen sobre los 6
    modos ventilatorios del emulador (SIMV-VC+PS ~3977 B con NTE)."""
    from wato_emulator import WATOEmulator, EmulatorConfig, EmulatorState
    from src.mllp.framing import MLLPFramer, frame_hl7_message

    cfg = yaml.safe_load((ROOT / "src" / "config" / "settings.yaml").read_text(encoding="utf-8"))
    max_sz = cfg["wato_observed_standby"]["mllp"]["max_message_size"]
    assert max_sz == 5120

    framer = MLLPFramer(max_message_size=max_sz)
    for mode in ["VCV", "SIMVVC_PLUS_PS", "PCV", "SIMVPC_PLUS_PS", "PS", "MANUAL"]:
        emu = WATOEmulator(EmulatorConfig(state=EmulatorState.RUNNING, vent_mode=mode))
        msg_bytes = emu._build_message().encode("utf-8")
        assert max_sz - len(msg_bytes) >= 1000, (
            f"Modo {mode} tiene {len(msg_bytes)} B, margen insuficiente vs {max_sz} B"
        )
        res = framer.feed(frame_hl7_message(msg_bytes))
        assert len(res.frames) == 1 and not res.errors


def test_a15_sigue_disparando_con_max_message_size_5120():
    """A15 (~16 KiB) supera ampliamente max_message_size=5120 y dispara error de framing."""
    from src.mllp.framing import MLLPFramer, frame_hl7_message

    framer = MLLPFramer(max_message_size=5120)
    msh = (
        "MSH|^~\\&|MINDRAY_WATOPRO-SERIES^000F14002D3586ec^EUI-64||||20261020170000-0500||"
        "ORU^R01^ORU_R01|999|P|2.6|||NE|AL||UNICODE UTF-8|||"
        "IHE_PCD_001^IHE PCD^1.3.6.1.4.1.19376.1.6.1.1.1^ISO"
    )
    filler = "NTE|1||" + ("SYNTHETIC-FILLER-" * 950)
    payload = frame_hl7_message((msh + "\r" + filler + "\r").encode("utf-8"))
    assert len(payload) > 5120
    res = framer.feed(payload)
    assert len(res.frames) == 0
    assert "message_too_large" in res.errors


def test_settings_baseline_builder_sincronizado_con_baseline_bimodal():
    """El bloque baseline_builder de settings.yaml coincide con baseline.yaml v1.1."""
    cfg = yaml.safe_load((ROOT / "src" / "config" / "settings.yaml").read_text(encoding="utf-8"))
    bl = yaml.safe_load((ROOT / "baseline.yaml").read_text(encoding="utf-8"))

    bb = cfg["baseline_builder"]
    assert bb["schema_version"] == bl["metadata"]["schema_version"] == "1.1"
    assert bb["source_sessions"] == bl["metadata"]["source_sessions"]
    stats = bb["statistics"]
    assert stats["obx_identifiers_observed"] == bl["obx_identifiers_observed"]
    assert stats["obx_units_observed"] == bl["obx_units_observed"]
    assert stats["obx_value_types_observed"] == bl["obx_value_types_observed"]
    assert stats["state_transitions_observed"] == bl["state_transitions_observed"]


def test_todos_los_subpaquetes_src_tienen_init_py():
    """Los 6 subpaquetes de src/ cuentan con __init__.py explícito y exportan __all__."""
    pkgs = ["mllp", "hl7", "detection", "alerting", "evidence", "config"]
    for p in pkgs:
        init_file = ROOT / "src" / p / "__init__.py"
        assert init_file.exists(), f"Falta {init_file}"
        mod = __import__(f"src.{p}", fromlist=["*"])
        assert mod.__doc__ and len(mod.__doc__.strip()) > 0
        assert hasattr(mod, "__all__") and len(mod.__all__) > 0
        for sym in mod.__all__:
            assert getattr(mod, sym) is not None


def test_framing_sin_codigo_muerto_tras_return():
    """Verifica que ninguna función de src/mllp/framing.py tenga sentencias tras un return."""
    src_code = (ROOT / "src" / "mllp" / "framing.py").read_text(encoding="utf-8")
    tree = ast.parse(src_code)
    for node in ast.walk(tree):
        for attr in ("body", "orelse"):
            stmts = getattr(node, attr, None)
            if isinstance(stmts, list):
                for idx, stmt in enumerate(stmts[:-1]):
                    assert not isinstance(stmt, ast.Return), (
                        f"Código inalcanzable tras return en línea {stmt.lineno}"
                    )


def test_run_experiment_soporta_state_running_y_vent_mode(monkeypatch):
    """run_experiment.parse_args acepta --state RUNNING --vent-mode SIMVVC_PLUS_PS."""
    import run_experiment as rexp

    monkeypatch.setattr(
        sys, "argv",
        ["run_experiment.py", "--mode", "local", "--state", "RUNNING", "--vent-mode", "SIMVVC_PLUS_PS"]
    )
    args = rexp.parse_args()
    assert args.state == "RUNNING"
    assert args.vent_mode == "SIMVVC_PLUS_PS"
