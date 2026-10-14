#!/usr/bin/env python3
"""
Tests del generador de anomalías: guardias de seguridad, escenarios y frames.
No envía tráfico real (dry-run / construcción de payloads).
"""

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from anomaly_generator import (
    SCENARIOS, SafetyGuard, base_hl7_message, now_hl7_timestamp,
    base_hl7_message as _bhm, MAX_PAYLOAD_BYTES, ALLOWED_HOSTNAMES,
)
from src.config.settings import Settings, SafetySettings
from src.mllp.framing import SB, EOM, frame_hl7_message


@pytest.fixture
def settings(tmp_path, monkeypatch):
    marker = tmp_path / "LAB_ONLY.marker"
    marker.write_text("lab")
    s = Settings(strict_validation=False)
    s.safety = SafetySettings(
        require_lab_authorized=True,
        require_lab_marker=True,
        lab_marker_path=str(marker),
        block_public_ips=True,
    )
    monkeypatch.setenv("LAB_AUTHORIZED", "YES")
    return s


class TestScenarioCatalog:
    def test_all_16_scenarios_defined(self):
        assert len(SCENARIOS) == 16
        for i in range(1, 17):
            assert f"A{i:02d}" in SCENARIOS

    def test_each_scenario_has_expected_rule(self):
        for sid, s in SCENARIOS.items():
            assert s.expected_rule.startswith("R-"), f"{sid} sin regla"
            assert s.expected_rule in {
                "R-ID-001", "R-ID-002", "R-NET-001", "R-MLLP-001",
                "R-HL7-001", "R-HL7-002", "R-HL7-003", "R-SEQ-001",
                "R-SEQ-002", "R-TIME-001", "R-TIME-002", "R-OBX-001",
                "R-OBX-002", "R-OBX-003", "R-STATE-001",
            }, f"{sid} regla desconocida {s.expected_rule}"

    def test_safety_limits_positive(self):
        for sid, s in SCENARIOS.items():
            assert s.safety_limit > 0, f"{sid} safety_limit <= 0"
            assert s.safety_limit <= 20, f"{sid} safety_limit demasiado alto"

    def test_mitre_techniques_present(self):
        for sid, s in SCENARIOS.items():
            assert s.mitre_ics, f"{sid} sin MITRE"


class TestSafetyGuard:
    def test_blocked_without_env(self, settings, monkeypatch):
        monkeypatch.delenv("LAB_AUTHORIZED", raising=False)
        g = SafetyGuard(settings)
        assert g.check("receiver", 1550) is False
        assert any("LAB_AUTHORIZED" in e for e in g.errors)

    def test_blocked_without_marker(self, tmp_path, monkeypatch):
        monkeypatch.setenv("LAB_AUTHORIZED", "YES")
        s = Settings(strict_validation=False)
        s.safety = SafetySettings(
            require_lab_authorized=True,
            require_lab_marker=True,
            lab_marker_path=str(tmp_path / "no_existe.marker"),
        )
        g = SafetyGuard(s)
        assert g.check("receiver", 1550) is False
        assert any("marker" in e.lower() for e in g.errors)

    def test_blocked_public_ip(self, settings):
        g = SafetyGuard(settings)
        assert g.check("8.8.8.8", 1550) is False
        assert any("NO permitido" in e for e in g.errors)

    def test_blocked_unknown_hostname(self, settings):
        g = SafetyGuard(settings)
        assert g.check("hospital-hl7-server", 1550) is False

    def test_allowed_localhost(self, settings):
        g = SafetyGuard(settings)
        assert g.check("127.0.0.1", 1550) is True
        assert g.errors == []

    def test_allowed_receiver_hostname(self, settings):
        g = SafetyGuard(settings)
        assert g.check("mllp-receiver", 1550) is True

    def test_allowed_docker_private(self, settings):
        g = SafetyGuard(settings)
        assert g.check("172.18.0.3", 1550) is True

    def test_blocked_invalid_port(self, settings):
        g = SafetyGuard(settings)
        assert g.check("receiver", 0) is False

    def test_hostname_allowlist(self):
        assert "receiver" in ALLOWED_HOSTNAMES
        assert "localhost" in ALLOWED_HOSTNAMES


class TestMessageConstruction:
    def test_base_message_structure(self):
        msg = base_hl7_message("TEST-1", "20260825141442-05:00")
        assert msg.startswith("MSH|")
        assert "\rPID|" in "\r" + msg
        assert "ORU^R01^ORU_R01" in msg
        assert "TEST-1" in msg
        assert msg.endswith("\r")

    def test_base_message_custom_identity(self):
        msg = base_hl7_message("X", "20260825141442-05:00",
                               sending_app="MALICIOUS_APP^hacker^L")
        assert "MALICIOUS_APP^hacker^L" in msg

    def test_base_message_datatype(self):
        msg = base_hl7_message("X", "20260825141442-05:00", obx_datatype="NM")
        assert "|NM|202886^" in msg

    def test_base_message_unit(self):
        msg = base_hl7_message("X", "20260825141442-05:00", obx_unit="mg/dL")
        assert "mg/dL" in msg

    def test_timestamp_format(self):
        ts = now_hl7_timestamp()
        # YYYYMMDDHHMMSS+HH:MM -> 20 caracteres
        assert len(ts) == 20
        assert ts[14] in "+-"
        assert ts[17] == ":"

    def test_frame_wraps_message(self):
        msg = base_hl7_message("T", "20260825141442-05:00")
        frame = frame_hl7_message(msg.encode("utf-8"))
        assert frame[:1] == SB
        assert frame[-2:] == EOM


def _write_lab_config(tmp_path) -> Path:
    """Copia settings.yaml con lab_marker_path apuntando a un marcador temporal."""
    src = ROOT / "src" / "config" / "settings.yaml"
    text = src.read_text(encoding="utf-8")
    marker = tmp_path / "LAB_ONLY.marker"
    marker.write_text("lab")
    text = text.replace('lab_marker_path: "/LAB_ONLY.marker"',
                        f'lab_marker_path: "{marker.as_posix()}"')
    cfg = tmp_path / "settings_lab.yaml"
    cfg.write_text(text, encoding="utf-8")
    return cfg


class TestDryRun:
    def test_dry_run_lists_scenarios(self, tmp_path, monkeypatch):
        """--dry-run con seguridad válida debe salir 0 sin enviar."""
        import subprocess, os
        env = os.environ.copy()
        env["LAB_AUTHORIZED"] = "YES"
        cfg = _write_lab_config(tmp_path)
        r = subprocess.run(
            [sys.executable, "anomaly_generator.py", "--scenario", "A02",
             "--dry-run", "--config", str(cfg)],
            cwd=str(ROOT), env=env, capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL)
        assert r.returncode == 0, r.stderr + r.stdout
        assert "A02" in r.stdout + r.stderr

    def test_dry_run_all_scenarios(self, tmp_path, monkeypatch):
        import subprocess, os
        env = os.environ.copy()
        env["LAB_AUTHORIZED"] = "YES"
        cfg = _write_lab_config(tmp_path)
        r = subprocess.run(
            [sys.executable, "anomaly_generator.py", "--all", "--dry-run",
             "--config", str(cfg)],
            cwd=str(ROOT), env=env, capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL)
        assert r.returncode == 0, r.stderr + r.stdout
        for i in range(1, 17):
            assert f"A{i:02d}" in r.stdout + r.stderr

    def test_blocked_without_env(self, tmp_path):
        import subprocess, os
        env = os.environ.copy()
        env.pop("LAB_AUTHORIZED", None)
        cfg = _write_lab_config(tmp_path)
        r = subprocess.run(
            [sys.executable, "anomaly_generator.py", "--scenario", "A02",
             "--dry-run", "--config", str(cfg)],
            cwd=str(ROOT), env=env, capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL)
        assert r.returncode == 3

    def test_blocked_public_target(self, tmp_path):
        import subprocess, os
        env = os.environ.copy()
        env["LAB_AUTHORIZED"] = "YES"
        cfg = _write_lab_config(tmp_path)
        r = subprocess.run(
            [sys.executable, "anomaly_generator.py", "--scenario", "A02",
             "--dry-run", "--host", "8.8.8.8", "--config", str(cfg)],
            cwd=str(ROOT), env=env, capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL)
        assert r.returncode == 3
        assert "permitido" in (r.stdout + r.stderr)
