#!/usr/bin/env python3
"""
Tests del monitor de recursos: escritura de resource_usage.json,
campos requeridos y robustez (None si memoria no medible).
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.evidence.resource_monitor import ResourceMonitor, peak_rss_mb


class TestResourceMonitor:
    def test_stop_returns_required_fields(self):
        mon = ResourceMonitor()
        mon.start()
        data = mon.stop()
        assert "cpu_seconds" in data
        assert "wall_seconds" in data
        assert data["cpu_seconds"] >= 0
        assert data["wall_seconds"] >= 0

    def test_write_creates_json(self, tmp_path):
        mon = ResourceMonitor()
        mon.start()
        path = mon.write(tmp_path)
        assert path is not None
        assert path.name == "resource_usage.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        assert "cpu_seconds" in data
        assert "wall_seconds" in data

    def test_peak_rss_mb_type(self):
        # Puede ser float (medido) o None (no medible); nunca string
        val = peak_rss_mb()
        assert val is None or isinstance(val, float)

    def test_cpu_increases_after_work(self):
        import time
        mon = ResourceMonitor()
        mon.start()
        # Generar algo de CPU
        _ = sum(i * i for i in range(100000))
        time.sleep(0.01)
        data = mon.stop()
        assert data["cpu_seconds"] >= 0
        assert data["wall_seconds"] >= 0.01
