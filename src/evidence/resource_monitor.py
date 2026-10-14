#!/usr/bin/env python3
"""
resource_monitor.py - Monitor ligero de CPU y memoria del proceso receptor.
Medido en runtime (no post-hoc) y escrito como resource_usage.json.

Sin dependencias externas:
- CPU: time.process_time() (portable).
- Memoria pico (RSS): ctypes GetProcessMemoryInfo en Windows;
  resource.getrusage en POSIX; None si no disponible (NO_VERIFICADO).
"""

import json
import sys
import time
from pathlib import Path
from typing import Dict, Optional


def _peak_rss_mb_windows() -> Optional[float]:
    """RSS pico (MB) via GetProcessMemoryInfo (Windows). None si falla."""
    try:
        import ctypes
        from ctypes import wintypes

        class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
            _fields_ = [
                ("cb", wintypes.DWORD),
                ("PageFaultCount", wintypes.DWORD),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        counters = PROCESS_MEMORY_COUNTERS()
        counters.cb = ctypes.sizeof(PROCESS_MEMORY_COUNTERS)
        handle = ctypes.windll.kernel32.GetCurrentProcess()
        ok = ctypes.windll.psapi.GetProcessMemoryInfo(
            handle, ctypes.byref(counters), counters.cb)
        if not ok:
            return None
        return counters.PeakWorkingSetSize / (1024 * 1024)
    except Exception:
        return None


def _peak_rss_mb_posix() -> Optional[float]:
    """RSS pico (MB) via resource.getrusage (POSIX). None si no disponible."""
    try:
        import resource
        # ru_maxrss en kilobytes en Linux/macOS
        return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024.0
    except Exception:
        return None


def peak_rss_mb() -> Optional[float]:
    """RSS pico del proceso en MB (None si no medible en esta plataforma)."""
    if sys.platform == "win32":
        return _peak_rss_mb_windows()
    return _peak_rss_mb_posix()


class ResourceMonitor:
    """Mide CPU (segundos de proceso) y memoria pico durante la vida del receptor."""

    def __init__(self):
        self._t0_cpu: Optional[float] = None
        self._t0_wall: Optional[float] = None

    def start(self) -> None:
        self._t0_cpu = time.process_time()
        self._t0_wall = time.monotonic()

    def stop(self) -> Dict[str, float]:
        """Devuelve métricas y deja el monitor listo para escribirse."""
        cpu_s = 0.0
        wall_s = 0.0
        if self._t0_cpu is not None:
            cpu_s = max(0.0, time.process_time() - self._t0_cpu)
        if self._t0_wall is not None:
            wall_s = max(0.0, time.monotonic() - self._t0_wall)
        mem = peak_rss_mb()
        result: Dict[str, float] = {
            "cpu_seconds": round(cpu_s, 3),
            "wall_seconds": round(wall_s, 3),
        }
        if mem is not None:
            result["peak_rss_mb"] = round(mem, 2)
            result["cpu_percent"] = round(
                (cpu_s / wall_s * 100.0) if wall_s > 0 else 0.0, 1)
        return result

    def write(self, outdir: Path) -> Optional[Path]:
        """Escribe resource_usage.json en outdir. Devuelve la ruta o None."""
        try:
            data = self.stop()
            outdir.mkdir(parents=True, exist_ok=True)
            path = outdir / "resource_usage.json"
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            return path
        except OSError:
            return None
