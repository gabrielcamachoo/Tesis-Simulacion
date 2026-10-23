#!/usr/bin/env python
"""Genera un settings temporal de despliegue para procesos standalone.

Copia src/config/settings.yaml y apunta laboratory.safety.lab_marker_path al
LAB_ONLY.marker del repositorio. Motivo: la ruta default /LAB_ONLY.marker
resuelve a la raiz del disco; en Windows no existe sin privilegios de
administrador, y en la Pi el repo ya trae su propio marcador.

Uso: python deploy/receptor/make_deploy_settings.py [salida.yaml]
     (default: evidence_output/settings_deploy.yaml, gitignored)
"""
from __future__ import annotations

import pathlib
import sys

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[2]


def main() -> int:
    out = (
        pathlib.Path(sys.argv[1])
        if len(sys.argv) > 1
        else ROOT / "evidence_output" / "settings_deploy.yaml"
    )
    if not out.is_absolute():
        out = (pathlib.Path.cwd() / out).resolve()

    marker = ROOT / "LAB_ONLY.marker"
    if not marker.exists():
        print(f"ERROR: falta {marker} (lab no autorizado)", file=sys.stderr)
        return 1

    src = ROOT / "src" / "config" / "settings.yaml"
    data = yaml.safe_load(src.read_text(encoding="utf-8"))
    data["laboratory"]["safety"]["lab_marker_path"] = str(marker)

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        yaml.safe_dump(data, allow_unicode=True, sort_keys=False),
        encoding="utf-8",
    )
    print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
