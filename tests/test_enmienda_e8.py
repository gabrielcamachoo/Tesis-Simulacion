#!/usr/bin/env python3
"""
Enmienda E8 (rama pruebas-santi-v2, 2026-10-20): R-TIME-001 respeta la zona
horaria del DTM HL7.

Hallazgo al integrar con el main del 2026-10-20: el emulador nuevo escribe
MSH-7 con -0500 (como el WATO real) y el generador de anomalías en UTC
(+00:00). El validador comparaba solo los 14 dígitos, así que el primer
mensaje benigno tras las inyecciones (17:03:21-0500 = 22:03:21Z) parecía
anterior a 22:03:21+00:00 y disparaba R-TIME-001 (campaña semilla 100001,
6 s y 10 s).
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.hl7.validator import validate_timestamp_regression as regression


def test_mismo_instante_en_zonas_distintas_no_es_regresivo():
    ok, _ = regression("20261020170321-0500", "20261020220321+00:00")
    assert ok


def test_regresion_real_entre_zonas_si_alerta():
    ok, reason = regression("20261020170320-0500", "20261020220321+00:00")
    assert not ok
    assert "R-TIME-001" in reason


def test_wato_real_cadencia_10s_misma_zona():
    # MSH-7 reales de LECTURAACK27AGOSTO (mismo offset -0500)
    assert regression("20260827101357-0500", "20260827101347-0500")[0]
    assert not regression("20260827101347-0500", "20260827101357-0500")[0]


def test_sin_zona_se_compara_como_antes():
    assert not regression("20260101000000", "20260101000001")[0]
    assert regression("20260101000001", "20260101000000")[0]


def test_una_sola_zona_se_compara_como_antes():
    """Si solo uno trae offset no se puede convertir: comparación por dígitos."""
    assert not regression("20260101000000-0500", "20260101000001")[0]


def test_formato_del_generador_y_del_emulador():
    from anomaly_generator import now_hl7_timestamp
    from src.hl7.validator import _parse_hl7_offset
    assert _parse_hl7_offset(now_hl7_timestamp()) is not None
    assert _parse_hl7_offset("20261020170321-0500").total_seconds() == -5 * 3600
