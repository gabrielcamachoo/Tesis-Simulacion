"""Regresion de mapeos MITRE ATT&CK ICS v20.

Verificado el 2026-10-13 (docs/THREAT_MODEL.md 4, 7):
- T0855 redirige a T1692.001 y T0857 a T1693.001 (obsoletas como IDs proprios).
- T0860 (Wireless Compromise), T0887 (Wireless Sniffing), T0869 (Standard Application
  Layer Protocol) y T0831 (Manipulation of Control) NO describen los escenarios del lab.
Este test evita que reintroduzcan IDs obsoletos o injustificados en la configuracion.
"""

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]

ALLOWED_TECHNIQUES = {"T1692.001", "T1692.002", "T0814"}
FORBIDDEN_TECHNIQUES = {"T0855", "T0857", "T0860", "T0887", "T0869", "T0831"}
WRONG_NAMES = ("Connection Proxy", "Manipulate I/O Image", "Unauthorized Command Message")

DOS_SCENARIOS = {"A12", "A13", "A14", "A15"}


def _load_yaml(path: Path):
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def test_rules_yaml_techniques_allowed():
    data = _load_yaml(ROOT / "config" / "rules.yaml")
    techniques = {r["mitre_technique"] for r in data["rules"]}
    assert techniques <= ALLOWED_TECHNIQUES, f"tecnica no permitida en rules.yaml: {techniques}"


def test_rules_yaml_no_deprecated_or_mismatched():
    data = _load_yaml(ROOT / "config" / "rules.yaml")
    for rule in data["rules"]:
        tech = rule["mitre_technique"]
        assert tech not in FORBIDDEN_TECHNIQUES, f"{rule['rule_id']}: {tech} obsoleta/no aplica"
        for wrong in WRONG_NAMES:
            assert wrong not in rule["mitre_justification"], f"{rule['rule_id']}: nombre incorrecto '{wrong}'"


def test_settings_scenarios_techniques_allowed():
    data = _load_yaml(ROOT / "src" / "config" / "settings.yaml")
    scenarios = data["anomaly_generator"]["scenarios"]
    assert set(scenarios) == {f"A{i:02d}" for i in range(1, 17)}
    for sid, sc in scenarios.items():
        tech = sc["mitre_ics"]
        assert tech not in FORBIDDEN_TECHNIQUES, f"{sid}: {tech} obsoleta/no aplica"
        assert tech in ALLOWED_TECHNIQUES, f"{sid}: {tech} fuera del conjunto permitido"
        if sid in DOS_SCENARIOS:
            assert tech == "T0814", f"{sid}: DoS/infraestructura debe ser T0814"
        else:
            assert tech == "T1692.002", f"{sid}: mensaje de reporte debe ser T1692.002"


def test_default_rules_match_allowed_set():
    from src.detection.rules import DEFAULT_RULES

    techniques = {r.mitre_technique for r in DEFAULT_RULES}
    assert techniques <= ALLOWED_TECHNIQUES, f"tecnica no permitida en DEFAULT_RULES: {techniques}"


def test_default_rules_and_yaml_agree():
    from src.detection.rules import DEFAULT_RULES

    yaml_rules = {r["rule_id"]: r["mitre_technique"]
                  for r in _load_yaml(ROOT / "config" / "rules.yaml")["rules"]}
    for rule in DEFAULT_RULES:
        assert yaml_rules.get(rule.rule_id) == rule.mitre_technique, (
            f"{rule.rule_id}: rules.py={rule.mitre_technique} "
            f"differs de rules.yaml={yaml_rules.get(rule.rule_id)}"
        )


def test_generator_scenarios_match_settings():
    """Solo invariantes MITRE: limites/nombres/sincronia fina los cubre
    tests/test_anomaly_generator.py (pueden evolucionar en paralelo)."""
    from anomaly_generator import SCENARIOS

    scenarios = _load_yaml(ROOT / "src" / "config" / "settings.yaml")[
        "anomaly_generator"]["scenarios"]
    assert set(SCENARIOS) == set(scenarios)
    for sid, sc in SCENARIOS.items():
        yaml_sc = scenarios[sid]
        assert sc.mitre_ics == yaml_sc["mitre_ics"], (
            f"{sid}: generator={sc.mitre_ics} vs settings={yaml_sc['mitre_ics']}")
        assert sc.mitre_ics in ALLOWED_TECHNIQUES, f"{sid}: {sc.mitre_ics} no permitida"
