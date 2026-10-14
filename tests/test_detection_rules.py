#!/usr/bin/env python3
"""
tests/test_detection_rules.py - Pruebas unitarias para reglas de detección
"""

import pytest
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from src.detection.rules import RuleSet, Rule, DEFAULT_RULES
from src.detection.baseline import Baseline
from src.hl7.parser import parse_hl7_message
from src.hl7.validator import (
    validate_network_origin, validate_sending_application, validate_sending_facility,
    validate_mllp_framing, validate_message_control_id_uniqueness,
    validate_timestamp_regression, validate_frequency, validate_state_transition
)
from src.mllp.framing import SB, EOM


class TestRuleSet:
    """Pruebas del conjunto de reglas."""
    
    def test_default_rules_loaded(self):
        rs = RuleSet()
        assert len(rs.rules) == 15
        assert all(r.enabled for r in rs.rules.values())
        assert len(rs.enabled) == 15
    
    def test_all_rule_ids_present(self):
        rs = RuleSet()
        expected_ids = [
            "R-ID-001", "R-ID-002", "R-NET-001", "R-MLLP-001",
            "R-HL7-001", "R-HL7-002", "R-HL7-003", "R-SEQ-001",
            "R-SEQ-002", "R-TIME-001", "R-TIME-002", "R-OBX-001",
            "R-OBX-002", "R-OBX-003", "R-STATE-001"
        ]
        for rid in expected_ids:
            assert rid in rs.rules
    
    def test_enable_disable_rules(self):
        rs = RuleSet()
        rs.disable("R-ID-001")
        assert not rs.is_enabled("R-ID-001")
        assert "R-ID-001" not in rs.enabled
        
        rs.enable("R-ID-001")
        assert rs.is_enabled("R-ID-001")
        assert "R-ID-001" in rs.enabled
    
    def test_get_rule(self):
        rs = RuleSet()
        rule = rs.get_rule("R-NET-001")
        assert rule is not None
        assert rule.rule_id == "R-NET-001"
        assert rule.category == "NET"
    
    def test_list_enabled_sorted(self):
        rs = RuleSet()
        enabled = rs.list_enabled()
        assert enabled == sorted(enabled)
    
    def test_to_yaml(self):
        rs = RuleSet()
        yaml_str = rs.to_yaml()
        assert "R-ID-001" in yaml_str
        assert "mitre_technique" in yaml_str


class TestNetworkValidation:
    """Pruebas de validación de origen de red."""
    
    def test_allowed_ip_passes(self):
        ok, reason = validate_network_origin("192.168.23.250", ["192.168.23.250"])
        assert ok
        assert reason == ""
    
    def test_unauthorized_ip_fails(self):
        ok, reason = validate_network_origin("10.0.0.1", ["192.168.23.250"])
        assert not ok
        assert "R-NET-001" in reason
        assert "10.0.0.1" in reason
    
    def test_empty_allowed_list_passes(self):
        ok, reason = validate_network_origin("192.168.23.250", [])
        assert ok


class TestIdentityValidation:
    """Pruebas de validación de identidad (MSH-3, MSH-4)."""
    
    def test_allowed_app_passes(self):
        ok, reason = validate_sending_application(
            "MINDRAY_WATOPRO-SERIES^000F14002D3586ec^EUI-64",
            ["MINDRAY_WATOPRO-SERIES^000F14002D3586ec^EUI-64"]
        )
        assert ok
    
    def test_unauthorized_app_fails(self):
        ok, reason = validate_sending_application(
            "UNKNOWN_APP",
            ["MINDRAY_WATOPRO-SERIES^000F14002D3586ec^EUI-64"]
        )
        assert not ok
        assert "R-ID-001" in reason
    
    def test_allowed_facility_passes(self):
        ok, reason = validate_sending_facility("", [""])
        assert ok
    
    def test_unauthorized_facility_fails(self):
        ok, reason = validate_sending_facility("HOSPITAL_X", [""])
        assert not ok
        assert "R-ID-002" in reason


class TestMLLPFramingValidation:
    """Pruebas de validación de framing MLLP."""
    
    def test_valid_framing_passes(self):
        framed = SB + b"MSH|^~\\&|A|B|||20260101||ORU^R01|1|P|2.6\r" + EOM
        ok, reason = validate_mllp_framing(framed)
        assert ok
    
    def test_missing_sb_fails(self):
        framed = b"MSH|...|" + EOM
        ok, reason = validate_mllp_framing(framed)
        assert not ok
        assert "R-MLLP-001" in reason
    
    def test_missing_eom_fails(self):
        framed = SB + b"MSH|...|"
        ok, reason = validate_mllp_framing(framed)
        assert not ok
        assert "R-MLLP-001" in reason
    
    def test_too_short_fails(self):
        framed = SB + EOM
        ok, reason = validate_mllp_framing(framed)
        assert not ok
        assert "R-MLLP-001" in reason


class TestSequenceValidation:
    """Pruebas de validación de secuencia (MCID, replay, timestamp)."""
    
    def test_unique_mcid_passes(self):
        seen = set()
        ok, reason = validate_message_control_id_uniqueness("1", seen)
        assert ok
        assert "1" in seen
    
    def test_duplicate_mcid_fails(self):
        seen = {"1"}
        ok, reason = validate_message_control_id_uniqueness("1", seen)
        assert not ok
        assert "R-SEQ-001" in reason
    
    def test_regressive_timestamp_fails(self):
        ok, reason = validate_timestamp_regression("20260101000000", "20260101000001")
        assert not ok
        assert "R-TIME-001" in reason
    
    def test_progressive_timestamp_passes(self):
        ok, reason = validate_timestamp_regression("20260101000001", "20260101000000")
        assert ok
    
    def test_same_timestamp_passes(self):
        ok, reason = validate_timestamp_regression("20260101000000", "20260101000000")
        assert ok
    
    def test_frequency_within_bounds_passes(self):
        baseline = Baseline()
        baseline.inter_message_interval_seconds = {'min': 9.5, 'max': 10.5, 'p95': 10.1}
        ok, reason = validate_frequency(10.0, baseline)
        assert ok
    
    def test_frequency_too_high_fails(self):
        baseline = Baseline()
        baseline.inter_message_interval_seconds = {'min': 9.5, 'max': 10.5, 'p95': 10.1}
        ok, reason = validate_frequency(3.0, baseline)  # Muy rápido (< lower bound 4.75)
        assert not ok
        assert "R-TIME-002" in reason
    
    def test_frequency_too_low_fails(self):
        baseline = Baseline()
        baseline.inter_message_interval_seconds = {'min': 9.5, 'max': 10.5, 'p95': 10.1}
        ok, reason = validate_frequency(20.0, baseline)  # Muy lento
        assert not ok
        assert "R-TIME-002" in reason


class TestStateTransitionValidation:
    """Pruebas de validación de transiciones FSM."""
    
    def setup_method(self):
        self.transitions = [
            ["SIN_GATEWAY", "HANDSHAKE"],
            ["HANDSHAKE", "SESION_ESTABLECIDA_STANDBY"],
            ["SESION_ESTABLECIDA_STANDBY", "SESION_ESTABLECIDA_STANDBY"]
        ]
    
    def test_valid_transition_passes(self):
        ok, reason = validate_state_transition(
            "SIN_GATEWAY", "HANDSHAKE", self.transitions
        )
        assert ok
    
    def test_invalid_transition_fails(self):
        ok, reason = validate_state_transition(
            "SIN_GATEWAY", "SESION_ESTABLECIDA_STANDBY", self.transitions
        )
        assert not ok
        assert "R-STATE-001" in reason
    
    def test_self_loop_allowed(self):
        ok, reason = validate_state_transition(
            "SESION_ESTABLECIDA_STANDBY", "SESION_ESTABLECIDA_STANDBY", self.transitions
        )
        assert ok
    
    def test_empty_from_state_passes(self):
        ok, reason = validate_state_transition("", "SIN_GATEWAY", self.transitions)
        assert ok


class TestBaseline:
    """Pruebas de línea base."""
    
    def test_baseline_loads_from_dict(self):
        data = {
            'metadata': {'created_at': '2026-01-01', 'schema_version': '1.0'},
            'message_types_allowed': ['ORU^R01'],
            'sending_applications_allowed': ['TEST_APP'],
            'inter_message_interval_seconds': {'min': 9.0, 'max': 11.0, 'p95': 10.5},
            'message_length': {'min': 900, 'max': 1000, 'p95': 980},
            'state_transitions_observed': [['A', 'B']],
            'network_parameters': {'wato_ip': '192.168.1.100'}
        }
        
        baseline = Baseline(**data)
        assert baseline.message_types_allowed == ['ORU^R01']
        assert 'TEST_APP' in baseline.allowed_sending_apps
        assert baseline.is_obx_code_allowed('ANY')  # Sin códigos, permite todo
    
    def test_interval_bounds(self):
        baseline = Baseline()
        baseline.inter_message_interval_seconds = {'min': 9.0, 'max': 11.0, 'p95': 10.5}
        lower, upper = baseline.get_interval_bounds()
        assert lower == 4.5  # min * 0.5
        assert upper == 15.75  # p95 * 1.5
    
    def test_message_size_bounds(self):
        baseline = Baseline()
        baseline.message_length = {'min': 900, 'max': 1000, 'p95': 980}
        lower, upper = baseline.get_message_size_bounds()
        assert lower == 900
        assert upper == 1470  # p95 * 1.5


if __name__ == "__main__":
    pytest.main([__file__, "-v"])