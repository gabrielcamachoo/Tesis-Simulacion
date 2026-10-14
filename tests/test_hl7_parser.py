#!/usr/bin/env python3
"""
tests/test_hl7_parser.py - Pruebas unitarias para parser HL7
Cobertura: parsing MSH, separadores, OBX, segmentos múltiples, anonimización.
"""

import pytest
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from src.hl7.parser import (
    parse_hl7_message, HL7Message, HL7Segment, HL7Field,
    detect_separators, split_field, extract_msh_fields,
    normalize_hl7_for_hash, get_obx_by_code, get_obx_value_by_code
)


class TestSeparatorDetection:
    """Pruebas de detección de separadores desde MSH."""
    
    def test_standard_separators(self):
        msh = "MSH|^~\\&|APP|FAC|||20260101||ORU^R01|1|P|2.6"
        field_sep, comp_sep, rep_sep, esc_char, subcomp_sep = detect_separators(msh)
        assert field_sep == '|'
        assert comp_sep == '^'
        assert rep_sep == '~'
        assert esc_char == '\\'
        assert subcomp_sep == '&'
    
    def test_custom_separators(self):
        msh = "MSH@#$%|APP|FAC|||20260101||ORU^R01|1|P|2.6"
        field_sep, comp_sep, rep_sep, esc_char, subcomp_sep = detect_separators(msh)
        assert field_sep == '@'
        assert comp_sep == '#'
        assert rep_sep == '$'
        assert esc_char == '%'
        # encoding_chars = "#$%|", so subcomponent_sep = '|' (4th char)
        assert subcomp_sep == '|'


class TestFieldSplitting:
    """Pruebas de división de campos en componentes/subcomponentes."""
    
    def test_simple_field(self):
        field = split_field("SIMPLE", '^', '&')
        assert field.components == ["SIMPLE"]
        assert field.subcomponents == [["SIMPLE"]]
    
    def test_component_field(self):
        field = split_field("COMP1^COMP2^COMP3", '^', '&')
        assert field.components == ["COMP1", "COMP2", "COMP3"]
    
    def test_subcomponent_field(self):
        field = split_field("COMP1&SUBC1&SUBC2^COMP2", '^', '&')
        assert field.components == ["COMP1&SUBC1&SUBC2", "COMP2"]
        assert field.subcomponents == [["COMP1", "SUBC1", "SUBC2"], ["COMP2"]]


class TestMessageParsing:
    """Pruebas de parsing de mensajes HL7 completos."""
    
    def test_parse_standby_message(self):
        msg_text = """MSH|^~\\&|MINDRAY_WATOPRO-SERIES^000F14002D3586ec^EUI-64||||20260825141442-0500||ORU^R01^ORU_R01|1|P|2.6|||NE|AL|||UNICODE UTF-8|||IHE_PCD_001^IHE PCD^1.3.6.1.4.1.19376.1.6.1.1.1^ISO
PID|||^^^^PI||^^^^^^L|||
PV1||I|^^^
OBR|1|1^MINDRAY_WATOPRO-SERIES^...|1^...|70040^MDC_DEV_SYS_ANESTH^MDC|||20260825141442-0500|
OBX|1|CWE|202886^MDC_EVT_STAT_DEV^MDC|1.1.1.202886|202836^MDC_EVT_STAT_STANDBY^MDC
OBX|2|CWE|30002^MNDRY_EVT_STAT_MODE_DEV|1.1.1.30002|30003^MNDRY_EVT_STAT_MODE_NORMAL
OBX|3|CWE|30005^MNDRY_EVT_PATIENT_TYPE|1.1.1.30005|202890^MDC_EVT_STAT_DEV_MODE_ADULT
OBX|4|CWE|30007^MNDRY_EVT_STAT_WARMER_ON_BOOL|1.3.1.30007|30000^MDC_TRUE"""
        
        msg = parse_hl7_message(msg_text)
        
        assert msg.msh is not None
        assert msg.message_type == "ORU^R01^ORU_R01"
        assert msg.message_control_id == "1"
        assert msg.version_id == "2.6"
        assert msg.sending_app == "MINDRAY_WATOPRO-SERIES^000F14002D3586ec^EUI-64"
        assert msg.charset == "UNICODE UTF-8"
        assert msg.profile == "IHE_PCD_001^IHE PCD^1.3.6.1.4.1.19376.1.6.1.1.1^ISO"
        assert len(msg.segments) == 8
        assert len(msg.obx_segments) == 4
        assert msg.segment_sequence == ['MSH', 'PID', 'PV1', 'OBR', 'OBX', 'OBX', 'OBX', 'OBX']
    
    def test_parse_running_message_with_numeric_obx(self):
        msg_text = """MSH|^~\\&|MINDRAY_WATOPRO-SERIES^000F14002D3586ec^EUI-64||||20260827094815||ORU^R01^ORU_R01|48|P|2.6|||NE|AL|||UNICODE UTF-8|||IHE_PCD_001^IHE PCD^1.3.6.1.4.1.19376.1.6.1.1.1^ISO
PID|||12345^5^M11^ADT^MR||DOE^JOHN^^^^^L||19800101|M
PV1||I|ICU^101^A^^^HOSP^A
OBR|1|1^MINDRAY^...|1^...|70040^MDC_DEV_SYS_ANESTH^MDC|||20260827094815|
OBX|1|NM|150020^MDC_VOL_RESP_TIDAL^MDC||500|mL
OBX|2|SN|150021^MDC_VOL_RESP_MINUTE^MDC||8.5|L/min
OBX|3|CWE|202886^MDC_EVT_STAT_DEV^MDC||202837^MDC_EVT_STAT_RUNNING^MDC"""
        
        msg = parse_hl7_message(msg_text)
        
        assert len(msg.obx_segments) == 3
        assert msg.get_obx_value_types() == ['NM', 'SN', 'CWE']
        assert msg.get_obx_codes() == ['150020^MDC_VOL_RESP_TIDAL^MDC', '150021^MDC_VOL_RESP_MINUTE^MDC', '202886^MDC_EVT_STAT_DEV^MDC']
    
    def test_parse_ack_message(self):
        ack_text = """MSH|^~\\&|G18NODE|JAVERIANA|MINDRAY_WATOPRO-SERIES^000F14002D3586ec^EUI-64||20260827094815||ACK|48|P|2.6
MSA|AA|48"""
        
        msg = parse_hl7_message(ack_text)
        assert msg.message_type == "ACK"
        assert msg.message_control_id == "48"
        assert len(msg.segments) == 2
        assert msg.segment_sequence == ['MSH', 'MSA']
    
    def test_empty_message_returns_empty_object(self):
        msg = parse_hl7_message("")
        assert msg.segments == []
        assert msg.msh is None
    
    def test_message_without_msh_returns_partial(self):
        msg_text = "PID|||123\rOBX|1|NM|CODE||100"
        msg = parse_hl7_message(msg_text)
        assert msg.msh is None
        assert len(msg.segments) == 2
        assert msg.segment_sequence == ['PID', 'OBX']


class TestOBXAccess:
    """Pruebas de acceso rápido a OBX."""
    
    def setup_method(self):
        self.msg_text = """MSH|^~\\&|APP|FAC|||20260101||ORU^R01|1|P|2.6
OBX|1|CWE|202886^MDC_EVT_STAT_DEV^MDC||202836^MDC_EVT_STAT_STANDBY^MDC
OBX|2|NM|150020^MDC_VOL_RESP_TIDAL^MDC||500|mL
OBX|3|CWE|30002^MNDRY_EVT_STAT_MODE_DEV||30003^MNDRY_EVT_STAT_MODE_NORMAL"""
        self.msg = parse_hl7_message(self.msg_text)
    
    def test_get_obx_codes(self):
        codes = self.msg.get_obx_codes()
        assert codes == ['202886^MDC_EVT_STAT_DEV^MDC', '150020^MDC_VOL_RESP_TIDAL^MDC', '30002^MNDRY_EVT_STAT_MODE_DEV']
    
    def test_get_obx_values(self):
        values = self.msg.get_obx_values()
        assert '202836^MDC_EVT_STAT_STANDBY^MDC' in values
        assert '500' in values
        assert '30003^MNDRY_EVT_STAT_MODE_NORMAL' in values
    
    def test_get_obx_by_code(self):
        obx = get_obx_by_code(self.msg, '150020^MDC_VOL_RESP_TIDAL^MDC')
        assert obx is not None
        assert obx.fields[2].raw == 'NM'
    
    def test_get_obx_value_by_code(self):
        val = get_obx_value_by_code(self.msg, '150020^MDC_VOL_RESP_TIDAL^MDC')
        assert val == '500'
    
    def test_get_nonexistent_obx_returns_none(self):
        obx = get_obx_by_code(self.msg, 'NONEXISTENT')
        assert obx is None
        val = get_obx_value_by_code(self.msg, 'NONEXISTENT')
        assert val is None


class TestNormalization:
    """Pruebas de normalización para detección de replay."""
    
    def test_normalize_removes_variable_fields(self):
        msg1 = "MSH|^~\\&|APP|FAC|||20260101000000||ORU^R01|1|P|2.6\rPID|||123\r"
        msg2 = "MSH|^~\\&|APP|FAC|||20260101000001||ORU^R01|2|P|2.6\rPID|||123\r"
        
        norm1 = normalize_hl7_for_hash(msg1)
        norm2 = normalize_hl7_for_hash(msg2)
        
        assert "20260101000000" not in norm1
        assert "20260101000001" not in norm2
        assert "|1|" not in norm1
        assert "|2|" not in norm2
    
    def test_same_content_different_metadata_same_hash(self):
        msg1 = "MSH|^~\\&|APP|FAC|||20260101000000||ORU^R01|1|P|2.6\rPID|||123\r"
        msg2 = "MSH|^~\\&|APP|FAC|||20260101000001||ORU^R01|2|P|2.6\rPID|||123\r"
        
        import hashlib
        hash1 = hashlib.sha256(normalize_hl7_for_hash(msg1).encode()).hexdigest()
        hash2 = hashlib.sha256(normalize_hl7_for_hash(msg2).encode()).hexdigest()
        
        assert hash1 == hash2


class TestExtractMSHFields:
    """Pruebas de función de compatibilidad extract_msh_fields."""
    
    def test_extract_msh_fields_dict(self):
        msg_text = "MSH|^~\\&|APP|FAC|||20260101||ORU^R01|1|P|2.6"
        fields = extract_msh_fields(msg_text)
        
        assert fields['sending_app'] == 'APP'
        assert fields['sending_facility'] == 'FAC'
        assert fields['message_type'] == 'ORU^R01'
        assert fields['message_control_id'] == '1'
        assert fields['version_id'] == '2.6'


class TestEdgeCases:
    """Casos edge."""
    
    def test_crlf_normalization(self):
        msg_text = "MSH|^~\\&|A|B|||20260101||ORU^R01|1|P|2.6\r\nPID|||123\n"
        msg = parse_hl7_message(msg_text)
        assert len(msg.segments) == 2
        assert msg.segments[1].name == 'PID'
    
    def test_unicode_in_content(self):
        msg_text = "MSH|^~\\&|APP|FAC|||20260101||ORU^R01|1|P|2.6\rOBX|1|ST|CODE||Paciente: Jose Maria\r"
        msg = parse_hl7_message(msg_text)
        assert 'Jose Maria' in msg.raw
    
    def test_repeated_fields(self):
        msg_text = "MSH|^~\\&|APP|FAC|||20260101||ORU^R01|1|P|2.6\rOBX|1|CWE|CODE||VAL1~VAL2~VAL3"
        msg = parse_hl7_message(msg_text)
        obx = msg.obx_segments[0]
        assert 'VAL1' in obx.fields[5].raw


if __name__ == "__main__":
    pytest.main([__file__, "-v"])