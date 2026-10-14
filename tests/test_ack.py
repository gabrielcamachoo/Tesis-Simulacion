#!/usr/bin/env python3
"""
tests/test_ack.py - Pruebas unitarias para generación y validación de ACK HL7
"""

import pytest
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from src.mllp.ack import (
    build_experimental_ack, build_emulator_ack, build_ack,
    build_ack_from_bytes, parse_ack, validate_ack, HL7Ack, AckResponse,
    ACK_ACCEPT, ACK_ERROR, ACK_REJECT
)
from src.mllp.framing import deframe_hl7_message


class TestACKGeneration:
    """Pruebas de generación de ACK."""
    
    def setup_method(self):
        self.test_msg = """MSH|^~\\&|MINDRAY_WATOPRO-SERIES^000F14002D3586ec^EUI-64||||20260825141442-0500||ORU^R01^ORU_R01|1|P|2.6|||NE|AL|||UNICODE UTF-8|||IHE_PCD_001^IHE PCD^1.3.6.1.4.1.19376.1.6.1.1.1^ISO
PID|||^^^^PI||^^^^^^L|||
PV1||I|^^^
OBR|1|1^MINDRAY^...|1^...|70040^MDC_DEV_SYS_ANESTH^MDC|||20260825141442-0500|
OBX|1|CWE|202886^MDC_EVT_STAT_DEV^MDC|1.1.1.202886|202836^MDC_EVT_STAT_STANDBY^MDC"""
    
    def test_build_experimental_ack_returns_bytes(self):
        ack_bytes = build_experimental_ack(self.test_msg)
        assert isinstance(ack_bytes, bytes)
        assert len(ack_bytes) > 0
        assert ack_bytes.startswith(b'\x0b')
        assert ack_bytes.endswith(b'\x1c\r')
    
    def test_ack_contains_correct_control_id(self):
        ack_bytes = build_experimental_ack(self.test_msg)
        hl7_content = deframe_hl7_message(ack_bytes)
        assert hl7_content is not None
        
        ack_parsed = parse_ack(hl7_content.decode('utf-8'))
        assert ack_parsed is not None
        assert ack_parsed.ack_code == ACK_ACCEPT
        assert ack_parsed.message_control_id == "1"
    
    def test_ack_msh_swaps_sender_receiver(self):
        ack_bytes = build_experimental_ack(self.test_msg)
        hl7_content = deframe_hl7_message(ack_bytes).decode('utf-8')
        
        # Verificar MSH del ACK
        lines = hl7_content.split('\r')
        msh = lines[0]
        fields = msh.split('|')
        
        # MSH-3 (sending_app) = G18_DETECTOR (receptor experimental)
        assert fields[2] == 'G18_DETECTOR'
        # MSH-5 (receiving_app) = MINDRAY_WATOPRO... (emisor original)
        assert fields[4] == 'MINDRAY_WATOPRO-SERIES^000F14002D3586ec^EUI-64'
        # MSH-9 = ACK
        assert fields[8] == 'ACK'
        # MSH-10 = mismo control ID
        assert fields[9] == '1'
        # MSH-16 = AL (application ack required)
        assert fields[15] == 'AL'
    
    def test_ack_with_custom_receiver(self):
        ack_response = build_ack(
            self.test_msg,
            receiver_app='MY_RECEIVER',
            receiver_facility='MY_FACILITY'
        )
        ack_bytes = ack_response.mllp_framed
        hl7_content = deframe_hl7_message(ack_bytes).decode('utf-8')
        msh = hl7_content.split('\r')[0]
        fields = msh.split('|')
        assert fields[2] == 'MY_RECEIVER'
        assert fields[3] == 'MY_FACILITY'
    
    def test_ack_error_code(self):
        ack_response = build_ack(self.test_msg, ack_code=ACK_ERROR, text_message="Test error")
        ack_bytes = ack_response.mllp_framed
        hl7_content = deframe_hl7_message(ack_bytes).decode('utf-8')
        ack_parsed = parse_ack(hl7_content)
        assert ack_parsed.ack_code == ACK_ERROR
        assert ack_parsed.text_message == "Test error"
    
    def test_ack_reject_code(self):
        ack_response = build_ack(self.test_msg, ack_code=ACK_REJECT, text_message="Rejected")
        ack_bytes = ack_response.mllp_framed
        hl7_content = deframe_hl7_message(ack_bytes).decode('utf-8')
        ack_parsed = parse_ack(hl7_content)
        assert ack_parsed.ack_code == ACK_REJECT
    
def test_build_ack_from_bytes():
        test_msg = """MSH|^~\\&|MINDRAY_WATOPRO-SERIES^000F14002D3586ec^EUI-64||||20260825141442-0500||ORU^R01^ORU_R01|1|P|2.6|||NE|AL|||UNICODE UTF-8|||IHE_PCD_001^IHE PCD^1.3.6.1.4.1.19376.1.6.1.1.1^ISO
PID|||12345||DOE^JOHN||19800101|M
OBX|1|NM|150020^MDC_VOL_RESP_TIDAL^MDC||500|mL"""
        msg_bytes = test_msg.encode('utf-8')
        ack_bytes = build_ack_from_bytes(msg_bytes)
        assert isinstance(ack_bytes, bytes)
        hl7_content = deframe_hl7_message(ack_bytes).decode('utf-8')
        assert hl7_content is not None


class TestACKParsing:
    """Pruebas de parsing de ACK recibido."""
    
    def test_parse_valid_ack(self):
        ack_hl7 = "MSH|^~\\&|REC|FAC|SEND|FAC2|20260101||ACK|123|P|2.6\rMSA|AA|123\r"
        parsed = parse_ack(ack_hl7)
        assert parsed is not None
        assert parsed.ack_code == 'AA'
        assert parsed.message_control_id == '123'
    
    def test_parse_ack_with_text(self):
        ack_hl7 = "MSH|^~\\&|REC|FAC|SEND|FAC2|20260101||ACK|123|P|2.6\rMSA|AE|123|Error message|ERR_CODE\r"
        parsed = parse_ack(ack_hl7)
        assert parsed.ack_code == 'AE'
        assert parsed.text_message == 'Error message'
        assert parsed.error_condition == 'ERR_CODE'
    
    def test_parse_non_ack_returns_none(self):
        oru_hl7 = "MSH|^~\\&|A|B|||20260101||ORU^R01|1|P|2.6\rPID|||123\r"
        parsed = parse_ack(oru_hl7)
        assert parsed is None
    
    def test_parse_malformed_ack_returns_none(self):
        bad_ack = "MSH|...|ACK|1|P|2.6\rMSA|AA"  # Falta control ID
        parsed = parse_ack(bad_ack)
        assert parsed is None


class TestACKValidation:
    """Pruebas de validación de ACK contra mensaje original."""
    
    def test_validate_ack_accept(self):
        ack = HL7Ack(ack_code=ACK_ACCEPT, message_control_id="123")
        valid, msg = validate_ack(ack, "123")
        assert valid
        assert msg == "ACK accepted"
    
    def test_validate_ack_error(self):
        ack = HL7Ack(ack_code=ACK_ERROR, message_control_id="123", text_message="Error")
        valid, msg = validate_ack(ack, "123")
        assert not valid
        assert "Application error" in msg
    
    def test_validate_ack_reject(self):
        ack = HL7Ack(ack_code=ACK_REJECT, message_control_id="123", text_message="Rejected")
        valid, msg = validate_ack(ack, "123")
        assert not valid
        assert "Application rejected" in msg
    
    def test_validate_wrong_control_id(self):
        ack = HL7Ack(ack_code=ACK_ACCEPT, message_control_id="456")
        valid, msg = validate_ack(ack, "123")
        assert not valid
        assert "Control ID mismatch" in msg
    
    def test_validate_invalid_ack_code(self):
        ack = HL7Ack(ack_code="XX", message_control_id="123")
        valid, msg = validate_ack(ack, "123")
        assert not valid
        assert "Invalid ACK code" in msg


class TestACKRoundTrip:
    """Pruebas de ida y vuelta: mensaje -> ACK -> validación."""
    
    def setup_method(self):
        self.original_msg = """MSH|^~\\&|MINDRAY_WATOPRO-SERIES^000F14002D3586ec^EUI-64||||20260825141442-0500||ORU^R01^ORU_R01|42|P|2.6|||NE|AL|||UNICODE UTF-8|||IHE_PCD_001^IHE PCD^1.3.6.1.4.1.19376.1.6.1.1.1^ISO
PID|||12345||DOE^JOHN||19800101|M
OBX|1|NM|150020^MDC_VOL_RESP_TIDAL^MDC||500|mL"""
    
    def test_round_trip_ack_validation(self):
        # Generar ACK
        ack_bytes = build_experimental_ack(self.original_msg)
        
        # Parsear ACK
        hl7_content = deframe_hl7_message(ack_bytes).decode('utf-8')
        parsed_ack = parse_ack(hl7_content)
        
        # Validar contra original
        valid, msg = validate_ack(parsed_ack, "42")
        assert valid
        assert parsed_ack.message_control_id == "42"
    
    def test_ack_preserves_charset(self):
        ack_bytes = build_experimental_ack(self.original_msg, encoding='utf-8')
        hl7_content = deframe_hl7_message(ack_bytes).decode('utf-8')
        
        # MSH-18 debería ser UTF-8
        msh = hl7_content.split('\r')[0]
        fields = msh.split('|')
        assert 'UTF-8' in fields[17] or 'UNICODE' in fields[17]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])