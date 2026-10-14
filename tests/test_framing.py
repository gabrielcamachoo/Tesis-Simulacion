#!/usr/bin/env python3
"""
tests/test_framing.py - Pruebas unitarias para framing MLLP
Cobertura: mensajes fragmentados, múltiples mensajes en recv, mensajes incompletos,
bytes previos a SB, delimitadores fragmentados entre paquetes.
"""

import pytest
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from src.mllp.framing import (
    MLLPFramer, MLLPFrame, FrameResult, SB, EB, CR, EOM,
    extract_frames_simple, count_frames, validate_mllp_frame,
    frame_hl7_message, deframe_hl7_message
)


class TestMLLPFraming:
    """Pruebas del framer MLLP stateful."""
    
    def setup_method(self):
        self.framer = MLLPFramer()
    
    def test_simple_frame(self):
        """Frame MLLP simple completo en un feed."""
        hl7 = "MSH|^~\\&|APP|FAC|||20260101||ORU^R01|1|P|2.6\rPID|||123\r"
        framed = SB + hl7.encode() + EOM
        
        result = self.framer.feed(framed)
        assert len(result.frames) == 1
        assert result.frames[0].content == hl7.encode()
        assert result.remaining_buffer == b''
    
    def test_multiple_frames_in_one_feed(self):
        """Múltiples frames MLLP en un solo feed."""
        hl7_1 = "MSH|^~\\&|APP|FAC|||20260101||ORU^R01|1|P|2.6\r"
        hl7_2 = "MSH|^~\\&|APP|FAC|||20260101||ORU^R01|2|P|2.6\r"
        framed = SB + hl7_1.encode() + EOM + SB + hl7_2.encode() + EOM
        
        result = self.framer.feed(framed)
        assert len(result.frames) == 2
        assert result.frames[0].content == hl7_1.encode()
        assert result.frames[1].content == hl7_2.encode()
    
    def test_fragmented_across_feeds(self):
        """Frame fragmentado entre múltiples llamadas a feed()."""
        hl7 = "MSH|^~\\&|APP|FAC|||20260101||ORU^R01|1|P|2.6\rPID|||123\r"
        framed = SB + hl7.encode() + EOM
        
        # Enviar en 3 partes
        part1 = framed[:10]
        part2 = framed[10:25]
        part3 = framed[25:]
        
        result1 = self.framer.feed(part1)
        assert len(result1.frames) == 0
        
        result2 = self.framer.feed(part2)
        assert len(result2.frames) == 0
        
        result3 = self.framer.feed(part3)
        assert len(result3.frames) == 1
        assert result3.frames[0].content == hl7.encode()
    
    def test_incomplete_message_waits(self):
        """Mensaje incompleto (sin EOM) espera más datos."""
        hl7 = "MSH|^~\\&|APP|FAC|||20260101||ORU^R01|1|P|2.6\r"
        partial = SB + hl7.encode()  # Sin EOM
        
        result = self.framer.feed(partial)
        assert len(result.frames) == 0
        assert len(self.framer.buffer) > 0
        
        # Completar con EOM
        result2 = self.framer.feed(EOM)
        assert len(result2.frames) == 1
    
    def test_garbage_before_sb(self):
        """Bytes basura antes de SB son descartados y reportados."""
        garbage = b"GARBAGE_DATA"
        hl7 = "MSH|^~\\&|APP|FAC|||20260101||ORU^R01|1|P|2.6\r"
        framed = garbage + SB + hl7.encode() + EOM
        
        result = self.framer.feed(framed)
        assert len(result.frames) == 1
        assert "garbage_before_sb" in str(result.errors)
        assert result.frames[0].content == hl7.encode()
    
    def test_no_sb_discards_all(self):
        """Sin SB, todo el buffer se descarta (modo strict)."""
        data = b"NO_MLLP_HERE_AT_ALL"
        result = self.framer.feed(data)
        assert len(result.frames) == 0
        assert "no_sb_found" in str(result.errors)
        assert self.framer.buffer == b''
    
    def test_message_too_large_triggers_error(self):
        """Mensaje que excede max_message_size genera error y reset."""
        large_hl7 = "X" * 70000  # > 65535 default
        framed = SB + large_hl7.encode() + EOM
        
        result = self.framer.feed(framed)
        assert len(result.frames) == 0
        assert "message_too_large" in str(result.errors)
        assert self.framer.state.name == "WAITING_SB"
    
    def test_buffer_limit_enforced(self):
        """Límite de buffer evita DoS por acumulación."""
        # Llenar buffer casi al límite
        filler = b"X" * (1024 * 1024 - 100)  # Cerca de 1MB
        self.framer.feed(filler)
        
        # Agregar más debería descartar lo antiguo
        hl7 = "MSH|^~\\&|APP|FAC|||20260101||ORU^R01|1|P|2.6\r"
        framed = SB + hl7.encode() + EOM
        result = self.framer.feed(framed)
        
        # Debe haber procesado el frame válido
        assert len(result.frames) == 1
    
    def test_reset_clears_state(self):
        """Reset limpia buffer y estado."""
        self.framer.feed(b"GARBAGE")
        self.framer.feed(SB + b"MSH|...|" + EOM)
        self.framer.reset()
        
        assert self.framer.buffer == b''
        assert self.framer.state.name == "WAITING_SB"
        assert self.framer.bytes_discarded == 0


class TestFrameValidation:
    """Pruebas de validación de frames MLLP."""
    
    def test_valid_frame(self):
        hl7 = b"MSH|^~\\&|APP|FAC|||20260101||ORU^R01|1|P|2.6\r"
        framed = SB + hl7 + EOM
        valid, msg = validate_mllp_frame(framed)
        assert valid
        assert msg == "ok"
    
    def test_missing_start_block(self):
        framed = b"MSH|...|" + EOM
        valid, msg = validate_mllp_frame(framed)
        assert not valid
        assert msg == "missing_start_block"
    
    def test_missing_end_block(self):
        framed = SB + b"MSH|...|"
        valid, msg = validate_mllp_frame(framed)
        assert not valid
        assert msg == "missing_end_block"
    
    def test_frame_too_short(self):
        framed = SB + EOM  # Solo 3 bytes
        valid, msg = validate_mllp_frame(framed)
        assert not valid
        assert msg == "frame_too_short"
    
    def test_message_too_large(self):
        large = b"X" * 70000
        framed = SB + large + EOM
        valid, msg = validate_mllp_frame(framed, max_size=65535)
        assert not valid
        assert msg == "message_too_large"


class TestConvenienceFunctions:
    """Pruebas de funciones de conveniencia."""
    
    def test_frame_hl7_message(self):
        hl7 = b"MSH|^~\\&|APP|FAC|||20260101||ORU^R01|1|P|2.6\r"
        framed = frame_hl7_message(hl7)
        assert framed.startswith(SB)
        assert framed.endswith(EOM)
        assert framed[1:-2] == hl7
    
    def test_deframe_hl7_message(self):
        hl7 = b"MSH|^~\\&|APP|FAC|||20260101||ORU^R01|1|P|2.6\r"
        framed = SB + hl7 + EOM
        extracted = deframe_hl7_message(framed)
        assert extracted == hl7
    
    def test_deframe_invalid_returns_none(self):
        assert deframe_hl7_message(b"INVALID") is None
        assert deframe_hl7_message(SB + b"NO_EOM") is None
    
    def test_extract_frames_simple(self):
        hl7_1 = b"MSH|...|1\r"
        hl7_2 = b"MSH|...|2\r"
        data = SB + hl7_1 + EOM + SB + hl7_2 + EOM
        frames = extract_frames_simple(data)
        assert len(frames) == 2
        assert frames[0].content == hl7_1
        assert frames[1].content == hl7_2
    
    def test_count_frames(self):
        data = SB + b"MSG1" + EOM + SB + b"MSG2" + EOM + SB + b"MSG3" + EOM
        assert count_frames(data) == 3


class TestEdgeCases:
    """Casos edge y boundary conditions."""
    
    def setup_method(self):
        self.framer = MLLPFramer()
    
    def test_sb_followed_immediately_by_eom(self):
        """Frame vacío (solo SB + EOM) - inválido por contenido vacío."""
        framed = SB + EOM
        result = self.framer.feed(framed)
        assert len(result.frames) == 0
        assert "empty_content" in str(result.errors)
    
    def test_multiple_sb_without_eom(self):
        """Múltiples SB sin EOM - solo el último se considera."""
        data = SB + b"MSG1" + SB + b"MSG2" + EOM
        result = self.framer.feed(data)
        # El segundo SB descarta el primero
        assert len(result.frames) == 1
        assert result.frames[0].content == b"MSG2"
    
    def test_cr_lf_variations(self):
        """Variaciones de terminadores de línea en HL7 content."""
        # HL7 usa \r como separador de segmentos
        hl7 = "MSH|^~\\&|A|B|||20260101||ORU^R01|1|P|2.6\rPID|||123\r"
        framed = SB + hl7.encode() + EOM
        result = self.framer.feed(framed)
        assert len(result.frames) == 1
        assert b"\r" in result.frames[0].content


class TestMLLPIterator:
    """Pruebas del iterador MLLP para archivos completos."""
    
    def test_iterate_over_file_data(self):
        from src.mllp.framing import MLLPIterator
        hl7_1 = b"MSH|...|1\r"
        hl7_2 = b"MSH|...|2\r"
        data = b"GARBAGE" + SB + hl7_1 + EOM + b"MORE_GARBAGE" + SB + hl7_2 + EOM
        
        frames = list(MLLPIterator(data))
        assert len(frames) == 2
        assert frames[0].content == hl7_1
        assert frames[1].content == hl7_2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])