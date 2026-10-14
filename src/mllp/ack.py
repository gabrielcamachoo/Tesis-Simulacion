#!/usr/bin/env python3
"""
ack.py - Generación de ACK HL7 v2.x (Application Level ACK)
Compatible con evidencia observada: WATO EX-35 requiere ACK (MSH-16 = AL)
Estándar: HL7 v2.x Chapter 2 - Control Messages
"""

from typing import Optional, Dict, Any
from dataclasses import dataclass
from datetime import datetime, timezone
import logging

logger = logging.getLogger(__name__)

# Tipos de ACK HL7
ACK_ACCEPT = 'AA'   # Application Accept
ACK_ERROR = 'AE'    # Application Error
ACK_REJECT = 'AR'   # Application Reject

# Según evidencia: WATO envía MSH-16 = AL (Application Level ACK requerido)
# El receptor DEBE responder MSA|AA con el mismo Message Control ID

@dataclass
class HL7Ack:
    """Estructura de ACK HL7 parseada."""
    ack_code: str           # AA, AE, AR
    message_control_id: str # Del mensaje original (MSH-10)
    text_message: str = ""  # MSA-3 opcional
    error_condition: str = "" # MSA-4 opcional (ERR segment)
    
    def to_hl7(self, encoding: str = 'utf-8') -> str:
        """Genera segmento MSA."""
        parts = ['MSA', self.ack_code, self.message_control_id]
        if self.text_message:
            parts.append(self.text_message)
        if self.error_condition:
            parts.append(self.error_condition)
        return '|'.join(parts) + '\r'

@dataclass
class AckResponse:
    """Respuesta ACK completa lista para enviar."""
    msh_segment: str
    msa_segment: str
    raw_hl7: str           # HL7 completo (MSH + MSA + terminadores)
    mllp_framed: bytes     # Listo para enviar por socket
    
    def __bytes__(self) -> bytes:
        return self.mllp_framed

def parse_msh_for_ack(hl7_message: str) -> Dict[str, str]:
    """
    Extrae campos MSH necesarios para construir ACK.
    Maneja separadores estándar HL7.
    """
    lines = hl7_message.replace('\r\n', '\r').replace('\n', '\r').split('\r')
    msh_line = next((l for l in lines if l.startswith('MSH')), None)
    
    if not msh_line:
        return {}
    
    # Detectar separadores desde MSH-1 y MSH-2
    field_sep = msh_line[3] if len(msh_line) > 3 else '|'
    encoding_chars = msh_line[4:8] if len(msh_line) > 7 else '^~\\&'
    component_sep = encoding_chars[0] if len(encoding_chars) > 0 else '^'
    repeat_sep = encoding_chars[1] if len(encoding_chars) > 1 else '~'
    escape_char = encoding_chars[2] if len(encoding_chars) > 2 else '\\'
    subcomponent_sep = encoding_chars[3] if len(encoding_chars) > 3 else '&'
    
    fields = msh_line.split(field_sep)
    # Pad fields to ensure indices up to 20 exist (for MSH-21)
    while len(fields) < 21:
        fields.append('')
    
    def get_field(idx: int, default: str = '') -> str:
        return fields[idx] if len(fields) > idx else default
    
    return {
        'field_sep': field_sep,
        'encoding_chars': encoding_chars,
        'sending_app': get_field(2),      # MSH-3
        'sending_facility': get_field(3), # MSH-4
        'receiving_app': get_field(4),    # MSH-5
        'receiving_facility': get_field(5), # MSH-6
        'timestamp': get_field(6),        # MSH-7
        'message_type': get_field(8),     # MSH-9
        'message_control_id': get_field(9), # MSH-10
        'processing_id': get_field(10),   # MSH-11
        'version_id': get_field(11),      # MSH-12
        'charset': get_field(17),         # MSH-18
        'profile': get_field(20),         # MSH-21
    }

def build_ack_msh(original_msh: Dict[str, str], 
                  receiver_app: str = 'G18_DETECTOR',
                  receiver_facility: str = 'JAVERIANA_LAB',
                  processing_id: str = 'P') -> str:
    """
    Construye segmento MSH para ACK.
    Invierte sending/receiving respecto al original.
    """
    now = datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%z')
    if len(now) > 14:
        now = now[:14] + now[-5:].replace(':', '')
    
    field_sep = original_msh.get('field_sep', '|')
    encoding_chars = original_msh.get('encoding_chars', '^~\\&')
    version = original_msh.get('version_id', '2.6')
    charset = original_msh.get('charset') or 'UNICODE UTF-8'
    profile = original_msh.get('profile', '')
    
    msh_fields = [
        'MSH',                    # MSH-1
        encoding_chars,           # MSH-2
        receiver_app,             # MSH-3: Aplicación receptora (era sending)
        receiver_facility,        # MSH-4: Institución receptora
        original_msh.get('sending_app', ''),    # MSH-5: App original
        original_msh.get('sending_facility', ''), # MSH-6: Fac original
        now,                      # MSH-7: Timestamp actual
        '',                       # MSH-8: Security
        'ACK',                    # MSH-9: Message Type = ACK
        original_msh.get('message_control_id', '1'), # MSH-10: MISMO control ID
        processing_id,            # MSH-11: Processing ID
        version,                  # MSH-12: Version ID
        '',                       # MSH-13: Sequence Number
        '',                       # MSH-14: Continuation Pointer
        '',                       # MSH-15: Accept Acknowledgment Type
        'AL',                     # MSH-16: Application Acknowledgment Type (AL = requerido)
        '',                       # MSH-17: Country Code
        charset,                  # MSH-18: Character Set
        '',                       # MSH-19: Principal Language
        '',                       # MSH-20: Alternate Character Set
        profile,                  # MSH-21: Profile Identifier
    ]
    
    return field_sep.join(msh_fields)

def build_ack(hl7_message: str,
                  ack_code: str = ACK_ACCEPT,
                  receiver_app: str = 'G18_DETECTOR',
                  receiver_facility: str = 'JAVERIANA_LAB',
                  text_message: str = '',
                  error_condition: str = '',
                  encoding: str = 'utf-8') -> AckResponse:
        """
        Construye ACK HL7 completo con framing MLLP.
        
        Args:
            hl7_message: Mensaje HL7 original (string)
            ack_code: AA (accept), AE (error), AR (reject)
            receiver_app: Nombre aplicación receptora (para MSH-3 del ACK)
            receiver_facility: Institución receptora (para MSH-4 del ACK)
            text_message: Texto descriptivo opcional (MSA-3)
            error_condition: Código error opcional (MSA-4)
            encoding: Codificación (UTF-8 según evidencia WATO)
        
        Returns:
            AckResponse con HL7 y MLLP listo para enviar
        """
        # Parsear MSH original
        original_msh = parse_msh_for_ack(hl7_message)
        
        if not original_msh:
            raise ValueError("No se encontró segmento MSH válido en mensaje original")
        
        ctrl_id = original_msh.get('message_control_id', '1')
        
        # Construir MSH del ACK
        msh = build_ack_msh(original_msh, receiver_app, receiver_facility)
        
        # Construir MSA
        msa_parts = ['MSA', ack_code, ctrl_id]
        if text_message:
            msa_parts.append(text_message)
        if error_condition:
            msa_parts.append(error_condition)
        msa = '|'.join(msa_parts)
        
        # HL7 completo (segmentos separados por \r, terminado en \r)
        hl7_body = msh + '\r' + msa + '\r'
        
        # Framing MLLP
        from .framing import frame_hl7_message
        mllp_bytes = frame_hl7_message(hl7_body.encode(encoding, errors='replace'), encoding)
        
        return AckResponse(
            msh_segment=msh,
            msa_segment=msa,
            raw_hl7=hl7_body,
            mllp_framed=mllp_bytes
        )

def build_ack_bytes(hl7_message: str,
                  ack_code: str = ACK_ACCEPT,
                  receiver_app: str = 'G18_DETECTOR',
                  receiver_facility: str = 'JAVERIANA_LAB',
                  text_message: str = '',
                  error_condition: str = '',
                  encoding: str = 'utf-8') -> bytes:
    """Versión que retorna solo bytes MLLP (compatibilidad)."""
    return build_ack(hl7_message, ack_code, receiver_app, receiver_facility, 
                     text_message, error_condition, encoding).mllp_framed

def build_ack_from_bytes(hl7_bytes: bytes,
                      ack_code: str = ACK_ACCEPT,
                      receiver_app: str = 'G18_DETECTOR',
                      receiver_facility: str = 'JAVERIANA_LAB',
                      encoding: str = 'utf-8') -> bytes:
    """Versión que acepta bytes directamente y retorna bytes."""
    try:
        hl7_str = hl7_bytes.decode(encoding, errors='replace')
    except UnicodeDecodeError:
        hl7_str = hl7_bytes.decode('iso-8859-1', errors='replace')
    return build_ack_bytes(hl7_str, ack_code, receiver_app, receiver_facility, '', '', encoding)

def parse_ack(hl7_message: str) -> Optional[HL7Ack]:
    """Parsea un mensaje ACK recibido y extrae código y control ID."""
    lines = hl7_message.replace('\r\n', '\r').replace('\n', '\r').split('\r')
    msa_line = next((l for l in lines if l.startswith('MSA')), None)
    
    if not msa_line:
        return None
    
    fields = msa_line.split('|')
    if len(fields) < 3:
        return None
    
    return HL7Ack(
        ack_code=fields[1],
        message_control_id=fields[2],
        text_message=fields[3] if len(fields) > 3 else '',
        error_condition=fields[4] if len(fields) > 4 else ''
    )

def validate_ack(ack: HL7Ack, expected_control_id: str) -> Tuple[bool, str]:
    """
    Valida que un ACK sea correcto para un mensaje enviado.
    Retorna (es_valido, mensaje).
    """
    if ack.message_control_id != expected_control_id:
        return False, f"Control ID mismatch: expected {expected_control_id}, got {ack.message_control_id}"
    
    if ack.ack_code not in (ACK_ACCEPT, ACK_ERROR, ACK_REJECT):
        return False, f"Invalid ACK code: {ack.ack_code}"
    
    if ack.ack_code == ACK_ACCEPT:
        return True, "ACK accepted"
    elif ack.ack_code == ACK_ERROR:
        return False, f"Application error: {ack.text_message}"
    else:  # AR
        return False, f"Application rejected: {ack.text_message}"

# Funciones de conveniencia para el receptor experimental
def build_experimental_ack(hl7_message: str, encoding: str = 'utf-8') -> bytes:
    """
    Construye ACK AA estándar para el receptor experimental.
    Usa valores por defecto del proyecto G18.
    """
    response = build_ack(
        hl7_message,
        ack_code=ACK_ACCEPT,
        receiver_app='G18_DETECTOR',
        receiver_facility='JAVERIANA_LAB',
        encoding=encoding
    )
    return response.mllp_framed

def build_emulator_ack(hl7_message: str, encoding: str = 'utf-8') -> bytes:
    """
    Construye ACK para el emulador (cuando emulador actúa como receptor).
    Solo AE/AR permitidos dentro del emulador según restricciones.
    """
    # El emulador normalmente NO responde ACK (es cliente), pero si lo hace:
    response = build_ack(
        hl7_message,
        ack_code=ACK_ACCEPT,
        receiver_app='WATO_EMULATOR',
        receiver_facility='SIMULATION_LAB',
        encoding=encoding
    )
    return response.mllp_framed

# Testing
if __name__ == '__main__':
    # Test con mensaje STANDBY observado
    test_msg = """MSH|^~\\&|MINDRAY_WATOPRO-SERIES^000F14002D3586ec^EUI-64||||20260825141442-0500||ORU^R01^ORU_R01|1|P|2.6|||NE|AL|||UNICODE UTF-8|||IHE_PCD_001^IHE PCD^1.3.6.1.4.1.19376.1.6.1.1.1^ISO
PID|||^^^^PI||^^^^^^L|||
PV1||I|^^^
OBR|1|1^MINDRAY_WATOPRO-SERIES^...|1^...|70040^MDC_DEV_SYS_ANESTH^MDC|||20260825141442-0500|
OBX|1|CWE|202886^MDC_EVT_STAT_DEV^MDC|1.1.1.202886|202836^MDC_EVT_STAT_STANDBY^MDC
OBX|2|CWE|30002^MNDRY_EVT_STAT_MODE_DEV|1.1.1.30002|30003^MNDRY_EVT_STAT_MODE_NORMAL
OBX|3|CWE|30005^MNDRY_EVT_PATIENT_TYPE|1.1.1.30005|202890^MDC_EVT_STAT_DEV_MODE_ADULT
OBX|4|CWE|30007^MNDRY_EVT_STAT_WARMER_ON_BOOL|1.3.1.30007|30000^MDC_TRUE"""
    
    ack = build_experimental_ack(test_msg)
    print("ACK generado (bytes MLLP):")
    print(f"  Longitud: {len(ack)} bytes")
    print(f"  Inicio: {ack[:10]!r}")
    print(f"  Fin: {ack[-10:]!r}")
    
    # Verificar parseo
    from .framing import deframe_hl7_message
    hl7_content = deframe_hl7_message(ack)
    if hl7_content:
        print(f"\nContenido HL7 del ACK:")
        print(hl7_content.decode('utf-8'))
        
        parsed = parse_ack(hl7_content.decode('utf-8'))
        if parsed:
            print(f"\nACK parseado: code={parsed.ack_code}, ctrl_id={parsed.message_control_id}")
            valid, msg = validate_ack(parsed, '1')
            print(f"Validación: {valid} - {msg}")