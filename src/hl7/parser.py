#!/usr/bin/env python3
"""
hl7/parser.py - Parser HL7 v2.x para mensajes ORU^R01
Extrae campos MSH, segmentos, OBX con detección de separadores.
Compatible con evidencia WATO EX-35 (MSH-18=UTF-8, separadores estándar).
"""

import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


@dataclass
class HL7Field:
    """Campo HL7 con componentes y subcomponentes."""
    raw: str
    components: List[str] = field(default_factory=list)
    subcomponents: List[List[str]] = field(default_factory=list)


@dataclass
class HL7Segment:
    """Segmento HL7 parseado."""
    name: str
    fields: List[HL7Field] = field(default_factory=list)
    raw: str = ""


@dataclass
class HL7Message:
    """Mensaje HL7 completo parseado."""
    raw: str
    segments: List[HL7Segment] = field(default_factory=list)
    msh: Optional[HL7Segment] = None
    
    # Campos MSH clave (acceso rápido)
    field_separator: str = "|"
    encoding_chars: str = "^~\\&"
    sending_app: str = ""
    sending_facility: str = ""
    receiving_app: str = ""
    receiving_facility: str = ""
    timestamp: str = ""
    message_type: str = ""
    trigger_event: str = ""
    message_structure: str = ""
    message_control_id: str = ""
    processing_id: str = ""
    version_id: str = ""
    charset: str = ""
    profile: str = ""
    
    segment_sequence: List[str] = field(default_factory=list)
    obx_segments: List[HL7Segment] = field(default_factory=list)
    
    def get_obx_codes(self) -> List[str]:
        """Extrae códigos OBX-3 (identificadores de observación) completos."""
        codes = []
        for obx in self.obx_segments:
            if len(obx.fields) > 3:
                comp = obx.fields[3].components
                if comp:
                    # Retornar código completo unido por ^
                    codes.append('^'.join(comp))
        return codes
    
    def get_obx_values(self) -> List[str]:
        """Extrae valores OBX-5."""
        values = []
        for obx in self.obx_segments:
            if len(obx.fields) > 5:
                values.append(obx.fields[5].raw)
        return values
    
    def get_obx_value_types(self) -> List[str]:
        """Extrae tipos de dato OBX-2 (NM, CWE, SN, etc.)."""
        types = []
        for obx in self.obx_segments:
            if len(obx.fields) > 2:
                types.append(obx.fields[2].raw)
        return types


def detect_separators(msh_line: str) -> tuple:
    """
    Detecta separadores desde MSH-1 y MSH-2.
    Retorna (field_sep, component_sep, repeat_sep, escape_char, subcomponent_sep).
    """
    if len(msh_line) < 4:
        return '|', '^', '~', '\\', '&'
    
    field_sep = msh_line[3]
    encoding_chars = msh_line[4:8] if len(msh_line) > 7 else '^~\\&'
    
    component_sep = encoding_chars[0] if len(encoding_chars) > 0 else '^'
    repeat_sep = encoding_chars[1] if len(encoding_chars) > 1 else '~'
    escape_char = encoding_chars[2] if len(encoding_chars) > 2 else '\\'
    subcomponent_sep = encoding_chars[3] if len(encoding_chars) > 3 else ''
    
    return field_sep, component_sep, repeat_sep, escape_char, subcomponent_sep


def split_field(field_text: str, component_sep: str, subcomponent_sep: str) -> HL7Field:
    """Divide un campo en componentes y subcomponentes."""
    components = field_text.split(component_sep) if component_sep in field_text else [field_text]
    subcomponents = [c.split(subcomponent_sep) for c in components]
    return HL7Field(raw=field_text, components=components, subcomponents=subcomponents)


def parse_hl7_message(hl7_text: str) -> HL7Message:
    """
    Parsea mensaje HL7 completo.
    Maneja separadores estándar y detectados desde MSH.
    """
    # Normalizar finales de línea
    normalized = hl7_text.replace('\r\n', '\r').replace('\n', '\r')
    lines = [l.strip() for l in normalized.split('\r') if l.strip()]
    
    if not lines:
        return HL7Message(raw=hl7_text)
    
    msg = HL7Message(raw=hl7_text)
    
    # Parsear MSH primero para detectar separadores
    msh_line = lines[0]
    if not msh_line.startswith('MSH'):
        logger.warning(f"Mensaje sin MSH válido: {msh_line[:50]}")
        # Aún intentamos parsear segmentos con separadores por defecto
        field_sep = '|'
        comp_sep = '^'
        rep_sep = '~'
        esc_char = '\\'
        subcomp_sep = '&'
        msg.field_separator = field_sep
        msg.encoding_chars = f"{comp_sep}{rep_sep}{esc_char}{subcomp_sep}"
    else:
        field_sep, comp_sep, rep_sep, esc_char, subcomp_sep = detect_separators(msh_line)
        
        msg.field_separator = field_sep
        msg.encoding_chars = f"{comp_sep}{rep_sep}{esc_char}{subcomp_sep}"
    
    # Parsear todos los segmentos
    for line in lines:
        if not line:
            continue
        seg_name = line[:3]
        field_texts = line.split(field_sep)
        
        fields = [split_field(f, comp_sep, subcomp_sep) for f in field_texts]
        segment = HL7Segment(name=seg_name, fields=fields, raw=line)
        msg.segments.append(segment)
        msg.segment_sequence.append(seg_name)
        
        if seg_name == 'MSH':
            msg.msh = segment
            _extract_msh_fields(msg, fields, field_sep)
# Fallback adicional: extraer charset directamente del raw si falló
            if not msg.charset and msg.msh and msg.msh.raw:
                msh_parts = msg.msh.raw.split(field_sep)
                if len(msh_parts) > 17:
                    msg.charset = msh_parts[17]
            
            # Fallback adicional 2: buscar charset en todo el mensaje raw
            if not msg.charset and msg.raw:
                # Buscar patrón "UNICODE UTF-8" o "UTF-8" en el mensaje
                import re
                match = re.search(r'(UNICODE\s+UTF-8|UTF-8)', msg.raw)
                if match:
                    msg.charset = match.group(1)
        elif seg_name == 'OBX':
            msg.obx_segments.append(segment)
    
    return msg


def _extract_msh_fields(msg: HL7Message, fields: List[HL7Field], field_sep: str):
    """Extrae campos clave del MSH usando índices estándar HL7."""
    def get_field(idx: int) -> str:
        if idx < len(fields):
            return fields[idx].raw
        return ""
    
    # Extraer component separator desde MSH-2 (encoding chars, índice 1)
    encoding_chars_raw = get_field(1)  # MSH-2
    if len(encoding_chars_raw) >= 4:
        comp_sep = encoding_chars_raw[0]
    else:
        comp_sep = '^'
    
    # MSH-1 es el nombre del segmento (índice 0), MSH-2 son encoding chars (índice 1)
    msg.sending_app = get_field(2)      # MSH-3
    msg.sending_facility = get_field(3)  # MSH-4
    msg.receiving_app = get_field(4)     # MSH-5
    msg.receiving_facility = get_field(5) # MSH-6
    msg.timestamp = get_field(6)         # MSH-7
    
    # MSH-9: Message Type (puede tener 3 componentes: type^trigger^structure)
    msg.message_type = get_field(8)
    if msg.message_type:
        parts = msg.message_type.split(comp_sep)
        if len(parts) >= 1:
            msg.trigger_event = parts[0]
        if len(parts) >= 2:
            pass  # trigger event (ya en parts[1])
        if len(parts) >= 3:
            msg.message_structure = parts[2]
    
    msg.message_control_id = get_field(9)   # MSH-10
    msg.processing_id = get_field(10)       # MSH-11
    msg.version_id = get_field(11)          # MSH-12
    
    # MSH-18 (charset) - índice 17 en split por field_sep
    # Si falla la extracción por campos, intentar extraer directamente del MSH raw
    charset = get_field(17) if len(fields) > 17 else ""
    if not charset and msg.msh and msg.msh.raw:
        # Fallback: parsear directamente del MSH raw
        msh_parts = msg.msh.raw.split(field_sep)
        if len(msh_parts) > 17:
            charset = msh_parts[17]
    msg.charset = charset
    
    # MSH-21 (profile) - último campo del segmento MSH
    # Intentar obtener del último campo del segmento MSH parseado
    if msg.msh and msg.msh.fields:
        profile = msg.msh.fields[-1].raw
    # Fallback: extraer de la línea MSH raw
    if not profile and msg.msh and msg.msh.raw:
        msh_parts = msg.msh.raw.split(field_sep)
        if msh_parts:
            profile = msh_parts[-1]
    # Fallback adicional: buscar en el mensaje raw
    if not profile and msg.raw:
        import re
        msh_line_match = re.search(r'^\s*MSH[^\r\n]*', msg.raw, re.MULTILINE)
        if msh_line_match:
            msh_line = msh_line_match.group(0)
            msh_parts = msh_line.split(field_sep)
            if msh_parts:
                profile = msh_parts[-1]
    msg.profile = profile


def extract_msh_fields(hl7_text: str) -> Dict[str, str]:
    """Función de compatibilidad: extrae campos MSH como diccionario simple."""
    msg = parse_hl7_message(hl7_text)
    return {
        'field_sep': msg.field_separator,
        'encoding_chars': msg.encoding_chars,
        'sending_app': msg.sending_app,
        'sending_facility': msg.sending_facility,
        'receiving_app': msg.receiving_app,
        'receiving_facility': msg.receiving_facility,
        'timestamp': msg.timestamp,
        'message_type': msg.message_type,
        'message_control_id': msg.message_control_id,
        'processing_id': msg.processing_id,
        'version_id': msg.version_id,
        'charset': msg.charset,
        'profile': msg.profile,
    }


def normalize_hl7_for_hash(hl7_text: str) -> str:
    """
    Normaliza mensaje HL7 para detección de replay (hash de contenido).
    Elimina campos variables: timestamp, message_control_id, secuencias.
    """
    msg = parse_hl7_message(hl7_text)
    
    # Reconstruir solo campos estables
    stable_parts = []
    for seg in msg.segments:
        if seg.name == 'MSH':
            # MSH sin timestamp (campo 7) ni control_id (campo 10)
            fields = [f.raw for f in seg.fields]
            if len(fields) > 6:
                fields[6] = ""  # MSH-7 timestamp
            if len(fields) > 9:
                fields[9] = ""  # MSH-10 control_id
            stable_parts.append(msg.field_separator.join(fields))
        else:
            stable_parts.append(seg.raw)
    
    return '\r'.join(stable_parts) + '\r'


# Funciones de conveniencia para acceso rápido a OBX
def get_obx_by_code(msg: HL7Message, code: str) -> Optional[HL7Segment]:
    """Busca OBX por código completo en OBX-3 (todos los componentes unidos por ^)"""
    for obx in msg.obx_segments:
        if len(obx.fields) > 3 and obx.fields[3].components:
            full_code = '^'.join(obx.fields[3].components)
            if full_code == code:
                return obx
    return None


def get_obx_value_by_code(msg: HL7Message, code: str) -> Optional[str]:
    """Obtiene valor OBX-5 por código OBX-3 completo"""
    obx = get_obx_by_code(msg, code)
    if obx and len(obx.fields) > 5:
        return obx.fields[5].raw
    return None