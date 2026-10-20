#!/usr/bin/env python3
"""
hl7/validator.py - Validador de estructura HL7 v2.x contra baseline
Reglas deterministas para detectar anomalías estructurales.
"""

from dataclasses import dataclass
from typing import List, Dict, Optional, Any, Set
from datetime import datetime
import logging

from .parser import HL7Message, parse_hl7_message
from ..detection.baseline import Baseline
from ..config.settings import Settings, HL7Settings

logger = logging.getLogger(__name__)


@dataclass
class ValidationResult:
    """Resultado de validación HL7."""
    is_valid: bool
    errors: List[str]
    warnings: List[str]
    rule_violations: List[str]  # IDs de reglas violadas


def validate_hl7_structure(msg: HL7Message, hl7_settings: HL7Settings) -> ValidationResult:
    """
    Valida estructura básica HL7 contra configuración esperada.
    No valida rangos clínicos (requieren aprobación clínica).
    """
    errors = []
    warnings = []
    violations = []
    
    # R-HL7-001: MSH presente
    if not msg.msh:
        errors.append("R-HL7-001: Missing MSH segment")
        violations.append("R-HL7-001")
    
    # R-HL7-002: Tipo de mensaje permitido
    if msg.message_type and hl7_settings.message_types_allowed:
        if msg.message_type not in hl7_settings.message_types_allowed:
            errors.append(f"R-HL7-002: Unknown message type: {msg.message_type}")
            violations.append("R-HL7-002")
    
    # R-HL7-003: Secuencia de segmentos válida
    if hl7_settings.segment_sequences_allowed:
        if not _validate_segment_sequence(msg.segment_sequence, hl7_settings.segment_sequences_allowed):
            errors.append(f"R-HL7-003: Invalid segment sequence: {msg.segment_sequence}")
            violations.append("R-HL7-003")
    
    # Validar versión HL7
    if msg.version_id and hl7_settings.hl7_versions_allowed:
        if msg.version_id not in hl7_settings.hl7_versions_allowed:
            warnings.append(f"Unexpected HL7 version: {msg.version_id}")
    
    # Validar aplicación emisora
    if msg.sending_app and hl7_settings.sending_applications_allowed:
        if msg.sending_app not in hl7_settings.sending_applications_allowed:
            warnings.append(f"Unexpected sending application: {msg.sending_app}")
    
    # Longitud mensaje
    msg_len = len(msg.raw)
    if msg_len > hl7_settings.max_message_size:
        errors.append(f"Message too large: {msg_len} > {hl7_settings.max_message_size}")
        violations.append("R-MLLP-001")
    
    return ValidationResult(
        is_valid=len(errors) == 0,
        errors=errors,
        warnings=warnings,
        rule_violations=violations
    )


def _validate_segment_sequence(observed: List[str], allowed_sequences: List[List[str]]) -> bool:
    """Valida que la secuencia observada coincida con alguna permitida."""
    for allowed in allowed_sequences:
        if _sequences_match(observed, allowed):
            return True
    return False


def _sequences_match(observed: List[str], allowed: List[str]) -> bool:
    """Compara secuencias permitiendo OBX repetidos y NTE opcional al final.
    El prefijo fijo (no-OBX) debe coincidir en orden; tras él se acepta
    cualquier número de OBX (el baseline documenta 4 en STANDBY, pero el
    número de OBX no es una regla de ORDEN de segmentos)."""
    
    # NTE (notas) es un segmento opcional legal al final - no forma parte
    # de la secuencia estructural observada en baseline
    trimmed = list(observed)
    while trimmed and trimmed[-1] == 'NTE':
        trimmed.pop()
    
    # Verificar prefijo fijo (MSH, PID, PV1, OBR)
    fixed_prefix = [s for s in allowed if s != 'OBX']
    if len(trimmed) < len(fixed_prefix):
        return False
    for i, seg in enumerate(fixed_prefix):
        if trimmed[i] != seg:
            return False
    
    # Verificar que el resto sean OBX
    remaining = trimmed[len(fixed_prefix):]
    return all(s == 'OBX' for s in remaining)


def validate_obx_constraints(msg: HL7Message, baseline: Baseline) -> ValidationResult:
    """
    Valida restricciones OBX contra baseline.
    Rangos clínicos NO se validan aquí (requieren aprobación).
    Solo: códigos permitidos, tipos de dato, unidades.
    """
    errors = []
    warnings = []
    violations = []
    
    allowed_codes = set(baseline.obx_identifiers_observed)
    # El baseline guarda el identificador completo ("202886^MDC...^MDC");
    # el código primario (OBX-3 primer componente) también debe aceptarse.
    allowed_primary = {c.split('^')[0] for c in allowed_codes}
    allowed_types = set(baseline.obx_value_types_observed)
    allowed_units = set(baseline.obx_units_observed)
    expected_type_by_code = {}
    for full_id, detail in (baseline.obx_identifier_details or {}).items():
        if isinstance(detail, dict) and detail.get('value_type'):
            expected_type_by_code[full_id] = detail['value_type']
            expected_type_by_code[full_id.split('^')[0]] = detail['value_type']
    
    for obx in msg.obx_segments:
        if len(obx.fields) < 3:
            continue
        
        # R-OBX-001: Identificador no autorizado
        code = obx.fields[3].components[0] if obx.fields[3].components else ""
        full_code = obx.fields[3].raw if len(obx.fields) > 3 else ""
        if (code and allowed_codes and code not in allowed_codes
                and full_code not in allowed_codes
                and code not in allowed_primary):
            errors.append(f"R-OBX-001: Unauthorized OBX code: {code}")
            violations.append("R-OBX-001")
        
        # R-OBX-003: Tipo de dato incompatible (global y por código en baseline)
        value_type = obx.fields[2].raw if len(obx.fields) > 2 else ""
        expected_vtype = expected_type_by_code.get(full_code) or expected_type_by_code.get(code)
        if value_type:
            if (allowed_types and value_type not in allowed_types) or (
                expected_vtype and value_type != expected_vtype
            ):
                errors.append(f"R-OBX-003: Unexpected value type: {value_type} for code {code}")
                violations.append("R-OBX-003")
        
        # R-OBX-002: Unidad no permitida. Solo se valida si el baseline
        # tiene unidades observadas: cualquier OBX-6 fuera de esa lista es
        # anómala. Enmienda E1 (2026-10-14): CWE con unidad ya NO es
        # inválido per se — la evidencia STANDBY real trae
        # OBX-6 = 262656^MDC_DIM_DIMLESS^MDC en los 4 OBX CWE (43/43 ORU);
        # la cláusula previa "cwe_with_unit" producía 43/43 FP en el replay.
        if (allowed_units and len(obx.fields) > 6 and obx.fields[6].raw
                and obx.fields[6].raw not in allowed_units):
            unit = obx.fields[6].raw
            errors.append(f"R-OBX-002: Unauthorized unit: {unit} for code {code}")
            violations.append("R-OBX-002")
    
    return ValidationResult(
        is_valid=len(errors) == 0,
        errors=errors,
        warnings=warnings,
        rule_violations=violations
    )


def validate_message_control_id_uniqueness(control_id: str, seen_ids: Set[str]) -> tuple:
    """R-SEQ-001: Detecta Message Control ID duplicado."""
    if control_id in seen_ids:
        return False, "R-SEQ-001: Duplicate Message Control ID"
    seen_ids.add(control_id)
    return True, ""


def validate_timestamp_regression(timestamp: str, last_timestamp: Optional[str]) -> tuple:
    """R-TIME-001: Detecta timestamp regresivo."""
    if not timestamp or not last_timestamp:
        return True, ""
    
    try:
        # Formato HL7: YYYYMMDDHHMMSS[.SSS][+/-ZZZZ]
        curr = _parse_hl7_timestamp(timestamp)
        last = _parse_hl7_timestamp(last_timestamp)
        if curr and last and curr < last:
            return False, f"R-TIME-001: Regressive timestamp: {timestamp} < {last_timestamp}"
    except Exception:
        pass  # Si no se puede parsear, no validar
    return True, ""


def _parse_hl7_timestamp(ts: str) -> Optional[datetime]:
    """Parsea timestamp HL7 a datetime (best effort)."""
    # Tomar primeros 14 dígitos: YYYYMMDDHHMMSS
    digits = ''.join(c for c in ts if c.isdigit())
    if len(digits) >= 14:
        try:
            return datetime.strptime(digits[:14], '%Y%m%d%H%M%S')
        except ValueError:
            pass
    return None


def validate_frequency(interval: float, baseline: Baseline) -> tuple:
    """R-TIME-002: Valida frecuencia contra baseline (intervalo entre mensajes)."""
    min_interval = baseline.inter_message_interval_seconds.get('min', 0)
    max_interval = baseline.inter_message_interval_seconds.get('max', float('inf'))
    p95_interval = baseline.inter_message_interval_seconds.get('p95', max_interval)
    
    # Usar p95 como límite superior con tolerancia
    upper_bound = p95_interval * 1.5 if p95_interval > 0 else max_interval
    lower_bound = min_interval * 0.5 if min_interval > 0 else 0
    
    if interval < lower_bound:
        return False, f"R-TIME-002: Interval too short: {interval:.3f}s < {lower_bound:.3f}s"
    if interval > upper_bound:
        return False, f"R-TIME-002: Interval too long: {interval:.3f}s > {upper_bound:.3f}s"
    return True, ""


def validate_state_transition(from_state: str, to_state: str, 
                              allowed_transitions: List[List[str]]) -> tuple:
    """R-STATE-001: Valida transición de estado FSM."""
    if not from_state:
        return True, ""
    
    transition = [from_state, to_state]
    if transition not in allowed_transitions:
        return False, f"R-STATE-001: Invalid state transition: {from_state} -> {to_state}"
    return True, ""


def validate_network_origin(source_ip: str, allowed_ips: List[str]) -> tuple:
    """R-NET-001: Valida IP de origen permitida."""
    if allowed_ips and source_ip not in allowed_ips:
        return False, f"R-NET-001: Unauthorized source IP: {source_ip}"
    return True, ""


def validate_sending_application(app: str, allowed: List[str]) -> tuple:
    """R-ID-001: Valida aplicación emisora."""
    if allowed and app not in allowed:
        return False, f"R-ID-001: Unauthorized sending application: {app}"
    return True, ""


def validate_sending_facility(fac: str, allowed: List[str]) -> tuple:
    """R-ID-002: Valida institución emisora."""
    if allowed and fac not in allowed:
        return False, f"R-ID-002: Unauthorized sending facility: {fac}"
    return True, ""


def validate_mllp_framing(frame_bytes: bytes) -> tuple:
    """R-MLLP-001: Valida framing MLLP básico."""
    from ..mllp.framing import validate_mllp_frame
    is_valid, error = validate_mllp_frame(frame_bytes)
    if not is_valid:
        return False, f"R-MLLP-001: {error}"
    return True, ""