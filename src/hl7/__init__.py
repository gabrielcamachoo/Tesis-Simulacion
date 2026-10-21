"""Paquete HL7: parser y validador determinista HL7 v2.6 (perfil IHE PCD-01)."""

from .parser import (
    HL7Field,
    HL7Segment,
    HL7Message,
    parse_hl7_message,
    extract_msh_fields,
    normalize_hl7_for_hash,
)

_VALIDATOR_EXPORTS = {
    "ValidationResult",
    "validate_hl7_structure",
    "validate_obx_constraints",
    "validate_message_control_id_uniqueness",
    "validate_timestamp_regression",
    "validate_frequency",
    "validate_state_transition",
    "validate_network_origin",
    "validate_sending_application",
    "validate_sending_facility",
    "validate_mllp_framing",
}

__all__ = [
    "HL7Field",
    "HL7Segment",
    "HL7Message",
    "parse_hl7_message",
    "extract_msh_fields",
    "normalize_hl7_for_hash",
    *_VALIDATOR_EXPORTS,
]


def __getattr__(name: str):
    if name in _VALIDATOR_EXPORTS:
        from . import validator
        return getattr(validator, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
