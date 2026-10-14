#!/usr/bin/env python3
"""
detection/baseline.py - Cargador de línea base desde YAML
Proporciona acceso tipado a parámetros baseline para el motor de detección.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Set
import yaml
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class Baseline:
    """Línea base cargada desde YAML con acceso tipado."""
    
    # Metadata
    created_at: str = ""
    schema_version: str = "1.0"
    source_sessions: List[str] = field(default_factory=list)
    source_hashes: Dict[str, str] = field(default_factory=dict)
    num_sessions: int = 0
    num_messages: int = 0
    states_included: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    clinical_approval_status: str = "PENDING"
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    # Parámetros HL7 permitidos
    message_types_allowed: List[str] = field(default_factory=list)
    segment_sequences_allowed: List[List[str]] = field(default_factory=list)
    sending_applications_allowed: List[str] = field(default_factory=list)
    sending_facilities_allowed: List[str] = field(default_factory=list)
    hl7_versions_allowed: List[str] = field(default_factory=list)
    
    # Estadísticas de longitud
    message_length: Dict[str, float] = field(default_factory=dict)
    inter_message_interval_seconds: Dict[str, float] = field(default_factory=dict)
    messages_per_minute: float = 0.0
    
    # OBX observados
    obx_identifiers_observed: List[str] = field(default_factory=list)
    obx_identifier_details: Dict[str, Dict] = field(default_factory=dict)
    obx_units_observed: List[str] = field(default_factory=list)
    obx_value_types_observed: List[str] = field(default_factory=list)
    
    # FSM
    state_transitions_observed: List[List[str]] = field(default_factory=list)
    fsm_states: Dict[str, Dict] = field(default_factory=dict)
    
    # Parámetros MLLP/HL7/Red
    mllp_parameters: Dict[str, Any] = field(default_factory=dict)
    hl7_parameters: Dict[str, Any] = field(default_factory=dict)
    network_parameters: Dict[str, Any] = field(default_factory=dict)
    
    # Propiedades computadas para acceso rápido
    _allowed_ips: Set[str] = field(default_factory=set, init=False)
    _allowed_apps: Set[str] = field(default_factory=set, init=False)
    _allowed_facilities: Set[str] = field(default_factory=set, init=False)
    _allowed_obx_codes: Set[str] = field(default_factory=set, init=False)
    _allowed_obx_types: Set[str] = field(default_factory=set, init=False)
    _allowed_obx_units: Set[str] = field(default_factory=set, init=False)
    
    def __post_init__(self):
        """Inicializa sets para lookup O(1)."""
        self._allowed_ips = set(self.network_parameters.get('allowed_ips', []))
        # Si no hay IPs explícitas, usar la observada
        if not self._allowed_ips and 'wato_ip' in self.network_parameters:
            self._allowed_ips.add(self.network_parameters['wato_ip'])
        
        self._allowed_apps = set(self.sending_applications_allowed)
        self._allowed_facilities = set(self.sending_facilities_allowed)
        self._allowed_obx_codes = set(self.obx_identifiers_observed)
        self._allowed_obx_types = set(self.obx_value_types_observed)
        self._allowed_obx_units = set(self.obx_units_observed)
    
    @property
    def allowed_ips(self) -> Set[str]:
        return self._allowed_ips
    
    @property
    def allowed_sending_apps(self) -> Set[str]:
        return self._allowed_apps
    
    @property
    def allowed_sending_facilities(self) -> Set[str]:
        return self._allowed_facilities
    
    @property
    def state_transitions(self) -> List[List[str]]:
        return self.state_transitions_observed
    
    def get_interval_bounds(self) -> tuple:
        """Retorna (min_interval, max_interval) para validación de frecuencia."""
        min_i = self.inter_message_interval_seconds.get('min', 0)
        max_i = self.inter_message_interval_seconds.get('max', float('inf'))
        p95 = self.inter_message_interval_seconds.get('p95', max_i)
        # Usar p95 * 1.5 como límite superior práctico
        upper = p95 * 1.5 if p95 > 0 else max_i
        lower = min_i * 0.5 if min_i > 0 else 0
        return lower, upper
    
    def get_message_size_bounds(self) -> tuple:
        """Retorna (min_size, max_size) para validación de longitud."""
        min_s = self.message_length.get('min', 0)
        max_s = self.message_length.get('max', 65535)
        p95 = self.message_length.get('p95', max_s)
        upper = p95 * 1.5 if p95 > 0 else max_s
        return min_s, upper
    
    def is_obx_code_allowed(self, code: str) -> bool:
        if not self._allowed_obx_codes:
            return True  # Sin baseline, permitir
        return code in self._allowed_obx_codes
    
    def is_obx_type_allowed(self, vtype: str) -> bool:
        if not self._allowed_obx_types:
            return True
        return vtype in self._allowed_obx_types
    
    def is_obx_unit_allowed(self, unit: str) -> bool:
        if not self._allowed_obx_units:
            return True
        return unit in self._allowed_obx_units
    
    def is_transition_allowed(self, from_state: str, to_state: str) -> bool:
        if not from_state:
            return True
        return [from_state, to_state] in self.state_transitions_observed
    
    def get_fsm_state_info(self, state: str) -> Optional[Dict]:
        return self.fsm_states.get(state)
    
    def get_obx_detail(self, code: str) -> Optional[Dict]:
        return self.obx_identifier_details.get(code)


def load_baseline(filepath: str) -> Baseline:
    """Carga baseline desde archivo YAML."""
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"Baseline file not found: {filepath}")
    
    with open(path, 'r', encoding='utf-8') as f:
        data = yaml.safe_load(f)
    
    if not data:
        raise ValueError("Empty baseline file")
    
    # Extraer metadata
    metadata = data.get('metadata', {})
    
    # Crear objeto Baseline con todos los campos
    baseline = Baseline(
        created_at=metadata.get('created_at', ''),
        schema_version=metadata.get('schema_version', '1.0'),
        source_sessions=metadata.get('source_sessions', []),
        source_hashes=metadata.get('source_hashes', {}),
        num_sessions=metadata.get('num_sessions', 0),
        num_messages=metadata.get('num_messages', 0),
        states_included=metadata.get('states_included', []),
        limitations=metadata.get('limitations', []),
        clinical_approval_status=metadata.get('clinical_approval_status', 'PENDING'),
        
        message_types_allowed=data.get('message_types_allowed', []),
        segment_sequences_allowed=data.get('segment_sequences_allowed', []),
        sending_applications_allowed=data.get('sending_applications_allowed', []),
        sending_facilities_allowed=data.get('sending_facilities_allowed', []),
        hl7_versions_allowed=data.get('hl7_versions_allowed', []),
        
        message_length=data.get('message_length', {}),
        inter_message_interval_seconds=data.get('inter_message_interval_seconds', {}),
        messages_per_minute=data.get('messages_per_minute', 0.0),
        
        obx_identifiers_observed=data.get('obx_identifiers_observed', []),
        obx_identifier_details=data.get('obx_identifier_details', {}),
        obx_units_observed=data.get('obx_units_observed', []),
        obx_value_types_observed=data.get('obx_value_types_observed', []),
        
        state_transitions_observed=data.get('state_transitions_observed', []),
        fsm_states=data.get('fsm_states', {}),
        
        mllp_parameters=data.get('mllp_parameters', {}),
        hl7_parameters=data.get('hl7_parameters', {}),
        network_parameters=data.get('network_parameters', {}),
    )
    
    logger.info(f"Baseline loaded: {baseline.num_sessions} sessions, "
                f"{baseline.num_messages} messages, "
                f"{len(baseline.obx_identifiers_observed)} OBX codes, "
                f"clinical_approval={baseline.clinical_approval_status}")
    
    return baseline


def create_baseline_from_evidence(evidence_dir: str, output_path: str):
    """Crea baseline desde evidencia analizada (delegado a baseline_builder.py)."""
    from ..evidence.baseline_builder import main as build_baseline
    import sys
    sys.argv = ['baseline_builder.py', '--source-dir', evidence_dir, '-o', output_path]
    build_baseline()