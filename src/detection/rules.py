#!/usr/bin/env python3
"""
detection/rules.py - Conjunto de reglas de detección configurables
Cada regla tiene ID, descripción, severidad por defecto y estado habilitado.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set
import yaml
import logging

logger = logging.getLogger(__name__)


@dataclass
class Rule:
    """Regla de detección individual."""
    rule_id: str
    name: str
    description: str
    category: str  # ID, NET, MLLP, HL7, SEQ, TIME, OBX, STATE
    default_severity: str  # HIGH, MEDIUM, LOW
    enabled: bool = True
    mitre_technique: str = ""
    mitre_justification: str = ""
    limitations: str = ""
    safety_limit: int = 0  # 0 = sin límite


@dataclass
class RuleResult:
    """Resultado de evaluar una regla."""
    rule_id: str
    triggered: bool
    reason: str = ""
    severity: str = ""
    metadata: Dict = field(default_factory=dict)


# Definición de reglas (R-ID-001 a R-STATE-001)
DEFAULT_RULES = [
    Rule(
        rule_id="R-ID-001",
        name="unauthorized_sending_application",
        description="Aplicación emisora (MSH-3) no incluida en baseline",
        category="ID",
        default_severity="HIGH",
        mitre_technique="T0855",
        mitre_justification="Suplantación de identidad lógica del dispositivo médico",
        limitations="Solo detecta valores no en baseline; no valida autenticidad criptográfica"
    ),
    Rule(
        rule_id="R-ID-002",
        name="unauthorized_sending_facility",
        description="Institución emisora (MSH-4) no incluida en baseline",
        category="ID",
        default_severity="MEDIUM",
        mitre_technique="T0855",
        mitre_justification="Suplantación de institución/origen organizacional",
        limitations="MSH-4 a menudo vacío en WATO; baja discriminación"
    ),
    Rule(
        rule_id="R-NET-001",
        name="unauthorized_network_origin",
        description="IP de origen TCP no permitida",
        category="NET",
        default_severity="HIGH",
        mitre_technique="T0855",
        mitre_justification="Conexión desde host no autorizado (MITRE T0855: Unauthorized Command Message)",
        limitations="IP spoofing posible en redes sin autenticación L2"
    ),
    Rule(
        rule_id="R-MLLP-001",
        name="invalid_mllp_framing",
        description="Framing MLLP inválido (delimitadores, longitud, estructura)",
        category="MLLP",
        default_severity="HIGH",
        mitre_technique="T0887",
        mitre_justification="Manipulación de framing para evasión de parser o DoS",
        limitations="Solo valida estructura básica; no detecta todos los casos de fragmentación maliciosa"
    ),
    Rule(
        rule_id="R-HL7-001",
        name="missing_msh_segment",
        description="Mensaje sin segmento MSH",
        category="HL7",
        default_severity="HIGH",
        mitre_technique="T0887",
        mitre_justification="Mensaje malformado para evasión o corrupción",
        limitations="Parser ya requiere MSH; detección redundante con parsing"
    ),
    Rule(
        rule_id="R-HL7-002",
        name="unknown_message_type",
        description="Tipo de mensaje (MSH-9) no en baseline",
        category="HL7",
        default_severity="HIGH",
        mitre_technique="T0857",
        mitre_justification="Inyección de tipo de mensaje no autorizado (ADT, ORM, etc.)",
        limitations="Baseline solo tiene ORU^R01; otros tipos legítimos podrían aparecer en RUNNING"
    ),
    Rule(
        rule_id="R-HL7-003",
        name="invalid_segment_sequence",
        description="Secuencia de segmentos HL7 no permitida",
        category="HL7",
        default_severity="HIGH",
        mitre_technique="T0887",
        mitre_justification="Reordenación maliciosa de segmentos (ej. OBX antes de MSH)",
        limitations="Baseline STANDBY tiene secuencia fija; RUNNING puede variar"
    ),
    Rule(
        rule_id="R-SEQ-001",
        name="duplicate_message_control_id",
        description="Message Control ID (MSH-10) duplicado en sesión",
        category="SEQ",
        default_severity="HIGH",
        mitre_technique="T0860",
        mitre_justification="Replay attack o duplicación de mensaje",
        limitations="WATO usa contador monotónico; reinicio de sesión puede resetear"
    ),
    Rule(
        rule_id="R-SEQ-002",
        name="replay_normalized_content_hash",
        description="Replay detectado por hash de contenido normalizado",
        category="SEQ",
        default_severity="HIGH",
        mitre_technique="T0860",
        mitre_justification="Reenvío de mensaje previo con MCID distinto pero mismo contenido",
        limitations="Normalización excluye timestamp y MCID; variaciones legítimas no detectadas"
    ),
    Rule(
        rule_id="R-TIME-001",
        name="regressive_timestamp",
        description="Timestamp HL7 (MSH-7) regresivo respecto al anterior",
        category="TIME",
        default_severity="MEDIUM",
        mitre_technique="T0887",
        mitre_justification="Manipulación temporal para evasión o confusión forense",
        limitations="Reloj WATO tiene offset +17min10s; usar timestamp de red para correlación"
    ),
    Rule(
        rule_id="R-TIME-002",
        name="frequency_out_of_baseline",
        description="Intervalo entre mensajes fuera de rango baseline (p95*1.5)",
        category="TIME",
        default_severity="MEDIUM",
        mitre_technique="T0814",
        mitre_justification="DoS/flooding o supresión de mensajes (MITRE T0814: Denial of Service)",
        limitations="Baseline STANDBY: 10s exactos; RUNNING puede variar; p95*1.5 = 15s"
    ),
    Rule(
        rule_id="R-OBX-001",
        name="unauthorized_obx_identifier",
        description="Código OBX-3 no en baseline observado",
        category="OBX",
        default_severity="HIGH",
        mitre_technique="T0831",
        mitre_justification="Inyección de parámetro de observación no autorizado (MITRE T0831: Manipulate I/O Image)",
        limitations="Baseline STANDBY solo 4 códigos CWE; RUNNING tiene ~23 códigos NM/SN no verificados"
    ),
    Rule(
        rule_id="R-OBX-002",
        name="unauthorized_obx_unit",
        description="Unidad OBX-6 no permitida",
        category="OBX",
        default_severity="MEDIUM",
        mitre_technique="T0831",
        mitre_justification="Manipulación de unidades de medida",
        limitations="STANDBY usa CWE (sin unidades); unidades RUNNING NO_VERIFICADO"
    ),
    Rule(
        rule_id="R-OBX-003",
        name="incompatible_obx_value_type",
        description="Tipo de dato OBX-2 incompatible con baseline",
        category="OBX",
        default_severity="HIGH",
        mitre_technique="T0831",
        mitre_justification="Cambio de tipo de dato (ej. NM en campo CWE) para corrupción",
        limitations="STANDBY solo CWE; RUNNING NM/SN NO_VERIFICADO"
    ),
    Rule(
        rule_id="R-STATE-001",
        name="invalid_state_transition",
        description="Transición FSM no permitida (SIN_GATEWAY→HANDSHAKE→ESTABLECIDA)",
        category="STATE",
        default_severity="HIGH",
        mitre_technique="T0869",
        mitre_justification="Secuencia anómala de establecimiento de sesión (MITRE T0869: Connection Proxy)",
        limitations="FSM inferido de 1 captura; transiciones RUNNING/ALARM NO_VERIFICADO"
    ),
]


class RuleSet:
    """Conjunto de reglas cargado desde YAML o defaults."""
    
    def __init__(self, rules_file: Optional[str] = None):
        self.rules: Dict[str, Rule] = {}
        self.enabled: Set[str] = set()
        
        if rules_file:
            self.load_from_yaml(rules_file)
        else:
            self.load_defaults()
    
    def load_defaults(self):
        for rule in DEFAULT_RULES:
            self.rules[rule.rule_id] = rule
            if rule.enabled:
                self.enabled.add(rule.rule_id)
    
    def load_from_yaml(self, filepath: str):
        with open(filepath, 'r') as f:
            data = yaml.safe_load(f)
        
        if 'rules' in data:
            for rule_data in data['rules']:
                rule = Rule(**rule_data)
                self.rules[rule.rule_id] = rule
                if rule.enabled:
                    self.enabled.add(rule.rule_id)
        else:
            # Formato simple: lista de rule_ids habilitados
            for rule_id in data.get('enabled_rules', []):
                if rule_id in self.rules:
                    self.enabled.add(rule_id)
    
    def is_enabled(self, rule_id: str) -> bool:
        return rule_id in self.enabled
    
    def enable(self, rule_id: str):
        if rule_id in self.rules:
            self.rules[rule_id].enabled = True
            self.enabled.add(rule_id)
    
    def disable(self, rule_id: str):
        if rule_id in self.rules:
            self.rules[rule_id].enabled = False
            self.enabled.discard(rule_id)
    
    def get_rule(self, rule_id: str) -> Optional[Rule]:
        return self.rules.get(rule_id)
    
    def list_enabled(self) -> List[str]:
        return sorted(self.enabled)
    
    def list_all(self) -> List[Rule]:
        return list(self.rules.values())
    
    def to_yaml(self) -> str:
        """Serializa reglas a YAML para configuración."""
        data = {
            'rules': [
                {
                    'rule_id': r.rule_id,
                    'name': r.name,
                    'description': r.description,
                    'category': r.category,
                    'default_severity': r.default_severity,
                    'enabled': r.enabled,
                    'mitre_technique': r.mitre_technique,
                    'mitre_justification': r.mitre_justification,
                    'limitations': r.limitations,
                    'safety_limit': r.safety_limit
                }
                for r in self.rules.values()
            ]
        }
        return yaml.dump(data, default_flow_style=False, sort_keys=False)


def create_rules_yaml(output_path: str):
    """Genera archivo rules.yaml con todas las reglas por defecto."""
    rs = RuleSet()
    with open(output_path, 'w') as f:
        f.write(rs.to_yaml())
    logger.info(f"Rules YAML written to {output_path}")