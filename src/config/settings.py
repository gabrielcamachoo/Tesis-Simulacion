#!/usr/bin/env python3
"""
config/settings.py - Cargador de configuración YAML con validación de seguridad
Valida LAB_AUTHORIZED, LAB_ONLY.marker, bloquea IPs públicas, etc.
"""

import os
import yaml
import logging
import ipaddress
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class NetworkSettings:
    bind_host: str = "0.0.0.0"
    bind_port: int = 1550
    server_ip: str = "192.168.23.200"
    server_port: int = 1550
    timeout: int = 60
    allowed_ips: List[str] = field(default_factory=list)


@dataclass
class MLPSettings:
    encoding: str = "UTF-8"
    start_block: int = 0x0B
    end_block: int = 0x1C
    carriage_return: int = 0x0D
    max_message_size: int = 65535
    max_buffer_size: int = 1048576
    strict: bool = True


@dataclass
class HL7Settings:
    version: str = "2.6"
    profile: str = "IHE_PCD_01"
    message_types_allowed: List[str] = field(default_factory=lambda: ["ORU^R01^ORU_R01"])
    segment_sequences_allowed: List[List[str]] = field(default_factory=lambda: [
        ["MSH", "PID", "PV1", "OBR", "OBX", "OBX", "OBX", "OBX"]
    ])
    sending_applications_allowed: List[str] = field(default_factory=lambda: [
        "MINDRAY_WATOPRO-SERIES^000F14002D3586ec^EUI-64"
    ])
    sending_facilities_allowed: List[str] = field(default_factory=lambda: [""])
    hl7_versions_allowed: List[str] = field(default_factory=lambda: ["2.6"])
    max_message_size: int = 65535


@dataclass
class EvidenceSettings:
    output_dir: str = "evidence_output"
    preserve_raw_bytes: bool = True
    rotate_logs_mb: int = 100
    max_log_files: int = 10
    hash_algorithm: str = "sha256"
    timestamp_source: str = "monotonic_utc"


@dataclass
class SafetySettings:
    require_lab_authorized: bool = True
    require_lab_marker: bool = True
    lab_marker_path: str = "/LAB_ONLY.marker"
    block_public_ips: bool = True
    block_hospital_routes: bool = True
    max_message_rate_per_sec: int = 10
    max_message_size_bytes: int = 65535
    max_concurrent_connections: int = 5
    anomaly_cooldown_seconds: int = 30


@dataclass
class AlertingSettings:
    output_format: str = "json"
    syslog_enabled: bool = False
    syslog_host: str = "127.0.0.1"
    syslog_port: int = 514
    include_evidence_hash: bool = True
    include_raw_message: bool = False
    anonymize_before_alert: bool = True


@dataclass
class AnomalyGeneratorSettings:
    safety_limits: Dict[str, Any] = field(default_factory=dict)
    scenarios: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Settings:
    """Configuración completa del laboratorio."""
    laboratory: Dict[str, Any] = field(default_factory=dict)
    network: NetworkSettings = field(default_factory=NetworkSettings)
    mllp: MLPSettings = field(default_factory=MLPSettings)
    hl7: HL7Settings = field(default_factory=HL7Settings)
    evidence: EvidenceSettings = field(default_factory=EvidenceSettings)
    safety: SafetySettings = field(default_factory=SafetySettings)
    alerting: AlertingSettings = field(default_factory=AlertingSettings)
    anomaly_generator: AnomalyGeneratorSettings = field(default_factory=AnomalyGeneratorSettings)
    
    # Runtime
    _lab_authorized: bool = field(default=False, init=False)
    _lab_marker_exists: bool = field(default=False, init=False)
    
    def __post_init__(self):
        self._validate_safety()
    
    def _validate_safety(self):
        """Valida requisitos de seguridad obligatorios."""
        errors = []
        
        # 1. LAB_AUTHORIZED=YES
        if self.safety.require_lab_authorized:
            lab_auth = os.environ.get("LAB_AUTHORIZED", "").strip().upper()
            if lab_auth != "YES":
                errors.append("LAB_AUTHORIZED=YES no está definido en variables de entorno")
            self._lab_authorized = (lab_auth == "YES")
        
        # 2. LAB_ONLY.marker existe
        if self.safety.require_lab_marker:
            marker_path = Path(self.safety.lab_marker_path)
            if not marker_path.exists():
                errors.append(f"Archivo marcador de laboratorio no encontrado: {marker_path}")
            self._lab_marker_exists = marker_path.exists()
        
        # 3. Validar IPs de bind (no públicas si block_public_ips)
        if self.safety.block_public_ips:
            try:
                bind_ip = ipaddress.ip_address(self.network.bind_host)
                if bind_ip.is_global and not bind_ip.is_loopback:
                    errors.append(f"IP de bind es pública: {self.network.bind_host}")
            except ValueError:
                pass  # hostname, validar luego
        
        # 4. Validar IP de servidor
        if self.safety.block_public_ips:
            try:
                server_ip = ipaddress.ip_address(self.network.server_ip)
                if server_ip.is_global and not server_ip.is_loopback:
                    errors.append(f"IP de servidor es pública: {self.network.server_ip}")
            except ValueError:
                pass
        
        # 5. Verificar rutas hacia redes hospitalarias (básico)
        if self.safety.block_hospital_routes:
            # En Docker internal network esto no aplica, pero verificamos
            hospital_ranges = [
                "10.0.0.0/8",
                "172.16.0.0/12", 
                "192.168.0.0/16"
            ]
            # Solo advertencia, no error
            for r in hospital_ranges:
                logger.warning(f"Verificar que no hay rutas a red hospitalaria: {r}")
        
        if errors:
            error_msg = "VALIDACIÓN DE SEGURIDAD FALLÓ:\n" + "\n".join(f"  - {e}" for e in errors)
            logger.error(error_msg)
            raise RuntimeError(error_msg)
        
        logger.info("Validación de seguridad PASÓ: LAB_AUTHORIZED=%s, LAB_MARKER=%s",
                   self._lab_authorized, self._lab_marker_exists)
    
    def is_lab_authorized(self) -> bool:
        return self._lab_authorized and self._lab_marker_exists
    
    def validate_target(self, target_ip: str, target_port: int) -> bool:
        """Valida que el objetivo sea permitido (solo emulador local)."""
        try:
            ip = ipaddress.ip_address(target_ip)
            
            # Solo localhost o red Docker internal
            if ip.is_loopback:
                return True
            
            # Verificar red privada Docker (172.17.0.0/16, 172.18.0.0/16, etc.)
            if ip.is_private:
                # En Docker Compose internal network, las IPs son 172.x.x.x
                return True
            
            return False
        except ValueError:
            return False
    
    def check_rate_limit(self, current_rate: float) -> bool:
        """Verifica límite de tasa."""
        return current_rate <= self.safety.max_message_rate_per_sec
    
    def check_size_limit(self, size: int) -> bool:
        """Verifica límite de tamaño."""
        return size <= self.safety.max_message_size_bytes


def load_settings(config_path: str) -> Settings:
    """Carga configuración desde YAML."""
    path = Path(config_path)
    if not path.exists():
        logger.warning(f"Config file not found: {config_path}, using defaults")
        return Settings()
    
    with open(path, 'r', encoding='utf-8') as f:
        data = yaml.safe_load(f)
    
    if not data:
        return Settings()
    
    # Network
    net_data = data.get('laboratory', {}).get('network', {})
    network = NetworkSettings(
        bind_host=net_data.get('bind_host', '0.0.0.0'),
        bind_port=net_data.get('bind_port', 1550),
        server_ip=data.get('wato_observed_standby', {}).get('destination', {}).get('ip', '192.168.23.200'),
        server_port=data.get('wato_observed_standby', {}).get('destination', {}).get('port', 1550),
        timeout=net_data.get('timeout', 60),
        allowed_ips=net_data.get('allowed_ips', [])
    )
    
    # MLLP
    mllp_data = data.get('wato_observed_standby', {}).get('mllp', {})
    mllp = MLPSettings(
        encoding=mllp_data.get('encoding', 'UTF-8'),
        start_block=mllp_data.get('start_block', 0x0B),
        end_block=mllp_data.get('end_block', 0x1C),
        carriage_return=mllp_data.get('carriage_return', 0x0D),
        max_message_size=mllp_data.get('max_message_size', 65535),
        max_buffer_size=mllp_data.get('max_buffer_size', 1048576),
        strict=mllp_data.get('strict', True)
    )
    
    # HL7
    hl7_data = data.get('wato_observed_standby', {}).get('hl7', {})
    baseline_data = data.get('baseline_builder', {}).get('statistics', {})
    hl7 = HL7Settings(
        version=hl7_data.get('version', '2.6'),
        profile=hl7_data.get('profile', 'IHE_PCD_01'),
        message_types_allowed=baseline_data.get('message_types_allowed', ["ORU^R01^ORU_R01"]),
        segment_sequences_allowed=baseline_data.get('segment_sequences_allowed', []),
        sending_applications_allowed=baseline_data.get('sending_applications_allowed', []),
        sending_facilities_allowed=baseline_data.get('sending_facilities_allowed', []),
        hl7_versions_allowed=baseline_data.get('hl7_versions_allowed', ['2.6']),
        max_message_size=65535
    )
    
    # Evidence
    ev_data = data.get('detector', {}).get('evidence', {})
    evidence = EvidenceSettings(
        output_dir=ev_data.get('output_dir', 'evidence_output'),
        preserve_raw_bytes=ev_data.get('preserve_raw_bytes', True),
        rotate_logs_mb=ev_data.get('rotate_logs_mb', 100),
        max_log_files=ev_data.get('max_log_files', 10),
        hash_algorithm=ev_data.get('hash_algorithm', 'sha256'),
        timestamp_source=ev_data.get('timestamp_source', 'monotonic_utc')
    )
    
    # Safety
    safe_data = data.get('laboratory', {}).get('safety', {})
    safety = SafetySettings(
        require_lab_authorized=safe_data.get('require_lab_authorized', True),
        require_lab_marker=safe_data.get('require_lab_marker', True),
        lab_marker_path=safe_data.get('lab_marker_path', '/LAB_ONLY.marker'),
        block_public_ips=safe_data.get('block_public_ips', True),
        block_hospital_routes=safe_data.get('block_hospital_routes', True),
        max_message_rate_per_sec=safe_data.get('max_message_rate_per_sec', 10),
        max_message_size_bytes=safe_data.get('max_message_size_bytes', 65535),
        max_concurrent_connections=safe_data.get('max_concurrent_connections', 5),
        anomaly_cooldown_seconds=safe_data.get('anomaly_cooldown_seconds', 30)
    )
    
    # Alerting
    alert_data = data.get('detector', {}).get('alerting', {})
    alerting = AlertingSettings(
        output_format=alert_data.get('output_format', 'json'),
        syslog_enabled=alert_data.get('syslog_enabled', False),
        syslog_host=alert_data.get('syslog_host', '127.0.0.1'),
        syslog_port=alert_data.get('syslog_port', 514),
        include_evidence_hash=alert_data.get('include_evidence_hash', True),
        include_raw_message=alert_data.get('include_raw_message', False),
        anonymize_before_alert=alert_data.get('anonymize_before_alert', True)
    )
    
    # Anomaly Generator
    anom_data = data.get('anomaly_generator', {})
    anomaly_generator = AnomalyGeneratorSettings(
        safety_limits=anom_data.get('safety_limits', {}),
        scenarios=anom_data.get('scenarios', {})
    )
    
    # Laboratory metadata
    laboratory = data.get('laboratory', {})
    
    return Settings(
        laboratory=laboratory,
        network=network,
        mllp=mllp,
        hl7=hl7,
        evidence=evidence,
        safety=safety,
        alerting=alerting,
        anomaly_generator=anomaly_generator
    )


def create_default_settings_yaml(output_path: str):
    """Genera settings.yaml por defecto desde la estructura actual."""
    # Usar el settings.yaml existente como base
    import shutil
    default_path = Path(__file__).parent.parent.parent / "config" / "settings.yaml"
    if default_path.exists():
        shutil.copy(default_path, output_path)
    else:
        logger.warning(f"Default settings.yaml not found at {default_path}")