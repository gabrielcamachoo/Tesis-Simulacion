#!/usr/bin/env python3
"""
alerting/json_logger.py - Logger de alertas en formato JSON/JSONL
Incluye hash de evidencia, timestamp UTC, sesión, severidad, razón explicable.
"""

import json
import logging
import socket
import threading
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional, Dict, Any
from pathlib import Path

logger = logging.getLogger(__name__)


class AlertSeverity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class AlertLabel(Enum):
    NORMAL = "NORMAL"
    ANOMALO = "ANOMALO"


@dataclass
class Alert:
    """Alerta de detección con toda la información forense."""
    alert_id: str
    rule_id: str
    timestamp_utc: str
    session_id: str
    source: str
    message_control_id: str
    severity: AlertSeverity
    reason: str
    evidence_hash: str
    experimental_state: str = "UNKNOWN"
    label: AlertLabel = AlertLabel.ANOMALO
    synthetic: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_json(self) -> str:
        """Serializa a JSON para logging."""
        data = asdict(self)
        data['severity'] = self.severity.value
        data['label'] = self.label.value
        return json.dumps(data, ensure_ascii=False)
    
    def to_syslog(self) -> str:
        """Formato syslog RFC 5424 compatible."""
        return (f"<{self._syslog_priority()}>1 {self.timestamp_utc} "
                f"{socket.gethostname()} wato-detector {self.alert_id} "
                f"[{self.rule_id}] {self.reason}")
    
    def _syslog_priority(self) -> int:
        """Calcula prioridad syslog (facility=local0=16, severity mapping)."""
        severity_map = {
            AlertSeverity.CRITICAL: 2,
            AlertSeverity.HIGH: 3,
            AlertSeverity.MEDIUM: 4,
            AlertSeverity.LOW: 5,
            AlertSeverity.INFO: 6,
        }
        return 16 * 8 + severity_map.get(self.severity, 6)


class AlertLogger:
    """Logger de alertas con salida JSONL y opcional Syslog."""
    
    def __init__(self, settings, evidence_writer=None):
        self.settings = settings
        self.evidence_writer = evidence_writer
        self._lock = threading.Lock()
        self.alert_count = 0
        
        # Configurar logging a archivo JSONL
        self.alert_file = None
        if settings.alerting.output_format == "json":
            alert_dir = Path(settings.evidence.output_dir) / "alerts"
            alert_dir.mkdir(parents=True, exist_ok=True)
            self.alert_file = open(alert_dir / "alerts.jsonl", "a", encoding="utf-8")
        
        # Syslog opcional
        self.syslog_socket = None
        if settings.alerting.syslog_enabled:
            self._setup_syslog()
    
    def _setup_syslog(self):
        try:
            self.syslog_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.syslog_target = (self.settings.alerting.syslog_host, 
                                  self.settings.alerting.syslog_port)
        except Exception as e:
            logger.error(f"Failed to setup syslog: {e}")
            self.syslog_socket = None
    
    def log_alert(self, alert: Alert):
        """Registra una alerta en todas las salidas configuradas."""
        with self._lock:
            self.alert_count += 1
            
            # JSONL file
            if self.alert_file:
                try:
                    self.alert_file.write(alert.to_json() + "\n")
                    self.alert_file.flush()
                except Exception as e:
                    logger.error(f"Failed to write alert to JSONL: {e}")
            
            # Syslog
            if self.syslog_socket:
                try:
                    self.syslog_socket.sendto(alert.to_syslog().encode('utf-8'), 
                                             self.syslog_target)
                except Exception as e:
                    logger.error(f"Failed to send syslog: {e}")
            
            # Console (structured)
            logger.warning(f"ALERT {alert.alert_id} rule={alert.rule_id} "
                          f"session={alert.session_id} severity={alert.severity.value} "
                          f"reason={alert.reason}")
    
    def log_normal(self, session_id: str, source: str, msg_control_id: str,
                   state: str, evidence_hash: str):
        """Registra mensaje normal (para métricas de true negative)."""
        alert = Alert(
            alert_id=f"NORMAL-{self.alert_count:06d}-{int(datetime.now().timestamp()*1000)}",
            rule_id="NORMAL",
            timestamp_utc=datetime.now(timezone.utc).isoformat(),
            session_id=session_id,
            source=source,
            message_control_id=msg_control_id,
            severity=AlertSeverity.INFO,
            reason="Normal message processed",
            evidence_hash=evidence_hash,
            experimental_state=state,
            label=AlertLabel.NORMAL
        )
        if self.alert_file:
            with self._lock:
                self.alert_file.write(alert.to_json() + "\n")
                self.alert_file.flush()
    
    def close(self):
        """Cierra recursos."""
        if self.alert_file:
            self.alert_file.close()
        if self.syslog_socket:
            self.syslog_socket.close()


def create_test_alert(rule_id: str = "R-TEST-001") -> Alert:
    """Crea alerta de prueba para validación."""
    return Alert(
        alert_id=f"TEST-{int(datetime.now().timestamp()*1000)}",
        rule_id=rule_id,
        timestamp_utc=datetime.now(timezone.utc).isoformat(),
        session_id="test_session",
        source="192.168.23.250:2070",
        message_control_id="1",
        severity=AlertSeverity.HIGH,
        reason="Test alert",
        evidence_hash="test_hash",
        experimental_state="TEST",
        label=AlertLabel.ANOMALO,
        synthetic=True
    )