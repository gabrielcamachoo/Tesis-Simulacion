#!/usr/bin/env python3
"""
detection/engine.py - Motor de detección determinista HL7/MLLP
Aplica reglas configuradas contra baseline y genera alertas.
"""

import time
import hashlib
import logging
import threading
from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional, Any
from datetime import datetime, timezone

from ..hl7.parser import HL7Message, parse_hl7_message, normalize_hl7_for_hash
from ..hl7.validator import (
    validate_hl7_structure, validate_obx_constraints,
    validate_message_control_id_uniqueness, validate_timestamp_regression,
    validate_frequency, validate_state_transition,
    validate_network_origin, validate_sending_application,
    validate_sending_facility, validate_mllp_framing
)
from ..detection.baseline import Baseline
from ..detection.rules import RuleSet, RuleResult
from ..alerting.json_logger import Alert, AlertSeverity, AlertLabel
from ..config.settings import Settings

logger = logging.getLogger(__name__)


@dataclass
class SessionState:
    """Estado de una sesión para detección."""
    session_id: str
    source_ip: str
    source_port: int
    message_count: int = 0
    seen_control_ids: Set[str] = field(default_factory=set)
    seen_content_hashes: Set[str] = field(default_factory=set)
    last_timestamp: Optional[str] = None
    last_message_time: float = 0
    current_state: str = ""  # vacío = primera transición no validada (sin estado previo)
    last_alert_time: float = 0
    logical_identity: tuple = ()  # (sending_app, sending_facility)


@dataclass
class DetectionResult:
    """Resultado de procesar un mensaje."""
    alerts: List[Alert]
    session_state: SessionState
    validation: Any  # ValidationResult
    processing_time_ms: float


class DetectionEngine:
    """
    Motor de detección determinista.
    - Carga reglas desde RuleSet
    - Mantiene estado por sesión
    - Aplica validaciones contra baseline
    - Genera alertas con evidencia y hash
    """
    
    def __init__(self, settings: Settings, baseline: Baseline, rules: RuleSet):
        self.settings = settings
        self.baseline = baseline
        self.rules = rules
        self.sessions: Dict[str, SessionState] = {}
        self._lock = threading.RLock()  # reentrant para callbacks
        self._alert_counter = 0
        # Estado global del emisor (laboratorio: un solo dispositivo esperado).
        # MCID, hash de contenido, timestamp y frecuencia se rastrean A TRAVÉS
        # de sesiones TCP: replay/duplicación suelen venir en una conexión nueva.
        self.global_control_ids: Set[str] = set()
        # hash -> último time.time() visto. Con VENTANA: la telemetría benigna
        # es periódica y su contenido se repite (STANDBY idéntico cada 10 s,
        # solo cambian MSH-7/MSH-10). Solo se considera replay si el mismo
        # contenido reaparece dentro de la ventana (mitad del intervalo baseline).
        self.global_content_hashes: Dict[str, float] = {}
        self.global_last_timestamp: Optional[str] = None
        self.global_last_message_time: float = 0.0

        # Ventana de replay: mitad del intervalo mínimo baseline (10 s → 5 s)
        interval_min = baseline.inter_message_interval_seconds.get('min', 10.0) or 10.0
        self.replay_window_s = max(1.0, interval_min * 0.5)

        # Enmienda E3 (vigilante de silencio): una alerta por episodio.
        self._silence_alerted = False
        self._last_session_id = ""
        self._last_source = ""
    
    def process_message(self, session_id: str, source_ip: str, source_port: int,
                        parsed_message: HL7Message, raw_bytes: bytes,
                        mllp_frame: bytes) -> DetectionResult:
        """Procesa un mensaje HL7 completo y genera alertas."""
        start_time = time.perf_counter()
        
        with self._lock:
            session = self._get_or_create_session(session_id, source_ip, source_port)
            
            # Validaciones estructurales
            validation = validate_hl7_structure(parsed_message, self.settings.hl7)
            
            # Validaciones OBX contra baseline
            obx_validation = validate_obx_constraints(parsed_message, self.baseline)
            validation.errors.extend(obx_validation.errors)
            validation.warnings.extend(obx_validation.warnings)
            validation.rule_violations.extend(obx_validation.rule_violations)
            
            # Reglas de detección
            alerts = []
            alerts.extend(self._check_rules(session, parsed_message, raw_bytes,
                                            mllp_frame, validation, obx_validation))
            
            # Actualizar estado de sesión
            self._update_session_state(session, parsed_message, raw_bytes)
            
            processing_time = (time.perf_counter() - start_time) * 1000
            
            return DetectionResult(
                alerts=alerts,
                session_state=session,
                validation=validation,
                processing_time_ms=processing_time
            )
    
    def _get_or_create_session(self, session_id: str, source_ip: str, source_port: int) -> SessionState:
        if session_id not in self.sessions:
            self.sessions[session_id] = SessionState(
                session_id=session_id,
                source_ip=source_ip,
                source_port=source_port
            )
        return self.sessions[session_id]
    
    def _check_rules(self, session: SessionState, msg: HL7Message,
                     raw_bytes: bytes, mllp_frame: bytes,
                     validation: Any, obx_validation: Any) -> List[Alert]:
        """Ejecuta todas las reglas habilitadas."""
        alerts = []
        now = time.time()
        
        # R-NET-001: Origen de red no permitido
        if self.rules.is_enabled('R-NET-001'):
            ok, reason = validate_network_origin(session.source_ip, self.baseline.allowed_ips)
            if not ok:
                alerts.append(self._make_alert('R-NET-001', session, msg, reason, AlertSeverity.HIGH))
        
        # R-ID-001: Aplicación emisora no permitida
        if self.rules.is_enabled('R-ID-001'):
            ok, reason = validate_sending_application(msg.sending_app, self.baseline.allowed_sending_apps)
            if not ok:
                alerts.append(self._make_alert('R-ID-001', session, msg, reason, AlertSeverity.HIGH))
        
        # R-ID-002: Institución emisora no permitida
        if self.rules.is_enabled('R-ID-002'):
            ok, reason = validate_sending_facility(msg.sending_facility, self.baseline.allowed_sending_facilities)
            if not ok:
                alerts.append(self._make_alert('R-ID-002', session, msg, reason, AlertSeverity.MEDIUM))
        
        # R-MLLP-001: Framing inválido
        if self.rules.is_enabled('R-MLLP-001'):
            ok, reason = validate_mllp_framing(mllp_frame)
            if not ok:
                alerts.append(self._make_alert('R-MLLP-001', session, msg, reason, AlertSeverity.HIGH))
        
        # R-HL7-001: MSH ausente (ya en validation)
        if 'R-HL7-001' in validation.rule_violations:
            alerts.append(self._make_alert('R-HL7-001', session, msg, 
                                          "Missing MSH segment", AlertSeverity.HIGH))
        
        # R-HL7-002: Tipo mensaje desconocido
        if 'R-HL7-002' in validation.rule_violations:
            alerts.append(self._make_alert('R-HL7-002', session, msg,
                                          f"Unknown message type: {msg.message_type}", AlertSeverity.HIGH))
        
        # R-HL7-003: Secuencia segmentos inválida
        if 'R-HL7-003' in validation.rule_violations:
            alerts.append(self._make_alert('R-HL7-003', session, msg,
                                          f"Invalid segment sequence: {msg.segment_sequence}", AlertSeverity.HIGH))
        
        # R-SEQ-001: MCID duplicado (rastreo global: replay suele venir en sesión nueva)
        if self.rules.is_enabled('R-SEQ-001') and msg.message_control_id:
            ok, reason = validate_message_control_id_uniqueness(
                msg.message_control_id, self.global_control_ids)
            if not ok:
                alerts.append(self._make_alert('R-SEQ-001', session, msg, reason, AlertSeverity.HIGH))
            session.seen_control_ids.add(msg.message_control_id)
        
        # R-SEQ-002: Replay por hash normalizado dentro de la ventana
        if self.rules.is_enabled('R-SEQ-002'):
            content_hash = hashlib.sha256(normalize_hl7_for_hash(msg.raw).encode()).hexdigest()
            prev_seen = self.global_content_hashes.get(content_hash)
            if prev_seen is not None and (now - prev_seen) < self.replay_window_s:
                alerts.append(self._make_alert('R-SEQ-002', session, msg,
                                              f"Replay detected: content hash {content_hash[:16]} "
                                              f"within {self.replay_window_s:.1f}s window",
                                              AlertSeverity.HIGH))
            else:
                self.global_content_hashes[content_hash] = now
            session.seen_content_hashes.add(content_hash)
        
        # R-TIME-001: Timestamp regresivo (global: aplica entre sesiones)
        if self.rules.is_enabled('R-TIME-001') and msg.timestamp:
            ok, reason = validate_timestamp_regression(msg.timestamp, self.global_last_timestamp)
            if not ok:
                alerts.append(self._make_alert('R-TIME-001', session, msg, reason, AlertSeverity.MEDIUM))
        
        # R-TIME-002: Frecuencia fuera de baseline (global: cubre ráfagas y
        # reconexiones repetidas, no solo dentro de una sesión TCP)
        if self.rules.is_enabled('R-TIME-002') and self.global_last_message_time > 0:
            interval = now - self.global_last_message_time
            ok, reason = validate_frequency(interval, self.baseline)
            if not ok:
                alerts.append(self._make_alert('R-TIME-002', session, msg, reason, AlertSeverity.MEDIUM))
        
        # R-OBX-001/002/003: Validaciones OBX (ya en obx_validation)
        for rule_id in ['R-OBX-001', 'R-OBX-002', 'R-OBX-003']:
            if rule_id in obx_validation.rule_violations:
                sev = AlertSeverity.HIGH if rule_id in ['R-OBX-001', 'R-OBX-003'] else AlertSeverity.MEDIUM
                alerts.append(self._make_alert(rule_id, session, msg, 
                                              obx_validation.errors[0] if obx_validation.errors else "OBX violation", sev))
        
        # R-STATE-001: Transición estado no permitida + coherencia estado/perfil
        if self.rules.is_enabled('R-STATE-001'):
            new_state = self._infer_state(msg)
            # Enmienda E2: un mensaje sin OBX de estado (202886) no aporta
            # información de estado; no se trata como transición.
            if new_state not in self.UNKNOWN_STATES:
                # Coherencia: el estado declarado debe traer los OBX que el
                # equipo real siempre envía en ese estado (fsm_states del baseline).
                missing = self._missing_required_obx(new_state, msg)
                if missing:
                    alerts.append(self._make_alert(
                        'R-STATE-001', session, msg,
                        f"R-STATE-001: Inconsistent state {new_state}: "
                        f"missing required OBX {','.join(missing)}",
                        AlertSeverity.HIGH))
                if new_state != session.current_state:
                    ok, reason = validate_state_transition(
                        session.current_state, new_state, self.baseline.state_transitions
                    )
                    if not ok:
                        alerts.append(self._make_alert('R-STATE-001', session, msg, reason, AlertSeverity.HIGH))
                    session.current_state = new_state

        return alerts

    # Enmienda E2 (2026-10-19): valores OBSERVADOS de OBX-5 para
    # 202886^MDC_EVT_STAT_DEV en las capturas reales (25-08 y 27-08).
    # OBX-5 llega como "codigo^NOMBRE^MDC": el primer componente es numérico,
    # por eso la versión anterior (buscar 'STANDBY' en el componente 0)
    # devolvía siempre SESION_ESTABLECIDA_UNKNOWN (158/158 mensajes reales).
    STATE_BY_CODE = {
        '202836': "SESION_ESTABLECIDA_STANDBY",   # MDC_EVT_STAT_STANDBY (OBSERVADO)
        '202902': "SESION_ESTABLECIDA_RUNNING",   # MDC_EVT_STAT_RUNNING (OBSERVADO)
    }
    UNKNOWN_STATES = ("UNKNOWN", "SESION_ESTABLECIDA_UNKNOWN")

    def _infer_state(self, msg: HL7Message) -> str:
        """Infiere estado FSM desde el OBX 202886 (MDC_EVT_STAT_DEV)."""
        if not msg.obx_segments:
            return "UNKNOWN"

        for obx in msg.obx_segments:
            if len(obx.fields) > 5 and obx.fields[3].components:
                if obx.fields[3].components[0] != '202886':
                    continue
                comps = obx.fields[5].components or []
                code = comps[0] if comps else ""
                name = comps[1] if len(comps) > 1 else ""
                if code in self.STATE_BY_CODE:
                    return self.STATE_BY_CODE[code]
                # Respaldo por nombre (intención original del código): cubre
                # plantillas sintéticas con otro código numérico.
                if 'STANDBY' in name:
                    return "SESION_ESTABLECIDA_STANDBY"
                if 'RUNNING' in name or 'VENT' in name:
                    return "SESION_ESTABLECIDA_RUNNING"
        return "SESION_ESTABLECIDA_UNKNOWN"

    def _missing_required_obx(self, state: str, msg: HL7Message) -> List[str]:
        """OBX-3 obligatorios del estado (baseline fsm_states) ausentes en el mensaje."""
        info = self.baseline.get_fsm_state_info(state) or {}
        required = [str(c) for c in info.get('required_obx_codes', [])]
        if not required:
            return []
        present = {obx.fields[3].components[0]
                   for obx in msg.obx_segments
                   if len(obx.fields) > 3 and obx.fields[3].components}
        return [c for c in required if c not in present]
    
    def _update_session_state(self, session: SessionState, msg: HL7Message, raw_bytes: bytes):
        session.message_count += 1
        if msg.message_control_id:
            session.seen_control_ids.add(msg.message_control_id)
        if msg.timestamp:
            session.last_timestamp = msg.timestamp
            self.global_last_timestamp = msg.timestamp
        session.last_message_time = time.time()
        self.global_last_message_time = session.last_message_time
        session.logical_identity = (msg.sending_app, msg.sending_facility)
        # E3: llegó un mensaje -> termina cualquier episodio de silencio
        self._silence_alerted = False
        self._last_session_id = session.session_id
        self._last_source = f"{session.source_ip}:{session.source_port}"

    def check_silence(self, now: Optional[float] = None) -> Optional[Alert]:
        """
        Enmienda E3 (2026-10-19) - vigilante de silencio (R-TIME-002).
        R-TIME-002 solo evaluaba el intervalo al llegar el SIGUIENTE mensaje,
        así que un canal caído o suprimido sin recuperación nunca alertaba
        (verificado: 60 s sin mensajes -> 0 alertas). Este chequeo, llamado
        periódicamente por el receptor, alerta una sola vez por episodio cuando
        el silencio supera el mismo límite superior de R-TIME-002
        (p95 * 1.5 = 15 s con la baseline STANDBY). No se arma antes del primer
        mensaje (el WATO aún no ha conectado: estado SIN_GATEWAY).
        """
        if not self.rules.is_enabled('R-TIME-002'):
            return None
        with self._lock:
            if self.global_last_message_time <= 0 or self._silence_alerted:
                return None
            now = time.time() if now is None else now
            _, upper = self.baseline.get_interval_bounds()
            silence = now - self.global_last_message_time
            if silence <= upper:
                return None
            self._silence_alerted = True
            self._alert_counter += 1
            reason = (f"R-TIME-002: Silence: no message for {silence:.1f}s "
                      f"> {upper:.3f}s (canal caído o suprimido)")
            return Alert(
                alert_id=f"ALERT-{self._alert_counter:06d}-{int(now*1000)}",
                rule_id='R-TIME-002',
                timestamp_utc=datetime.fromtimestamp(now, timezone.utc).isoformat(),
                session_id=self._last_session_id or "N/A",
                source=self._last_source or "N/A",
                message_control_id="N/A",
                severity=AlertSeverity.MEDIUM,
                reason=reason,
                evidence_hash=hashlib.sha256(reason.encode()).hexdigest(),
                experimental_state="SILENCE",
                label=AlertLabel.ANOMALO,
                synthetic=False
            )
    
    def _make_alert(self, rule_id: str, session: SessionState, msg: HL7Message,
                    reason: str, severity: AlertSeverity) -> Alert:
        self._alert_counter += 1
        alert_id = f"ALERT-{self._alert_counter:06d}-{int(time.time()*1000)}"
        
        # Hash de evidencia (raw bytes del mensaje)
        evidence_hash = hashlib.sha256(msg.raw.encode('utf-8', errors='replace')).hexdigest()
        
        return Alert(
            alert_id=alert_id,
            rule_id=rule_id,
            timestamp_utc=datetime.now(timezone.utc).isoformat(),
            session_id=session.session_id,
            source=f"{session.source_ip}:{session.source_port}",
            message_control_id=msg.message_control_id or "N/A",
            severity=severity,
            reason=reason,
            evidence_hash=evidence_hash,
            experimental_state=session.current_state,
            label=AlertLabel.ANOMALO,
            synthetic=False
        )
    
    def get_session_stats(self, session_id: str) -> Optional[Dict]:
        """Obtiene estadísticas de una sesión."""
        session = self.sessions.get(session_id)
        if not session:
            return None
        return {
            'session_id': session.session_id,
            'source': f"{session.source_ip}:{session.source_port}",
            'messages': session.message_count,
            'unique_control_ids': len(session.seen_control_ids),
            'unique_content_hashes': len(session.seen_content_hashes),
            'current_state': session.current_state,
            'logical_identity': session.logical_identity
        }