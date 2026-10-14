#!/usr/bin/env python3
"""
mllp/server.py - Servidor MLLP/TCP para recepción HL7 v2.x
Refactor modular de ackdummy: separación de framing, parsing, detección, evidencia.
Compatible con evidencia observada WATO EX-35 (STANDBY 25-08-2026).
"""

import socket
import socketserver
import threading
import logging
import time
from datetime import datetime, timezone
from typing import Optional, Callable, Dict, Any
from dataclasses import dataclass, field

from .framing import MLLPFramer, MLLPFrame, FrameResult, SB, EOM, validate_mllp_frame
from ..hl7.parser import parse_hl7_message, HL7Message
from ..hl7.validator import validate_hl7_structure
from ..evidence.writer import EvidenceWriter
from ..detection.engine import DetectionEngine
from ..alerting.json_logger import AlertLogger
from ..config.settings import Settings

logger = logging.getLogger(__name__)


@dataclass
class SessionInfo:
    """Información de una sesión TCP/MLLP."""
    session_id: str
    client_ip: str
    client_port: int
    start_time: float
    last_activity: float
    message_count: int = 0
    bytes_received: int = 0
    ack_sent_count: int = 0
    errors: list = field(default_factory=list)


class MLLPRequestHandler(socketserver.BaseRequestHandler):
    """Manejador de conexión MLLP por hilo."""

    def __init__(self, request, client_address, server):
        self.session_info: Optional[SessionInfo] = None
        self.framer = MLLPFramer(
            encoding=server.settings.mllp.encoding,
            max_message_size=server.settings.mllp.max_message_size,
            max_buffer_size=server.settings.mllp.max_buffer_size,
            strict=server.settings.mllp.strict
        )
        self.evidence_writer = server.evidence_writer
        self.detection_engine = server.detection_engine
        self.alert_logger = server.alert_logger
        self.settings = server.settings
        self.send_ack = server.send_ack
        self._lock = threading.Lock()
        super().__init__(request, client_address, server)

    def setup(self):
        ip, port = self.client_address
        self.session_info = SessionInfo(
            session_id=f"{ip}:{port}:{int(time.time()*1000)}",
            client_ip=ip,
            client_port=port,
            start_time=time.monotonic(),
            last_activity=time.monotonic()
        )
        self.server.sessions[self.session_info.session_id] = self.session_info
        
        self.evidence_writer.open_session(
            self.session_info.session_id,
            ip, port,
            self.settings.network.server_ip,
            self.settings.network.server_port
        )
        
        logger.info(f"SESSION_START session_id={self.session_info.session_id} "
                    f"client={ip}:{port}")

    def handle(self):
        self.request.settimeout(self.settings.network.timeout)
        
        while True:
            try:
                data = self.request.recv(8192)
            except socket.timeout:
                self._log_timeout()
                continue
            except ConnectionResetError:
                logger.info(f"SESSION_RST session_id={self.session_info.session_id}")
                break
            except OSError as e:
                logger.error(f"SESSION_ERROR session_id={self.session_info.session_id} error={e}")
                break
            
            if not data:
                break
            
            self._process_data(data)

    def _process_data(self, data: bytes):
        with self._lock:
            self.session_info.bytes_received += len(data)
            self.session_info.last_activity = time.monotonic()
            
            self.evidence_writer.write_raw(self.session_info.session_id, data)
            
            result: FrameResult = self.framer.feed(data)
            
            for frame in result.frames:
                self._handle_frame(frame)
            
            for error in result.errors:
                self._handle_framing_error(error)

    def _handle_frame(self, frame: MLLPFrame):
        self.session_info.message_count += 1
        msg_num = self.session_info.message_count
        
        try:
            hl7_text = frame.decode()
        except UnicodeDecodeError as e:
            logger.warning(f"DECODE_ERROR session_id={self.session_info.session_id} "
                          f"msg={msg_num} error={e}")
            self.evidence_writer.write_error(self.session_info.session_id, 
                                           f"decode_error: {e}", frame.raw_bytes)
            return
        
        parsed = parse_hl7_message(hl7_text)
        
        self.evidence_writer.write_hl7(self.session_info.session_id, msg_num, 
                                      hl7_text, frame.raw_bytes)
        
        logger.info(f"MSG_RECV session_id={self.session_info.session_id} "
                    f"msg={msg_num} type={parsed.message_type} "
                    f"ctrl_id={parsed.message_control_id} "
                    f"segments={parsed.segment_sequence} "
                    f"size={len(frame.content)}")
        
        validation_result = validate_hl7_structure(parsed, self.settings.hl7)
        
        detection_result = self.detection_engine.process_message(
            session_id=self.session_info.session_id,
            source_ip=self.session_info.client_ip,
            source_port=self.session_info.client_port,
            parsed_message=parsed,
            raw_bytes=frame.content,
            mllp_frame=frame.raw_bytes
        )
        
        for alert in detection_result.alerts:
            self.alert_logger.log_alert(alert)
            self.evidence_writer.write_alert(self.session_info.session_id, alert)
        
        if self.send_ack and parsed.message_control_id:
            ack_bytes = self._build_ack(parsed, hl7_text)
            try:
                self.request.sendall(ack_bytes)
                self.session_info.ack_sent_count += 1
                logger.debug(f"ACK_SENT session_id={self.session_info.session_id} "
                            f"msg={msg_num} ctrl_id={parsed.message_control_id} "
                            f"bytes={len(ack_bytes)}")
                self.evidence_writer.write_ack(self.session_info.session_id, 
                                              parsed.message_control_id, ack_bytes)
            except OSError as e:
                logger.error(f"ACK_SEND_FAILED session_id={self.session_info.session_id} "
                            f"msg={msg_num} error={e}")

    def _build_ack(self, parsed: HL7Message, original_hl7: str) -> bytes:
        from ..mllp.ack import build_experimental_ack
        return build_experimental_ack(original_hl7, encoding=self.settings.mllp.encoding)

    def _handle_framing_error(self, error: str):
        logger.warning(f"FRAMING_ERROR session_id={self.session_info.session_id} error={error}")
        self.session_info.errors.append(error)
        self.evidence_writer.write_error(self.session_info.session_id, error, b'')

    def _log_timeout(self):
        elapsed = time.monotonic() - self.session_info.last_activity
        logger.debug(f"SESSION_TIMEOUT session_id={self.session_info.session_id} "
                    f"elapsed={elapsed:.1f}s")

    def finish(self):
        if self.session_info:
            duration = time.monotonic() - self.session_info.start_time
            logger.info(f"SESSION_END session_id={self.session_info.session_id} "
                        f"duration={duration:.1f}s messages={self.session_info.message_count} "
                        f"bytes={self.session_info.bytes_received} "
                        f"acks_sent={self.session_info.ack_sent_count} "
                        f"errors={len(self.session_info.errors)}")
            
            self.evidence_writer.close_session(self.session_info.session_id)
            self.server.sessions.pop(self.session_info.session_id, None)


class MLLPServer(socketserver.ThreadingTCPServer):
    """Servidor MLLP multi-hilo con componentes modulares."""
    
    allow_reuse_address = True
    daemon_threads = True
    
    def __init__(self, server_address, settings: Settings, 
                 evidence_writer: EvidenceWriter,
                 detection_engine: DetectionEngine,
                 alert_logger: AlertLogger,
                 send_ack: bool = True):
        self.settings = settings
        self.evidence_writer = evidence_writer
        self.detection_engine = detection_engine
        self.alert_logger = alert_logger
        self.send_ack = send_ack
        self.sessions: Dict[str, SessionInfo] = {}
        super().__init__(server_address, MLLPRequestHandler)

    def get_session_stats(self) -> Dict[str, Any]:
        return {
            'active_sessions': len(self.sessions),
            'sessions': {sid: {
                'client_ip': s.client_ip,
                'client_port': s.client_port,
                'duration': time.monotonic() - s.start_time,
                'messages': s.message_count,
                'bytes': s.bytes_received,
                'acks_sent': s.ack_sent_count,
                'errors': len(s.errors)
            } for sid, s in self.sessions.items()}
        }


def run_server(settings: Settings, evidence_writer: EvidenceWriter,
               detection_engine: DetectionEngine, alert_logger: AlertLogger,
               send_ack: bool = True) -> MLLPServer:
    """Factory para crear y configurar el servidor."""
    server = MLLPServer(
        (settings.network.bind_host, settings.network.bind_port),
        settings, evidence_writer, detection_engine, alert_logger, send_ack
    )
    return server