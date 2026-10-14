#!/usr/bin/env python3
"""
evidence/writer.py - Escritor de evidencia forense con rotación y hashes
Preserva bytes originales, anonimiza antes de almacenar derivados.
Compatible con requisitos de cadena de custodia.
"""

import os
import json
import hashlib
import threading
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional, Any, BinaryIO
from dataclasses import dataclass, asdict

from ..alerting.json_logger import Alert

logger = logging.getLogger(__name__)


@dataclass
class SessionFiles:
    """Archivos abiertos para una sesión."""
    raw: Optional[BinaryIO] = None
    hl7: Optional[BinaryIO] = None
    log: Optional[BinaryIO] = None
    alerts: Optional[BinaryIO] = None
    raw_path: str = ""
    hl7_path: str = ""
    log_path: str = ""
    alerts_path: str = ""
    bytes_written: int = 0
    rotated: bool = False


class EvidenceWriter:
    """
    Escritor de evidencia con:
    - Rotación por tamaño (configurable)
    - Hash SHA-256 de cada archivo
    - Timestamps UTC monotónicos
    - Anonimización de campos sensibles
    - Preservación de bytes originales (raw)
    """
    
    def __init__(self, base_dir: str, settings):
        self.base_dir = Path(base_dir)
        self.settings = settings
        self.max_size_mb = settings.evidence.rotate_logs_mb
        self.max_files = settings.evidence.max_log_files
        self.preserve_raw = settings.evidence.preserve_raw_bytes
        self.hash_algorithm = settings.evidence.hash_algorithm
        
        self.sessions: Dict[str, SessionFiles] = {}
        self._lock = threading.Lock()
        self.session_metadata: Dict[str, Dict] = {}
        
        self.base_dir.mkdir(parents=True, exist_ok=True)
        (self.base_dir / "raw").mkdir(exist_ok=True)
        (self.base_dir / "hl7").mkdir(exist_ok=True)
        (self.base_dir / "logs").mkdir(exist_ok=True)
        (self.base_dir / "alerts").mkdir(exist_ok=True)

    def open_session(self, session_id: str, src_ip: str, src_port: int,
                     dst_ip: str, dst_port: int):
        """Abre archivos para nueva sesión."""
        with self._lock:
            safe_id = session_id.replace(':', '_').replace('.', '_')
            
            raw_path = self.base_dir / "raw" / f"raw_{safe_id}.bin"
            hl7_path = self.base_dir / "hl7" / f"messages_{safe_id}.hl7"
            log_path = self.base_dir / "logs" / f"session_{safe_id}.log"
            alerts_path = self.base_dir / "alerts" / f"alerts_{safe_id}.jsonl"
            
            # Rotar si existe y supera tamaño
            for p in [raw_path, hl7_path, log_path, alerts_path]:
                self._rotate_if_needed(p)
            
            sf = SessionFiles(
                raw=open(raw_path, 'ab') if self.preserve_raw else None,
                hl7=open(hl7_path, 'ab'),
                log=open(log_path, 'ab'),
                alerts=open(alerts_path, 'ab'),
                raw_path=str(raw_path),
                hl7_path=str(hl7_path),
                log_path=str(log_path),
                alerts_path=str(alerts_path)
            )
            self.sessions[session_id] = sf
            
            # Metadata de sesión
            self.session_metadata[session_id] = {
                'session_id': session_id,
                'src_ip': src_ip,
                'src_port': src_port,
                'dst_ip': dst_ip,
                'dst_port': dst_port,
                'start_time': datetime.now(timezone.utc).isoformat(),
                'files': {
                    'raw': str(raw_path),
                    'hl7': str(hl7_path),
                    'log': str(log_path),
                    'alerts': str(alerts_path)
                }
            }
            
            self._write_log(session_id, "SESSION_OPEN", {
                'src_ip': src_ip, 'src_port': src_port,
                'dst_ip': dst_ip, 'dst_port': dst_port
            })

    def close_session(self, session_id: str):
        """Cierra archivos de sesión y genera hashes."""
        with self._lock:
            sf = self.sessions.pop(session_id, None)
            if not sf:
                return
            
            for f in [sf.raw, sf.hl7, sf.log, sf.alerts]:
                if f:
                    f.flush()
                    f.close()
            
            # Calcular hashes finales
            hashes = {}
            for name, path in [('raw', sf.raw_path), ('hl7', sf.hl7_path), 
                               ('log', sf.log_path), ('alerts', sf.alerts_path)]:
                if os.path.exists(path):
                    hashes[name] = self._compute_hash(path)
            
            meta = self.session_metadata.get(session_id, {})
            meta['end_time'] = datetime.now(timezone.utc).isoformat()
            meta['hashes'] = hashes
            meta['bytes_written'] = sf.bytes_written
            
            # Guardar metadata
            meta_path = self.base_dir / "logs" / f"meta_{session_id.replace(':', '_').replace('.', '_')}.json"
            with open(meta_path, 'w') as f:
                json.dump(meta, f, indent=2)
            
            logger.info(f"SESSION_CLOSED session_id={session_id} hashes={hashes}")

    def write_raw(self, session_id: str, data: bytes):
        """Escribe bytes crudos recibidos (sin modificar)."""
        with self._lock:
            sf = self.sessions.get(session_id)
            if sf and sf.raw:
                sf.raw.write(data)
                sf.raw.flush()
                sf.bytes_written += len(data)
                self._check_rotation(sf, 'raw')

    def write_hl7(self, session_id: str, msg_num: int, hl7_text: str, raw_bytes: bytes):
        """Escribe mensaje HL7 parseado con metadatos."""
        with self._lock:
            sf = self.sessions.get(session_id)
            if not sf or not sf.hl7:
                return
            
            timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            header = f"### {timestamp} | msg {msg_num} | {len(raw_bytes)} bytes\n"
            content = hl7_text.replace('\r', '\n').rstrip() + "\n\n"
            
            sf.hl7.write(header.encode('utf-8'))
            sf.hl7.write(content.encode('utf-8'))
            sf.hl7.flush()
            self._check_rotation(sf, 'hl7')

    def write_log(self, session_id: str, event_type: str, data: Dict[str, Any]):
        """Escribe entrada de log estructurada."""
        self._write_log(session_id, event_type, data)

    def _write_log(self, session_id: str, event_type: str, data: Dict[str, Any]):
        with self._lock:
            sf = self.sessions.get(session_id)
            if not sf or not sf.log:
                return
            
            timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            entry = {
                'timestamp': timestamp,
                'session_id': session_id,
                'event': event_type,
                'data': data
            }
            line = json.dumps(entry, ensure_ascii=False) + "\n"
            sf.log.write(line.encode('utf-8'))
            sf.log.flush()
            self._check_rotation(sf, 'log')

    def write_ack(self, session_id: str, control_id: str, ack_bytes: bytes):
        """Registra ACK enviado."""
        self._write_log(session_id, "ACK_SENT", {
            'control_id': control_id,
            'bytes': len(ack_bytes)
        })

    def write_error(self, session_id: str, error: str, context: bytes = b''):
        """Registra error de framing/parsing."""
        self._write_log(session_id, "ERROR", {
            'error': error,
            'context_bytes': len(context),
            'context_preview': context[:40].hex() if context else ''
        })

    def write_alert(self, session_id: str, alert: Alert):
        """Escribe alerta en formato JSONL."""
        with self._lock:
            sf = self.sessions.get(session_id)
            if not sf or not sf.alerts:
                return
            
            # Anonimizar antes de escribir si configurado
            alert_dict = asdict(alert)
            if self.settings.alerting.anonymize_before_alert:
                alert_dict = self._anonymize_alert(alert_dict)
            
            line = json.dumps(alert_dict, ensure_ascii=False) + "\n"
            sf.alerts.write(line.encode('utf-8'))
            sf.alerts.flush()
            self._check_rotation(sf, 'alerts')

    def _check_rotation(self, sf: SessionFiles, file_type: str):
        """Verifica y rota archivo si supera tamaño máximo."""
        path_map = {
            'raw': (sf.raw, sf.raw_path),
            'hl7': (sf.hl7, sf.hl7_path),
            'log': (sf.log, sf.log_path),
            'alerts': (sf.alerts, sf.alerts_path)
        }
        f, path = path_map.get(file_type, (None, ""))
        if f and os.path.exists(path):
            size_mb = os.path.getsize(path) / (1024 * 1024)
            if size_mb >= self.max_size_mb:
                self._rotate_file(sf, file_type)

    def _rotate_file(self, sf: SessionFiles, file_type: str):
        """Rota un archivo específico."""
        path_map = {
            'raw': ('raw', 'raw_path'),
            'hl7': ('hl7', 'hl7_path'),
            'log': ('log', 'log_path'),
            'alerts': ('alerts', 'alerts_path')
        }
        attr, path_attr = path_map[file_type]
        old_f = getattr(sf, attr)
        old_path = getattr(sf, path_attr)
        
        if old_f:
            old_f.close()
        
        # Renombrar con timestamp
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        base, ext = os.path.splitext(old_path)
        new_path = f"{base}_{timestamp}{ext}"
        os.rename(old_path, new_path)
        
        # Crear nuevo archivo
        new_f = open(old_path, 'ab')
        setattr(sf, attr, new_f)
        
        # Limpiar archivos antiguos
        self._cleanup_old_files(base, ext)
        
        sf.rotated = True
        logger.info(f"ROTATED session_file={file_type} old={new_path} new={old_path}")

    def _rotate_if_needed(self, path: Path):
        """Rota archivo existente al abrir nueva sesión."""
        if path.exists():
            size_mb = path.stat().st_size / (1024 * 1024)
            if size_mb >= self.max_size_mb:
                timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
                new_path = path.with_name(f"{path.stem}_{timestamp}{path.suffix}")
                path.rename(new_path)
                self._cleanup_old_files(path.stem, path.suffix)

    def _cleanup_old_files(self, base: str, ext: str):
        """Elimina archivos rotados antiguos superando max_files."""
        dir_path = Path(base).parent
        pattern = f"{Path(base).name}_*{ext}"
        files = sorted(dir_path.glob(pattern), key=lambda p: p.stat().st_mtime)
        while len(files) >= self.max_files:
            oldest = files.pop(0)
            oldest.unlink()
            logger.debug(f"CLEANUP removed old rotated file: {oldest}")

    def _compute_hash(self, filepath: str) -> str:
        """Calcula SHA-256 de archivo."""
        h = hashlib.sha256()
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                h.update(chunk)
        return h.hexdigest()

    def _anonymize_alert(self, alert_dict: Dict) -> Dict:
        """Anonimiza campos sensibles en alerta."""
        # Claves que pueden contener PHI/PII
        sensitive_keys = ['message_control_id', 'source', 'evidence']
        for key in sensitive_keys:
            if key in alert_dict and alert_dict[key]:
                val = str(alert_dict[key])
                # Hash consistente pero irreversible
                alert_dict[key] = f"ANON_{hashlib.sha256(val.encode()).hexdigest()[:12]}"
        return alert_dict

    def get_session_hashes(self, session_id: str) -> Dict[str, str]:
        """Obtiene hashes de archivos de sesión."""
        sf = self.sessions.get(session_id)
        if not sf:
            return {}
        hashes = {}
        for name, path in [('raw', sf.raw_path), ('hl7', sf.hl7_path), 
                           ('log', sf.log_path), ('alerts', sf.alerts_path)]:
            if os.path.exists(path):
                hashes[name] = self._compute_hash(path)
        return hashes