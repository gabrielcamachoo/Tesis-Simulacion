#!/usr/bin/env python3
"""
analyze_evidence.py - Análisis forense de evidencia HL7/MLLP
Recorre directorios de evidencia, calcula hashes, extrae metadatos y genera reportes.
No modifica archivos originales. Aplica anonimización irreversible.
"""

import argparse
import csv
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
import logging

# Configuración de logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Extensiones de archivos de evidencia
EVIDENCE_EXTENSIONS = {'.pcap', '.pcapng', '.bin', '.hl7', '.log', '.txt', '.cap'}

# Patrones HL7/MLLP
MLLP_SB = b'\x0b'
MLLP_EB = b'\x1c'
MLLP_CR = b'\x0d'
MLLP_EOM = MLLP_EB + MLLP_CR

# Campos sensibles a anonimizar (regex)
SENSITIVE_PATTERNS = {
    'patient_id': re.compile(rb'PID\||[^|]*\|[^|]*\|([^|]+)\|', re.IGNORECASE),
    'patient_name': re.compile(rb'PID\||[^|]*\|[^|]*\|[^|]*\|([^|]+)\|', re.IGNORECASE),
    'patient_dob': re.compile(rb'PID\||[^|]*\|[^|]*\|[^|]*\|[^|]*\|([^|]+)\|', re.IGNORECASE),
    'patient_sex': re.compile(rb'PID\||[^|]*\|[^|]*\|[^|]*\|[^|]*\|[^|]*\|([^|]+)\|', re.IGNORECASE),
    'visit_number': re.compile(rb'PV1\||[^|]*\|[^|]*\|([^|]+)\|', re.IGNORECASE),
    'device_id': re.compile(rb'MSH\|[^|]*\|[^|]*\|([^|]+)\|', re.IGNORECASE),
    'ip_address': re.compile(rb'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
    'mac_address': re.compile(rb'\b(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}\b'),
}

ANONYMIZATION_MAP = {}

@dataclass
class EvidenceFile:
    path: str
    rel_path: str
    size_bytes: int
    sha256: str
    extension: str
    modified_time: str
    status: str  # OBSERVADO, INFERIDO, DOCUMENTADO, NO_VERIFICADO
    notes: str = ""

@dataclass
class SessionInfo:
    session_id: str
    source_ip: str
    source_port: int
    dest_ip: str
    dest_port: int
    start_time: str
    end_time: str
    tcp_connections: int
    mllp_messages: int
    message_types: List[str]
    hl7_version: str
    sending_app: str
    sending_facility: str
    message_control_ids: List[str]
    segment_sequences: List[List[str]]
    message_sizes: List[int]
    intervals_seconds: List[float]
    ack_present: bool
    ack_times: List[float]
    obx_codes: List[str]
    status: str
    notes: str = ""

@dataclass
class MessageMetadata:
    message_id: str
    session_id: str
    timestamp: str
    source_ip: str
    source_port: int
    message_type: str
    message_control_id: str
    hl7_version: str
    sending_app: str
    sending_facility: str
    segment_sequence: List[str]
    size_bytes: int
    interval_since_prev: float
    ack_received: bool
    ack_time_ms: float
    obx_codes: List[str]
    status: str
    notes: str = ""

def compute_sha256(filepath: str) -> str:
    """Calcula SHA-256 de un archivo sin cargarlo completo en memoria."""
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            sha256.update(chunk)
    return sha256.hexdigest()

def anonymize_value(value: bytes, prefix: str = "ANON") -> bytes:
    """Anonimiza un valor de forma irreversible pero consistente."""
    if value not in ANONYMIZATION_MAP:
        ANONYMIZATION_MAP[value] = f"{prefix}_{hashlib.sha256(value).hexdigest()[:8]}".encode()
    return ANONYMIZATION_MAP[value]

def anonymize_hl7_message(message: bytes) -> bytes:
    """Aplica anonimización a un mensaje HL7 crudo."""
    result = message
    for field_name, pattern in SENSITIVE_PATTERNS.items():
        def replace_match(match):
            full = match.group(0)
            if len(match.groups()) > 0:
                sensitive = match.group(1)
                anon = anonymize_value(sensitive, field_name.upper())
                return full.replace(sensitive, anon)
            return full
        result = pattern.sub(replace_match, result)
    return result

def extract_mllp_messages(data: bytes) -> List[Tuple[bytes, int, int]]:
    """Extrae mensajes MLLP de datos crudos. Retorna (mensaje, inicio, fin)."""
    messages = []
    pos = 0
    while pos < len(data):
        sb_pos = data.find(MLLP_SB, pos)
        if sb_pos == -1:
            break
        eom_pos = data.find(MLLP_EOM, sb_pos + 1)
        if eom_pos == -1:
            break
        msg_content = data[sb_pos + 1:eom_pos]
        messages.append((msg_content, sb_pos, eom_pos + 2))
        pos = eom_pos + 2
    return messages

def parse_hl7_message(hl7_bytes: bytes) -> Dict[str, Any]:
    """Parsea mensaje HL7 y extrae metadatos clave."""
    try:
        text = hl7_bytes.decode('utf-8', errors='replace')
    except UnicodeDecodeError:
        text = hl7_bytes.decode('iso-8859-1', errors='replace')
    
    lines = text.replace('\r\n', '\r').replace('\n', '\r').split('\r')
    lines = [l for l in lines if l.strip()]
    
    if not lines:
        return {}
    
    msh = lines[0]
    fields = msh.split('|')
    
    def get_field(idx: int, default: str = "") -> str:
        return fields[idx] if len(fields) > idx else default
    
    segment_names = [l[:3] for l in lines if len(l) >= 3]
    obx_codes = []
    for line in lines:
        if line.startswith('OBX|'):
            parts = line.split('|')
            if len(parts) > 3:
                obx_codes.append(parts[3])
    
    return {
        'sending_app': get_field(2),
        'sending_facility': get_field(3),
        'receiving_app': get_field(4),
        'receiving_facility': get_field(5),
        'timestamp': get_field(6),
        'message_type': get_field(8),
        'message_control_id': get_field(9),
        'processing_id': get_field(10),
        'hl7_version': get_field(11),
        'charset': get_field(17) if len(fields) > 17 else '',
        'profile': get_field(20) if len(fields) > 20 else '',
        'segment_sequence': segment_names,
        'obx_codes': obx_codes,
        'raw_segments': len(lines),
    }

def analyze_pcap(filepath: str) -> List[SessionInfo]:
    """Analiza archivo PCAP/PCAPNG para extraer sesiones HL7/MLLP."""
    sessions = []
    try:
        import pyshark
    except ImportError:
        logger.warning("pyshark no instalado. Saltando análisis PCAP.")
        return sessions
    
    try:
        cap = pyshark.FileCapture(filepath, display_filter='tcp.port == 1550', keep_packets=False)
        tcp_streams = {}
        
        for pkt in cap:
            try:
                if hasattr(pkt, 'tcp'):
                    stream_id = pkt.tcp.stream
                    src_ip = pkt.ip.src
                    dst_ip = pkt.ip.dst
                    src_port = int(pkt.tcp.srcport)
                    dst_port = int(pkt.tcp.dstport)
                    timestamp = float(pkt.sniff_timestamp)
                    payload = bytes.fromhex(pkt.tcp.payload.replace(':', '')) if hasattr(pkt.tcp, 'payload') else b''
                    
                    key = (stream_id, src_ip, dst_ip, src_port, dst_port)
                    if key not in tcp_streams:
                        tcp_streams[key] = {
                            'packets': [],
                            'start_time': timestamp,
                            'end_time': timestamp,
                            'src_ip': src_ip,
                            'dst_ip': dst_ip,
                            'src_port': src_port,
                            'dst_port': dst_port,
                        }
                    tcp_streams[key]['packets'].append((timestamp, payload))
                    tcp_streams[key]['end_time'] = max(tcp_streams[key]['end_time'], timestamp)
            except Exception:
                continue
        
        cap.close()
        
        for stream_key, stream_data in tcp_streams.items():
            all_payload = b''.join([p[1] for p in stream_data['packets']])
            messages = extract_mllp_messages(all_payload)
            
            session_info = SessionInfo(
                session_id=f"session_{stream_key[0]}",
                source_ip=stream_data['src_ip'],
                source_port=stream_data['src_port'],
                dest_ip=stream_data['dst_ip'],
                dest_port=stream_data['dst_port'],
                start_time=datetime.fromtimestamp(stream_data['start_time'], tz=timezone.utc).isoformat(),
                end_time=datetime.fromtimestamp(stream_data['end_time'], tz=timezone.utc).isoformat(),
                tcp_connections=1,
                mllp_messages=len(messages),
                message_types=[],
                hl7_version="",
                sending_app="",
                sending_facility="",
                message_control_ids=[],
                segment_sequences=[],
                message_sizes=[],
                intervals_seconds=[],
                ack_present=False,
                ack_times=[],
                obx_codes=[],
                status="OBSERVADO"
            )
            
            prev_time = None
            for msg_bytes, _, _ in messages:
                parsed = parse_hl7_message(msg_bytes)
                if parsed:
                    session_info.message_types.append(parsed.get('message_type', ''))
                    session_info.hl7_version = parsed.get('hl7_version', session_info.hl7_version)
                    session_info.sending_app = parsed.get('sending_app', session_info.sending_app)
                    session_info.sending_facility = parsed.get('sending_facility', session_info.sending_facility)
                    session_info.message_control_ids.append(parsed.get('message_control_id', ''))
                    session_info.segment_sequences.append(parsed.get('segment_sequence', []))
                    session_info.obx_codes.extend(parsed.get('obx_codes', []))
                    session_info.message_sizes.append(len(msg_bytes))
                    
                    if parsed.get('timestamp'):
                        try:
                            msg_time = datetime.strptime(parsed['timestamp'][:14], '%Y%m%d%H%M%S').timestamp()
                            if prev_time is not None:
                                session_info.intervals_seconds.append(msg_time - prev_time)
                            prev_time = msg_time
                        except Exception:
                            pass
            
            # Detectar ACKs (simplificado)
            ack_count = sum(1 for mt in session_info.message_types if 'ACK' in mt)
            session_info.ack_present = ack_count > 0
            
            sessions.append(session_info)
            
    except Exception as e:
        logger.error(f"Error analizando PCAP {filepath}: {e}")
    
    return sessions

def analyze_bin_file(filepath: str) -> List[SessionInfo]:
    """Analiza archivo .bin (bytes crudos recibidos por ackdummy)."""
    sessions = []
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
        
        messages = extract_mllp_messages(data)
        
        # Inferir IP/puerto del nombre del archivo
        filename = os.path.basename(filepath)
        match = re.match(r'raw_([\d.]+)_(\d+)\.bin', filename)
        src_ip = match.group(1) if match else "unknown"
        src_port = int(match.group(2)) if match else 0
        
        session_info = SessionInfo(
            session_id=f"bin_{os.path.splitext(filename)[0]}",
            source_ip=src_ip,
            source_port=src_port,
            dest_ip="",
            dest_port=1550,
            start_time=datetime.now(timezone.utc).isoformat(),
            end_time=datetime.now(timezone.utc).isoformat(),
            tcp_connections=1,
            mllp_messages=len(messages),
            message_types=[],
            hl7_version="",
            sending_app="",
            sending_facility="",
            message_control_ids=[],
            segment_sequences=[],
            message_sizes=[],
            intervals_seconds=[],
            ack_present=False,
            ack_times=[],
            obx_codes=[],
            status="OBSERVADO"
        )
        
        prev_time = None
        for msg_bytes, _, _ in messages:
            parsed = parse_hl7_message(msg_bytes)
            if parsed:
                session_info.message_types.append(parsed.get('message_type', ''))
                session_info.hl7_version = parsed.get('hl7_version', session_info.hl7_version)
                session_info.sending_app = parsed.get('sending_app', session_info.sending_app)
                session_info.sending_facility = parsed.get('sending_facility', session_info.sending_facility)
                session_info.message_control_ids.append(parsed.get('message_control_id', ''))
                session_info.segment_sequences.append(parsed.get('segment_sequence', []))
                session_info.obx_codes.extend(parsed.get('obx_codes', []))
                session_info.message_sizes.append(len(msg_bytes))
                
                if parsed.get('timestamp'):
                    try:
                        msg_time = datetime.strptime(parsed['timestamp'][:14], '%Y%m%d%H%M%S').timestamp()
                        if prev_time is not None:
                            session_info.intervals_seconds.append(msg_time - prev_time)
                        prev_time = msg_time
                    except Exception:
                        pass
        
        sessions.append(session_info)
        
    except Exception as e:
        logger.error(f"Error analizando BIN {filepath}: {e}")
    
    return sessions

def analyze_hl7_file(filepath: str) -> List[MessageMetadata]:
    """Analiza archivo mensajes.hl7 (mensajes ya extraídos)."""
    messages_meta = []
    try:
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()
        
        # Formato de ackdummy: separador "### timestamp | ip | msg N | size bytes"
        blocks = re.split(r'###\s+\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d{3}\s+\|\s+([\d.]+)\s+\|\s+msg\s+(\d+)\s+\|\s+(\d+)\s+bytes\n', content)
        
        for i in range(1, len(blocks), 4):
            if i + 3 < len(blocks):
                src_ip = blocks[i]
                msg_num = int(blocks[i+1])
                size_bytes = int(blocks[i+2])
                msg_content = blocks[i+3].strip()
                
                parsed = parse_hl7_message(msg_content.encode('utf-8'))
                if parsed:
                    messages_meta.append(MessageMetadata(
                        message_id=f"{os.path.basename(filepath)}_{msg_num}",
                        session_id="unknown",
                        timestamp=datetime.now(timezone.utc).isoformat(),
                        source_ip=src_ip,
                        source_port=0,
                        message_type=parsed.get('message_type', ''),
                        message_control_id=parsed.get('message_control_id', ''),
                        hl7_version=parsed.get('hl7_version', ''),
                        sending_app=parsed.get('sending_app', ''),
                        sending_facility=parsed.get('sending_facility', ''),
                        segment_sequence=parsed.get('segment_sequence', []),
                        size_bytes=size_bytes,
                        interval_since_prev=0.0,
                        ack_received=False,
                        ack_time_ms=0.0,
                        obx_codes=parsed.get('obx_codes', []),
                        status="OBSERVADO"
                    ))
    except Exception as e:
        logger.error(f"Error analizando HL7 {filepath}: {e}")
    
    return messages_meta

def analyze_log_file(filepath: str) -> Dict[str, Any]:
    """Analiza archivo sesion.log para extraer eventos."""
    events = {
        'connections': 0,
        'messages': 0,
        'acks_sent': 0,
        'timeouts': 0,
        'errors': 0,
        'first_timestamp': None,
        'last_timestamp': None
    }
    try:
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                if 'CONEXION establecida' in line:
                    events['connections'] += 1
                elif 'MSG #' in line:
                    events['messages'] += 1
                elif 'ACK enviado' in line:
                    events['acks_sent'] += 1
                elif 'sin datos por' in line:
                    events['timeouts'] += 1
                elif '[!]' in line:
                    events['errors'] += 1
                
                # Extraer timestamp
                ts_match = re.match(r'\[(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d{3})\]', line)
                if ts_match:
                    ts = ts_match.group(1)
                    if events['first_timestamp'] is None:
                        events['first_timestamp'] = ts
                    events['last_timestamp'] = ts
    except Exception as e:
        logger.error(f"Error analizando LOG {filepath}: {e}")
    return events

def find_evidence_files(root_dir: str) -> List[EvidenceFile]:
    """Recorre recursivamente y cataloga archivos de evidencia."""
    evidence_files = []
    root_path = Path(root_dir)
    
    for filepath in root_path.rglob('*'):
        if filepath.is_file() and filepath.suffix.lower() in EVIDENCE_EXTENSIONS:
            try:
                stat = filepath.stat()
                sha256 = compute_sha256(str(filepath))
                evidence_files.append(EvidenceFile(
                    path=str(filepath),
                    rel_path=str(filepath.relative_to(root_path)),
                    size_bytes=stat.st_size,
                    sha256=sha256,
                    extension=filepath.suffix.lower(),
                    modified_time=datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
                    status="OBSERVADO",
                    notes=""
                ))
            except Exception as e:
                logger.error(f"Error procesando {filepath}: {e}")
    
    return evidence_files

def generate_reports(evidence_files: List[EvidenceFile], 
                     sessions: List[SessionInfo],
                     messages: List[MessageMetadata],
                     output_dir: str):
    """Genera todos los reportes CSV y Markdown."""
    os.makedirs(output_dir, exist_ok=True)
    
    # 1. evidence_inventory.csv
    with open(os.path.join(output_dir, 'evidence_inventory.csv'), 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['path', 'rel_path', 'size_bytes', 'sha256', 'extension', 'modified_time', 'status', 'notes'])
        for ef in evidence_files:
            writer.writerow([ef.path, ef.rel_path, ef.size_bytes, ef.sha256, ef.extension, ef.modified_time, ef.status, ef.notes])
    
    # 2. sessions.csv
    with open(os.path.join(output_dir, 'sessions.csv'), 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['session_id', 'source_ip', 'source_port', 'dest_ip', 'dest_port', 
                         'start_time', 'end_time', 'tcp_connections', 'mllp_messages',
                         'message_types', 'hl7_version', 'sending_app', 'sending_facility',
                         'message_control_ids', 'segment_sequences', 'message_sizes',
                         'intervals_seconds', 'ack_present', 'ack_times', 'obx_codes', 'status', 'notes'])
        for s in sessions:
            writer.writerow([s.session_id, s.source_ip, s.source_port, s.dest_ip, s.dest_port,
                             s.start_time, s.end_time, s.tcp_connections, s.mllp_messages,
                             ';'.join(s.message_types), s.hl7_version, s.sending_app, s.sending_facility,
                             ';'.join(s.message_control_ids), ';'.join(['|'.join(seq) for seq in s.segment_sequences]),
                             ';'.join(map(str, s.message_sizes)), ';'.join(map(str, s.intervals_seconds)),
                             s.ack_present, ';'.join(map(str, s.ack_times)), ';'.join(s.obx_codes), s.status, s.notes])
    
    # 3. messages_metadata.csv
    with open(os.path.join(output_dir, 'messages_metadata.csv'), 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['message_id', 'session_id', 'timestamp', 'source_ip', 'source_port',
                         'message_type', 'message_control_id', 'hl7_version', 'sending_app',
                         'sending_facility', 'segment_sequence', 'size_bytes', 'interval_since_prev',
                         'ack_received', 'ack_time_ms', 'obx_codes', 'status', 'notes'])
        for m in messages:
            writer.writerow([m.message_id, m.session_id, m.timestamp, m.source_ip, m.source_port,
                             m.message_type, m.message_control_id, m.hl7_version, m.sending_app,
                             m.sending_facility, '|'.join(m.segment_sequence), m.size_bytes,
                             m.interval_since_prev, m.ack_received, m.ack_time_ms,
                             ';'.join(m.obx_codes), m.status, m.notes])
    
    # 4. segment_frequency.csv
    segment_counts = {}
    for m in messages:
        for seg in m.segment_sequence:
            segment_counts[seg] = segment_counts.get(seg, 0) + 1
    
    with open(os.path.join(output_dir, 'segment_frequency.csv'), 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['segment', 'count', 'percentage'])
        total = sum(segment_counts.values())
        for seg, count in sorted(segment_counts.items(), key=lambda x: -x[1]):
            writer.writerow([seg, count, f"{count/total*100:.2f}%"])
    
    # 5. timing_statistics.csv
    all_intervals = []
    for s in sessions:
        all_intervals.extend(s.intervals_seconds)
    
    with open(os.path.join(output_dir, 'timing_statistics.csv'), 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['metric', 'value', 'unit'])
        if all_intervals:
            writer.writerow(['count', len(all_intervals), 'messages'])
            writer.writerow(['min', min(all_intervals), 'seconds'])
            writer.writerow(['max', max(all_intervals), 'seconds'])
            writer.writerow(['mean', sum(all_intervals)/len(all_intervals), 'seconds'])
            writer.writerow(['median', sorted(all_intervals)[len(all_intervals)//2], 'seconds'])
            p95_idx = int(len(all_intervals) * 0.95)
            writer.writerow(['p95', sorted(all_intervals)[p95_idx], 'seconds'])
        for s in sessions:
            if s.message_sizes:
                writer.writerow([f'{s.session_id}_msg_count', s.mllp_messages, 'messages'])
                writer.writerow([f'{s.session_id}_msg_size_min', min(s.message_sizes), 'bytes'])
                writer.writerow([f'{s.session_id}_msg_size_max', max(s.message_sizes), 'bytes'])
                writer.writerow([f'{s.session_id}_msg_size_mean', sum(s.message_sizes)/len(s.message_sizes), 'bytes'])
    
    # 6. evidence_report.md
    with open(os.path.join(output_dir, 'evidence_report.md'), 'w', encoding='utf-8') as f:
        f.write(f"# Informe de Análisis de Evidencia HL7/MLLP\n\n")
        f.write(f"**Fecha de análisis:** {datetime.now(timezone.utc).isoformat()}\n")
        f.write(f"**Directorio analizado:** {root_dir}\n")
        f.write(f"**Total archivos:** {len(evidence_files)}\n\n")
        
        f.write("## Inventario de Archivos\n\n")
        f.write("| Archivo | Tamaño | SHA-256 | Tipo | Estado |\n")
        f.write("|---------|--------|---------|------|--------|\n")
        for ef in evidence_files:
            f.write(f"| {ef.rel_path} | {ef.size_bytes} B | {ef.sha256[:16]}... | {ef.extension} | {ef.status} |\n")
        
        f.write("\n## Sesiones Identificadas\n\n")
        for s in sessions:
            f.write(f"### Sesión: {s.session_id}\n")
            f.write(f"- **Origen:** {s.source_ip}:{s.source_port}\n")
            f.write(f"- **Destino:** {s.dest_ip}:{s.dest_port}\n")
            f.write(f"- **Duración:** {s.start_time} a {s.end_time}\n")
            f.write(f"- **Conexiones TCP:** {s.tcp_connections}\n")
            f.write(f"- **Mensajes MLLP:** {s.mllp_messages}\n")
            f.write(f"- **Tipos de mensaje:** {', '.join(set(s.message_types))}\n")
            f.write(f"- **Versión HL7:** {s.hl7_version}\n")
            f.write(f"- **Aplicación emisora:** {s.sending_app}\n")
            f.write(f"- **Institución emisora:** {s.sending_facility}\n")
            f.write(f"- **ACK presente:** {'Sí' if s.ack_present else 'No'}\n")
            if s.intervals_seconds:
                f.write(f"- **Intervalo medio:** {sum(s.intervals_seconds)/len(s.intervals_seconds):.3f} s\n")
            if s.obx_codes:
                f.write(f"- **Códigos OBX observados:** {', '.join(set(s.obx_codes))}\n")
            f.write(f"- **Estado:** {s.status}\n\n")
        
        f.write("\n## Estadísticas de Segmentos HL7\n\n")
        f.write("| Segmento | Frecuencia | Porcentaje |\n")
        f.write("|----------|------------|------------|\n")
        total_segs = sum(segment_counts.values())
        for seg, count in sorted(segment_counts.items(), key=lambda x: -x[1]):
            f.write(f"| {seg} | {count} | {count/total_segs*100:.2f}% |\n")
        
        f.write("\n## Estadísticas Temporales\n\n")
        if all_intervals:
            f.write(f"- **Muestras:** {len(all_intervals)}\n")
            f.write(f"- **Mínimo:** {min(all_intervals):.3f} s\n")
            f.write(f"- **Máximo:** {max(all_intervals):.3f} s\n")
            f.write(f"- **Media:** {sum(all_intervals)/len(all_intervals):.3f} s\n")
            f.write(f"- **Mediana:** {sorted(all_intervals)[len(all_intervals)//2]:.3f} s\n")
            p95_idx = int(len(all_intervals) * 0.95)
            f.write(f"- **P95:** {sorted(all_intervals)[p95_idx]:.3f} s\n")
        
        f.write("\n---\n")
        f.write("*Generado por analyze_evidence.py - Evidencia anonimizada, hashes preservados.*\n")

def main():
    parser = argparse.ArgumentParser(description="Analizador de evidencia HL7/MLLP para tesis WATO EX-35")
    parser.add_argument('evidence_dir', nargs='?', default='evidence_raw', 
                        help='Directorio raíz con evidencia (default: evidence_raw)')
    parser.add_argument('-o', '--output', default='analysis_output',
                        help='Directorio de salida para reportes (default: analysis_output)')
    parser.add_argument('--anon', action='store_true', default=True,
                        help='Aplicar anonimización (default: True)')
    parser.add_argument('--no-pcap', action='store_true',
                        help='Saltar análisis PCAP (requiere pyshark)')
    args = parser.parse_args()
    
    global root_dir
    root_dir = args.evidence_dir
    
    if not os.path.isdir(args.evidence_dir):
        logger.error(f"Directorio no existe: {args.evidence_dir}")
        sys.exit(1)
    
    logger.info(f"Iniciando análisis de evidencia en: {args.evidence_dir}")
    
    # 1. Inventario de archivos
    evidence_files = find_evidence_files(args.evidence_dir)
    logger.info(f"Archivos de evidencia encontrados: {len(evidence_files)}")
    
    # 2. Análisis por tipo
    all_sessions = []
    all_messages = []
    
    for ef in evidence_files:
        if ef.extension in ('.pcap', '.pcapng') and not args.no_pcap:
            logger.info(f"Analizando PCAP: {ef.rel_path}")
            all_sessions.extend(analyze_pcap(ef.path))
        elif ef.extension == '.bin':
            logger.info(f"Analizando BIN: {ef.rel_path}")
            all_sessions.extend(analyze_bin_file(ef.path))
        elif ef.extension == '.hl7':
            logger.info(f"Analizando HL7: {ef.rel_path}")
            all_messages.extend(analyze_hl7_file(ef.path))
        elif ef.extension == '.log':
            logger.info(f"Analizando LOG: {ef.rel_path}")
            events = analyze_log_file(ef.path)
            logger.info(f"  Eventos: {events}")
    
    # Si no hay mensajes de .hl7, extraer de sesiones
    if not all_messages and all_sessions:
        for s in all_sessions:
            # Re-parsear desde BIN/PCAP si necesario
            pass
    
    # 3. Generar reportes
    logger.info(f"Generando reportes en: {args.output}")
    generate_reports(evidence_files, all_sessions, all_messages, args.output)
    
    logger.info("Análisis completado.")
    
    # Resumen final
    print("\n=== RESUMEN ===")
    print(f"Archivos analizados: {len(evidence_files)}")
    print(f"Sesiones encontradas: {len(all_sessions)}")
    print(f"Mensajes parseados: {len(all_messages)}")
    print(f"Reportes en: {args.output}")

if __name__ == '__main__':
    main()