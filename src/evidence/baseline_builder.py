#!/usr/bin/env python3
"""
baseline_builder.py - Constructor de línea base desde sesiones normales etiquetadas
Calcula estadísticas descriptivas (NO machine learning) a partir de evidencia observada.
Genera baseline.yaml trazable a hashes de fuentes.
"""

import argparse
import hashlib
import json
import os
import statistics
import sys
import yaml
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from collections import Counter

@dataclass
class BaselineStats:
    message_types_allowed: List[str]
    segment_sequences_allowed: List[List[str]]
    sending_applications_allowed: List[str]
    sending_facilities_allowed: List[str]
    hl7_versions_allowed: List[str]
    message_length: Dict[str, float]
    inter_message_interval_seconds: Dict[str, float]
    messages_per_minute: float
    obx_identifiers_observed: List[str]
    obx_units_observed: List[str]
    obx_value_types_observed: List[str]
    state_transitions_observed: List[List[str]]

def compute_file_hashes(filepaths: List[str]) -> Dict[str, str]:
    """Calcula SHA-256 de archivos fuente."""
    hashes = {}
    for fp in filepaths:
        if os.path.exists(fp):
            sha256 = hashlib.sha256()
            with open(fp, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    sha256.update(chunk)
            hashes[fp] = sha256.hexdigest()
    return hashes

def percentile(data: List[float], p: float) -> float:
    """Calcula percentil p (0-100)."""
    if not data:
        return 0.0
    sorted_data = sorted(data)
    k = (len(sorted_data) - 1) * (p / 100)
    f = int(k)
    c = min(f + 1, len(sorted_data) - 1)
    if f == c:
        return sorted_data[f]
    return sorted_data[f] + (k - f) * (sorted_data[c] - sorted_data[f])

def analyze_sessions_from_csv(sessions_csv: str, messages_csv: str) -> BaselineStats:
    """Analiza CSVs generados por analyze_evidence.py para construir baseline."""
    import csv
    
    sessions = []
    with open(sessions_csv, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            sessions.append(row)
    
    messages = []
    with open(messages_csv, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            messages.append(row)
    
    # Tipos de mensaje permitidos
    msg_types = set()
    for s in sessions:
        for mt in s.get('message_types', '').split(';'):
            if mt:
                msg_types.add(mt)
    
    # Secuencias de segmentos
    seg_sequences = set()
    for s in sessions:
        for seq_str in s.get('segment_sequences', '').split(';'):
            if seq_str:
                seq = tuple(seq_str.split('|'))
                seg_sequences.add(seq)
    
    # Aplicaciones e instituciones
    apps = set()
    facs = set()
    versions = set()
    for s in sessions:
        if s.get('sending_app'):
            apps.add(s['sending_app'])
        if s.get('sending_facility'):
            facs.add(s['sending_facility'])
        if s.get('hl7_version'):
            versions.add(s['hl7_version'])
    
    # Longitudes de mensaje
    msg_sizes = []
    for s in sessions:
        for sz in s.get('message_sizes', '').split(';'):
            if sz:
                msg_sizes.append(int(sz))
    
    # Intervalos
    intervals = []
    for s in sessions:
        for iv in s.get('intervals_seconds', '').split(';'):
            if iv:
                intervals.append(float(iv))
    
    # OBX
    obx_ids = set()
    obx_units = set()
    obx_types = set()
    for s in sessions:
        for code in s.get('obx_codes', '').split(';'):
            if code:
                obx_ids.add(code)
        # Unidades y tipos vendrían de análisis más profundo
    
    # Transiciones de estado (desde documento STANDBY)
    state_transitions = [
        ["SIN_GATEWAY", "HANDSHAKE"],
        ["HANDSHAKE", "SESION_ESTABLECIDA_STANDBY"],
        ["SESION_ESTABLECIDA_STANDBY", "SESION_ESTABLECIDA_STANDBY"],
        # Enmienda E2 (2026-10-19): OBSERVADO en LECTURAACK27AGOSTO
        ["SESION_ESTABLECIDA_STANDBY", "SESION_ESTABLECIDA_RUNNING"],
        ["SESION_ESTABLECIDA_RUNNING", "SESION_ESTABLECIDA_RUNNING"]
    ]
    
    msg_count = len(messages)
    duration_min = 1.0
    if sessions and intervals:
        duration_min = sum(intervals) / 60.0
    
    return BaselineStats(
        message_types_allowed=sorted(msg_types),
        segment_sequences_allowed=[list(s) for s in seg_sequences],
        sending_applications_allowed=sorted(apps),
        sending_facilities_allowed=sorted(facs),
        hl7_versions_allowed=sorted(versions),
        message_length={
            'min': min(msg_sizes) if msg_sizes else 0,
            'median': statistics.median(msg_sizes) if msg_sizes else 0,
            'p95': percentile(msg_sizes, 95) if msg_sizes else 0,
            'max': max(msg_sizes) if msg_sizes else 0
        },
        inter_message_interval_seconds={
            'min': min(intervals) if intervals else 0,
            'median': statistics.median(intervals) if intervals else 0,
            'p95': percentile(intervals, 95) if intervals else 0,
            'max': max(intervals) if intervals else 0
        },
        messages_per_minute=msg_count / duration_min if duration_min > 0 else 0,
        obx_identifiers_observed=sorted(obx_ids),
        obx_units_observed=sorted(obx_units),
        obx_value_types_observed=sorted(obx_types),
        state_transitions_observed=state_transitions
    )

def build_baseline_from_standby_documented() -> Dict[str, Any]:
    """Construye baseline directamente desde valores documentados en STANDBY 25-08-2026."""
    
    # Valores OBSERVADOS en la captura STANDBY
    message_sizes = [971] * 34 + [968] * 9  # 43 mensajes
    intervals = [10.0] * 42  # 42 intervalos entre 43 mensajes
    
    return {
        'metadata': {
            'created_at': datetime.now(timezone.utc).isoformat(),
            'schema_version': '1.0',
            'source_sessions': ['standby_20260825'],
            'source_hashes': {},  # Se llenará después
            'num_sessions': 1,
            'num_messages': 43,
            'states_included': ['SESION_ESTABLECIDA_STANDBY'],
            'limitations': [
                'Baseline construida SOLO desde modo STANDBY (captura 25-08-2026)',
                'Fuente: LECTURACONACK25AGOSTO.pcapng (43 ORU + 43 ACK observados)',
                'Modo RUNNING no verificado - parámetros fisiológicos NO_VERIFICADO',
                'Solo 4 códigos OBX tipo CWE observados (estados, no numéricos)',
                'No hay alarmas ni eventos en baseline',
                'Reloj WATO con offset +17min10s vs captura - usar timestamp de red',
                'Intervalos documentados por MSH-7 (10.000s); tiempo de captura varía ±4ms',
                'Codificación UTF-8 declarada en MSH-18 (ackdummy usaba ISO-8859-1)',
                'Enmienda E2: FSM agrega estado RUNNING y transición STANDBY->RUNNING '
                '(OBSERVADO 27-08); estadísticas OBX siguen siendo solo STANDBY'
            ],
            'clinical_approval_status': 'PENDING',
            'clinical_approval_date': None,
            'clinical_approver': None
        },
        'message_types_allowed': ['ORU^R01^ORU_R01'],
        'segment_sequences_allowed': [
            ['MSH', 'PID', 'PV1', 'OBR', 'OBX', 'OBX', 'OBX', 'OBX']
        ],
        'sending_applications_allowed': ['MINDRAY_WATOPRO-SERIES^000F14002D3586ec^EUI-64'],
        'sending_facilities_allowed': [''],
        'hl7_versions_allowed': ['2.6'],
        'message_length': {
            'min': min(message_sizes),
            'median': statistics.median(message_sizes),
            'p95': percentile(message_sizes, 95),
            'max': max(message_sizes)
        },
        'inter_message_interval_seconds': {
            'min': min(intervals),
            'median': statistics.median(intervals),
            'p95': percentile(intervals, 95),
            'max': max(intervals)
        },
        'messages_per_minute': 6.0,  # 1 msg cada 10s = 6/min
        'obx_identifiers_observed': [
            '202886^MDC_EVT_STAT_DEV^MDC',
            '30002^MNDRY_EVT_STAT_MODE_DEV',
            '30005^MNDRY_EVT_PATIENT_TYPE',
            '30007^MNDRY_EVT_STAT_WARMER_ON_BOOL'
        ],
        'obx_identifier_details': {
            '202886^MDC_EVT_STAT_DEV^MDC': {
                'description': 'Estado del dispositivo',
                'observed_values': ['202836^MDC_EVT_STAT_STANDBY^MDC'],
                'value_type': 'CWE',
                'status': 'OBSERVADO'
            },
            '30002^MNDRY_EVT_STAT_MODE_DEV': {
                'description': 'Modo del dispositivo',
                'observed_values': ['30003^MNDRY_EVT_STAT_MODE_NORMAL'],
                'value_type': 'CWE',
                'status': 'OBSERVADO'
            },
            '30005^MNDRY_EVT_PATIENT_TYPE': {
                'description': 'Tipo de paciente',
                'observed_values': ['202890^MDC_EVT_STAT_DEV_MODE_ADULT'],
                'value_type': 'CWE',
                'status': 'OBSERVADO'
            },
            '30007^MNDRY_EVT_STAT_WARMER_ON_BOOL': {
                'description': 'Estado calentador',
                'observed_values': ['30000^MDC_TRUE'],
                'value_type': 'CWE',
                'status': 'OBSERVADO'
            }
        },
        # Enmienda E1 (2026-10-14): los 4 OBX CWE del STANDBY real SÍ traen
        # OBX-6 = 262656^MDC_DIM_DIMLESS^MDC (43/43 ORU, evidencia pcap
        # 25-08). La premisa previa "STANDBY usa CWE, no unidades" era falsa
        # y produjo 43/43 FP en R-OBX-002 sobre el replay del corpus.
        'obx_units_observed': ['262656^MDC_DIM_DIMLESS^MDC'],
        'obx_value_types_observed': ['CWE'],
        'state_transitions_observed': [
            ['SIN_GATEWAY', 'HANDSHAKE'],
            ['HANDSHAKE', 'SESION_ESTABLECIDA_STANDBY'],
            ['SESION_ESTABLECIDA_STANDBY', 'SESION_ESTABLECIDA_STANDBY'],
            # Enmienda E2 (2026-10-19): OBSERVADO 1 vez en LECTURAACK27AGOSTO
            # (13 ORU STANDBY -> 86 ORU RUNNING). RUNNING->STANDBY NO_VERIFICADO.
            ['SESION_ESTABLECIDA_STANDBY', 'SESION_ESTABLECIDA_RUNNING'],
            ['SESION_ESTABLECIDA_RUNNING', 'SESION_ESTABLECIDA_RUNNING']
        ],
        'fsm_states': {
            'SIN_GATEWAY': {
                'description': 'Reintentos SYN sin respuesta (gateway no disponible)',
                'observed_duration_range': [0, 80],  # segundos
                'behavior': 'SYN cada ~30s, luego reinicio puerto efímero'
            },
            'HANDSHAKE': {
                'description': 'Establecimiento TCP exitoso',
                'observed_duration_range': [0, 2],
                'behavior': 'SYN -> SYN-ACK -> ACK, luego primer ORU^R01'
            },
            'SESION_ESTABLECIDA_STANDBY': {
                'description': 'Sesión persistente con ORU^R01 periódicos + ACK',
                'observed_duration_range': [0, 509],
                'behavior': 'ORU^R01 cada 10.000s exactos, ACK MSA|AA en <1ms',
                'message_profile': {
                    'type': 'ORU^R01^ORU_R01',
                    'interval_seconds': 10.0,
                    'ack_required': True,
                    'ack_type': 'AL',
                    'obx_count': 4,
                    'obx_types': ['CWE', 'CWE', 'CWE', 'CWE']
                }
            },
            # Enmienda E2 (2026-10-19). Fuente: LECTURAACK27AGOSTO.pcapng.
            # OBSERVADO: 184352^MDC_VENT_MODE en 86/86 ORU RUNNING y 0/56
            # STANDBY; nº de OBX varía 17-28 por modo (no se exige conteo).
            'SESION_ESTABLECIDA_RUNNING': {
                'description': 'Sesión persistente con el equipo ventilando (RUNNING)',
                'behavior': 'ORU^R01 cada 10 s con OBX de configuración y medición',
                'required_obx_codes': ['184352'],
                'status': 'OBSERVADO'
            }
        },
        'mllp_parameters': {
            'start_block': '0x0B',
            'end_block': '0x1C',
            'carriage_return': '0x0D',
            'encoding': 'UTF-8',
            'max_message_size_bytes': 65535
        },
        'hl7_parameters': {
            'version': '2.6',
            'profile': 'IHE_PCD_01',
            'separators': '|^~\\&',
            'processing_id': 'P',
            'ack_required': 'AL',
            'charset': 'UNICODE UTF-8'
        },
        'network_parameters': {
            'wato_ip': '192.168.23.250',
            'wato_mac': '00:0f:14:35:86:ec',
            'server_ip': '192.168.23.200',
            'server_port': 1550,
            'protocol': 'TCP',
            'client_role': 'WATO inicia conexión (cliente TCP)',
            # IPs de origen permitidas (R-NET-001). 192.168.23.250 = OBSERVADA
            # en captura real; loopback e IP del emulador Docker = INFERIDO
            # para el laboratorio aislado.
            'allowed_ips': [
                '192.168.23.250',
                '127.0.0.1',
                '::1',
                '172.30.0.10',
                '172.30.0.11',
            ]
        }
    }

def main():
    parser = argparse.ArgumentParser(description="Constructor de línea base para detector HL7/MLLP")
    parser.add_argument('--source-dir', default='analysis_output',
                        help='Directorio con CSVs de analyze_evidence.py')
    parser.add_argument('-o', '--output', default='baseline.yaml',
                        help='Archivo YAML de salida')
    parser.add_argument('--from-csv', action='store_true',
                        help='Construir desde CSVs (vs valores documentados STANDBY)')
    parser.add_argument('--source-files', nargs='*', default=[],
                        help='Archivos fuente para calcular hashes')
    args = parser.parse_args()
    
    if args.from_csv:
        sessions_csv = os.path.join(args.source_dir, 'sessions.csv')
        messages_csv = os.path.join(args.source_dir, 'messages_metadata.csv')
        if not os.path.exists(sessions_csv) or not os.path.exists(messages_csv):
            print(f"CSVs no encontrados en {args.source_dir}. Use --from-csv solo después de analyze_evidence.py")
            sys.exit(1)
        stats = analyze_sessions_from_csv(sessions_csv, messages_csv)
        baseline = asdict(stats)
        baseline['metadata'] = {
            'created_at': datetime.now(timezone.utc).isoformat(),
            'schema_version': '1.0',
            'source_sessions': ['from_csv'],
            'source_hashes': compute_file_hashes(args.source_files),
            'clinical_approval_status': 'PENDING'
        }
    else:
        # Usar valores documentados STANDBY
        baseline = build_baseline_from_standby_documented()
        baseline['metadata']['source_hashes'] = compute_file_hashes(args.source_files)
    
    # Escribir YAML
    with open(args.output, 'w', encoding='utf-8') as f:
        yaml.dump(baseline, f, default_flow_style=False, sort_keys=False, allow_unicode=True)
    
    print(f"Baseline guardada en: {args.output}")
    print(f"  Tipos de mensaje: {baseline['message_types_allowed']}")
    print(f"  Versiones HL7: {baseline['hl7_versions_allowed']}")
    print(f"  Aplicaciones: {baseline['sending_applications_allowed']}")
    print(f"  Longitud msg: min={baseline['message_length']['min']}, median={baseline['message_length']['median']:.0f}, p95={baseline['message_length']['p95']:.0f}, max={baseline['message_length']['max']}")
    print(f"  Intervalo: min={baseline['inter_message_interval_seconds']['min']:.1f}s, median={baseline['inter_message_interval_seconds']['median']:.1f}s, p95={baseline['inter_message_interval_seconds']['p95']:.1f}s, max={baseline['inter_message_interval_seconds']['max']:.1f}s")
    print(f"  OBX observados: {len(baseline['obx_identifiers_observed'])}")
    print(f"  Estados FSM: {len(baseline['fsm_states'])}")
    print(f"  Aprobación clínica: {baseline['metadata']['clinical_approval_status']}")

if __name__ == '__main__':
    main()