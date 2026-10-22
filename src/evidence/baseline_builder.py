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
    """Construye baseline bimodal (STANDBY + RUNNING) desde evidencia observada
    en las 3 capturas reales del equipo Mindray WATO EX-35 (2026-08-18/25/27)."""
    
    # Longitudes de mensaje observadas en STANDBY (1019-1022 B en red; 968-971 B en .hl7)
    # y RUNNING (2535 B en MANUAL a 3945 B en SIMV-VC+PS)
    message_sizes = (
        [968] * 9 + [971] * 34 + [1022] * 13 +
        [3303] * 43 + [3945] * 27 + [3169] * 2 +
        [3689] * 3 + [3570] * 6 + [2535] * 5
    )
    intervals = [10.0] * 140  # 140 intervalos de 10.0 s (42 en 25-08 + 98 en 27-08)
    
    return {
        'metadata': {
            'created_at': datetime.now(timezone.utc).isoformat(),
            'schema_version': '1.1',
            'source_sessions': [
                'arp_discovery_20260818',
                'standby_20260825',
                'running_multimode_20260827',
            ],
            'source_hashes': {},  # Se llenará después
            'num_sessions': 2,
            'num_messages': 142,
            'states_included': [
                'SIN_GATEWAY',
                'HANDSHAKE',
                'SESION_ESTABLECIDA_STANDBY',
                'SESION_ESTABLECIDA_RUNNING',
            ],
            'limitations': [
                'Baseline bimodal construida desde evidencia real STANDBY (25-08-2026, 43 ORU) y RUNNING (27-08-2026, 99 ORU: 13 STANDBY + 86 RUNNING)',
                'Fuentes PCAP: WATOPARANALIZAR18AGOSTO.pcap (ARP), LECTURACONACK25AGOSTO.pcapng (43 ORU + 43 ACK), LECTURAACK27AGOSTO.pcapng (99 ORU + 99 ACK)',
                '6 modos ventilatorios observados en RUNNING: VCV (50005), SIMV-VC+PS (50008), PCV (50011), SIMV-PC+PS (50010), PS (50006) y MANUAL (50000)',
                '33 identificadores OBX observados (5 estado/modo CWE, 16 ajustes 99MNDRY NM/SN con OBX-11=F, 12 mediciones MDC NM/SN con OBX-11=R o INV/X)',
                'Sensor de O2 inspiratorio (152196^MDC_CONC_AWAY_O2_INSP^MDC) observado con OBX-8=INV y OBX-11=X (tipo vacío) cuando celda O2 no reporta valor numérico',
                'No se observaron segmentos de alarma fisiológica activa en las capturas; rangos clínicos fisiológicos requieren aprobación clínica',
                'Reloj interno WATO con desfase respecto a reloj de captura; intervalo nominal MSH-7 = 10.000 s',
                'Codificación UNICODE UTF-8 declarada en MSH-18; perfil IHE_PCD_001^IHE PCD^1.3.6.1.4.1.19376.1.6.1.1.1^ISO en MSH-21'
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
            # Estado y modo del dispositivo (STANDBY + RUNNING)
            '202886^MDC_EVT_STAT_DEV^MDC',
            '30002^MNDRY_EVT_STAT_MODE_DEV^99MNDRY',
            '30002^MNDRY_EVT_STAT_MODE_DEV',
            '30005^MNDRY_EVT_PATIENT_TYPE^99MNDRY',
            '30005^MNDRY_EVT_PATIENT_TYPE',
            '30007^MNDRY_EVT_STAT_WARMER_ON_BOOL^99MNDRY',
            '30007^MNDRY_EVT_STAT_WARMER_ON_BOOL',
            '184352^MDC_VENT_MODE^MDC',
            # Ajustes ventilatorios (settings, OBX-11 = F, 99MNDRY)
            '20000^MDC_RATIO_IE_SETTING^99MNDRY',
            '20001^MNDRY_RESP_RATE_MIN_SETTING^99MNDRY',
            '20002^MNDRY_VENT_PRESS_INSP_SETTING^99MNDRY',
            '20003^MNDRY_VENT_DELTA_PRESS_SETTING^99MNDRY',
            '20004^MNDRY_VENT_INSP_TIME_SETTING^99MNDRY',
            '20005^MNDRY_VENT_SLOPE_TIME_SETTING^99MNDRY',
            '20007^MNDRY_VENT_PAUSE_TIME_PERCENT_SETTING^99MNDRY',
            '20013^MNDRY_VENT_PRESS_LIMIT_SETTING^99MNDRY',
            '20014^MDC_VENT_PRESS_TRIG_SENS_SETTING^99MNDRY',
            '20015^MDC_VOL_AWAY_TIDAL_SETTING^99MNDRY',
            '20016^MDC_VENT_RESP_RATE_SETTING^99MNDRY',
            '20017^MDC_PRESS_AWAY_END_EXP_POS_SETTING^99MNDRY',
            '20026^MNDRY_VENT_EXP_TRIGGER_SETTING^99MNDRY',
            '20027^MNDRY_VENT_DELTA_PRESS_APNEA_SETTING^99MNDRY',
            '20043^MNDRY_VENT_APNEA_RATIO_IE_SETTING^99MNDRY',
            '20044^MNDRY_VENT_TRIG_WINDOW_SETTING^99MNDRY',
            # Mediciones fisiológicas / mecánicas ventilatorias (IEEE 11073-10101 MDC, OBX-11 = R / X)
            '151586^MDC_VENT_RESP_RATE^MDC',
            '151688^MDC_COMPL_LUNG^MDC',
            '151784^MDC_PRESS_RESP_PLAT^MDC',
            '151819^MDC_PRESS_AWAY_INSP_MEAN^MDC',
            '151832^MDC_RATIO_IE^MDC',
            '151840^MDC_RES_AWAY^MDC',
            '151880^MDC_VOL_MINUTE_AWAY^MDC',
            '151957^MDC_VENT_PRESS_MAX^MDC',
            '151976^MDC_VENT_PRESS_AWAY_END_EXP_POS^MDC',
            '152196^MDC_CONC_AWAY_O2_INSP^MDC',
            '152660^MDC_VOL_AWAY_TIDAL_INSP^MDC',
            '152664^MDC_VOL_AWAY_TIDAL_EXP^MDC',
        ],
        'obx_identifier_details': {
            '202886^MDC_EVT_STAT_DEV^MDC': {
                'description': 'Estado operativo del dispositivo (STANDBY / RUNNING)',
                'sub_id': '1.1.1.202886',
                'observed_values': [
                    '202836^MDC_EVT_STAT_STANDBY^MDC',
                    '202902^MDC_EVT_STAT_RUNNING^MDC',
                ],
                'unit': '262656^MDC_DIM_DIMLESS^MDC',
                'value_type': 'CWE',
                'status': 'OBSERVADO'
            },
            '30002^MNDRY_EVT_STAT_MODE_DEV^99MNDRY': {
                'description': 'Modo operativo del sistema Mindray',
                'sub_id': '1.1.1.30002',
                'observed_values': ['30003^MNDRY_EVT_STAT_MODE_NORMAL^99MNDRY'],
                'unit': '262656^MDC_DIM_DIMLESS^MDC',
                'value_type': 'CWE',
                'status': 'OBSERVADO'
            },
            '30005^MNDRY_EVT_PATIENT_TYPE^99MNDRY': {
                'description': 'Categoría demográfica de paciente configurada',
                'sub_id': '1.1.1.30005',
                'observed_values': ['202890^MDC_EVT_STAT_DEV_MODE_ADULT^MDC'],
                'unit': '262656^MDC_DIM_DIMLESS^MDC',
                'value_type': 'CWE',
                'status': 'OBSERVADO'
            },
            '30007^MNDRY_EVT_STAT_WARMER_ON_BOOL^99MNDRY': {
                'description': 'Estado del calentador del circuito respiratorio',
                'sub_id': '1.3.1.30007',
                'observed_values': ['30000^MDC_TRUE^99MNDRY'],
                'unit': '262656^MDC_DIM_DIMLESS^MDC',
                'value_type': 'CWE',
                'status': 'OBSERVADO'
            },
            '184352^MDC_VENT_MODE^MDC': {
                'description': 'Modo de ventilación activo (6 modos observados)',
                'sub_id': '1.3.1.184352',
                'observed_values': [
                    '50005^MNDRY_VENT_MODE_VCV^99MNDRY',
                    '50008^MNDRY_VENT_MODE_SIMVVC_PLUS_PS^99MNDRY',
                    '50011^MNDRY_VENT_MODE_PCV^99MNDRY',
                    '50010^MNDRY_VENT_MODE_SIMVPC_PLUS_PS^99MNDRY',
                    '50006^MNDRY_VENT_MODE_PS^99MNDRY',
                    '50000^MNDRY_VENT_MODE_MANUAL^99MNDRY',
                ],
                'unit': '262656^MDC_DIM_DIMLESS^MDC',
                'value_type': 'CWE',
                'status': 'OBSERVADO'
            },
            '20000^MDC_RATIO_IE_SETTING^99MNDRY': {
                'description': 'Ajuste de relación I:E',
                'sub_id': '1.3.2.20000',
                'observed_values': ['^1^:^2'],
                'unit': '262656^MDC_DIM_DIMLESS^MDC',
                'value_type': 'SN',
                'status': 'OBSERVADO'
            },
            '20001^MNDRY_RESP_RATE_MIN_SETTING^99MNDRY': {
                'description': 'Ajuste de frecuencia respiratoria mínima (apnea/PS)',
                'sub_id': '1.3.2.20001',
                'observed_values': ['4'],
                'unit': '264928^MDC_DIM_RESP_PER_MIN^MDC',
                'value_type': 'NM',
                'status': 'OBSERVADO'
            },
            '20002^MNDRY_VENT_PRESS_INSP_SETTING^99MNDRY': {
                'description': 'Ajuste de presión inspiratoria (Pinsp en PCV/SIMV-PC)',
                'sub_id': '1.3.2.20002',
                'observed_values': ['29'],
                'unit': '266048^MDC_DIM_CM_H2O^MDC',
                'value_type': 'NM',
                'status': 'OBSERVADO'
            },
            '20003^MNDRY_VENT_DELTA_PRESS_SETTING^99MNDRY': {
                'description': 'Ajuste de presión de soporte (Delta P / Psupp)',
                'sub_id': '1.3.2.20003',
                'observed_values': ['15'],
                'unit': '266048^MDC_DIM_CM_H2O^MDC',
                'value_type': 'NM',
                'status': 'OBSERVADO'
            },
            '20004^MNDRY_VENT_INSP_TIME_SETTING^99MNDRY': {
                'description': 'Ajuste de tiempo inspiratorio (Tinsp)',
                'sub_id': '1.3.2.20004',
                'observed_values': ['1.5'],
                'unit': '264320^MDC_DIM_SEC^MDC',
                'value_type': 'NM',
                'status': 'OBSERVADO'
            },
            '20005^MNDRY_VENT_SLOPE_TIME_SETTING^99MNDRY': {
                'description': 'Ajuste de tiempo de rampa de presión (Tslope)',
                'sub_id': '1.3.2.20005',
                'observed_values': ['0.5'],
                'unit': '264320^MDC_DIM_SEC^MDC',
                'value_type': 'NM',
                'status': 'OBSERVADO'
            },
            '20007^MNDRY_VENT_PAUSE_TIME_PERCENT_SETTING^99MNDRY': {
                'description': 'Ajuste de pausa inspiratoria porcentual (Tpause %)',
                'sub_id': '1.3.2.20007',
                'observed_values': ['0'],
                'unit': '262688^MDC_DIM_PERCENT^MDC',
                'value_type': 'NM',
                'status': 'OBSERVADO'
            },
            '20013^MNDRY_VENT_PRESS_LIMIT_SETTING^99MNDRY': {
                'description': 'Ajuste de límite de presión en vía aérea (Plimit)',
                'sub_id': '1.3.2.20013',
                'observed_values': ['30', '35'],
                'unit': '266048^MDC_DIM_CM_H2O^MDC',
                'value_type': 'NM',
                'status': 'OBSERVADO'
            },
            '20014^MDC_VENT_PRESS_TRIG_SENS_SETTING^99MNDRY': {
                'description': 'Ajuste de sensibilidad de disparo por flujo (Trigger)',
                'sub_id': '1.3.2.20014',
                'observed_values': ['3.0'],
                'unit': '265216^MDC_DIM_L_PER_MIN^MDC',
                'value_type': 'NM',
                'status': 'OBSERVADO'
            },
            '20015^MDC_VOL_AWAY_TIDAL_SETTING^99MNDRY': {
                'description': 'Ajuste de volumen corriente (VT)',
                'sub_id': '1.3.2.20015',
                'observed_values': ['400', '450'],
                'unit': '263762^MDC_DIM_MILLI_L^MDC',
                'value_type': 'NM',
                'status': 'OBSERVADO'
            },
            '20016^MDC_VENT_RESP_RATE_SETTING^99MNDRY': {
                'description': 'Ajuste de frecuencia respiratoria (FR)',
                'sub_id': '1.3.2.20016',
                'observed_values': ['12', '14'],
                'unit': '264928^MDC_DIM_RESP_PER_MIN^MDC',
                'value_type': 'NM',
                'status': 'OBSERVADO'
            },
            '20017^MDC_PRESS_AWAY_END_EXP_POS_SETTING^99MNDRY': {
                'description': 'Ajuste de PEEP',
                'sub_id': '1.3.2.20017',
                'observed_values': ['6', '8'],
                'unit': '266048^MDC_DIM_CM_H2O^MDC',
                'value_type': 'NM',
                'status': 'OBSERVADO'
            },
            '20026^MNDRY_VENT_EXP_TRIGGER_SETTING^99MNDRY': {
                'description': 'Ajuste de sensibilidad de ciclado espiratorio (Esens %)',
                'sub_id': '1.3.2.20026',
                'observed_values': ['25'],
                'unit': '262688^MDC_DIM_PERCENT^MDC',
                'value_type': 'NM',
                'status': 'OBSERVADO'
            },
            '20027^MNDRY_VENT_DELTA_PRESS_APNEA_SETTING^99MNDRY': {
                'description': 'Ajuste de presión inspiratoria de respaldo en apnea',
                'sub_id': '1.3.2.20027',
                'observed_values': ['15'],
                'unit': '266048^MDC_DIM_CM_H2O^MDC',
                'value_type': 'NM',
                'status': 'OBSERVADO'
            },
            '20043^MNDRY_VENT_APNEA_RATIO_IE_SETTING^99MNDRY': {
                'description': 'Ajuste de relación I:E en ventilación de apnea',
                'sub_id': '1.3.2.20043',
                'observed_values': ['^1^:^2'],
                'unit': '262656^MDC_DIM_DIMLESS^MDC',
                'value_type': 'SN',
                'status': 'OBSERVADO'
            },
            '20044^MNDRY_VENT_TRIG_WINDOW_SETTING^99MNDRY': {
                'description': 'Ajuste de ventana de sincronización SIMV (%)',
                'sub_id': '1.3.2.20044',
                'observed_values': ['25'],
                'unit': '262688^MDC_DIM_PERCENT^MDC',
                'value_type': 'NM',
                'status': 'OBSERVADO'
            },
            '151957^MDC_VENT_PRESS_MAX^MDC': {
                'description': 'Presión pico en vía aérea medida (Ppeak)',
                'sub_id': '1.3.2.151957',
                'observed_values': ['31', '32', '33', '35'],
                'unit': '266048^MDC_DIM_CM_H2O^MDC',
                'value_type': 'NM',
                'status': 'OBSERVADO'
            },
            '151819^MDC_PRESS_AWAY_INSP_MEAN^MDC': {
                'description': 'Presión media en vía aérea medida (Pmean)',
                'sub_id': '1.3.2.151819',
                'observed_values': ['10', '11', '12', '16'],
                'unit': '266048^MDC_DIM_CM_H2O^MDC',
                'value_type': 'NM',
                'status': 'OBSERVADO'
            },
            '151784^MDC_PRESS_RESP_PLAT^MDC': {
                'description': 'Presión meseta medida (Pplat)',
                'sub_id': '1.3.2.151784',
                'observed_values': ['29', '31', '32', '34'],
                'unit': '266048^MDC_DIM_CM_H2O^MDC',
                'value_type': 'NM',
                'status': 'OBSERVADO'
            },
            '151976^MDC_VENT_PRESS_AWAY_END_EXP_POS^MDC': {
                'description': 'PEEP medida al final de la espiración',
                'sub_id': '1.3.2.151976',
                'observed_values': ['5', '6', '8', '9'],
                'unit': '266048^MDC_DIM_CM_H2O^MDC',
                'value_type': 'NM',
                'status': 'OBSERVADO'
            },
            '151880^MDC_VOL_MINUTE_AWAY^MDC': {
                'description': 'Volumen minuto espirado medido (MV)',
                'sub_id': '1.3.2.151880',
                'observed_values': ['0.6', '0.8', '0.9', '1.0'],
                'unit': '265216^MDC_DIM_L_PER_MIN^MDC',
                'value_type': 'NM',
                'status': 'OBSERVADO'
            },
            '152664^MDC_VOL_AWAY_TIDAL_EXP^MDC': {
                'description': 'Volumen corriente espirado medido (VTe)',
                'sub_id': '1.3.2.152664',
                'observed_values': ['65', '68', '74', '78'],
                'unit': '263762^MDC_DIM_MILLI_L^MDC',
                'value_type': 'NM',
                'status': 'OBSERVADO'
            },
            '152660^MDC_VOL_AWAY_TIDAL_INSP^MDC': {
                'description': 'Volumen corriente inspirado medido (VTi)',
                'sub_id': '1.3.2.152660',
                'observed_values': ['69', '75', '76', '83'],
                'unit': '263762^MDC_DIM_MILLI_L^MDC',
                'value_type': 'NM',
                'status': 'OBSERVADO'
            },
            '151832^MDC_RATIO_IE^MDC': {
                'description': 'Relación I:E medida',
                'sub_id': '1.3.2.151832',
                'observed_values': ['^1^:^2.0', '^1^:^2.1', '^1^:^2.3', '^1.3^:^1'],
                'unit': '262656^MDC_DIM_DIMLESS^MDC',
                'value_type': 'SN',
                'status': 'OBSERVADO'
            },
            '151840^MDC_RES_AWAY^MDC': {
                'description': 'Resistencia dinámica de vía aérea (Raw)',
                'sub_id': '1.3.2.151840',
                'observed_values': ['55', '57', '58', '59', '95'],
                'unit': '268064^MDC_DIM_CM_H2O_PER_L_PER_SEC^MDC',
                'value_type': 'NM',
                'status': 'OBSERVADO'
            },
            '151688^MDC_COMPL_LUNG^MDC': {
                'description': 'Complianza pulmonar dinámica (Cdyn)',
                'sub_id': '1.3.2.151688',
                'observed_values': ['2', '3'],
                'unit': '268050^MDC_DIM_MILLI_L_PER_CM_H2O^MDC',
                'value_type': 'NM',
                'status': 'OBSERVADO'
            },
            '152196^MDC_CONC_AWAY_O2_INSP^MDC': {
                'description': 'Concentración inspiratoria de O2 (FiO2, observado con INV/X cuando sensor desconectado)',
                'sub_id': '1.4.1.152196',
                'observed_values': [],
                'unit': '262688^MDC_DIM_PERCENT^MDC',
                'value_type': 'NM',
                'status': 'OBSERVADO'
            },
            '151586^MDC_VENT_RESP_RATE^MDC': {
                'description': 'Frecuencia respiratoria total medida (FR)',
                'sub_id': '1.3.2.151586',
                'observed_values': ['7', '10', '12', '13'],
                'unit': '264928^MDC_DIM_RESP_PER_MIN^MDC',
                'value_type': 'NM',
                'status': 'OBSERVADO'
            },
        },
        # Unidades ISO/IEEE 11073-10101 MDC observadas en STANDBY y RUNNING
        'obx_units_observed': [
            '262656^MDC_DIM_DIMLESS^MDC',
            '262688^MDC_DIM_PERCENT^MDC',
            '263762^MDC_DIM_MILLI_L^MDC',
            '264320^MDC_DIM_SEC^MDC',
            '264928^MDC_DIM_RESP_PER_MIN^MDC',
            '265216^MDC_DIM_L_PER_MIN^MDC',
            '266048^MDC_DIM_CM_H2O^MDC',
            '268050^MDC_DIM_MILLI_L_PER_CM_H2O^MDC',
            '268064^MDC_DIM_CM_H2O_PER_L_PER_SEC^MDC',
        ],
        'obx_value_types_observed': ['CWE', 'NM', 'SN'],
        'state_transitions_observed': [
            ['SIN_GATEWAY', 'HANDSHAKE'],
            ['HANDSHAKE', 'SESION_ESTABLECIDA_STANDBY'],
            ['SESION_ESTABLECIDA_STANDBY', 'SESION_ESTABLECIDA_STANDBY'],
            ['SESION_ESTABLECIDA_STANDBY', 'SESION_ESTABLECIDA_RUNNING'],
            ['SESION_ESTABLECIDA_RUNNING', 'SESION_ESTABLECIDA_RUNNING'],
        ],
        'fsm_states': {
            'SIN_GATEWAY': {
                'description': 'Descubrimiento ARP y reintentos SYN sin respuesta (gateway no disponible, observado en 18-08 y 25-08)',
                'observed_duration_range': [0, 299],  # segundos
                # Enmienda E7 (2026-10-20): ciclo SYN medido en LECTURA25AGOSYO.pcapng
                # (sha256 cd9122c67bd3082c...), 19 ciclos, puertos 2048-2066.
                'behavior': 'ARP Who has 192.168.23.200? Tell 192.168.23.250; por puerto efímero SYN en t=0, reintentos a +1.6 s, +16.6 s y +31.6 s, RST del WATO a +46.6 s; nuevo SYN con puerto+1 a +47.6 s (ciclo ~47.6 s)'
            },
            'HANDSHAKE': {
                'description': 'Establecimiento TCP exitoso hacia puerto 1550',
                'observed_duration_range': [0, 2],
                'behavior': 'SYN -> SYN-ACK -> ACK, luego primer ORU^R01 MLLP'
            },
            'SESION_ESTABLECIDA_STANDBY': {
                'description': 'Sesión persistente en modo STANDBY con ORU^R01 periódicos + ACK (25-08 msg 1..43, 27-08 msg 1..13)',
                'observed_duration_range': [0, 509],
                'behavior': 'ORU^R01 cada 10.000s exactos, ACK MSA|AA en <1ms, 4 segmentos OBX CWE',
                'message_profile': {
                    'type': 'ORU^R01^ORU_R01',
                    'interval_seconds': 10.0,
                    'ack_required': True,
                    'ack_type': 'AL',
                    'obx_count': 4,
                    'obx_types': ['CWE', 'CWE', 'CWE', 'CWE']
                }
            },
            'SESION_ESTABLECIDA_RUNNING': {
                'description': 'Sesión activa de ventilación mecánica (27-08 msg 14..99) en modos VCV, SIMV-VC+PS, PCV, SIMV-PC+PS, PS y MANUAL',
                'observed_duration_range': [0, 860],
                # Enmienda E2 (pruebas-santi): 184352 en 86/86 RUNNING, 0/56 STANDBY.
                'required_obx_codes': ['184352'],
                'behavior': 'ORU^R01 cada 10.000s con 17 a 28 segmentos OBX (5 CWE estado/modo + 0..11 ajustes F + 12 mediciones R/X)',
                'message_profile': {
                    'type': 'ORU^R01^ORU_R01',
                    'interval_seconds': 10.0,
                    'ack_required': True,
                    'ack_type': 'AL',
                    'obx_count_range': [17, 28],
                    'obx_types': ['CWE', 'NM', 'SN']
                }
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
            'profile': 'IHE_PCD_001^IHE PCD^1.3.6.1.4.1.19376.1.6.1.1.1^ISO',
            'device_class': '70040^MDC_DEV_SYS_ANESTH^MDC',
            'separators': '|^~\\&',
            'processing_id': 'P',
            'accept_ack_type': 'NE',
            'application_ack_type': 'AL',
            'charset': 'UNICODE UTF-8'
        },
        'network_parameters': {
            'wato_ip': '192.168.23.250',
            'wato_mac': '00:0f:14:35:86:ec',
            'wato_eui64': '000F14002D3586ec',
            'server_ip': '192.168.23.200',
            'server_port': 1550,
            'protocol': 'TCP',
            'client_role': 'WATO inicia conexión activa (cliente TCP / DOR IHE PCD-01)',
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