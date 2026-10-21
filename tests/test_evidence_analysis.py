#!/usr/bin/env python3
"""Pruebas del pipeline de analisis de evidencia (Fase 1).

Usa los PCAP reales de evidence_raw en modo solo lectura; ningun archivo de
evidencia se modifica. Los conteos esperados provienen de la verificacion
independiente de la Fase 1 (2 oraciones de captura con HL7).
"""

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.evidence.analyze_evidence import (  # noqa: E402
    anonymize_hl7_message,
    extract_mllp_messages,
    parse_hl7_message,
    analyze_pcap,
)
from src.evidence.pcap_reader import iter_packets, decode_frame  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
PCAP_DIR = ROOT / "evidence_raw" / "pcap"
PCAP_25 = PCAP_DIR / "LECTURACONACK25AGOSTO.pcapng"
PCAP_27 = PCAP_DIR / "LECTURAACK27AGOSTO.pcapng"
PCAP_ARP = PCAP_DIR / "WATOPARANALIZAR18AGOSTO.pcap"

pytestmark = pytest.mark.skipif(
    not PCAP_25.exists(), reason="evidence_raw/pcap no disponible"
)


def test_pcap_reader_reads_all_captures():
    total = 0
    for p in sorted(PCAP_DIR.glob("*")):
        pkts = iter_packets(p)
        assert pkts, f"captura sin paquetes: {p.name}"
        total += len(pkts)
    assert total > 1000


def test_decode_frame_finds_tcp_payload():
    pkts = iter_packets(PCAP_25)
    tcp_payloads = 0
    for pkt in pkts:
        d = decode_frame(pkt.data)
        if d and d.l4 == "tcp" and d.payload:
            tcp_payloads += 1
    assert tcp_payloads > 0


def test_analyze_pcap_25_agosto():
    sessions, messages = analyze_pcap(str(PCAP_25))
    assert len(sessions) == 1
    s = sessions[0]
    assert s.mllp_messages == 86
    assert s.dest_port == 1550
    assert s.ack_present is True
    assert len(s.ack_times) == 43
    oru = [m for m in messages if m.message_type.startswith("ORU")]
    ack = [m for m in messages if "ACK" in m.message_type]
    assert len(oru) == 43
    assert len(ack) == 43
    assert all(m.ack_received for m in oru)
    assert all(m.ack_time_ms > 0 for m in oru)


def test_analyze_pcap_27_agosto():
    sessions, messages = analyze_pcap(str(PCAP_27))
    assert len(sessions) == 1
    s = sessions[0]
    assert s.mllp_messages == 198
    assert len(s.ack_times) == 99
    assert len(messages) == 198


def test_analyze_pcap_without_hl7_yields_no_sessions():
    sessions, messages = analyze_pcap(str(PCAP_ARP))
    assert sessions == []
    assert messages == []


def test_oru_intervals_are_capture_time():
    _sessions, messages = analyze_pcap(str(PCAP_25))
    oru = [m for m in messages if m.message_type.startswith("ORU")]
    assert oru[0].interval_since_prev == 0.0
    for m in oru[1:]:
        assert 9.0 <= m.interval_since_prev <= 11.0


def test_anonymize_preserves_hl7_structure():
    pv1_fields = ['PV1', '', 'I', 'ICU^101^A^^^HOSP^A'] + [''] * 15 + ['VIS999']
    msg = (
        b"MSH|^~\\&|MINDRAY_WATOPRO-SERIES^000F14002D3586ec^EUI-64||||"
        b"20260825141442-0500||ORU^R01^ORU_R01|1|P|2.6\r"
        b"PID|||12345^5^M11^ADT^MR||DOE^JOHN^^^^^L||19800101|M\r"
        + '|'.join(pv1_fields).encode() + b"\r"
        b"OBR|1|1^MINDRAY|1^X|70040^MDC_DEV_SYS_ANESTH^MDC\r"
        b"OBX|1|NM|150020^MDC_VOL_RESP_TIDAL^MDC||500|mL"
    )
    out = anonymize_hl7_message(msg)
    parsed = parse_hl7_message(out)
    assert parsed["message_type"] == "ORU^R01^ORU_R01"
    assert parsed["message_control_id"] == "1"
    assert parsed["sending_app"] == "MINDRAY_WATOPRO-SERIES^000F14002D3586ec^EUI-64"
    assert parsed["segment_sequence"] == ["MSH", "PID", "PV1", "OBR", "OBX"]
    text = out.decode("utf-8")
    assert "DOE" not in text
    assert "19800101" not in text
    assert "12345" not in text
    assert "VIS999" not in text
    assert "PATIENT_NAME_" in text
    assert "PATIENT_DOB_" in text
    assert "VISIT_NUMBER_" in text


def test_anonymize_is_deterministic():
    msg = b"PID|||ID1||DOE^JOHN||19800101|M"
    a = anonymize_hl7_message(msg)
    b = anonymize_hl7_message(msg)
    assert a == b


def test_anonymize_keeps_empty_pid_untouched():
    msg = b"PID|||^^^^PI||^^^^^^L|||"
    out = anonymize_hl7_message(msg)
    assert out.startswith(b"PID|||")


def test_mllp_extraction_roundtrip():
    payload = b"\x0bMSH|^~\\&|A|B\rMSA|AA|1\x1c\r\x0bsecond\x1c\r"
    msgs = extract_mllp_messages(payload)
    assert len(msgs) == 2
    assert msgs[0][0].startswith(b"MSH|")
    assert msgs[1][0] == b"second"


def test_anonymize_preserves_ihe_pcd_oid():
    msg = (
        b"MSH|^~\\&|MINDRAY_WATOPRO-SERIES^000F14002D3586ec^EUI-64||||"
        b"20260825141442-0500||ORU^R01^ORU_R01|1|P|2.6|||NE|AL||UNICODE UTF-8|||"
        b"IHE_PCD_001^IHE PCD^1.3.6.1.4.1.19376.1.6.1.1.1^ISO\r"
        b"PID|||^^^^PI||^^^^^^L|||\r"
    )
    out = anonymize_hl7_message(msg).decode("utf-8")
    assert "1.3.6.1.4.1.19376.1.6.1.1.1^ISO" in out
    assert "IP_ADDRESS_" not in out
