#!/usr/bin/env python3
"""Tests de detect_pcap.py (detección offline sobre PCAP sintético)."""

import struct
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.hl7.parser import parse_hl7_message  # noqa: E402
from src.mllp.framing import frame_hl7_message  # noqa: E402


def _ipv4_header(src: str, dst: str, total_len: int) -> bytes:
    def ip4(s):
        return bytes(int(x) for x in s.split("."))
    return struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, total_len, 0x1234, 0, 64, 6, 0, ip4(src), ip4(dst))


def _tcp_header(sport: int, dport: int, seq: int, payload_len: int) -> bytes:
    offset_flags = (5 << 12) | 0x18  # data offset 5, PSH+ACK
    return struct.pack("!HHIIHHHH", sport, dport, seq, 0,
                       offset_flags, 8192, 0, 0)


def _ethernet_ip_tcp(src_ip: str, dst_ip: str, sport: int, dport: int,
                     seq: int, payload: bytes) -> bytes:
    eth = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"
    tcp = _tcp_header(sport, dport, seq, len(payload))
    ip = _ipv4_header(src_ip, dst_ip, 20 + 20 + len(payload))
    return eth + ip + tcp + payload


def _pcap_bytes(frames_with_ts) -> bytes:
    """PCAP clasico little-endian, linktype Ethernet."""
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for ts, frame in frames_with_ts:
        sec = int(ts)
        usec = int((ts - sec) * 1_000_000)
        out += struct.pack("<IIII", sec, usec, len(frame), len(frame))
        out += frame
    return out


@pytest.fixture
def lab_paths(tmp_path, monkeypatch):
    """Config laboratorio + baseline + reglas reales del repo."""
    monkeypatch.setenv("LAB_AUTHORIZED", "YES")
    marker = ROOT / "LAB_ONLY.marker"
    created = False
    if not marker.exists():
        marker.write_text("LAB ONLY\n", encoding="utf-8")
        created = True
    try:
        from run_experiment import write_lab_config
        outdir = tmp_path / "out"
        outdir.mkdir()
        cfg = write_lab_config(outdir)
        yield cfg, ROOT / "baseline.yaml", ROOT / "config" / "rules.yaml"
    finally:
        if created:
            marker.unlink()


@pytest.fixture
def standby_text():
    import re
    text = (ROOT / "tests" / "conftest.py").read_text(encoding="utf-8")
    return re.search(r'return """(MSH.*?)"""', text, re.S).group(1)


def test_extract_and_detect_offline(tmp_path, lab_paths, standby_text):
    """PCAP sintético: 1 NORMAL (STANDBY) + 1 R-ID-001 (app desconocida)."""
    from detect_pcap import run_detect

    cfg, baseline, rules = lab_paths

    anon_app = standby_text.replace(
        "MINDRAY_WATOPRO-SERIES^000F14002D3586ec^EUI-64",
        "UNKNOWN_LAB_APP^FAC^X", 1)
    anon_app = anon_app.replace("|ORU^R01^ORU_R01|1|P|",
                                "|ORU^R01^ORU_R01|2|P|", 1)

    frame1 = frame_hl7_message(standby_text.encode("utf-8"))
    frame2 = frame_hl7_message(anon_app.encode("utf-8"))
    # 192.168.23.250 = WATO OBSERVADO en baseline.allowed_ips (R-NET-001 ok)
    pkt1 = _ethernet_ip_tcp("192.168.23.250", "192.168.23.200",
                            40000, 1550, 1000, frame1)
    pkt2 = _ethernet_ip_tcp("192.168.23.250", "192.168.23.200",
                            40000, 1550, 1000 + len(frame1), frame2)
    pcap_path = tmp_path / "synthetic.pcap"
    pcap_path.write_bytes(_pcap_bytes([(1750000000.0, pkt1),
                                       (1750000010.0, pkt2)]))

    outdir = tmp_path / "detect"
    manifest = run_detect(pcap_path, outdir, cfg, baseline, rules,
                          label="SYNTH", realtime=False)

    assert manifest["n_mensajes"] == 2
    assert manifest["n_flujos"] == 1
    assert manifest["eventos_normales"] >= 1
    assert manifest["anomalias"] >= 1
    assert manifest["alertas_por_regla"].get("R-ID-001", 0) >= 1

    alerts_file = outdir / "alerts" / "alerts.jsonl"
    assert alerts_file.exists()
    lines = [l for l in alerts_file.read_text(encoding="utf-8").splitlines() if l]
    assert len(lines) == manifest["eventos_totales"]

    import json
    rec = json.loads((outdir / "detect_pcap_manifest.json").read_text(
        encoding="utf-8"))
    assert rec["advertencia"].startswith("LAB ONLY")
    assert rec["pcap_sha256"]
    assert any("R-MLLP-001" in lim for lim in rec["limitaciones"])


def test_offline_no_network_side_effects(tmp_path, lab_paths, standby_text):
    """El modo offline no requiere puerto abierto ni conectividad."""
    from detect_pcap import run_detect
    cfg, baseline, rules = lab_paths
    frame1 = frame_hl7_message(standby_text.encode("utf-8"))
    pkt = _ethernet_ip_tcp("192.168.23.250", "192.168.23.200", 51000, 1550,
                           500, frame1)
    pcap_path = tmp_path / "one.pcap"
    pcap_path.write_bytes(_pcap_bytes([(1750000000.0, pkt)]))
    manifest = run_detect(pcap_path, tmp_path / "o", cfg, baseline, rules)
    assert manifest["n_mensajes"] == 1
    assert manifest["eventos_normales"] == 1
    assert manifest["anomalias"] == 0


def test_anonymize_changes_derived_not_source(tmp_path, lab_paths,
                                              standby_text):
    """La anonimización toca los derivados, no el PCAP original."""
    from detect_pcap import run_detect
    from src.evidence.analyze_evidence import anonymize_hl7_message
    cfg, baseline, rules = lab_paths
    frame1 = frame_hl7_message(standby_text.encode("utf-8"))
    pkt = _ethernet_ip_tcp("192.168.23.250", "192.168.23.200", 51000, 1550,
                           500, frame1)
    pcap_path = tmp_path / "one.pcap"
    original = _pcap_bytes([(1750000000.0, pkt)])
    pcap_path.write_bytes(original)

    import hashlib
    before = hashlib.sha256(pcap_path.read_bytes()).hexdigest()
    run_detect(pcap_path, tmp_path / "o2", cfg, baseline, rules,
               anonymize=True)
    after = hashlib.sha256(pcap_path.read_bytes()).hexdigest()
    assert before == after

    anon = anonymize_hl7_message(standby_text.encode("utf-8"))
    parsed = parse_hl7_message(anon.decode("utf-8"))
    assert parsed is not None
    assert parsed.message_type.startswith("ORU")


def test_realtime_flag_records_limitation(tmp_path, lab_paths,
                                          standby_text):
    from detect_pcap import run_detect
    cfg, baseline, rules = lab_paths
    frame1 = frame_hl7_message(standby_text.encode("utf-8"))
    pkt = _ethernet_ip_tcp("192.168.23.250", "192.168.23.200", 51000, 1550,
                           500, frame1)
    pcap_path = tmp_path / "rt.pcap"
    pcap_path.write_bytes(_pcap_bytes([(1750000000.0, pkt)]))
    manifest = run_detect(pcap_path, tmp_path / "o3", cfg, baseline, rules,
                          realtime=True, max_sleep=0.01)
    assert manifest["realtime"] is True
    assert any("R-TIME-002" in lim for lim in manifest["limitaciones"])
