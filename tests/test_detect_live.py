#!/usr/bin/env python3
"""
Cierre de código (rama final, 2026-11-18): detect_live.py, detección pasiva
en vivo de la Raspberry Pi.

Se alimenta el detector con las capturas reales como si llegaran por
tcpdump -U -w - (pcap clásico por stdin) y se verifica que:
  1. da exactamente las mismas alertas que detect_pcap.py (mismo motor);
  2. las capturas reales STANDBY y RUNNING siguen en 0 falsos positivos;
  3. un silencio de 45 s se detecta aunque cruce un corte de 60 s
     (con tcpdump -G 60 + detect_pcap por archivo se perdía);
  4. el vigilante de silencio alerta si el canal muere, una vez por episodio;
  5. el resumen separa alertas por IP: tráfico normal desde una IP no
     autorizada sale como R-NET-001, y con --extra-allowed-ips no;
  6. segmentos TCP desordenados o retransmitidos no cambian el resultado;
  7. los pcap de evidencia rotan y quedan con su SHA-256.
"""

import hashlib
import io
import os
import socket
import struct
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.evidence.pcap_reader import iter_packets  # noqa: E402
from detect_live import LiveDetector, PcapRotator, read_pcap_stream  # noqa: E402
from detect_pcap import run_detect  # noqa: E402
from run_experiment import write_lab_config  # noqa: E402

PCAP = ROOT / "evidence_raw" / "pcap"
STANDBY = PCAP / "LECTURACONACK25AGOSTO.pcapng"
RUNNING = PCAP / "LECTURAACK27AGOSTO.pcapng"
WATO_IP = socket.inet_aton("192.168.23.250")


@pytest.fixture(autouse=True)
def _lab(monkeypatch):
    monkeypatch.setenv("LAB_AUTHORIZED", "YES")


def _packets(path):
    return [(p.ts, p.data) for p in iter_packets(str(path)) if p.ts]


def _stream(packets) -> io.BytesIO:
    buf = io.BytesIO()
    buf.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for ts, data in packets:
        sec = int(ts)
        usec = int(round((ts - sec) * 1e6))
        if usec >= 1000000:
            sec, usec = sec + 1, 0
        buf.write(struct.pack("<IIII", sec, usec, len(data), len(data)) + data)
    buf.seek(0)
    return buf


def _detector(tmp_path, **kw) -> LiveDetector:
    out = tmp_path / "live"
    out.mkdir(parents=True, exist_ok=True)
    return LiveDetector(out, write_lab_config(out), ROOT / "baseline.yaml",
                        ROOT / "config" / "rules.yaml", **kw)


def _run(tmp_path, packets, **kw) -> LiveDetector:
    det = _detector(tmp_path, **kw)
    read_pcap_stream(_stream(packets), lambda *a: None, det.feed_packet)
    det.close()
    return det


@pytest.mark.parametrize("pcap,n", [(STANDBY, 43), (RUNNING, 99)])
def test_capturas_reales_cero_falsos_positivos(tmp_path, pcap, n):
    det = _run(tmp_path, _packets(pcap))
    assert det.messages == n
    assert det.anomalies == 0, det.by_rule
    assert det.normals == n


@pytest.mark.parametrize("pcap", sorted(PCAP.glob("*.pcap*")), ids=lambda p: p.name)
def test_mismas_alertas_que_detect_pcap(tmp_path, pcap):
    out = tmp_path / "offline"
    out.mkdir()
    ref = run_detect(pcap, out, write_lab_config(out), ROOT / "baseline.yaml",
                     ROOT / "config" / "rules.yaml")
    det = _run(tmp_path, _packets(pcap))
    assert det.messages == ref["n_mensajes"]
    assert det.by_rule == ref["alertas_por_regla"]
    assert det.normals == ref["eventos_normales"]


def test_silencio_que_cruza_el_corte_de_60s(tmp_path):
    pk = _packets(STANDBY)
    t0 = pk[0][0]
    sin_hueco = [p for p in pk if not (130 <= p[0] - t0 < 175)]
    det = _run(tmp_path, sin_hueco)
    # Quitar paquetes deja un hueco de secuencia TCP, como una pérdida en el
    # puerto espejo: el detector lo salta y sigue con el flujo.
    assert det.resyncs >= 1
    assert det.by_rule == {"R-TIME-002": 1}


def test_vigilante_alerta_si_el_canal_muere(tmp_path):
    pk = _packets(STANDBY)
    det = _detector(tmp_path)
    read_pcap_stream(_stream(pk), lambda *a: None, det.feed_packet)
    ultimo = pk[-1][0]
    assert det.tick(now=ultimo + 5) is None           # dentro de la cadencia
    alerta = det.tick(now=ultimo + 20)                # 20 s > 15 s de límite
    assert alerta is not None and alerta.rule_id == "R-TIME-002"
    assert det.tick(now=ultimo + 40) is None          # una vez por episodio
    assert det.silence_alerts == 1
    det.close()


def _desde_ip(packets, nueva):
    out = []
    ip = socket.inet_aton(nueva)
    for ts, data in packets:
        d = bytearray(data)
        if len(d) > 34 and d[12:14] == b"\x08\x00":
            if d[26:30] == WATO_IP:
                d[26:30] = ip
            if d[30:34] == WATO_IP:
                d[30:34] = ip
        out.append((ts, bytes(d)))
    return out


def test_ip_no_autorizada_queda_separada_en_el_resumen(tmp_path):
    pk = _desde_ip(_packets(STANDBY), "192.168.5.50")
    det = _run(tmp_path, pk)
    assert det.by_rule == {"R-NET-001": 43}
    assert det.by_source == {"192.168.5.50": 43}
    s = det.summary()
    assert s["alertas_por_ip_y_regla"] == {"192.168.5.50": {"R-NET-001": 43}}


def test_ip_extra_autorizada_solo_para_la_corrida(tmp_path):
    pk = _desde_ip(_packets(STANDBY), "192.168.5.50")
    det = _run(tmp_path / "a", pk, extra_allowed_ips=["192.168.5.50"])
    assert det.anomalies == 0 and det.normals == 43
    # baseline.yaml no se toca
    assert "192.168.5.50" not in (ROOT / "baseline.yaml").read_text(encoding="utf-8")


def test_segmentos_desordenados_y_retransmitidos(tmp_path):
    pk = _packets(RUNNING)
    revuelto = []
    i = 0
    while i < len(pk):
        if i + 1 < len(pk) and i % 7 == 0:
            revuelto += [pk[i + 1], pk[i], pk[i]]       # adelantado + duplicado
            i += 2
        else:
            revuelto.append(pk[i])
            i += 1
    det = _run(tmp_path, revuelto)
    assert det.messages == 99
    assert det.anomalies == 0, det.by_rule


def test_pcap_de_evidencia_rota_con_sha256(tmp_path):
    pk = _packets(STANDBY)
    rot = PcapRotator(tmp_path, rotate_seconds=60, linktype=1, snaplen=65535)
    for ts, data in pk:
        rot.write(ts, data)
    rot.close()
    archivos = sorted((tmp_path / "pcap").glob("live_*.pcap"))
    duracion = pk[-1][0] - pk[0][0]
    assert len(archivos) == int(duracion // 60) + 1
    sums = (tmp_path / "pcap" / "SHA256SUMS.txt").read_text().split("\n")
    for linea in filter(None, sums):
        h, nombre = linea.split("  ")
        assert hashlib.sha256((tmp_path / "pcap" / nombre).read_bytes()).hexdigest() == h
    # Los archivos rotados juntos contienen exactamente los paquetes originales
    total = sum(len(list(iter_packets(str(a)))) for a in archivos)
    assert total == len(pk)
