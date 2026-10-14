"""Lector de capturas en Python puro, solo lectura.

Soporta los dos formatos presentes en la evidencia:
  - pcap clasico (magic usec/nsec, endian grande/pequeno)
  - pcapng (SHB/IDB/EPB, resolucion de timestamp por interfaz)

No usa librerias de terceros para poder ejecutarse en Raspberry Pi OS
sin dependencias de sistema. Limitaciones documentadas: enlace Ethernet
(con VLAN simple opcional), IPv4/IPv6 sin fragmentos reensamblados.
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass
from pathlib import Path

PCAP_MAGICS_US = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">"}
PCAP_MAGICS_NS = {b"\x4d\x3c\xb2\xa1": "<", b"\xa1\xb2\x3c\x4d": ">"}
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"

SHB = 0x0A0D0D0A
IDB = 0x00000001
SPB = 0x00000003
EPB = 0x00000006


@dataclass
class Packet:
    ts: float          # epoch seconds (0.0 si no disponible)
    data: bytes        # trama de enlace


def iter_packets(path: str | Path) -> list[Packet]:
    """Lee todo el archivo de captura en modo solo lectura."""
    with open(path, "rb") as f:
        head = f.read(4)
        f.seek(0)
        if head == PCAPNG_MAGIC:
            return _read_pcapng(f)
        return _read_pcap(f)


def _read_pcap(f) -> list[Packet]:
    gh = f.read(24)
    if len(gh) < 24:
        raise ValueError("pcap: cabecera global truncada")
    magic = gh[:4]
    if magic in PCAP_MAGICS_US:
        endian, scale = PCAP_MAGICS_US[magic], 1e-6
    elif magic in PCAP_MAGICS_NS:
        endian, scale = PCAP_MAGICS_NS[magic], 1e-9
    else:
        raise ValueError(f"pcap: magic desconocido {magic!r}")
    linktype = struct.unpack(endian + "I", gh[20:24])[0]
    if linktype != 1:
        raise ValueError(f"pcap: linktype {linktype} no soportado (se requiere Ethernet=1)")
    out: list[Packet] = []
    while True:
        hdr = f.read(16)
        if not hdr:
            break
        if len(hdr) < 16:
            break
        ts_sec, ts_frac, incl, _orig = struct.unpack(endian + "IIII", hdr)
        data = f.read(incl)
        if len(data) < incl:
            break
        out.append(Packet(ts=ts_sec + ts_frac * scale, data=data))
    return out


def _read_pcapng(f) -> list[Packet]:
    out: list[Packet] = []
    endian = "<"                      # se confirma con el BOM de cada SHB
    ifaces: dict[int, tuple[float, int]] = {}  # if_id -> (factor_ts, linktype)
    while True:
        hdr = f.read(8)
        if not hdr:
            break
        if len(hdr) < 8:
            break
        # El tipo del SHB es fijo en bytes; para los demas se usa el endian de la seccion.
        if hdr[:4] == PCAPNG_MAGIC:
            total_raw = hdr[4:8]
            bom = f.read(4)
            if bom == b"\x1a\x2b\x3c\x4d":
                endian = ">"
            elif bom == b"\x4d\x3c\x2b\x1a":
                endian = "<"
            else:
                raise ValueError("pcapng: byte-order magic invalido")
            total = struct.unpack(endian + "I", total_raw)[0]
            rest = f.read(total - 12)
            if len(rest) < total - 12:
                break
            ifaces = {}
            continue
        btype, total = struct.unpack(endian + "II", hdr)
        if total < 12:
            break
        body = f.read(total - 12)
        tail = f.read(4)
        if len(body) < total - 12 or len(tail) < 4:
            break
        if btype == IDB:
            if_id = len(ifaces)
            linktype = struct.unpack(endian + "H", body[0:2])[0]
            if linktype != 1:
                raise ValueError(f"pcapng: linktype {linktype} no soportado")
            factor = 1e-6
            opt_off = 8
            while opt_off + 4 <= len(body):
                code, olen = struct.unpack(endian + "HH", body[opt_off:opt_off + 4])
                val = body[opt_off + 4:opt_off + 4 + olen]
                if code == 0:
                    break
                if code == 9 and val:                      # if_tsresol
                    b = val[0]
                    factor = (2.0 ** -(b & 0x7F)) if (b & 0x80) else (10.0 ** -b)
                opt_off += 4 + olen + ((4 - (olen % 4)) % 4)
            ifaces[if_id] = (factor, linktype)
        elif btype == EPB:
            if_id, tsh, tsl, caplen, _orig = struct.unpack(endian + "IIIII", body[0:20])
            factor = ifaces.get(if_id, (1e-6, 1))[0]
            data = body[20:20 + caplen]
            if len(data) == caplen:
                ts = ((tsh << 32) | tsl) * factor
                out.append(Packet(ts=ts, data=data))
        elif btype == SPB:
            continue   # sin timestamp: se omite (documentado)
    return out


# ---------------------------------------------------------------- enlace/IP

@dataclass
class Decoded:
    l3: str                 # arp | ipv4 | ipv6 | other
    l4: str = ""            # tcp | udp | icmp | fragment | other | ""
    src_ip: str = ""
    dst_ip: str = ""
    src_mac: str = ""
    dst_mac: str = ""
    sport: int = 0
    dport: int = 0
    seq: int = 0
    flags: int = 0
    payload: bytes = b""
    arp_op: int = 0
    arp_sender_ip: str = ""
    arp_target_ip: str = ""


def _mac(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


def decode_frame(frame: bytes) -> Decoded | None:
    if len(frame) < 14:
        return None
    ethertype = struct.unpack("!H", frame[12:14])[0]
    off = 14
    if ethertype == 0x8100 and len(frame) >= 18:            # VLAN simple
        ethertype = struct.unpack("!H", frame[16:18])[0]
        off = 18
    smac, dmac = _mac(frame[6:12]), _mac(frame[0:6])
    if ethertype == 0x0806:
        return _decode_arp(frame[off:], smac, dmac)
    if ethertype == 0x0800:
        return _decode_ipv4(frame[off:], smac, dmac)
    if ethertype == 0x86DD:
        return _decode_ipv6(frame[off:], smac, dmac)
    return Decoded(l3="other", src_mac=smac, dst_mac=dmac)


def _decode_arp(b: bytes, smac: str, dmac: str) -> Decoded | None:
    if len(b) < 28:
        return Decoded(l3="other", src_mac=smac, dst_mac=dmac)
    op = struct.unpack("!H", b[6:8])[0]
    sender_ip = socket.inet_ntoa(b[14:18])
    target_ip = socket.inet_ntoa(b[24:28])
    return Decoded(l3="arp", src_mac=smac, dst_mac=dmac, arp_op=op,
                   arp_sender_ip=sender_ip, arp_target_ip=target_ip)


def _decode_ipv4(b: bytes, smac: str, dmac: str) -> Decoded | None:
    if len(b) < 20:
        return None
    ver_ihl = b[0]
    if ver_ihl >> 4 != 4:
        return None
    ihl = (ver_ihl & 0x0F) * 4
    total_len = struct.unpack("!H", b[2:4])[0]
    frag = struct.unpack("!H", b[6:8])[0]
    frag_off, mf = frag & 0x1FFF, (frag >> 13) & 1
    proto = b[9]
    src = socket.inet_ntoa(b[12:16])
    dst = socket.inet_ntoa(b[16:20])
    payload = b[ihl:total_len] if total_len <= len(b) else b[ihl:]
    d = Decoded(l3="ipv4", src_ip=src, dst_ip=dst, src_mac=smac, dst_mac=dmac)
    if frag_off or mf:
        d.l4 = "fragment"
        return d
    if proto == 6:
        _decode_tcp(payload, d)
    elif proto == 17:
        d.l4 = "udp"
        if len(payload) >= 4:
            d.sport, d.dport = struct.unpack("!HH", payload[0:4])
    elif proto == 1:
        d.l4 = "icmp"
    else:
        d.l4 = "other"
    return d


def _decode_ipv6(b: bytes, smac: str, dmac: str) -> Decoded | None:
    if len(b) < 40 or (b[0] >> 4) != 6:
        return None
    nxt = b[6]
    src = socket.inet_ntop(socket.AF_INET6, b[8:24])
    dst = socket.inet_ntop(socket.AF_INET6, b[24:40])
    payload = b[40:]
    d = Decoded(l3="ipv6", src_ip=src, dst_ip=dst, src_mac=smac, dst_mac=dmac)
    if nxt == 6:
        _decode_tcp(payload, d)
    elif nxt == 17:
        d.l4 = "udp"
        if len(payload) >= 4:
            d.sport, d.dport = struct.unpack("!HH", payload[0:4])
    else:
        d.l4 = "other"       # extension headers: fuera de alcance (documentado)
    return d


def _decode_tcp(b: bytes, d: Decoded) -> None:
    d.l4 = "tcp"
    if len(b) < 20:
        return
    d.sport, d.dport, d.seq = struct.unpack("!HHI", b[0:8])
    off = (b[12] >> 4) * 4
    d.flags = b[13]
    d.payload = b[off:] if off <= len(b) else b""
