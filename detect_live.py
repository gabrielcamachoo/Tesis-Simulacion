#!/usr/bin/env python3
"""
detect_live.py - Detección PASIVA EN VIVO para la Raspberry Pi (puerto espejo).

Reemplaza el esquema "tcpdump -G 60 + detect_pcap.py por archivo", que
procesaba cada minuto por separado y perdía el estado del motor entre
archivos (un silencio de 45 s que cruzaba el corte de 60 s no alertaba, y si
el canal moría del todo no se creaba archivo nuevo y nunca había alerta).

Aquí un solo proceso mantiene el motor vivo todo el tiempo:

  tcpdump -Z root -U -w - "tcp port 1550"  ──stdout──►  detect_live.py
                                                         │ reensamblado TCP
                                                         │ incremental por flujo
                                                         │ delimitación MLLP
                                                         │ motor de detección
                                                         │ (mismo de detect_pcap)
                                                         ├► alerts/alerts.jsonl
                                                         ├► pcap/ (evidencia
                                                         │   rotada + SHA256SUMS)
                                                         └► detect_live_summary.json

- Vigilante de silencio (Enmienda E3) cada segundo, igual que el receptor:
  si el canal deja de transmitir, R-TIME-002 alerta aunque no llegue nada más.
- Resumen por regla y por IP de origen: así se distingue un ataque detectado
  por su contenido de uno detectado solo porque viene de una IP no autorizada
  (R-NET-001).
- --extra-allowed-ips: autoriza IPs adicionales SOLO para esta corrida (no
  toca baseline.yaml); sirve para una campaña "atacante interno" donde el
  origen está autorizado y deben disparar las reglas de contenido.
- Solo lee: no abre conexiones ni reenvía bytes. Exige LAB_AUTHORIZED=YES y
  LAB_ONLY.marker, como el resto del laboratorio.

Uso (Pi, desde la raíz del repo):
    LAB_AUTHORIZED=YES python detect_live.py --interface eth0 --outdir runs/live
Uso (stdin, p. ej. reproducir una captura):
    tcpdump -r X.pcap -w - | LAB_AUTHORIZED=YES python detect_live.py --input -
"""

import argparse
import hashlib
import json
import os
import platform
import signal
import struct
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent

from src.evidence.analyze_evidence import anonymize_hl7_message
from src.evidence.pcap_reader import decode_frame
from src.mllp.framing import EOM, SB
from src.config.settings import load_settings
from src.detection.baseline import load_baseline
from src.detection.rules import RuleSet
from src.detection.engine import DetectionEngine
from src.alerting.json_logger import AlertLogger
from src.hl7.parser import parse_hl7_message

LAB_ONLY_WARNING = (
    "LAB ONLY — monitoreo pasivo de la red aislada del laboratorio; no abrir ni "
    "reenviar tráfico hacia dispositivos médicos, hospitales o sistemas de terceros.")

TCP_FIN, TCP_SYN, TCP_RST, TCP_ACK = 0x01, 0x02, 0x04, 0x10
MAX_PENDING_BYTES = 1 << 20     # 1 MiB fuera de orden por flujo antes de resincronizar
GAP_TIMEOUT_S = 2.0             # hueco de secuencia sin rellenar tras 2 s -> se salta
MAX_BUFFER_BYTES = 1 << 20      # 1 MiB sin cierre MLLP -> se descarta (basura/flood)


def _seq_diff(a: int, b: int) -> int:
    """a - b en aritmética de secuencia TCP (módulo 2^32, con signo)."""
    return ((a - b + (1 << 31)) % (1 << 32)) - (1 << 31)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


class _Flow:
    """Estado de un flujo emisor -> :puerto MLLP."""

    __slots__ = ("src_ip", "src_port", "next_seq", "pending", "pending_bytes",
                 "buf", "last_ts", "idx")

    def __init__(self, src_ip, src_port, idx):
        self.src_ip = src_ip
        self.src_port = src_port
        self.next_seq = None
        self.pending = {}
        self.pending_bytes = 0
        self.buf = bytearray()
        self.last_ts = None
        self.idx = idx


class PcapRotator:
    """Guarda los paquetes crudos en pcap clásico rotado (evidencia)."""

    def __init__(self, outdir: Path, rotate_seconds: float, linktype: int, snaplen: int):
        self.dir = outdir / "pcap"
        self.dir.mkdir(parents=True, exist_ok=True)
        self.rotate = rotate_seconds
        self.linktype = linktype
        self.snaplen = snaplen
        self.fh = None
        self.path = None
        self.opened_at = 0.0
        self.files = []

    def _open(self, ts: float):
        name = datetime.fromtimestamp(ts).strftime("live_%Y%m%d_%H%M%S.pcap")
        self.path = self.dir / name
        n = 1
        while self.path.exists():
            self.path = self.dir / name.replace(".pcap", f"_{n}.pcap")
            n += 1
        self.fh = open(self.path, "wb")
        self.fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0,
                                  self.snaplen, self.linktype))
        self.opened_at = ts

    def _close(self):
        if self.fh is None:
            return
        self.fh.close()
        digest = sha256_file(self.path)
        with open(self.dir / "SHA256SUMS.txt", "a", encoding="utf-8") as s:
            s.write(f"{digest}  {self.path.name}\n")
        self.files.append({"archivo": self.path.name, "sha256": digest})
        self.fh = None

    def write(self, ts: float, data: bytes):
        if self.fh is None or (self.rotate > 0 and ts - self.opened_at >= self.rotate):
            self._close()
            self._open(ts)
        sec = int(ts)
        usec = int(round((ts - sec) * 1e6))
        if usec >= 1000000:
            sec, usec = sec + 1, 0
        self.fh.write(struct.pack("<IIII", sec, usec, len(data), len(data)) + data)
        self.fh.flush()

    def close(self):
        self._close()


class LiveDetector:
    """Motor de detección alimentado paquete a paquete (estado continuo)."""

    def __init__(self, outdir: Path, config: Path, baseline_path: Path,
                 rules_path: Path, label: str = "live", port: int = 1550,
                 anonymize: bool = True, extra_allowed_ips=None):
        self.outdir = outdir
        self.label = label
        self.port = port
        self.anonymize = anonymize
        self.config = config
        self.baseline_path = baseline_path
        self.rules_path = rules_path
        self.started = datetime.now(timezone.utc)

        settings = load_settings(str(config))
        settings.evidence.output_dir = str(outdir)
        self.baseline = load_baseline(str(baseline_path))
        self.extra_allowed_ips = sorted(set(extra_allowed_ips or []))
        for ip in self.extra_allowed_ips:
            self.baseline.allowed_ips.add(ip)
        self.engine = DetectionEngine(settings, self.baseline, RuleSet(str(rules_path)))
        self.alert_logger = AlertLogger(settings, evidence_writer=None)
        self._lock = threading.Lock()

        self.flows = {}
        self.n_flows = 0
        self.packets = 0
        self.messages = 0
        self.skipped = 0
        self.normals = 0
        self.anomalies = 0
        self.by_rule = {}
        self.by_source = {}
        self.by_source_rule = {}
        self.silence_alerts = 0
        self.resyncs = 0
        self.discarded_bytes = 0
        self.last_packet_ts = None
        self.last_packet_mono = None
        self.lat_ms = []

    # ------------------------------------------------------------ paquetes
    def feed_packet(self, ts: float, data: bytes):
        with self._lock:
            self.packets += 1
            self.last_packet_ts = ts
            self.last_packet_mono = time.monotonic()
            d = decode_frame(data)
            if d is None or d.l4 != "tcp" or self.port not in (d.sport, d.dport):
                return
            if d.dport != self.port:
                # Sentido receptor -> emisor (ACK HL7): solo cierre de flujo
                if d.flags & (TCP_FIN | TCP_RST):
                    self.flows.pop((d.dst_ip, d.dport, d.src_ip, d.sport), None)
                return
            key = (d.src_ip, d.sport, d.dst_ip, d.dport)
            fl = self.flows.get(key)
            if d.flags & TCP_SYN and not d.flags & TCP_ACK:
                fl = _Flow(d.src_ip, d.sport, self.n_flows)
                self.n_flows += 1
                fl.next_seq = (d.seq + 1) & 0xFFFFFFFF
                self.flows[key] = fl
            elif fl is None:
                # Conexión ya abierta cuando empezó la captura
                fl = _Flow(d.src_ip, d.sport, self.n_flows)
                self.n_flows += 1
                self.flows[key] = fl
            if d.payload:
                self._segment(fl, d.seq, d.payload, ts)
            if d.flags & (TCP_FIN | TCP_RST):
                self.flows.pop(key, None)

    def _segment(self, fl: _Flow, seq: int, payload: bytes, ts: float):
        if fl.next_seq is None:
            fl.next_seq = seq
        off = _seq_diff(seq, fl.next_seq)
        if off + len(payload) <= 0:
            return                                  # retransmisión ya vista
        if off > 0:
            if seq not in fl.pending:               # llegó adelantado
                fl.pending[seq] = (payload, ts)
                fl.pending_bytes += len(payload)
            oldest = min(t for _p, t in fl.pending.values())
            if fl.pending_bytes > MAX_PENDING_BYTES or ts - oldest > GAP_TIMEOUT_S:
                # Un segmento nunca llegó a la captura (pérdida en el puerto
                # espejo): se salta el hueco. El mensaje partido se descarta
                # y el resto del flujo sigue procesándose.
                first = min(fl.pending, key=lambda s: _seq_diff(s, fl.next_seq))
                fl.next_seq = first
                self.discarded_bytes += len(fl.buf)
                fl.buf.clear()
                self.resyncs += 1
                self._drain(fl)
            return
        fl.buf += payload[-off:] if off < 0 else payload
        fl.next_seq = (fl.next_seq + len(payload) + off) & 0xFFFFFFFF
        self._extract(fl, ts)
        self._drain(fl)

    def _drain(self, fl: _Flow):
        """Encadena los segmentos adelantados que ya son contiguos."""
        while fl.pending:
            hit = None
            for s, (p, pts) in fl.pending.items():
                o = _seq_diff(s, fl.next_seq)
                if o <= 0:
                    hit = (s, p, pts, o)
                    break
            if hit is None:
                break
            s, p, pts, o = hit
            del fl.pending[s]
            fl.pending_bytes -= len(p)
            if o + len(p) > 0:
                fl.buf += p[-o:] if o < 0 else p
                fl.next_seq = (fl.next_seq + len(p) + o) & 0xFFFFFFFF
                # Cada segmento rellenado entrega sus mensajes con su propia
                # hora de captura (no con la del paquete que destrabó el hueco)
                self._extract(fl, pts)

    def _extract(self, fl: _Flow, ts: float):
        # Hora de entrega monótona por flujo (Enmienda E5)
        t = ts if fl.last_ts is None else max(ts, fl.last_ts)
        fl.last_ts = t
        while True:
            sb = fl.buf.find(SB)
            if sb < 0:
                self.discarded_bytes += len(fl.buf)
                fl.buf.clear()
                return
            eom = fl.buf.find(EOM, sb + 1)
            if eom < 0:
                if sb > 0:
                    self.discarded_bytes += sb
                    del fl.buf[:sb]
                if len(fl.buf) > MAX_BUFFER_BYTES:
                    self.discarded_bytes += len(fl.buf)
                    fl.buf.clear()
                return
            content = bytes(fl.buf[sb + 1:eom])
            del fl.buf[:eom + len(EOM)]
            self._process(fl, content, t)

    def _process(self, fl: _Flow, content: bytes, ts: float):
        raw = anonymize_hl7_message(content) if self.anonymize else content
        parsed = parse_hl7_message(raw.decode("utf-8", errors="replace"))
        if parsed is None or not parsed.segments:
            self.skipped += 1
            return
        self.messages += 1
        session_id = f"live:{fl.idx}:{fl.src_ip}:{fl.src_port}"
        result = self.engine.process_message(
            session_id=session_id, source_ip=fl.src_ip, source_port=fl.src_port,
            parsed_message=parsed, raw_bytes=raw, mllp_frame=SB + raw + EOM,
            capture_time=ts)
        self.lat_ms.append(result.processing_time_ms)
        if len(self.lat_ms) > 10000:
            self.lat_ms = self.lat_ms[-5000:]
        if result.alerts:
            for alert in result.alerts:
                self._count(alert.rule_id, fl.src_ip)
                self.alert_logger.log_alert(alert)
        else:
            self.normals += 1
            self.alert_logger.log_normal(
                session_id=session_id, source=f"{fl.src_ip}:{fl.src_port}",
                msg_control_id=parsed.message_control_id or "N/A",
                state=result.session_state.current_state,
                evidence_hash=hashlib.sha256(raw).hexdigest())

    def _count(self, rule_id: str, src_ip: str):
        self.anomalies += 1
        self.by_rule[rule_id] = self.by_rule.get(rule_id, 0) + 1
        self.by_source[src_ip] = self.by_source.get(src_ip, 0) + 1
        per = self.by_source_rule.setdefault(src_ip, {})
        per[rule_id] = per.get(rule_id, 0) + 1

    # ------------------------------------------------------------ silencio
    def tick(self, now: float = None):
        """Vigilante de silencio (E3). Llamar cada ~1 s.

        El reloj es el de la captura: hora del último paquete + tiempo real
        transcurrido desde que llegó. En vivo coincide con el reloj de pared;
        al reproducir un archivo no inventa silencios por la fecha antigua
        de la captura.
        """
        with self._lock:
            if now is None:
                if self.last_packet_ts is None:
                    return None
                now = self.last_packet_ts + (time.monotonic() - self.last_packet_mono)
            alert = self.engine.check_silence(now)
            if alert:
                self.silence_alerts += 1
                src = alert.source.split(":")[0] if alert.source else "N/A"
                self._count(alert.rule_id, src)
                self.alert_logger.log_alert(alert)
            return alert

    # ------------------------------------------------------------ salida
    def summary(self, final: bool = False, pcap_files=None) -> dict:
        with self._lock:
            lat = sorted(self.lat_ms)
            return {
                "tool": "detect_live.py",
                "schema_version": "1.0",
                "label": self.label,
                "modo": "pasivo en vivo (puerto espejo); estado continuo del motor",
                "estado": "finalizado" if final else "en curso",
                "timestamp_utc_inicio": self.started.isoformat(),
                "timestamp_utc_actual": datetime.now(timezone.utc).isoformat(),
                "paquetes": self.packets,
                "flujos": self.n_flows,
                "mensajes": self.messages,
                "mensajes_no_parseables": self.skipped,
                "eventos_normales": self.normals,
                "anomalias": self.anomalies,
                "alertas_por_regla": dict(sorted(self.by_rule.items())),
                "alertas_por_ip_origen": dict(sorted(self.by_source.items())),
                "alertas_por_ip_y_regla": {k: dict(sorted(v.items()))
                                           for k, v in sorted(self.by_source_rule.items())},
                "alertas_silencio_e3": self.silence_alerts,
                "ips_autorizadas": sorted(self.baseline.allowed_ips),
                "ips_autorizadas_extra_solo_esta_corrida": self.extra_allowed_ips,
                "resincronizaciones_tcp": self.resyncs,
                "bytes_descartados_sin_mllp": self.discarded_bytes,
                "latencia_proceso_ms": ({"p50": round(lat[len(lat) // 2], 4),
                                         "p95": round(lat[int(len(lat) * 0.95) - 1], 4),
                                         "max": round(lat[-1], 4)} if lat else None),
                "pcap_evidencia": pcap_files or [],
                "anonimizado": self.anonymize,
                "config_sha256": sha256_file(self.config) if self.config.exists() else None,
                "baseline_sha256": sha256_file(self.baseline_path)
                if self.baseline_path.exists() else None,
                "rules_sha256": sha256_file(self.rules_path)
                if self.rules_path.exists() else None,
                "runtime": {"platform": platform.platform(),
                            "python": platform.python_version()},
                "advertencia": LAB_ONLY_WARNING,
            }

    def close(self):
        self.alert_logger.close()


def _write_json_atomic(path: Path, data: dict):
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, path)


def read_pcap_stream(stream, on_header, on_packet):
    """Lee pcap clásico de un stream (tcpdump -w -) paquete a paquete."""
    def read_exact(n):
        out = bytearray()
        while len(out) < n:
            chunk = stream.read(n - len(out))
            if not chunk:
                return None
            out += chunk
        return bytes(out)

    gh = read_exact(24)
    if gh is None:
        return
    magic = gh[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian = "<"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian = ">"
    else:
        raise ValueError("la entrada no es pcap clásico (¿tcpdump -w - ?)")
    scale = 1e-9 if magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d") else 1e-6
    snaplen, linktype = struct.unpack(endian + "II", gh[16:24])
    if linktype != 1:
        raise ValueError(f"linktype {linktype} no soportado (se requiere Ethernet=1; "
                         "capture en una interfaz concreta, no en 'any')")
    on_header(linktype, snaplen)
    while True:
        rh = read_exact(16)
        if rh is None:
            return
        sec, frac, incl, _orig = struct.unpack(endian + "IIII", rh)
        data = read_exact(incl)
        if data is None:
            return
        on_packet(sec + frac * scale, data)


def parse_args():
    p = argparse.ArgumentParser(description="Detección pasiva en vivo HL7/MLLP (Pi)")
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--interface", help="Interfaz de captura (lanza tcpdump -Z root -U -w -)")
    src.add_argument("--input", help="Stream pcap clásico ('-' = stdin) o archivo .pcap")
    p.add_argument("--bpf", default="", help="Filtro BPF (default: 'tcp port <port>')")
    p.add_argument("--port", type=int, default=1550)
    p.add_argument("--outdir", default="", help="Default: runs/live_<label>_<ts>")
    p.add_argument("--label", default="live")
    p.add_argument("--config", default=str(ROOT / "src" / "config" / "settings.yaml"))
    p.add_argument("--baseline", default=str(ROOT / "baseline.yaml"))
    p.add_argument("--rules", default=str(ROOT / "config" / "rules.yaml"))
    p.add_argument("--extra-allowed-ips", default="",
                   help="IPs autorizadas adicionales SOLO para esta corrida, separadas por comas")
    p.add_argument("--rotate-seconds", type=float, default=3600.0,
                   help="Rotación de los pcap de evidencia (default 3600 s; 0 = un solo archivo)")
    p.add_argument("--summary-every", type=float, default=30.0,
                   help="Cada cuántos segundos reescribir el resumen y loguear contadores")
    p.add_argument("--no-anonymize", action="store_true")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    if os.environ.get("LAB_AUTHORIZED", "").strip().upper() != "YES":
        print("ERROR: define LAB_AUTHORIZED=YES primero", file=sys.stderr)
        return 3
    if not (ROOT / "LAB_ONLY.marker").exists():
        print("ERROR: falta LAB_ONLY.marker en la raíz del repo", file=sys.stderr)
        return 3

    ts_dir = datetime.now().strftime("%Y%m%d_%H%M%S")
    outdir = Path(args.outdir) if args.outdir else ROOT / "runs" / f"live_{args.label}_{ts_dir}"
    if not outdir.is_absolute():
        outdir = ROOT / outdir
    outdir.mkdir(parents=True, exist_ok=True)

    config = Path(args.config)
    if not config.is_absolute():
        config = ROOT / config
    if config.resolve() == (ROOT / "src" / "config" / "settings.yaml").resolve():
        from run_experiment import write_lab_config
        config = write_lab_config(outdir)

    extra = [ip.strip() for ip in args.extra_allowed_ips.split(",") if ip.strip()]
    det = LiveDetector(outdir, config, Path(args.baseline), Path(args.rules),
                       label=args.label, port=args.port,
                       anonymize=not args.no_anonymize, extra_allowed_ips=extra)
    summary_path = outdir / "detect_live_summary.json"
    stop = threading.Event()
    rot = {"r": None}
    proc = None

    def on_header(linktype, snaplen):
        rot["r"] = PcapRotator(outdir, args.rotate_seconds, linktype, snaplen)

    def on_packet(ts, data):
        rot["r"].write(ts, data)
        det.feed_packet(ts, data)

    def files():
        r = rot["r"]
        return list(r.files) if r else []

    def watchdog():
        last_summary = time.monotonic()
        while not stop.wait(1.0):
            det.tick()
            if time.monotonic() - last_summary >= args.summary_every:
                last_summary = time.monotonic()
                s = det.summary(pcap_files=files())
                _write_json_atomic(summary_path, s)
                print(f"[live] paquetes={s['paquetes']} mensajes={s['mensajes']} "
                      f"normales={s['eventos_normales']} anomalías={s['anomalias']} "
                      f"por_regla={s['alertas_por_regla']} "
                      f"por_ip={s['alertas_por_ip_origen']}", flush=True)

    def on_signal(signum, _frame):
        stop.set()
        if proc and proc.poll() is None:
            proc.terminate()

    signal.signal(signal.SIGINT, on_signal)
    signal.signal(signal.SIGTERM, on_signal)

    if args.interface:
        bpf = args.bpf or f"tcp port {args.port}"
        # -Z root: sin esto tcpdump cambia al usuario 'tcpdump' y no puede
        # escribir en volúmenes de root. -U: un paquete por escritura.
        cmd = ["tcpdump", "-Z", "root", "-i", args.interface, "-nn", "-s0",
               "-U", "-w", "-", bpf]
        print(f"[live] {' '.join(cmd)}", flush=True)
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE)
        stream = proc.stdout
    elif args.input == "-":
        stream = sys.stdin.buffer
    else:
        stream = open(args.input, "rb")

    print(f"[live] salidas en {outdir}", flush=True)
    if extra:
        print(f"[live] IPs autorizadas extra (solo esta corrida): {extra}", flush=True)
    threading.Thread(target=watchdog, daemon=True).start()
    rc = 0
    try:
        read_pcap_stream(stream, on_header, on_packet)
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        rc = 2
    finally:
        stop.set()
        if proc and proc.poll() is None:
            proc.terminate()
        if rot["r"]:
            rot["r"].close()
        s = det.summary(final=True, pcap_files=files())
        det.close()
        _write_json_atomic(summary_path, s)
        print(f"[live] FIN mensajes={s['mensajes']} normales={s['eventos_normales']} "
              f"anomalías={s['anomalias']} por_regla={s['alertas_por_regla']} "
              f"por_ip={s['alertas_por_ip_origen']}", flush=True)
        print(f"Resumen: {summary_path}", flush=True)
    if proc:
        proc.wait(timeout=10)
        if proc.returncode not in (0, None, -15, 143) and rc == 0:
            print(f"ERROR: tcpdump terminó con código {proc.returncode}", file=sys.stderr)
            rc = 4
    return rc


if __name__ == "__main__":
    sys.exit(main())
