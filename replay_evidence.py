#!/usr/bin/env python3
"""
replay_evidence.py - Replay de evidencia capturada (corpus negativo, H3).

Extrae los mensajes ORU^R01 MLLP en dirección emisor->receptor (cliente -> :1550)
desde un PCAP de la evidencia usando el MISMO pipeline de analyze_evidence
(reensamblado TCP por secuencia + extracción MLLP + anonimización por defecto)
y los reenvía al receptor del laboratorio en modo observador (receptor
--no-ack) con el pacing original de captura.

Protocolo §3.2 / §5.3:
  - STANDBY (evidence_raw/pcap/LECTURACONACK25AGOSTO.pcapng): expectativa FP = 0.
  - RUNNING (evidence_raw/pcap/LECTURAACK27AGOSTO.pcapng): se ejecuta y los FP
    se REPORTAN sin umbral previo (códigos NM/SN NO_VERIFICADOS anticipados).

Corpus: solo los ORU del lado emisor. Los ACK de la captura no se reenvían:
el receptor del laboratorio ocupa el lado servidor (los ACK salen de él hacia
el emisor), por lo que el corpus inbound aplicable es ORU. Este desvío respecto
al conteo 142 ORU + 142 ACK del template queda registrado en el manifiesto.

Uso:
  LAB_AUTHORIZED=YES python replay_evidence.py ^
      --pcap evidence_raw/pcap/LECTURACONACK25AGOSTO.pcapng ^
      --label STANDBY --start-receiver ^
      --outdir analysis_output/validation/replay_STANDBY_<ts>
  python replay_evidence.py --pcap <pcap> --dry-run   # solo extracción
"""

import argparse
import hashlib
import json
import os
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PY = sys.executable

from src.evidence.analyze_evidence import (
    MLLP_PORT, _flow_key, _reassemble_stream, anonymize_hl7_message,
    extract_mllp_messages, parse_hl7_message,
)
from src.evidence.pcap_reader import decode_frame, iter_packets
from src.mllp.framing import EOM, SB


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def extract_oru_flows(pcap_path: Path):
    """Flujos TCP (orden cronológico) con mensajes ORU emisor->receptor.

    Cada flujo = una conexión TCP original; cada mensaje = (content_bytes,
    ts_captura). Réplica de la lógica de analyze_pcap solo para el lado
    'fwd' (dst == MLLP_PORT), que es la dirección emisor -> WATO.
    """
    flows = {}
    for pkt in iter_packets(str(pcap_path)):
        d = decode_frame(pkt.data)
        if d is None or d.l4 != "tcp":
            continue
        if MLLP_PORT not in (d.sport, d.dport):
            continue
        key = _flow_key(d)
        fl = flows.setdefault(key, {"fwd": [], "t0": None})
        if pkt.ts:
            fl["t0"] = pkt.ts if fl["t0"] is None else min(fl["t0"], pkt.ts)
        if d.dport == MLLP_PORT and d.payload:
            fl["fwd"].append((d.seq, pkt.ts, d.payload))

    out = []
    for key, fl in sorted(flows.items(), key=lambda kv: (kv[1]["t0"] or 0)):
        if not fl["fwd"]:
            continue
        buf, ts_arr = _reassemble_stream(fl["fwd"])
        msgs = []
        for content, start, _end in extract_mllp_messages(buf):
            content = anonymize_hl7_message(content)
            meta = parse_hl7_message(content)
            if not meta:
                continue
            if not str(meta.get("message_type", "")).startswith("ORU"):
                continue
            ts = ts_arr[start] if start < len(ts_arr) else (fl["t0"] or 0.0)
            msgs.append((content, ts))
        if msgs:
            out.append({
                "flow": f"{key[0][0]}:{key[0][1]} -> {key[1][0]}:{key[1][1]}",
                "t0": fl["t0"],
                "messages": msgs,
            })
    return out


def flatten(flows):
    flat = []
    for fl in flows:
        flat.extend(fl["messages"])
    return flat


def interval_stats(flat):
    deltas = [flat[i][1] - flat[i - 1][1] for i in range(1, len(flat))]
    if not deltas:
        return {"n": 0}
    return {
        "n": len(deltas),
        "min_s": round(min(deltas), 3),
        "max_s": round(max(deltas), 3),
        "avg_s": round(sum(deltas) / len(deltas), 3),
    }


def replay(flat, host: str, port: int, speed: float) -> int:
    """Reenvía los mensajes con los deltas originales de captura (/ speed)."""
    sent = 0
    prev_ts = None
    with socket.create_connection((host, port), timeout=15) as sock:
        for content, ts in flat:
            if prev_ts is not None:
                delta = max(0.0, ts - prev_ts) / speed
                if delta > 0:
                    time.sleep(delta)
            prev_ts = ts
            sock.sendall(SB + content + EOM)
            sent += 1
    return sent


def start_receiver(run_dir: Path, port: int):
    from run_experiment import lab_env, wait_port, write_lab_config
    cfg = write_lab_config(run_dir)
    log_f = open(run_dir / "receiver.log", "w", encoding="utf-8")
    proc = subprocess.Popen(
        [PY, "mllp_receiver.py", "--host", "127.0.0.1", "--port", str(port),
         "--config", str(cfg), "--outdir", str(run_dir), "--no-ack"],
        cwd=ROOT, env=lab_env(), stdout=log_f, stderr=subprocess.STDOUT)
    wait_port("127.0.0.1", port)
    return proc, log_f


def count_alerts(run_dir: Path):
    p = run_dir / "alerts" / "alerts.jsonl"
    if not p.exists():
        return 0, {}
    total = 0
    by_rule = {}
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        rec = json.loads(line)
        total += 1
        rid = rec.get("rule_id", "?")
        by_rule[rid] = by_rule.get(rid, 0) + 1
    return total, by_rule


def parse_args():
    p = argparse.ArgumentParser(
        description="Replay de evidencia capturada (corpus negativo H3)")
    p.add_argument("--pcap", required=True, help="PCAP/PCAPNG de la evidencia")
    p.add_argument("--label", required=True,
                   help="Etiqueta del corpus (STANDBY / RUNNING)")
    p.add_argument("--outdir", default="",
                   help="Directorio de salidas (default: "
                        "analysis_output/validation/replay_<label>_<ts>)")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=0,
                   help="Puerto del receptor (0 = puerto libre automático "
                        "si --start-receiver, si no 1550)")
    p.add_argument("--speed", type=float, default=1.0,
                   help="Factor de aceleración del pacing original (default 1.0)")
    p.add_argument("--start-receiver", action="store_true",
                   help="Levanta mllp_receiver --no-ack y lo detiene al final")
    p.add_argument("--dry-run", action="store_true",
                   help="Solo extraer e informar el corpus, no envía nada")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    pcap = Path(args.pcap)
    if not pcap.is_absolute():
        pcap = ROOT / pcap
    if not pcap.exists():
        print(f"ERROR: no existe {pcap}", file=sys.stderr)
        return 1

    flows = extract_oru_flows(pcap)
    flat = flatten(flows)
    stats = interval_stats(flat)
    print(f"[{args.label}] {pcap.name}: {len(flows)} flujo(s), "
          f"{len(flat)} ORU, intervalos {stats}", flush=True)

    if args.dry_run:
        return 0 if flat else 2

    if os.environ.get("LAB_AUTHORIZED", "").strip().upper() != "YES":
        print("ERROR: define LAB_AUTHORIZED=YES primero", file=sys.stderr)
        return 3
    if not (ROOT / "LAB_ONLY.marker").exists():
        print("ERROR: falta LAB_ONLY.marker en la raíz del repo", file=sys.stderr)
        return 3
    if not args.start_receiver and args.port in (0, None):
        print("ERROR: --port es requerido sin --start-receiver", file=sys.stderr)
        return 3

    ts_dir = datetime.now().strftime("%Y%m%d_%H%M%S")
    outdir = (Path(args.outdir) if args.outdir else
              ROOT / "analysis_output" / "validation" /
              f"replay_{args.label}_{ts_dir}")
    if not outdir.is_absolute():
        outdir = ROOT / outdir
    outdir.mkdir(parents=True, exist_ok=True)

    port = args.port
    recv_proc = recv_log = None
    if args.start_receiver:
        from run_experiment import free_port
        port = port or free_port()
        recv_proc, recv_log = start_receiver(outdir, port)

    started = datetime.now(timezone.utc)
    t0 = time.monotonic()
    error = None
    sent = 0
    try:
        sent = replay(flat, args.host, port, args.speed)
    except OSError as e:
        error = str(e)
    finally:
        if recv_proc is not None:
            time.sleep(2.0)
            recv_proc.terminate()
            try:
                recv_proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                recv_proc.kill()
                recv_proc.wait(timeout=5)
            recv_log.close()
    elapsed = round(time.monotonic() - t0, 1)

    alerts_total, alerts_by_rule = count_alerts(outdir)
    expectativa = ("FP = 0 (corpus benigno STANDBY, protocolo §3.2)"
                   if args.label.upper() == "STANDBY" else
                   "FP reportados sin umbral (códigos NM/SN NO_VERIFICADOS, "
                   "protocolo §3.2)")
    manifest = {
        "tool": "replay_evidence.py",
        "label": args.label,
        "timestamp_utc_inicio": started.isoformat(),
        "pcap": str(pcap.relative_to(ROOT)),
        "pcap_sha256": sha256_file(pcap),
        "anonimizado": True,
        "pipeline": "analyze_evidence (reasamblado TCP + MLLP + anonimización)",
        "flujos": [f["flow"] for f in flows],
        "n_mensajes_oru_extraidos": len(flat),
        "n_mensajes_enviados": sent,
        "n_ack_no_reenviados": ("los ACK de la captura no aplican: el receptor "
                                "es el lado servidor (emisor->:1550 = solo ORU)"),
        "pacing": f"delta original de captura / {args.speed}",
        "intervalos_s": stats,
        "target": f"{args.host}:{port}",
        "modo": "observador (receptor --no-ack)",
        "receiver_spawned": args.start_receiver,
        "elapsed_s": elapsed,
        "error": error,
        "alertas_totales": alerts_total,
        "alertas_por_regla": alerts_by_rule,
        "expectativa": expectativa,
        "entorno": {
            "python": sys.version.split()[0],
            "host_declarado": "PC",
            "comando": " ".join(sys.argv),
        },
    }
    (outdir / "replay_manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"Enviados: {sent}/{len(flat)} | alertas (FP): {alerts_total} "
          f"{alerts_by_rule if alerts_by_rule else ''}", flush=True)
    print(f"Manifiesto: {outdir.relative_to(ROOT)}/replay_manifest.json")
    if error:
        print(f"ERROR durante replay: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
