#!/usr/bin/env python3
"""
detect_pcap.py - Detección OFFLINE sobre PCAP (Modalidad B del laboratorio).

Ejecuta el motor de detección determinista sobre los mensajes MLLP
emisor->receptor (:1550) extraídos de una captura, SIN abrir conexiones de
red ni reenviar bytes. Pensado para la Raspberry Pi en modo forense y para
análisis repetible de la evidencia (validación de la cadena de custodia).

Pipeline de extracción idéntico al de analyze_evidence/replay_evidence:
  reensamblado TCP por secuencia -> delimitación MLLP -> anonimización
  irreversible POR DEFECTO (los bytes originales del PCAP no se tocan).

Limitaciones documentadas (se registran en el manifiesto):
  - R-MLLP-001 no es evaluable: solo se procesan tramas MLLP completas
    (los framing errors del receptor requieren la Modalidad A/replay).
  - R-TIME-002 usa el reloj de pared del proceso; sin --realtime los
    mensajes se procesan a velocidad de CPU y la regla puede dispararse
    por el propio modo offline. --realtime aplica los deltas de captura
    con tope por mensaje (--max-sleep).
  - Los timestamps MSH-7 originales se preservan (anonimización no toca
    MSH-7): R-TIME-001 sí es evaluable offline.

No genera tráfico de red, pero mantiene el mismo guardrail que el resto del
laboratorio: requiere LAB_AUTHORIZED=YES y LAB_ONLY.marker.

Uso:
    LAB_AUTHORIZED=YES python detect_pcap.py \
        --pcap evidence_raw/pcap/LECTURACONACK25AGOSTO.pcapng
    LAB_AUTHORIZED=YES python detect_pcap.py --pcap X.pcapng --realtime
    LAB_AUTHORIZED=YES python detect_pcap.py --pcap X.pcapng --no-anonymize
"""

import argparse
import hashlib
import json
import platform
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent

from src.evidence.analyze_evidence import (
    MLLP_PORT, _flow_key, _reassemble_stream, anonymize_hl7_message,
    extract_mllp_messages,
)
from src.evidence.pcap_reader import decode_frame, iter_packets
from src.mllp.framing import EOM, SB
from src.config.settings import load_settings
from src.detection.baseline import load_baseline
from src.detection.rules import RuleSet
from src.detection.engine import DetectionEngine
from src.alerting.json_logger import AlertLogger
from src.hl7.parser import parse_hl7_message

LAB_ONLY_WARNING = (
    "LAB ONLY — análisis offline de evidencia aislada; no abrir ni reenviar "
    "tráfico hacia dispositivos médicos, hospitales o sistemas de terceros.")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def extract_flows(pcap_path: Path):
    """Flujos TCP (orden cronológico) con payload emisor->:1550.

    Cada flujo = una conexión TCP original. Réplica de la lógica 'fwd' de
    analyze_evidence aplicada a todos los mensajes MLLP, no solo ORU.
    """
    flows = {}
    for pkt in iter_packets(str(pcap_path)):
        d = decode_frame(pkt.data)
        if d is None or d.l4 != "tcp":
            continue
        if MLLP_PORT not in (d.sport, d.dport):
            continue
        key = _flow_key(d)
        fl = flows.setdefault(key, {"fwd": [], "t0": None,
                                    "src": f"{d.src_ip}:{d.sport}"})
        if pkt.ts:
            fl["t0"] = pkt.ts if fl["t0"] is None else min(fl["t0"], pkt.ts)
        if d.dport == MLLP_PORT and d.payload:
            fl["fwd"].append((d.seq, pkt.ts, d.payload))

    out = []
    for idx, (key, fl) in enumerate(
            sorted(flows.items(), key=lambda kv: (kv[1]["t0"] or 0))):
        if not fl["fwd"]:
            continue
        # _flow_key ordena lexicográficamente: el emisor es el lado != :1550
        client = key[1] if key[0][1] == MLLP_PORT else key[0]
        buf, ts_arr = _reassemble_stream(fl["fwd"])
        msgs = []
        for content, start, _end in extract_mllp_messages(buf):
            ts = ts_arr[start] if start < len(ts_arr) else (fl["t0"] or 0.0)
            msgs.append((content, ts))
        out.append({
            "flow_idx": idx,
            "flow": f"{key[0][0]}:{key[0][1]} -> {key[1][0]}:{key[1][1]}",
            "src_ip": client[0],
            "src_port": client[1],
            "t0": fl["t0"],
            "messages": msgs,
        })
    return out


def run_detect(pcap_path: Path, outdir: Path, config: Path,
               baseline_path: Path, rules_path: Path,
               label: str = "", realtime: bool = False,
               max_sleep: float = 2.0,
               anonymize: bool = True) -> dict:
    """Procesa el PCAP con el motor y escribe alerts/ + manifiesto."""
    started = datetime.now(timezone.utc)
    t0 = time.monotonic()

    settings = load_settings(str(config))
    settings.evidence.output_dir = str(outdir)
    baseline = load_baseline(str(baseline_path))
    rules = RuleSet(str(rules_path))
    engine = DetectionEngine(settings, baseline, rules)
    alert_logger = AlertLogger(settings, evidence_writer=None)

    flows = extract_flows(pcap_path)
    n_messages = 0
    n_skipped = 0
    n_anonymized = 0
    by_rule = {}
    anomalies = 0
    normals = 0
    lat_ms = []
    prev_ts = None
    try:
        for fl in flows:
            session_id = (f"offline:{fl['flow_idx']}:"
                          f"{fl['src_ip']}:{fl['src_port']}")
            for content, ts in fl["messages"]:
                if realtime and prev_ts is not None and ts:
                    delta = min(max(0.0, ts - prev_ts), max_sleep)
                    if delta > 0:
                        time.sleep(delta)
                if ts:
                    prev_ts = ts

                raw = content
                if anonymize:
                    anon = anonymize_hl7_message(content)
                    if anon != content:
                        n_anonymized += 1
                    raw = anon
                try:
                    hl7_text = raw.decode("utf-8", errors="replace")
                except Exception:
                    n_skipped += 1
                    continue
                parsed = parse_hl7_message(hl7_text)
                if parsed is None or not parsed.segments:
                    n_skipped += 1
                    continue

                n_messages += 1
                frame = SB + raw + EOM
                result = engine.process_message(
                    session_id=session_id,
                    source_ip=fl["src_ip"],
                    source_port=fl["src_port"],
                    parsed_message=parsed,
                    raw_bytes=raw,
                    mllp_frame=frame,
                    capture_time=ts if (ts and not realtime) else None)
                lat_ms.append(result.processing_time_ms)
                if result.alerts:
                    anomalies += len(result.alerts)
                    for alert in result.alerts:
                        by_rule[alert.rule_id] = by_rule.get(alert.rule_id, 0) + 1
                        alert_logger.log_alert(alert)
                else:
                    normals += 1
                    digest = hashlib.sha256(raw).hexdigest()
                    alert_logger.log_normal(
                        session_id=session_id,
                        source=f"{fl['src_ip']}:{fl['src_port']}",
                        msg_control_id=parsed.message_control_id or "N/A",
                        state=result.session_state.current_state,
                        evidence_hash=digest)
    finally:
        alert_logger.close()

    elapsed = round(time.monotonic() - t0, 3)
    limitations = [
        "R-MLLP-001 no evaluable offline (solo tramas MLLP completas)",
        ("R-TIME-002 depende del reloj de pared: sin --realtime puede "
         "dispararse por la velocidad de procesamiento, no por la captura")
        if not realtime else
        (f"R-TIME-002 con pacing de captura tope {max_sleep}s/mensaje "
         "(huecos mayores se comprimen)"),
        "sin ACK observados en el camino emisor->receptor (el ACK sale del "
        "receptor hacia el emisor; ver replay_evidence.py)",
    ]

    pcap_sha = sha256_file(pcap_path)
    manifest = {
        "tool": "detect_pcap.py",
        "schema_version": "1.0",
        "label": label,
        "timestamp_utc_inicio": started.isoformat(),
        "timestamp_utc_fin": datetime.now(timezone.utc).isoformat(),
        "pcap": str(pcap_path),
        "pcap_sha256": pcap_sha,
        "anonimizado": anonymize,
        "modo": "offline (sin red; Modalidad B)",
        "realtime": realtime,
        "flujos": [f["flow"] for f in flows],
        "n_flujos": len(flows),
        "n_mensajes": n_messages,
        "n_skipped": n_skipped,
        "n_anonymized": n_anonymized,
        "anomalias": anomalies,
        "eventos_normales": normals,
        "eventos_totales": anomalies + normals,
        "alertas_por_regla": by_rule,
        "latencia_proceso_ms": (
            {"p50": round(sorted(lat_ms)[len(lat_ms) // 2], 4),
             "max": round(max(lat_ms), 4)}
            if lat_ms else None),
        "elapsed_s": elapsed,
        "config_sha256": sha256_file(config) if config.exists() else None,
        "baseline_sha256": (sha256_file(baseline_path)
                            if baseline_path.exists() else None),
        "rules_sha256": (sha256_file(rules_path)
                         if rules_path.exists() else None),
        "limitaciones": limitations,
        "runtime": {
            "platform": platform.platform(),
            "python": platform.python_version(),
            "host_declarado": "PC o Raspberry Pi (offline)",
        },
        "advertencia": LAB_ONLY_WARNING,
    }
    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / "detect_pcap_manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")

    summary = (
        f"[{label or 'PCAP'}] {pcap_path.name}: {len(flows)} flujo(s), "
        f"{n_messages} mensaje(s) procesado(s), anomalías={format_anomalias(by_rule, anomalies)} "
        f"normales={normals} elapsed={elapsed}s\n"
        f"Manifiesto: {outdir / 'detect_pcap_manifest.json'}")
    print(summary, flush=True)
    return manifest


def format_anomalias(by_rule: dict, anomalies: int) -> str:
    if not by_rule:
        return "0"
    det = ", ".join(f"{k}={v}" for k, v in sorted(by_rule.items()))
    return f"{anomalies} ({det})"


def parse_args():
    p = argparse.ArgumentParser(
        description="Detección offline HL7/MLLP sobre PCAP (Modalidad B)")
    p.add_argument("--pcap", required=True, help="PCAP/PCAPNG de la evidencia")
    p.add_argument("--outdir", default="",
                   help="Directorio de salidas "
                        "(default: analysis_output/offline_detect_<label>_<ts>)")
    p.add_argument("--config", default=str(ROOT / "src" / "config" / "settings.yaml"))
    p.add_argument("--baseline", default=str(ROOT / "baseline.yaml"))
    p.add_argument("--rules", default=str(ROOT / "config" / "rules.yaml"))
    p.add_argument("--label", default="", help="Etiqueta del corpus (ej: STANDBY)")
    p.add_argument("--realtime", action="store_true",
                   help="Aplica deltas de captura entre mensajes (para "
                        "R-TIME-002 más fiel; más lento)")
    p.add_argument("--max-sleep", type=float, default=2.0,
                   help="Tope de sleep por mensaje en --realtime (default 2.0)")
    p.add_argument("--no-anonymize", action="store_true",
                   help="Deshabilita anonimización (solo uso local; los "
                        "derivados NO deben salir del laboratorio)")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    import os
    if os.environ.get("LAB_AUTHORIZED", "").strip().upper() != "YES":
        print("ERROR: define LAB_AUTHORIZED=YES primero "
              "(mismo guardrail que el resto del laboratorio)", file=sys.stderr)
        return 3
    if not (ROOT / "LAB_ONLY.marker").exists():
        print("ERROR: falta LAB_ONLY.marker en la raíz del repo", file=sys.stderr)
        return 3
    pcap = Path(args.pcap)
    if not pcap.is_absolute():
        pcap = ROOT / pcap
    if not pcap.exists():
        print(f"ERROR: no existe {pcap}", file=sys.stderr)
        return 1

    ts_dir = datetime.now().strftime("%Y%m%d_%H%M%S")
    tag = args.label or "pcap"
    outdir = (Path(args.outdir) if args.outdir else
              ROOT / "analysis_output" / f"offline_detect_{tag}_{ts_dir}")
    if not outdir.is_absolute():
        outdir = ROOT / outdir

    # settings.yaml apunta lab_marker_path a /LAB_ONLY.marker (raíz Linux);
    # en Windows/macOS eso no existe y write_lab_config parchea la ruta.
    config = Path(args.config)
    if not config.is_absolute():
        config = ROOT / config
    from run_experiment import write_lab_config
    outdir.mkdir(parents=True, exist_ok=True)
    if config.resolve() == (ROOT / "src" / "config" / "settings.yaml").resolve():
        config = write_lab_config(outdir)

    try:
        run_detect(pcap, outdir, config, Path(args.baseline), Path(args.rules),
                   label=args.label, realtime=args.realtime,
                   max_sleep=args.max_sleep,
                   anonymize=not args.no_anonymize)
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
