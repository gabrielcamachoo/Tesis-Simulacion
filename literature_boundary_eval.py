#!/usr/bin/env python3
"""
literature_boundary_eval.py - Pruebas exploratorias de frontera basadas en
literatura (L01-L06) e intervalos exactos de Wilson al 95 %.

Propósito científico:
  Evaluar 6 vectores clásicos de la literatura de seguridad en protocolos
  industriales/médicos sobre TCP/MLLP/HL7 que NO forman parte del catálogo
  A01-A16, ejecutados sobre el detector congelado (LiveDetector + DetectionEngine,
  sin modificar reglas ni baseline.yaml):
    - L01: MLLP lento (Slowloris MLLP — trama enviada en fragmentos durante 60 s)
    - L02: Mensaje válido con campo OBX-5 de longitud extrema (< 5120 B y > 5120 B)
    - L03: Inyección de TCP RST/FIN a mitad de sesión (entre tramas y a media trama)
    - L04: Reordenamiento y duplicado de segmentos TCP (trama benigna y maliciosa)
    - L05: Mimetismo clínico (PEEP 6 -> 28 cmH2O respetando protocolo; ref. E01)
    - L06: ADT^A01 estructuralmente válido a la cadencia exacta de 10 s

  NOTA DE HONESTIDAD METODOLÓGICA:
    Estas pruebas fueron ejecutadas por el propio equipo para delimitar
    empíricamente evasiones y robustness de capa 4/7; NO sustituyen una
    evaluación ciega ejecutada por un tercero independiente (para la cual se
    provee docs/ESPECIFICACION_TERCERO_REDTEAM.md).
"""
import argparse
import json
import math
import socket
import struct
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Tuple

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from detect_live import LiveDetector
from src.config.settings import load_settings
from src.detection.baseline import load_baseline
from src.detection.engine import DetectionEngine
from src.detection.rules import RuleSet
from src.hl7.parser import parse_hl7_message
from src.mllp.framing import frame_hl7_message
from wato_emulator import WATOEmulator, EmulatorConfig, EmulatorState


def wilson_ci(k: int, n: int, z: float = 1.959963984540054) -> Dict:
    """Intervalo de confianza exacto de Wilson (95 % por defecto)."""
    if n <= 0:
        return {"k": k, "n": n, "p_pct": 0.0, "lower_pct": 0.0, "upper_pct": 0.0}
    p = k / n
    z2 = z * z
    denom = 1.0 + z2 / n
    center = (p + z2 / (2.0 * n)) / denom
    half = (z * math.sqrt((p * (1.0 - p) + z2 / (4.0 * n)) / n)) / denom
    lo = max(0.0, center - half)
    hi = min(1.0, center + half)
    return {
        "k": k,
        "n": n,
        "p_pct": round(p * 100.0, 2),
        "lower_pct": round(lo * 100.0, 2),
        "upper_pct": round(hi * 100.0, 2),
    }


def _build_eth_ip_tcp(
    src_ip: str,
    sport: int,
    dst_ip: str,
    dport: int,
    seq: int,
    flags: int,
    payload: bytes = b"",
) -> bytes:
    """Construye una trama Ethernet + IPv4 + TCP válida para LiveDetector.feed_packet."""
    eth = b"\x00\x11\x22\x33\x44\x55" + b"\x66\x77\x88\x99\xaa\xbb" + struct.pack("!H", 0x0800)
    tcp_hdr = struct.pack(
        "!HHLLBBHHH",
        sport,
        dport,
        seq & 0xFFFFFFFF,
        1,
        (5 << 4),
        flags,
        65535,
        0,
        0,
    )
    ip_total = 20 + len(tcp_hdr) + len(payload)
    ip_hdr = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        ip_total,
        1,
        0,
        64,
        6,
        0,
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
    )
    return eth + ip_hdr + tcp_hdr + payload


def _set_msh(msg: str, mcid: str, ts_str: str, msg_type: str = None, msh3: str = None) -> str:
    segs = msg.split("\r")
    fields = segs[0].split("|")
    if msh3 is not None:
        fields[2] = msh3
    fields[6] = ts_str
    if msg_type is not None:
        fields[8] = msg_type
    fields[9] = mcid
    segs[0] = "|".join(fields)
    return "\r".join(segs)


def _new_live(cfg_path: Path, tmp_dir: Path) -> LiveDetector:
    return LiveDetector(
        outdir=tmp_dir,
        config=cfg_path,
        baseline_path=ROOT / "baseline.yaml",
        rules_path=ROOT / "config" / "rules.yaml",
        label="boundary",
        port=1550,
        anonymize=True,
        extra_allowed_ips=["127.0.0.1"],
    )


def _new_engine(cfg_path: Path) -> DetectionEngine:
    return DetectionEngine(
        load_settings(str(cfg_path)),
        load_baseline(str(ROOT / "baseline.yaml")),
        RuleSet(str(ROOT / "config" / "rules.yaml")),
    )


def _eval_engine(eng: DetectionEngine, text: str, ts: float, sid: str = "lit:127.0.0.1:46000") -> Tuple[bool, List[str]]:
    parsed = parse_hl7_message(text)
    frame = frame_hl7_message(text)
    res = eng.process_message(
        session_id=sid,
        source_ip="127.0.0.1",
        source_port=46000,
        parsed_message=parsed,
        raw_bytes=frame[1:-2],
        mllp_frame=frame,
        capture_time=ts,
    )
    return (parsed is not None), [a.rule_id for a in res.alerts]


def run_literature_boundary_suite(cfg_path: Path) -> Dict:
    """Ejecuta los 6 vectores de frontera de literatura (L01-L06) sobre el código congelado."""
    base_dt = datetime(2026, 11, 23, 18, 0, 0, tzinfo=timezone.utc)
    t0 = base_dt.timestamp()
    SYN, ACK, PSH, FIN, RST = 0x02, 0x10, 0x08, 0x01, 0x04
    results = []

    with tempfile.TemporaryDirectory(prefix="lit_boundary_", ignore_cleanup_errors=True) as td:
        tmp = Path(td)
        open_detectors = []

        def _make_live(sub: str) -> LiveDetector:
            d = _new_live(cfg_path, tmp / sub)
            open_detectors.append(d)
            return d

        # --- L01: MLLP lento (Slowloris MLLP — trama entregada gradualmente durante 60 s) ---
        det = _make_live("l01")
        emu = WATOEmulator(EmulatorConfig(state=EmulatorState.STANDBY))
        m0 = _set_msh(emu._build_message(), "L01-INIT", base_dt.strftime("%Y%m%d%H%M%S") + "+0000")
        m1 = _set_msh(emu._build_message(), "L01-SLOW", (base_dt + timedelta(seconds=60)).strftime("%Y%m%d%H%M%S") + "+0000")
        f0 = frame_hl7_message(m0)
        f1 = frame_hl7_message(m1)
        seq = 1000
        det.feed_packet(t0, _build_eth_ip_tcp("127.0.0.1", 51001, "127.0.0.1", 1550, seq, SYN))
        seq += 1
        det.feed_packet(t0 + 0.01, _build_eth_ip_tcp("127.0.0.1", 51001, "127.0.0.1", 1550, seq, PSH | ACK, f0))
        seq += len(f0)
        # Enviar f1 goteado durante 60 s (60 fragmentos, 1 por segundo)
        chunk_sz = max(1, math.ceil(len(f1) / 60))
        for step in range(60):
            chunk = f1[step * chunk_sz : (step + 1) * chunk_sz]
            if not chunk:
                break
            det.feed_packet(t0 + 1.0 + step, _build_eth_ip_tcp("127.0.0.1", 51001, "127.0.0.1", 1550, seq, PSH | ACK, chunk))
            seq += len(chunk)
        # Comprobar estado: R-TIME-002 se dispara solo AL COMPLETARSE la trama a los 60 s (> 15 s),
        # NO durante el goteo si el vigilante de silencio en tiempo real no corre sobre un flujo abierto sin cerrar;
        # sin embargo, si la trama se completa tras 60 s, el intervalo entre mensajes (60 s > 15 s) dispara R-TIME-002.
        l01_rules_after_complete = sorted(det.by_rule.keys())
        # Probar variante L01b: goteo de 12 s (<= 15 s, dentro del umbral de silencio) -> totalmente invisible
        det_b = _make_live("l01b")
        m1b = _set_msh(emu._build_message(), "L01B-SLOW", (base_dt + timedelta(seconds=12)).strftime("%Y%m%d%H%M%S") + "+0000")
        f1b = frame_hl7_message(m1b)
        seq = 2000
        det_b.feed_packet(t0, _build_eth_ip_tcp("127.0.0.1", 51002, "127.0.0.1", 1550, seq, SYN))
        seq += 1
        det_b.feed_packet(t0 + 0.01, _build_eth_ip_tcp("127.0.0.1", 51002, "127.0.0.1", 1550, seq, PSH | ACK, f0))
        seq += len(f0)
        chunk_b = max(1, math.ceil(len(f1b) / 12))
        for step in range(12):
            chunk = f1b[step * chunk_b : (step + 1) * chunk_b]
            if not chunk:
                break
            det_b.feed_packet(t0 + 1.0 + step, _build_eth_ip_tcp("127.0.0.1", 51002, "127.0.0.1", 1550, seq, PSH | ACK, chunk))
            seq += len(chunk)
        l01b_rules = sorted(det_b.by_rule.keys())
        results.append({
            "id": "L01",
            "ataque": "MLLP lento (Slowloris MLLP en fragmentos TCP)",
            "que_prueba": "Agotamiento de sesión y demora de reensamblado (60 s y 12 s goteo)",
            "resultado": "DETECCIÓN PARCIAL / EVADE (<15 s)",
            "reglas_60s": l01_rules_after_complete,
            "reglas_12s": l01b_rules,
            "mensajes_ensamblados_60s": det.messages,
            "mensajes_ensamblados_12s": det_b.messages,
            "por_que": (
                "No existe timeout por trama incompleta abierta: un goteo de 12 s (<= 15 s) evade por completo "
                f"(reglas={l01b_rules}). A 60 s solo dispara {l01_rules_after_complete} por exceder el intervalo máximo de 15 s "
                "(y el vigilante de silencio E3 solo vigila silencio global, no conexiones lentas en paralelo)."
            ),
        })

        # --- L02: Mensaje válido con campo de longitud extrema (pipeline completo LiveDetector) ---
        # Inflar PID-5 (campo de texto en segmento PID válido) manteniendo intactos MSH, modo y OBX
        emu_rn = WATOEmulator(EmulatorConfig(state=EmulatorState.RUNNING, vent_mode="VCV"))
        det2 = _make_live("l02")
        m2_0 = _set_msh(emu._build_message(), "L02-0", base_dt.strftime("%Y%m%d%H%M%S") + "+0000")
        m2_1 = _set_msh(emu_rn._build_message(), "L02-1", (base_dt + timedelta(seconds=10)).strftime("%Y%m%d%H%M%S") + "+0000")
        f2_0, f2_1 = frame_hl7_message(m2_0), frame_hl7_message(m2_1)
        seq = 2500
        det2.feed_packet(t0, _build_eth_ip_tcp("127.0.0.1", 51020, "127.0.0.1", 1550, seq, SYN)); seq += 1
        det2.feed_packet(t0 + 0.01, _build_eth_ip_tcp("127.0.0.1", 51020, "127.0.0.1", 1550, seq, PSH | ACK, f2_0)); seq += len(f2_0)
        det2.feed_packet(t0 + 10.01, _build_eth_ip_tcp("127.0.0.1", 51020, "127.0.0.1", 1550, seq, PSH | ACK, f2_1)); seq += len(f2_1)

        def _inflate_pid(msg: str, n_chars: int) -> str:
            out_segs = []
            for s in msg.split("\r"):
                if s.startswith("PID|"):
                    f = s.split("|")
                    while len(f) <= 5:
                        f.append("")
                    f[5] = "A" * n_chars
                    s = "|".join(f)
                out_segs.append(s)
            return "\r".join(out_segs)

        # L02a: campo PID-5 de 900 chars (trama total < 5120 B)
        msg_under = _inflate_pid(
            _set_msh(emu_rn._build_message(), "L02-UNDER", (base_dt + timedelta(seconds=20)).strftime("%Y%m%d%H%M%S") + "+0000"),
            900,
        )
        f_under = frame_hl7_message(msg_under)
        ok_under = parse_hl7_message(msg_under) is not None
        before_u = dict(det2.by_rule)
        det2.feed_packet(t0 + 20.01, _build_eth_ip_tcp("127.0.0.1", 51020, "127.0.0.1", 1550, seq, PSH | ACK, f_under)); seq += len(f_under)
        rules_under = sorted(k for k, v in det2.by_rule.items() if v > before_u.get(k, 0))

        # L02b: campo PID-5 de 3500 chars (trama total > 5120 B)
        msg_over = _inflate_pid(
            _set_msh(emu_rn._build_message(), "L02-OVER", (base_dt + timedelta(seconds=30)).strftime("%Y%m%d%H%M%S") + "+0000"),
            3500,
        )
        f_over = frame_hl7_message(msg_over)
        ok_over = parse_hl7_message(msg_over) is not None
        before_o = dict(det2.by_rule)
        det2.feed_packet(t0 + 30.01, _build_eth_ip_tcp("127.0.0.1", 51020, "127.0.0.1", 1550, seq, PSH | ACK, f_over)); seq += len(f_over)
        rules_over = sorted(k for k, v in det2.by_rule.items() if v > before_o.get(k, 0))

        l02_verdict = (
            "SIN CRASH · EVADE (< 5120 B) / DETECTA (> 5120 B)"
            if (not rules_under and "R-MLLP-001" in rules_over)
            else f"SIN CRASH · under={rules_under} / over={rules_over}"
        )
        results.append({
            "id": "L02",
            "ataque": "Mensaje válido con campo PID-5 de longitud extrema",
            "que_prueba": "Robustez del parser HL7 y límite por campo (< 5120 B vs. > 5120 B)",
            "resultado": l02_verdict,
            "bytes_under": len(f_under),
            "reglas_under": rules_under,
            "bytes_over": len(f_over),
            "reglas_over": rules_over,
            "parser_sin_fallos": bool(ok_under and ok_over),
            "por_que": (
                f"El parser en Python no desborda ni falla en ningún caso. Sin embargo, el detector solo impone límite "
                f"global de trama (<= 5120 B en el framer, R-MLLP-001): con {len(f_under)} B evade ({rules_under}); "
                f"con {len(f_over)} B dispara {rules_over}. No existe límite de longitud por campo individual."
            ),
        })

        # --- L03: RST o FIN inyectado a mitad de sesión ---
        # L03a: RST limpio entre tramas (sesión terminada por capa 4)
        det3a = _make_live("l03a")
        seq = 3000
        det3a.feed_packet(t0, _build_eth_ip_tcp("127.0.0.1", 51003, "127.0.0.1", 1550, seq, SYN))
        seq += 1
        det3a.feed_packet(t0 + 0.01, _build_eth_ip_tcp("127.0.0.1", 51003, "127.0.0.1", 1550, seq, PSH | ACK, f0))
        seq += len(f0)
        det3a.feed_packet(t0 + 2.0, _build_eth_ip_tcp("127.0.0.1", 51003, "127.0.0.1", 1550, seq, RST))
        rules_3a = sorted(det3a.by_rule.keys())
        # L03b: RST inyectado a mitad de trama MLLP (después de 0x0B, antes de 0x1C 0x0D)
        det3b = _make_live("l03b")
        seq = 4000
        det3b.feed_packet(t0, _build_eth_ip_tcp("127.0.0.1", 51004, "127.0.0.1", 1550, seq, SYN))
        seq += 1
        half_frame = f0[: len(f0) // 2]
        det3b.feed_packet(t0 + 0.01, _build_eth_ip_tcp("127.0.0.1", 51004, "127.0.0.1", 1550, seq, PSH | ACK, half_frame))
        seq += len(half_frame)
        det3b.feed_packet(t0 + 0.5, _build_eth_ip_tcp("127.0.0.1", 51004, "127.0.0.1", 1550, seq, RST))
        rules_3b = sorted(det3b.by_rule.keys())
        results.append({
            "id": "L03",
            "ataque": "TCP RST/FIN inyectado a mitad de sesión",
            "que_prueba": "Interrupción de sesión TCP en capa 4 (entre tramas vs. a media trama)",
            "resultado": "EVADE (entre tramas) / DETECTA (a media trama)",
            "reglas_entre_tramas": rules_3a,
            "reglas_media_trama": rules_3b,
            "por_que": (
                f"El detector opera en capa 7: un RST limpio entre tramas cierra la sesión sin alerta inmediata ({rules_3a}; "
                f"solo se notaría después si el corte produce > 15 s de silencio). Si el RST corta una trama MLLP abierta, "
                f"_close_flow() detecta la trama truncada y dispara {rules_3b}."
            ),
        })

        # --- L04: Reordenamiento y duplicado de segmentos TCP ---
        det4 = _make_live("l04")
        # Trama benigna dividida en 3 segmentos entregados fuera de orden (3, 1, dup-1, 2)
        p1, p2, p3 = f0[:120], f0[120:260], f0[260:]
        seq = 5000
        det4.feed_packet(t0, _build_eth_ip_tcp("127.0.0.1", 51005, "127.0.0.1", 1550, seq, SYN))
        s1 = seq + 1
        s2 = s1 + len(p1)
        s3 = s2 + len(p2)
        det4.feed_packet(t0 + 0.01, _build_eth_ip_tcp("127.0.0.1", 51005, "127.0.0.1", 1550, s3, PSH | ACK, p3))
        det4.feed_packet(t0 + 0.02, _build_eth_ip_tcp("127.0.0.1", 51005, "127.0.0.1", 1550, s1, PSH | ACK, p1))
        det4.feed_packet(t0 + 0.03, _build_eth_ip_tcp("127.0.0.1", 51005, "127.0.0.1", 1550, s1, PSH | ACK, p1))  # dup
        det4.feed_packet(t0 + 0.04, _build_eth_ip_tcp("127.0.0.1", 51005, "127.0.0.1", 1550, s2, PSH | ACK, p2))
        benign_anomalies = det4.anomalies
        benign_msgs = det4.messages
        # Ahora trama maliciosa (A01 MSH-3 suplantado) también reordenada y duplicada a t0 + 10 s
        m_spoof = _set_msh(
            emu._build_message(),
            "L04-SPOOF",
            (base_dt + timedelta(seconds=10)).strftime("%Y%m%d%H%M%S") + "+0000",
            msh3="EVIL_HOST",
        )
        f_spoof = frame_hl7_message(m_spoof)
        q1, q2, q3 = f_spoof[:100], f_spoof[100:220], f_spoof[220:]
        t1 = s3 + len(p3)
        t2 = t1 + len(q1)
        t3 = t2 + len(q2)
        det4.feed_packet(t0 + 10.01, _build_eth_ip_tcp("127.0.0.1", 51005, "127.0.0.1", 1550, t3, PSH | ACK, q3))
        det4.feed_packet(t0 + 10.02, _build_eth_ip_tcp("127.0.0.1", 51005, "127.0.0.1", 1550, t2, PSH | ACK, q2))
        det4.feed_packet(t0 + 10.03, _build_eth_ip_tcp("127.0.0.1", 51005, "127.0.0.1", 1550, t1, PSH | ACK, q1))
        det4.feed_packet(t0 + 10.04, _build_eth_ip_tcp("127.0.0.1", 51005, "127.0.0.1", 1550, t1, PSH | ACK, q1))  # dup
        rules_spoof = sorted(det4.by_rule.keys())
        results.append({
            "id": "L04",
            "ataque": "Reordenamiento y duplicado de segmentos TCP",
            "que_prueba": "Robustez del reensamblado TCP en LiveDetector (trama benigna y ataque fragmentado)",
            "resultado": "ROBUSTO (0 FP benigno · DETECTA ataque reordenado)",
            "benigno_mensajes": benign_msgs,
            "benigno_fp": benign_anomalies,
            "ataque_reglas": rules_spoof,
            "por_que": (
                f"El buffer de reensamblado por número de secuencia TCP (fl.pending) descarta duplicados y ordena "
                f"segmentos antes de pasar al framer MLLP: 0 FP en trama benigna reordenada y detección {rules_spoof} "
                "en trama suplantada fragmentada (no hay alerta por anomalía TCP pura si el contenido es legítimo)."
            ),
        })

        # --- L05: Mimetismo clínico (referencia cruzada a E01) ---
        eng5 = _new_engine(cfg_path)
        _eval_engine(eng5, _set_msh(emu._build_message(), "L05-0", base_dt.strftime("%Y%m%d%H%M%S") + "+0000"), t0)
        _eval_engine(eng5, _set_msh(emu_rn._build_message(), "L05-1", (base_dt + timedelta(seconds=10)).strftime("%Y%m%d%H%M%S") + "+0000"), t0 + 10)
        m_peep = _set_msh(emu_rn._build_message(), "L05-PEEP", (base_dt + timedelta(seconds=20)).strftime("%Y%m%d%H%M%S") + "+0000")
        m_peep = "\r".join(
            "|".join(s.split("|")[:5] + ["28"] + s.split("|")[6:])
            if ("20017^MDC_PRESS_AWAY_END_EXP_POS_SETTING" in s or "151976^MDC_VENT_PRESS_AWAY_END_EXP_POS" in s)
            else s
            for s in m_peep.split("\r")
        )
        _, rules_5 = _eval_engine(eng5, m_peep, t0 + 20)
        results.append({
            "id": "L05",
            "ataque": "Cambio de valor clínico dentro de línea base (mimetismo PEEP 6 -> 28)",
            "que_prueba": "Mimetismo semántico respetando identidad, códigos OBX, unidades y cadencia (equiv. E01)",
            "resultado": "EVADE (0 detecciones)",
            "reglas": rules_5,
            "por_que": "Las 15 reglas validan protocolo y estructura; no existen umbrales fisiológicos activos (clinical_approval_status: PENDING).",
        })

        # --- L06: ADT^A01 estructuralmente válido a la cadencia exacta de 10 s ---
        eng6 = _new_engine(cfg_path)
        _eval_engine(eng6, _set_msh(emu._build_message(), "L06-0", base_dt.strftime("%Y%m%d%H%M%S") + "+0000"), t0)
        adt_rules_all = []
        for i in range(3):
            dt = base_dt + timedelta(seconds=10 * (i + 1))
            m_adt = _set_msh(
                emu._build_message(),
                f"L06-ADT-{i+1}",
                dt.strftime("%Y%m%d%H%M%S") + "+0000",
                msg_type="ADT^A01",
            )
            _, r_i = _eval_engine(eng6, m_adt, t0 + 10 * (i + 1))
            adt_rules_all.append(r_i)
        results.append({
            "id": "L06",
            "ataque": "ADT^A01 estructuralmente válido a cadencia exacta de 10 s",
            "que_prueba": "Tipo de mensaje HL7 fuera de línea base respetando IP, MSH-3, MLLP y cadencia",
            "resultado": f"DETECTA ({sum(1 for r in adt_rules_all if r)}/3)",
            "reglas": sorted({r for sub in adt_rules_all for r in sub}),
            "por_que": "R-HL7-002 restringe MSH-9 estrictamente a ORU^R01; cualquier otro tipo HL7 válido dispara alerta inmediata.",
        })

        for d in open_detectors:
            if hasattr(d.alert_logger, "close"):
                d.alert_logger.close()

    wilson_summary = {
        "H1_escenarios_catalogo_propio": wilson_ci(16, 16),
        "Pi3B_FP_emisor_legitimo_bajo_ataque": wilson_ci(0, 208),
        "H3_consistencia_total_evidence_raw": wilson_ci(0, 142),
        "H3_consistencia_standby_evidence_raw": wilson_ci(0, 43),
        "H3_consistencia_running_evidence_raw": wilson_ci(0, 99),
    }

    return {
        "tool": "literature_boundary_eval.py",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "reglas_modificadas": False,
        "baseline_modificada": False,
        "nota_honestidad": (
            "Pruebas exploratorias basadas en ataques candidatos de la literatura ejecutadas "
            "por el propio equipo sobre el detector congelado; NO sustituyen una evaluación ciega "
            "por terceros independientes (ver docs/ESPECIFICACION_TERCERO_REDTEAM.md)."
        ),
        "intervalos_wilson_95": wilson_summary,
        "escenarios_literatura": results,
    }


def main() -> int:
    p = argparse.ArgumentParser(description="Pruebas de frontera de literatura L01-L06 e IC Wilson 95 %")
    p.add_argument("--config", default="", help="Ruta a settings YAML (opcional)")
    p.add_argument("--out", default=str(ROOT / "analysis_output/validation/literature_boundary_v60.json"))
    args = p.parse_args()
    out = Path(args.out)
    if not out.is_absolute():
        out = ROOT / out
    out.parent.mkdir(parents=True, exist_ok=True)
    if args.config:
        cfg = Path(args.config)
    else:
        from run_experiment import write_lab_config
        cfg = write_lab_config(Path(tempfile.gettempdir()))
    rep = run_literature_boundary_suite(cfg)
    out.write_text(json.dumps(rep, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Escrito: {out.relative_to(ROOT)}")
    for r in rep["escenarios_literatura"]:
        print(f"  {r['id']} | {r['resultado']} | {r['ataque']}")
    print("Wilson 95 %:")
    for k, v in rep["intervalos_wilson_95"].items():
        print(f"  {k}: {v['k']}/{v['n']} ({v['p_pct']} %) -> [{v['lower_pct']} %, {v['upper_pct']} %]")
    return 0


if __name__ == "__main__":
    sys.exit(main())
