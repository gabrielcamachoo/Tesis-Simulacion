#!/usr/bin/env python3
"""
evaluate.py - Evaluación del motor de detección contra verdad de terreno
Cruza ground_truth.jsonl (inyecciones del generador) con alerts.jsonl (salida
del receptor) y calcula TP/FP/TN/FN, recall, precision, F1, FPR, latencia,
throughput (msg/s) y pérdida de mensajes (esperado vs recibido, desde seed.txt).

No modifica evidencia existente; solo lee y escribe reportes de evaluación.

Uso:
    python evaluate.py --run runs/20261013_120000
    python evaluate.py --ground-truth gt.jsonl --alerts alerts.jsonl --out report.json
"""

import argparse
import json
import logging
import re
import statistics
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Ventana de matching inyección -> alerta (segundos)
DEFAULT_MATCH_WINDOW_S = 5.0


@dataclass
class Injection:
    """Registro de verdad de terreno."""
    injection_id: str
    scenario_id: str
    scenario_name: str
    expected_rule: str
    timestamp_utc: str
    monotonic_ns: int = 0
    control_id: str = ""
    bytes_sent: int = 0
    target: str = ""
    mitre_ics: str = ""
    threat: str = ""
    # Calculado durante matching
    matched_alert_id: Optional[str] = None
    matched_rule: Optional[str] = None
    latency_ms: Optional[float] = None


@dataclass
class AlertRecord:
    """Alerta ANOMALA leída de alerts.jsonl."""
    alert_id: str
    rule_id: str
    timestamp_utc: str
    label: str = "ANOMALO"
    matched_injection_id: Optional[str] = None


@dataclass
class EvaluationResult:
    """Resultado completo de la evaluación."""
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0
    recall: float = 0.0
    precision: float = 0.0
    f1_score: float = 0.0
    fpr: float = 0.0
    accuracy: float = 0.0
    injections_total: int = 0
    alerts_total: int = 0
    normal_messages: int = 0
    latency_ms: Dict[str, float] = field(default_factory=dict)
    throughput: Dict[str, float] = field(default_factory=dict)
    message_loss: Dict[str, float] = field(default_factory=dict)
    resource_usage: Dict[str, float] = field(default_factory=dict)
    per_scenario: Dict[str, Dict] = field(default_factory=dict)
    per_rule: Dict[str, Dict] = field(default_factory=dict)
    unmatched_alerts: List[str] = field(default_factory=list)
    correlated_alerts: int = 0  # alertas extra dentro de ventana de una inyección
    missed_injections: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


def parse_ts(ts: str) -> datetime:
    """Parsea timestamp ISO 8601 con o sin zona."""
    try:
        return datetime.fromisoformat(ts)
    except ValueError:
        return datetime.min


def load_ground_truth(path: Path) -> List[Injection]:
    injections = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            data = json.loads(line)
            injections.append(Injection(
                injection_id=data.get("injection_id", ""),
                scenario_id=data.get("scenario_id", ""),
                scenario_name=data.get("scenario_name", ""),
                expected_rule=data.get("expected_rule", ""),
                timestamp_utc=data.get("timestamp_utc", ""),
                monotonic_ns=data.get("monotonic_ns", 0),
                control_id=data.get("control_id", ""),
                bytes_sent=data.get("bytes_sent", 0),
                target=data.get("target", ""),
                mitre_ics=data.get("mitre_ics", ""),
                threat=data.get("threat", ""),
            ))
    return injections


def load_alerts(path: Path) -> Tuple[List[AlertRecord], int, List[datetime]]:
    """
    Carga alerts.jsonl. Devuelve (alertas ANOMALO, conteo NORMAL, timestamps).
    Entradas con rule_id=NORMAL o label=NORMAL cuentan como TN fuente.
    timestamps incluye todas las entradas (NORMAL + ANOMALO) para throughput.
    """
    alerts: List[AlertRecord] = []
    normal_count = 0
    timestamps: List[datetime] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            data = json.loads(line)
            label = data.get("label", "ANOMALO")
            rule_id = data.get("rule_id", "")
            ts = parse_ts(data.get("timestamp_utc", ""))
            if ts != datetime.min:
                timestamps.append(ts)
            if label == "NORMAL" or rule_id == "NORMAL":
                normal_count += 1
                continue
            alerts.append(AlertRecord(
                alert_id=data.get("alert_id", ""),
                rule_id=rule_id,
                timestamp_utc=data.get("timestamp_utc", ""),
                label=label,
            ))
    return alerts, normal_count, timestamps


def match_injections(injections: List[Injection],
                     alerts: List[AlertRecord],
                     window_s: float = DEFAULT_MATCH_WINDOW_S
                     ) -> Tuple[int, List[float], List[AlertRecord]]:
    """
    Matching 1:1 greedy por regla esperada dentro de ventana temporal.
    - Una alerta solo puede matchear una inyección.
    - Prefiere alertas con la regla esperada; si no hay, acepta cualquier
      regla dentro de la ventana (se registra como wrong_rule en per_scenario).
    Devuelve (n_matches, latencias_ms, alertas_sin_match).
    """
    latencies: List[float] = []
    used_alerts = set()

    # Ordenar por tiempo para matching estable
    injections_sorted = sorted(injections, key=lambda i: i.timestamp_utc)

    for inj in injections_sorted:
        t0 = parse_ts(inj.timestamp_utc)
        best: Optional[AlertRecord] = None
        best_latency = None
        best_is_expected = False

        for al in alerts:
            if al.alert_id in used_alerts:
                continue
            t1 = parse_ts(al.timestamp_utc)
            delta = (t1 - t0).total_seconds()
            # La alerta debe venir después de la inyección y dentro de ventana
            if delta < -0.05 or delta > window_s:
                continue
            is_expected = (al.rule_id == inj.expected_rule)
            if is_expected:
                best, best_latency, best_is_expected = al, delta * 1000.0, True
                break
            # candidato de respaldo (misma ventana, regla distinta)
            if best is None or not best_is_expected:
                if best is None or (best_latency is not None and delta * 1000.0 < best_latency):
                    best, best_latency = al, delta * 1000.0

        if best is not None:
            used_alerts.add(best.alert_id)
            best.matched_injection_id = inj.injection_id
            inj.matched_alert_id = best.alert_id
            inj.matched_rule = best.rule_id
            inj.latency_ms = best_latency
            if best_latency is not None:
                latencies.append(best_latency)

    unmatched = [a for a in alerts if a.alert_id not in used_alerts]
    return len(used_alerts), latencies, unmatched


def compute_metrics(tp: int, fp: int, tn: int, fn: int) -> Dict[str, float]:
    """Métricas del espacio de confusión (cero-división protegida)."""
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    total = tp + fp + tn + fn
    accuracy = (tp + tn) / total if total > 0 else 0.0
    return {
        "recall": round(recall, 4),
        "precision": round(precision, 4),
        "f1_score": round(f1, 4),
        "fpr": round(fpr, 4),
        "accuracy": round(accuracy, 4),
    }


def percentile(values: List[float], pct: float) -> float:
    """Percentil por interpolación lineal (sin numpy)."""
    if not values:
        return 0.0
    vs = sorted(values)
    k = (len(vs) - 1) * (pct / 100.0)
    lo = int(k)
    hi = min(lo + 1, len(vs) - 1)
    return vs[lo] + (vs[hi] - vs[lo]) * (k - lo)


def partition_unmatched(alerts: List[AlertRecord], injections: List[Injection],
                        window_s: float = DEFAULT_MATCH_WINDOW_S
                        ) -> Tuple[List[AlertRecord], int]:
    """
    Separa alertas sin match en:
    - FP reales (fuera de toda ventana de inyección)
    - correlacionadas: caen dentro de la ventana de ALGUNA inyección (son
      alertas adicionales legítimas del mismo evento, p. ej. R-TIME-002
      disparado junto a la regla esperada) -> no cuentan como FP.
    """
    true_fp: List[AlertRecord] = []
    correlated = 0
    times = [parse_ts(i.timestamp_utc) for i in injections]
    for al in alerts:
        t1 = parse_ts(al.timestamp_utc)
        in_window = any(-0.05 <= (t1 - t0).total_seconds() <= window_s
                        for t0 in times)
        if in_window:
            correlated += 1
        else:
            true_fp.append(al)
    return true_fp, correlated


def parse_expected_counts(run_dir: Path) -> Optional[Dict[str, int]]:
    """
    Lee seed.txt para obtener benign_count (por fase; el protocolo del
    laboratorio ejecuta DOS fases benignas -> benign*2) y calcula el total
    esperado de mensajes: benign*2 + inyecciones reales (lineas de
    ground_truth.jsonl, si existe; si no, anomaly_count de seed.txt es
    POR ESCENARIO y NO se usa como total). None si no hay seed.txt.
    """
    seed_path = run_dir / "seed.txt"
    if not seed_path.exists():
        return None
    text = seed_path.read_text(encoding="utf-8")
    benign = re.search(r"^benign_count=(\d+)", text, re.M)
    if not benign:
        return None
    benign_n = int(benign.group(1))
    gt_path = run_dir / "ground_truth.jsonl"
    if gt_path.exists():
        with open(gt_path, encoding="utf-8") as f:
            injections = sum(1 for line in f if line.strip())
    else:
        anomaly = re.search(r"^anomaly_count=(\d+)", text, re.M)
        injections = int(anomaly.group(1)) if anomaly else 0
    return {
        "benign": benign_n * 2,
        "injections": injections,
        "expected_total": benign_n * 2 + injections,
    }


def count_received_messages(run_dir: Path) -> Optional[int]:
    """
    Cuenta los mensajes MLLP realmente procesados por el receptor,
    leyendo los encabezados '### <ts> | msg N | <bytes>' de hl7/*.hl7.
    None si no hay hl7/ (no fabricar datos).
    """
    hl7_dir = run_dir / "hl7"
    if not hl7_dir.is_dir():
        return None
    total = 0
    found = False
    for f in hl7_dir.glob("*.hl7"):
        found = True
        with open(f, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if line.startswith("### "):
                    total += 1
    return total if found else None


def read_resource_usage(run_dir: Path) -> Optional[Dict[str, float]]:
    """
    Lee resource_usage.json si existe (escrito por el receptor en runtime).
    Devuelve None si no existe (no fabricar datos).
    """
    res_path = run_dir / "resource_usage.json"
    if not res_path.exists():
        return None
    try:
        with open(res_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return {k: v for k, v in data.items() if isinstance(v, (int, float))}
    except (json.JSONDecodeError, OSError):
        return None


def compute_throughput(timestamps: List[datetime],
                       total_msgs: int) -> Dict[str, float]:
    """
    Throughput = mensajes procesados / ventana temporal (segundos).
    Ventana = último - primer timestamp de alerts.jsonl.
    """
    if len(timestamps) < 2 or total_msgs == 0:
        return {"msgs_per_s": 0.0, "window_s": 0.0, "total_msgs": total_msgs}
    t_min, t_max = min(timestamps), max(timestamps)
    span = (t_max - t_min).total_seconds()
    if span <= 0:
        return {"msgs_per_s": 0.0, "window_s": 0.0, "total_msgs": total_msgs}
    return {
        "msgs_per_s": round(total_msgs / span, 3),
        "window_s": round(span, 3),
        "total_msgs": total_msgs,
    }


def compute_message_loss(expected: Optional[Dict[str, int]],
                         received: Optional[int],
                         normal_count: int, alerts_total: int
                         ) -> Dict[str, float]:
    """
    Pérdida de mensajes = esperado - recibido.
    Esperado = benign*2 (dos fases benignas del protocolo) + inyecciones
    (ground_truth.jsonl) — ver parse_expected_counts.
    Recibido = conteo real de hl7/*.hl7 del receptor (count_received_messages).
    Fallback sin hl7/: normal_count+alerts_total con source='estimado'
    (sobreestima: una inyeccion puede generar varias alertas).
    Si no hay esperado, calculable=0 (no fabricar).
    """
    source = "hl7"
    if received is None:
        received = normal_count + alerts_total
        source = "estimado"
    if expected is None:
        return {"calculable": 0, "received": received, "source": source}
    exp_total = expected["expected_total"]
    lost = max(0, exp_total - received)
    return {
        "calculable": 1,
        "expected": exp_total,
        "received": received,
        "lost": lost,
        "loss_rate": round(lost / exp_total, 4) if exp_total > 0 else 0.0,
        "source": source,
    }


def evaluate(injections: List[Injection], alerts: List[AlertRecord],
             normal_count: int, window_s: float = DEFAULT_MATCH_WINDOW_S,
             timestamps: Optional[List[datetime]] = None,
             expected_counts: Optional[Dict[str, int]] = None,
             resource_usage: Optional[Dict[str, float]] = None,
             received_messages: Optional[int] = None
             ) -> EvaluationResult:
    """Calcula resultado completo de evaluación."""
    res = EvaluationResult()
    res.injections_total = len(injections)
    res.alerts_total = len(alerts)
    res.normal_messages = normal_count

    n_match, latencies, unmatched = match_injections(injections, alerts, window_s)

    # Alertas dentro de ventana de una inyección: correlacionadas (no FP)
    true_fp, correlated = partition_unmatched(unmatched, injections, window_s)

    res.tp = n_match
    res.fn = len(injections) - n_match
    res.fp = len(true_fp)
    res.correlated_alerts = correlated
    res.tn = normal_count

    m = compute_metrics(res.tp, res.fp, res.tn, res.fn)
    res.recall = m["recall"]
    res.precision = m["precision"]
    res.f1_score = m["f1_score"]
    res.fpr = m["fpr"]
    res.accuracy = m["accuracy"]

    # Throughput y pérdida de mensajes
    total_msgs = normal_count + res.alerts_total
    if timestamps:
        res.throughput = compute_throughput(timestamps, total_msgs)
    res.message_loss = compute_message_loss(expected_counts,
                                            received_messages,
                                            normal_count, res.alerts_total)
    if resource_usage:
        res.resource_usage = resource_usage

    if latencies:
        res.latency_ms = {
            "p50": round(percentile(latencies, 50), 3),
            "p95": round(percentile(latencies, 95), 3),
            "p99": round(percentile(latencies, 99), 3),
            "max": round(max(latencies), 3),
            "mean": round(statistics.fmean(latencies), 3),
            "samples": len(latencies),
        }

    # Desglose por escenario
    by_scenario: Dict[str, List[Injection]] = {}
    for inj in injections:
        by_scenario.setdefault(inj.scenario_id, []).append(inj)

    for sid, items in sorted(by_scenario.items()):
        ok = [i for i in items if i.matched_alert_id]
        wrong_rule = [i for i in ok if i.matched_rule != i.expected_rule]
        lats = [i.latency_ms for i in ok if i.latency_ms is not None]
        sc = items[0]
        res.per_scenario[sid] = {
            "name": sc.scenario_name,
            "expected_rule": sc.expected_rule,
            "mitre_ics": sc.mitre_ics,
            "injected": len(items),
            "detected": len(ok),
            "missed": len(items) - len(ok),
            "wrong_rule": len(wrong_rule),
            "detection_rate": round(len(ok) / len(items), 4) if items else 0.0,
            "latency_p50_ms": round(percentile(lats, 50), 3) if lats else None,
        }

    # Desglose por regla esperada
    for sid, items in sorted(by_scenario.items()):
        rule = items[0].expected_rule
        ok = [i for i in items if i.matched_alert_id]
        res.per_rule[rule] = {
            "expected": len(items),
            "detected": len(ok),
            "missed": len(items) - len(ok),
        }

    res.unmatched_alerts = [a.alert_id for a in true_fp]
    res.missed_injections = [i.injection_id for i in injections if not i.matched_alert_id]

    if res.tp == 0 and res.injections_total > 0:
        res.warnings.append("Ninguna inyección fue detectada: revisar reglas o ventana de matching")
    if res.alerts_total == 0:
        res.warnings.append("No hay alertas en alerts.jsonl: ¿receptor corriendo con motor de detección?")
    if res.normal_messages == 0:
        res.warnings.append("Sin mensajes normales registrados: FPR no calculable (TN=0)")
    if not res.resource_usage:
        res.warnings.append("Sin resource_usage.json: CPU/memoria no medidos en runtime (NO_VERIFICADO)")

    return res


def format_report(res: EvaluationResult) -> str:
    lines = []
    lines.append("=" * 70)
    lines.append("REPORTE DE EVALUACIÓN - DETECCIÓN DE ANOMALÍAS HL7/MLLP")
    lines.append("=" * 70)
    lines.append(f"Espacio de confusión: TP={res.tp} FP={res.fp} TN={res.tn} FN={res.fn} "
                 f"(+{res.correlated_alerts} alertas correlacionadas)")
    lines.append(f"Recall:    {res.recall:.4f}")
    lines.append(f"Precision: {res.precision:.4f}")
    lines.append(f"F1:        {res.f1_score:.4f}")
    lines.append(f"FPR:       {res.fpr:.4f}")
    lines.append(f"Accuracy:  {res.accuracy:.4f}")
    lines.append(f"Inyecciones: {res.injections_total}  Alertas: {res.alerts_total}  "
                 f"Normales: {res.normal_messages}")
    if res.latency_ms:
        lines.append(f"Latencia detección (ms): p50={res.latency_ms['p50']} "
                     f"p95={res.latency_ms['p95']} p99={res.latency_ms['p99']} "
                     f"max={res.latency_ms['max']}")
    if res.throughput:
        lines.append(f"Throughput: {res.throughput['msgs_per_s']} msg/s "
                     f"({res.throughput['total_msgs']} msgs en "
                     f"{res.throughput['window_s']} s)")
    if res.message_loss.get("calculable"):
        src = res.message_loss.get("source", "hl7")
        suffix = " (ESTIMADO: sin hl7/, sobreestima)" if src == "estimado" else ""
        lines.append(f"Pérdida: {res.message_loss['lost']}/{res.message_loss['expected']} "
                     f"({res.message_loss['loss_rate']*100:.2f}%) "
                     f"[esperado={res.message_loss['expected']} "
                     f"recibido={res.message_loss['received']}]{suffix}")
    else:
        lines.append("Pérdida: NO_CALCULABLE (sin seed.txt con conteos esperados)")
    if res.resource_usage:
        cpu = res.resource_usage.get("cpu_percent")
        mem = res.resource_usage.get("peak_rss_mb")
        parts = []
        if cpu is not None:
            parts.append(f"CPU={cpu:.1f}%")
        if mem is not None:
            parts.append(f"mem_pico={mem:.1f} MB")
        if parts:
            lines.append(f"Recursos (runtime): {' '.join(parts)}")
    lines.append("-" * 70)
    lines.append(f"{'Esc':<4} {'Escenario':<34} {'Regla':<12} {'Det':>4} {'Fal':>4} {'%Det':>7}")
    for sid, sc in sorted(res.per_scenario.items()):
        lines.append(f"{sid:<4} {sc['name'][:34]:<34} {sc['expected_rule']:<12} "
                     f"{sc['detected']:>4} {sc['missed']:>4} {sc['detection_rate']*100:>6.1f}%")
    lines.append("-" * 70)
    for w in res.warnings:
        lines.append(f"ADVERTENCIA: {w}")
    lines.append("=" * 70)
    return "\n".join(lines)


def run_from_dir(run_dir: Path, window_s: float = DEFAULT_MATCH_WINDOW_S,
                 out_path: Optional[Path] = None) -> EvaluationResult:
    """Evalúa una corrida completa desde su directorio."""
    gt_path = run_dir / "ground_truth.jsonl"
    # El receptor escribe en <outdir>/alerts/alerts.jsonl; también se
    # acepta alerts.jsonl plano (corridas movidas/manualmente).
    alerts_path = run_dir / "alerts" / "alerts.jsonl"
    if not alerts_path.exists():
        alerts_path = run_dir / "alerts.jsonl"

    if not gt_path.exists():
        raise FileNotFoundError(f"No existe {gt_path}")
    if not alerts_path.exists():
        raise FileNotFoundError(f"No existe {alerts_path}")

    injections = load_ground_truth(gt_path)
    alerts, normal_count, timestamps = load_alerts(alerts_path)
    logger.info(f"Cargadas {len(injections)} inyecciones, {len(alerts)} alertas, "
                f"{normal_count} mensajes normales")

    expected_counts = parse_expected_counts(run_dir)
    resource_usage = read_resource_usage(run_dir)
    received_messages = count_received_messages(run_dir)
    if received_messages is not None:
        logger.info(f"Mensajes procesados por receptor (hl7/*.hl7): "
                    f"{received_messages}")
    res = evaluate(injections, alerts, normal_count, window_s,
                   timestamps=timestamps, expected_counts=expected_counts,
                   resource_usage=resource_usage,
                   received_messages=received_messages)

    out = out_path or (run_dir / "evaluation.json")
    payload = asdict(res)
    with open(out, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    logger.info(f"Reporte escrito en {out}")

    report_txt = run_dir / "evaluation.txt"
    report_txt.write_text(format_report(res), encoding="utf-8")
    return res


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Evalúa detecciones contra verdad de terreno")
    p.add_argument("--run", help="Directorio de corrida (contiene ground_truth.jsonl y alerts.jsonl)")
    p.add_argument("--ground-truth", help="Ruta alternativa ground_truth.jsonl")
    p.add_argument("--alerts", help="Ruta alternativa alerts.jsonl")
    p.add_argument("--out", help="Ruta salida evaluation.json")
    p.add_argument("--window", type=float, default=DEFAULT_MATCH_WINDOW_S,
                   help=f"Ventana matching inyección-alerta en segundos (default {DEFAULT_MATCH_WINDOW_S})")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if args.run:
            res = run_from_dir(Path(args.run), args.window,
                               Path(args.out) if args.out else None)
        elif args.ground_truth and args.alerts:
            injections = load_ground_truth(Path(args.ground_truth))
            alerts, normal_count, timestamps = load_alerts(Path(args.alerts))
            res = evaluate(injections, alerts, normal_count, args.window,
                           timestamps=timestamps)
            if args.out:
                with open(args.out, "w", encoding="utf-8") as f:
                    json.dump(asdict(res), f, ensure_ascii=False, indent=2)
        else:
            logger.error("Especifica --run DIR o --ground-truth X --alerts Y")
            return 2
    except FileNotFoundError as e:
        logger.error(str(e))
        return 3

    print(format_report(res))
    return 0


if __name__ == "__main__":
    sys.exit(main())
