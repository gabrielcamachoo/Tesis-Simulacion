#!/usr/bin/env python3
"""
anomaly_generator.py - Generador de anomalías sintéticas HL7/MLLP (A01-A16)
ÚNICO propósito: inyectar tráfico anómalo etiquetado en el receptor del laboratorio
para evaluar el motor de detección. NO prueba vulnerabilidades reales.

Seguridad obligatoria (falla seguro si no se cumple):
  - LAB_AUTHORIZED=YES en variables de entorno
  - Archivo marcador LAB_ONLY.marker existente
  - Solo destinos localhost / red Docker internal / hostname fijo "receiver"
  - Límites de tasa, tamaño y cantidad de anomalías por corrida

Salida: archivo ground_truth.jsonl con la verdad de terreno (timestamp, escenario,
regla esperada) que evaluate.py cruza con alerts.jsonl.

Uso:
    LAB_AUTHORIZED=YES python anomaly_generator.py --scenario A02 --count 5
    LAB_AUTHORIZED=YES python anomaly_generator.py --all --count 5
"""

import argparse
import json
import logging
import os
import random
import signal
import socket
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

sys.path.insert(0, str(Path(__file__).parent))

from src.mllp.framing import SB, EOM, frame_hl7_message
from src.config.settings import load_settings, Settings

# Hostnames permitidos (nunca IPs públicas)
ALLOWED_HOSTNAMES = {"receiver", "mllp-receiver", "localhost", "127.0.0.1"}
MAX_PAYLOAD_BYTES = 32768  # Límite duro A15


@dataclass
class AnomalyScenario:
    """Definición de un escenario de anomalía."""
    id: str
    name: str
    description: str
    threat: str
    mitre_ics: str
    expected_rule: str
    enabled: bool = True
    safety_limit: int = 10
    params: Dict[str, Any] = field(default_factory=dict)


# Definición canónica de los 16 escenarios (A01-A16)
SCENARIOS: Dict[str, AnomalyScenario] = {
    "A01": AnomalyScenario(
        id="A01", name="unknown_logical_source",
        description="Fuente lógica desconocida en MSH-3/MSH-4",
        threat="Suplantación de identidad (Spoofing)",
        mitre_ics="T1692.002", expected_rule="R-ID-001", safety_limit=10),
    "A02": AnomalyScenario(
        id="A02", name="duplicate_control_id",
        description="Message Control ID duplicado",
        threat="Replay / Duplicación",
        mitre_ics="T1692.002", expected_rule="R-SEQ-001", safety_limit=10),
    "A03": AnomalyScenario(
        id="A03", name="replay_synthetic_message",
        description="Replay byte a byte de un mensaje previo (mismo contenido)",
        threat="Replay attack",
        mitre_ics="T1692.002", expected_rule="R-SEQ-002", safety_limit=10),
    "A04": AnomalyScenario(
        id="A04", name="regressive_timestamp",
        description="Timestamp regresivo en MSH-7",
        threat="Manipulación temporal",
        mitre_ics="T1692.002", expected_rule="R-TIME-001", safety_limit=10),
    "A05": AnomalyScenario(
        id="A05", name="missing_final_delimiter",
        description="Trama MLLP sin delimitador final (0x1C 0x0D)",
        threat="Framing inválido / DoS parser",
        mitre_ics="T1692.002", expected_rule="R-MLLP-001", safety_limit=5),
    "A06": AnomalyScenario(
        id="A06", name="unexpected_bytes_before_start",
        description="Bytes inesperados antes del SB (0x0B)",
        threat="Framing inválido / Evasión parser",
        mitre_ics="T1692.002", expected_rule="R-MLLP-001", safety_limit=5),
    "A07": AnomalyScenario(
        id="A07", name="missing_msh_segment",
        description="Segmento MSH ausente",
        threat="Mensaje malformado",
        mitre_ics="T1692.002", expected_rule="R-HL7-001", safety_limit=5),
    "A08": AnomalyScenario(
        id="A08", name="invalid_segment_order",
        description="Orden de segmentos inválido (OBX antes de MSH)",
        threat="Mensaje malformado",
        mitre_ics="T1692.002", expected_rule="R-HL7-003", safety_limit=5),
    "A09": AnomalyScenario(
        id="A09", name="unknown_message_type",
        description="Tipo de mensaje fuera del baseline (ADT^A01)",
        threat="Inyección de tipo de mensaje no autorizado",
        mitre_ics="T1692.002", expected_rule="R-HL7-002", safety_limit=10),
    "A10": AnomalyScenario(
        id="A10", name="synthetic_obx_unexpected_datatype",
        description="Tipo de dato OBX incompatible (NM donde baseline dice CWE)",
        threat="Manipulación de datos de observación",
        mitre_ics="T1692.002", expected_rule="R-OBX-003", safety_limit=10),
    "A11": AnomalyScenario(
        id="A11", name="synthetic_obx_unauthorized_unit",
        description="Unidad no autorizada en OBX-6",
        threat="Manipulación de unidades de medida",
        mitre_ics="T1692.002", expected_rule="R-OBX-002", safety_limit=10),
    "A12": AnomalyScenario(
        id="A12", name="frequency_out_of_baseline",
        description="Ráfaga de mensajes fuera de frecuencia baseline",
        threat="DoS / Flooding",
        mitre_ics="T0814", expected_rule="R-TIME-002", safety_limit=20,
        params={"max_burst_messages": 20, "burst_duration_seconds": 5}),
    "A13": AnomalyScenario(
        id="A13", name="repeated_reconnections",
        description="Reconexiones repetidas cortas con mensajes (ráfaga de frecuencia)",
        threat="Connection flooding / Resource exhaustion",
        mitre_ics="T0814", expected_rule="R-TIME-002", safety_limit=5,
        params={"max_reconnects": 5, "cooldown_seconds": 60}),
    "A14": AnomalyScenario(
        id="A14", name="periodic_silence",
        description=("Silencio del emisor superior al intervalo baseline y luego "
                     "un mensaje: simula canal degradado / ACK ausente (lado receptor "
                     "no puede ver ACKs, detecta el hueco de periodicidad)"),
        threat="Degradación de canal / DoS parcial",
        mitre_ics="T0814", expected_rule="R-TIME-002", safety_limit=3,
        params={"gap_seconds": 45}),
    "A15": AnomalyScenario(
        id="A15", name="oversized_message",
        description="Mensaje sintético grande (dentro de límite duro seguro)",
        threat="Buffer overflow / DoS de parser",
        mitre_ics="T0814", expected_rule="R-MLLP-001", safety_limit=5,
        params={"max_size_bytes": MAX_PAYLOAD_BYTES}),
    "A16": AnomalyScenario(
        id="A16", name="logical_identity_change_mid_session",
        description="Cambio de identidad lógica MSH-3/MSH-4 durante la sesión",
        threat="Suplantación / Session hijacking",
        mitre_ics="T1692.002", expected_rule="R-ID-001", safety_limit=5),
}


def select_scenarios(exclude_ids=None, seed: Optional[int] = None):
    """Selección de escenarios con orden determinista controlado por semilla.

    Protocolo §6: alternar el orden de escenarios entre corridas; la semilla
    registra el orden (scenario_order.txt en la corrida)."""
    excluded = set(exclude_ids) if exclude_ids else set()
    selected = [s for s in SCENARIOS.values() if s.id not in excluded]
    if seed is not None:
        random.Random(seed).shuffle(selected)
    return selected


def base_hl7_message(control_id: str, timestamp: str,
                     sending_app: str = "MINDRAY_WATOPRO-SERIES^000F14002D3586ec^EUI-64",
                     message_type: str = "ORU^R01^ORU_R01",
                     msh7: Optional[str] = None,
                     obx_datatype: str = "CWE",
                     obx_unit: str = "") -> str:
    """Construye mensaje HL7 base sintético similar al observado."""
    ts = msh7 or timestamp
    msh = (f"MSH|^~\\&|{sending_app}||||{ts}||{message_type}|"
           f"{control_id}|P|2.6|||NE|AL||UNICODE UTF-8|||"
           f"IHE_PCD_001^IHE PCD^1.3.6.1.4.1.19376.1.6.1.1.1^ISO")
    pid = "PID|||^^^^PI||^^^^^^L|||"
    pv1 = "PV1||I|^^^"
    obr = f"OBR|1|1^MINDRAY_WATOPRO-SERIES^...|1^...|70040^MDC_DEV_SYS_ANESTH^MDC|||{ts}|"
    unit_field = f"|{obx_unit}" if obx_unit else ""
    obx = ("OBX|1|" + obx_datatype +
           "|202886^MDC_EVT_STAT_DEV^MDC|1.1.1.202886|"
           "202836^MDC_EVT_STAT_STANDBY^MDC" + unit_field)
    return "\r".join([msh, pid, pv1, obr, obx]) + "\r"


def now_hl7_timestamp() -> str:
    """Timestamp HL7 local con offset."""
    now = datetime.now(timezone.utc)
    base = now.strftime("%Y%m%d%H%M%S")
    off = now.strftime("%z")
    return f"{base}{off[:-2]}:{off[-2:]}"


class SafetyGuard:
    """
    Guardias de seguridad obligatorias del generador de anomalías.
    Si cualquiera falla, el generador NO envía nada (fail-safe).
    """

    def __init__(self, settings: Settings):
        self.settings = settings
        self._errors: List[str] = []

    def check(self, target_host: str, target_port: int) -> bool:
        self._errors = []

        # 1. Variable de entorno LAB_AUTHORIZED=YES
        if os.environ.get("LAB_AUTHORIZED", "").strip().upper() != "YES":
            self._errors.append("LAB_AUTHORIZED=YES no está definido en el entorno")

        # 2. Marcador LAB_ONLY.marker en la ruta configurada (sin atajos)
        marker = Path(self.settings.safety.lab_marker_path)
        if self.settings.safety.require_lab_marker and not marker.exists():
            self._errors.append(
                f"Marcador LAB_ONLY.marker no encontrado: {marker}")

        # 3. Hostname/IP de destino permitido
        host_ok = target_host in ALLOWED_HOSTNAMES
        if not host_ok:
            try:
                import ipaddress
                ip = ipaddress.ip_address(target_host)
                host_ok = ip.is_loopback or (ip.is_private and not ip.is_global)
            except ValueError:
                host_ok = False
        if not host_ok:
            self._errors.append(
                f"Destino NO permitido: {target_host!r} (solo localhost / red interna / 'receiver')")

        # 4. Puerto válido
        if not (1 <= target_port <= 65535):
            self._errors.append(f"Puerto inválido: {target_port}")

        if self._errors:
            for e in self._errors:
                logger.error(f"BLOQUEO DE SEGURIDAD: {e}")
            return False
        return True

    @property
    def errors(self) -> List[str]:
        return self._errors.copy()


@dataclass
class GroundTruthRecord:
    """Registro de verdad de terreno para evaluación."""
    injection_id: str
    scenario_id: str
    scenario_name: str
    expected_rule: str
    timestamp_utc: str
    monotonic_ns: int
    control_id: str
    bytes_sent: int
    target: str
    mitre_ics: str
    threat: str
    # Enmienda E6 (evaluación honesta). source = ip:puerto LOCAL de la
    # conexión que llevó la inyección, tal como la ve el receptor en la
    # alerta (Alert.source). started_utc = cuándo empezó la anomalía; solo
    # difiere de timestamp_utc en A14, cuyo silencio empieza 45 s antes del
    # mensaje que lo cierra. Vacíos en ground truth antiguos.
    source: str = ""
    started_utc: str = ""


def _sock_source(sock: Optional[socket.socket]) -> str:
    try:
        host, port = sock.getsockname()[:2]
        return f"{host}:{port}"
    except (OSError, AttributeError):
        return ""


class AnomalyGenerator:
    """
    Inyecta anomalías sintéticas etiquetadas contra el receptor del laboratorio.
    Cada inyección queda registrada en ground_truth.jsonl.
    """

    def __init__(self, settings: Settings, target_host: str, target_port: int,
                 ground_truth_path: Path, session_label: str = "exp"):
        self.settings = settings
        self.target_host = target_host
        self.target_port = target_port
        self.session_label = session_label
        self.ground_truth_path = ground_truth_path
        self.counters: Dict[str, int] = {sid: 0 for sid in SCENARIOS}
        self._injection_counter = 0
        self._total_injections = 0
        self._sock: Optional[socket.socket] = None
        self._last_send = 0.0
        self._prev_message: Optional[bytes] = None  # para A03 replay
        self._prev_timestamp: Optional[str] = None  # para A04 regresivo
        self._a02_seeded = False
        self.running = True

        # Límites globales de seguridad (fail-safe)
        gen_limits = settings.anomaly_generator.safety_limits or {}
        self.max_total_injections = int(gen_limits.get("max_anomalies_per_run", 50))
        self.max_rate_per_sec = float(gen_limits.get("max_rate_per_second", 5))
        self.max_payload_bytes = min(
            int(gen_limits.get("max_message_size_bytes", MAX_PAYLOAD_BYTES)),
            MAX_PAYLOAD_BYTES)

        self.ground_truth_path.parent.mkdir(parents=True, exist_ok=True)
        self._gt_file = open(self.ground_truth_path, "a", encoding="utf-8")

    def _rate_limit(self):
        """Aplica límite de tasa global (min de safety general y del generador)."""
        max_rate = min(self.settings.safety.max_message_rate_per_sec or 10,
                       self.max_rate_per_sec or 5)
        if max_rate <= 0:
            return
        min_interval = 1.0 / max_rate
        elapsed = time.monotonic() - self._last_send
        if elapsed < min_interval:
            time.sleep(min_interval - elapsed)
        self._last_send = time.monotonic()

    def _connect(self) -> bool:
        try:
            self._sock = socket.create_connection(
                (self.target_host, self.target_port), timeout=5)
            self._sock.settimeout(5)
            return True
        except OSError as e:
            logger.error(f"No se pudo conectar a {self.target_host}:{self.target_port}: {e}")
            return False

    def _close(self):
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

    def _record(self, scenario: AnomalyScenario, control_id: str,
                bytes_sent: int, sock: Optional[socket.socket] = None,
                started_utc: Optional[str] = None) -> GroundTruthRecord:
        # Cap global de inyecciones por corrida
        if self._total_injections >= self.max_total_injections:
            raise RuntimeError(
                f"Límite global de inyecciones alcanzado ({self.max_total_injections})")
        self._injection_counter += 1
        self._total_injections += 1
        self.counters[scenario.id] += 1
        now_utc = datetime.now(timezone.utc).isoformat()
        rec = GroundTruthRecord(
            injection_id=f"INJ-{self._injection_counter:05d}",
            scenario_id=scenario.id,
            scenario_name=scenario.name,
            expected_rule=scenario.expected_rule,
            timestamp_utc=now_utc,
            monotonic_ns=time.monotonic_ns(),
            control_id=control_id,
            bytes_sent=bytes_sent,
            target=f"{self.target_host}:{self.target_port}",
            mitre_ics=scenario.mitre_ics,
            threat=scenario.threat,
            source=_sock_source(sock if sock is not None else self._sock),
            started_utc=started_utc or now_utc,
        )
        self._gt_file.write(json.dumps(asdict(rec), ensure_ascii=False) + "\n")
        self._gt_file.flush()
        return rec

    def _send_raw(self, payload: bytes, scenario: AnomalyScenario,
                  control_id: str,
                  started_utc: Optional[str] = None) -> Optional[GroundTruthRecord]:
        """Envía payload crudo respetando rate limit; registra ground truth."""
        if not self._sock:
            if not self._connect():
                return None
        self._rate_limit()
        try:
            self._sock.sendall(payload)
            return self._record(scenario, control_id, len(payload),
                                started_utc=started_utc)
        except OSError as e:
            logger.warning(f"Error enviando {scenario.id}: {e}")
            self._close()
            return None

    def _send_hl7(self, hl7_text: str, scenario: AnomalyScenario,
                  control_id: str, frame: Optional[bytes] = None) -> Optional[GroundTruthRecord]:
        payload = frame if frame is not None else frame_hl7_message(hl7_text.encode("utf-8"))
        rec = self._send_raw(payload, scenario, control_id)
        if rec:
            self._prev_message = payload
        return rec

    def _send_setup(self, hl7_text: str) -> bool:
        """
        Envía un mensaje de preparación (seed) SIN registrarlo como inyección.
        Se usa para que la inyección posterior sea detectable (ej. MCID
        duplicado requiere un MCID previo visto).
        """
        payload = frame_hl7_message(hl7_text.encode("utf-8"))
        if not self._sock and not self._connect():
            return False
        self._rate_limit()
        try:
            self._sock.sendall(payload)
            self._prev_message = payload
            logger.debug("SETUP enviado (no registrado en ground truth)")
            return True
        except OSError as e:
            logger.warning(f"Error enviando setup: {e}")
            self._close()
            return False

    def _send_fresh_connection(self, payload: bytes,
                               scenario: AnomalyScenario,
                               control_id: str,
                               close_after: bool = True) -> Optional[GroundTruthRecord]:
        """
        Envía en una conexión DEDICADA (se abre y cierra).
        Necesario para A05: el servidor detecta la trama incompleta al
        cerrarse la sesión.
        """
        sock = None
        try:
            sock = socket.create_connection((self.target_host, self.target_port),
                                            timeout=5)
            sock.settimeout(5)
            self._rate_limit()
            sock.sendall(payload)
            rec = self._record(scenario, control_id, len(payload), sock=sock)
            return rec
        except OSError as e:
            logger.warning(f"Error en conexión dedicada ({scenario.id}): {e}")
            return None
        finally:
            if sock and close_after:
                try:
                    sock.close()
                except OSError:
                    pass

    # ------------------------------------------------------------------
    # Constructores de anomalías por escenario
    # ------------------------------------------------------------------
    def inject(self, scenario: AnomalyScenario, seq: int) -> Optional[GroundTruthRecord]:
        ts = now_hl7_timestamp()
        cid = f"ANOM-{scenario.id}-{seq}"

        if scenario.id == "A01":
            # Identidad lógica desconocida
            hl7 = base_hl7_message(cid, ts,
                                   sending_app="MALICIOUS_APP^hacker^L")
            return self._send_hl7(hl7, scenario, cid)

        if scenario.id == "A02":
            # MCID duplicado: sembrar UNA vez con un MCID fijo (sin registrar)
            # y luego inyectar otro mensaje con el MISMO MCID.
            # MCID fijo "DUP-SEED-0001" no colisiona con los secuenciales
            # del emulador benigno.
            dup_cid = "DUP-SEED-0001"
            if not self._a02_seeded:
                if not self._send_setup(base_hl7_message(dup_cid, now_hl7_timestamp())):
                    return None
                self._a02_seeded = True
                time.sleep(0.1)
            hl7 = base_hl7_message(dup_cid, ts)
            return self._send_hl7(hl7, scenario, dup_cid)

        if scenario.id == "A03":
            # Replay byte a byte del mensaje anterior (seed no se registra)
            if not self._prev_message:
                if not self._send_setup(base_hl7_message(f"SEED-{seq}", now_hl7_timestamp())):
                    return None
                time.sleep(0.1)
            replay = self._prev_message
            if not replay:
                return None
            return self._send_raw(replay, scenario, f"REPLAY-{seq}")

        if scenario.id == "A04":
            # Timestamp regresivo: sembrar con ts actual (sin registrar) y
            # luego inyectar una hora antes. Usar MCID con prefijo SEED- (D-05)
            # para no colisionar con el MCID de la inyección ni confundirse con tráfico benigno.
            if not self._prev_timestamp:
                seed_ts = now_hl7_timestamp()
                if not self._send_setup(base_hl7_message(f"SEED-A04-{seq}", seed_ts)):
                    return None
                self._prev_timestamp = seed_ts
                time.sleep(0.1)
            prev = datetime.strptime(self._prev_timestamp, "%Y%m%d%H%M%S%z")
            earlier = prev.timestamp() - 3600
            reg = datetime.fromtimestamp(earlier, tz=prev.tzinfo)
            reg_ts = reg.strftime("%Y%m%d%H%M%S") + reg.strftime("%z")[:-2] + ":" + reg.strftime("%z")[-2:]
            hl7 = base_hl7_message(cid, reg_ts)
            rec = self._send_hl7(hl7, scenario, cid)
            # Encadenar: la siguiente inyección será aún más antigua que
            # esta, manteniendo la regresión frente al global del motor.
            self._prev_timestamp = reg_ts
            return rec

        if scenario.id == "A05":
            # MLLP sin delimitador final, en conexión DEDICADA que se cierra:
            # el servidor alerta la trama incompleta al cerrar la sesión.
            hl7 = base_hl7_message(cid, ts)
            broken = SB + hl7.encode("utf-8")
            return self._send_fresh_connection(broken, scenario, cid)

        if scenario.id == "A06":
            # Bytes basura antes del SB
            hl7 = base_hl7_message(cid, ts)
            garbage = b"\x00\xFFGARBAGE" + frame_hl7_message(hl7.encode("utf-8"))
            return self._send_raw(garbage, scenario, cid)

        if scenario.id == "A07":
            # Sin segmento MSH
            no_msh = ("PID|||^^^^PI||^^^^^^L|||\r"
                      "PV1||I|^^^\r"
                      f"OBR|1|1^X|1^X|70040^MDC_DEV_SYS_ANESTH^MDC|||{ts}|\r"
                      "OBX|1|CWE|202886^MDC_EVT_STAT_DEV^MDC|1.1.1.202886|202836^MDC_EVT_STAT_STANDBY^MDC\r")
            return self._send_hl7(no_msh, scenario, cid)

        if scenario.id == "A08":
            # Orden inválido: OBX antes de MSH
            msh = (f"MSH|^~\\&|MINDRAY_WATOPRO-SERIES^000F14002D3586ec^EUI-64||||{ts}||"
                   f"ORU^R01^ORU_R01|{cid}|P|2.6|||NE|AL||UNICODE UTF-8|||"
                   f"IHE_PCD_001^IHE PCD^1.3.6.1.4.1.19376.1.6.1.1.1^ISO")
            obx_first = ("OBX|1|CWE|202886^MDC_EVT_STAT_DEV^MDC|1.1.1.202886|"
                         "202836^MDC_EVT_STAT_STANDBY^MDC\r")
            bad = obx_first + msh + "\r"
            return self._send_hl7(bad, scenario, cid)

        if scenario.id == "A09":
            # Tipo de mensaje no permitido
            hl7 = base_hl7_message(cid, ts, message_type="ADT^A01^ADT_A01")
            return self._send_hl7(hl7, scenario, cid)

        if scenario.id == "A10":
            # Tipo de dato OBX incompatible (NM donde baseline espera CWE)
            hl7 = base_hl7_message(cid, ts, obx_datatype="NM")
            return self._send_hl7(hl7, scenario, cid)

        if scenario.id == "A11":
            # Unidad no autorizada en OBX-6
            hl7 = base_hl7_message(cid, ts, obx_unit="mg/dL")
            return self._send_hl7(hl7, scenario, cid)

        if scenario.id == "A12":
            # Ráfaga corta controlada (rate limit sigue aplicando)
            burst = min(scenario.params.get("max_burst_messages", 20),
                        scenario.safety_limit)
            last = None
            for i in range(burst):
                b_cid = f"{cid}-{i}"
                hl7 = base_hl7_message(b_cid, now_hl7_timestamp())
                last = self._send_hl7(hl7, scenario, b_cid)
                if not self.running:
                    break
            return last

        if scenario.id == "A13":
            # Reconexiones repetidas
            attempts = min(scenario.params.get("max_reconnects", 5),
                           scenario.safety_limit)
            last = None
            for i in range(attempts):
                self._close()
                if self._connect():
                    hl7 = base_hl7_message(f"{cid}-r{i}", now_hl7_timestamp())
                    last = self._send_hl7(hl7, scenario, f"{cid}-r{i}")
                time.sleep(0.5)
                if not self.running:
                    break
            return last

        if scenario.id == "A14":
            # Silencio periódico: esperar un hueco superior al intervalo
            # baseline (>15 s) y luego enviar un mensaje. El motor detecta
            # el intervalo anómalo (R-TIME-002) en el receptor.
            gap = float(scenario.params.get("gap_seconds", 45))
            logger.info(f"A14: silencio de {gap}s simulando canal degradado...")
            # E6: el silencio (la anomalía) empieza aquí, no al enviar el
            # mensaje que lo cierra. El vigilante E3 alerta durante el hueco.
            silence_start = datetime.now(timezone.utc).isoformat()
            end = time.monotonic() + gap
            while time.monotonic() < end and self.running:
                time.sleep(min(1.0, end - time.monotonic()))
            if not self.running:
                return None
            hl7 = base_hl7_message(cid, now_hl7_timestamp())
            frame = frame_hl7_message(hl7.encode("utf-8"))
            return self._send_raw(frame, scenario, cid,
                                  started_utc=silence_start)

        if scenario.id == "A15":
            # Mensaje grande pero bajo el límite duro
            target_size = min(scenario.params.get("max_size_bytes", MAX_PAYLOAD_BYTES),
                              MAX_PAYLOAD_BYTES)
            filler_count = max(0, target_size - 512)
            msh = (f"MSH|^~\\&|MINDRAY_WATOPRO-SERIES^000F14002D3586ec^EUI-64||||{ts}||"
                   f"ORU^R01^ORU_R01|{cid}|P|2.6|||NE|AL||UNICODE UTF-8|||"
                   f"IHE_PCD_001^IHE PCD^1.3.6.1.4.1.19376.1.6.1.1.1^ISO")
            nte = "NTE|1||" + ("SYNTHETIC-FILLER-" * ((filler_count // 17) + 1))[:filler_count]
            big = msh + "\r" + nte + "\r"
            payload = frame_hl7_message(big.encode("utf-8"))
            if len(payload) > MAX_PAYLOAD_BYTES + 8:
                payload = payload[:MAX_PAYLOAD_BYTES]
            return self._send_raw(payload, scenario, cid)

        if scenario.id == "A16":
            # Cambio de identidad a mitad de sesión
            hl7 = base_hl7_message(cid, ts,
                                   sending_app="MINDRAY_WATOPRO-SERIES^000F14002DEVI1234^EUI-64")
            return self._send_hl7(hl7, scenario, cid)

        logger.warning(f"Escenario {scenario.id} sin implementación")
        return None

    def run_scenario(self, scenario: AnomalyScenario, count: int) -> int:
        """Ejecuta un escenario N veces. Devuelve inyecciones registradas
        en ground truth (los escenarios de ráfaga registran varias por
        llamada, ej. A12=20, A13=5)."""
        if not scenario.enabled:
            logger.info(f"{scenario.id} deshabilitado, omitiendo")
            return 0
        
        injections_before = self._injection_counter
        
        # Escenarios de ráfaga/reconexión internas: UNA sola llamada ya
        # genera todas las inyecciones (evita multiplicar por count)
        burst_scenarios = {"A12", "A13"}
        if scenario.id in burst_scenarios:
            effective = 1
        else:
            effective = min(count, scenario.safety_limit)
            if effective < count:
                logger.info(f"{scenario.id}: limitado a {effective} (safety_limit="
                            f"{scenario.safety_limit}) de {count} solicitadas")
        ok = 0
        for seq in range(1, effective + 1):
            if not self.running:
                break
            if self._total_injections >= self.max_total_injections:
                logger.warning(f"Límite global de inyecciones alcanzado "
                               f"({self.max_total_injections}); deteniendo")
                break
            try:
                rec = self.inject(scenario, seq)
            except RuntimeError as e:
                logger.warning(str(e))
                break
            if rec:
                ok += 1
                logger.info(f"{scenario.id} [{rec.injection_id}] "
                            f"regla_esperada={scenario.expected_rule} "
                            f"bytes={rec.bytes_sent}")
            if scenario.id not in burst_scenarios:
                time.sleep(0.2)
        return self._injection_counter - injections_before

    def close(self):
        self._close()
        if self._gt_file:
            self._gt_file.close()

    def summary(self) -> Dict[str, int]:
        return {k: v for k, v in self.counters.items() if v > 0}


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Generador de anomalías sintéticas HL7/MLLP (laboratorio aislado)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Escenarios:
  A01 identidad desconocida        A09 tipo mensaje no permitido
  A02 MCID duplicado               A10 tipo dato OBX incompatible
  A03 replay de contenido          A11 unidad OBX no autorizada
  A04 timestamp regresivo          A12 ráfaga de frecuencia
  A05 MLLP sin EB/CR               A13 reconexiones repetidas
  A06 basura antes de SB           A14 silencio periódico (hueco >15 s)
  A07 sin segmento MSH             A15 mensaje grande (límite duro)
  A08 orden de segmentos inválido  A16 cambio identidad en sesión

Requiere: LAB_AUTHORIZED=YES y LAB_ONLY.marker
        """)
    p.add_argument("--scenario", choices=list(SCENARIOS.keys()),
                   help="Escenario a ejecutar")
    p.add_argument("--all", action="store_true", help="Ejecutar los 16 escenarios")
    p.add_argument("--exclude", default="",
                   help="Escenarios a excluir con --all, separados por coma (ej: A14)")
    p.add_argument("--seed", type=int, default=None,
                   help="Semilla PRNG: alterna el orden de escenarios con --all "
                        "(protocolo §6; registrada en scenario_order.txt)")
    p.add_argument("--count", type=int, default=5,
                   help="Inyecciones por escenario (default 5, tope safety_limit)")
    p.add_argument("--host", default="mllp-receiver",
                   help="Destino (solo hostname interno o localhost)")
    p.add_argument("--port", type=int, default=1550, help="Puerto destino")
    p.add_argument("--config", default="src/config/settings.yaml",
                   help="Archivo de configuración")
    p.add_argument("--ground-truth", default=None,
                   help="Ruta ground_truth.jsonl (default runs/<ts>/ground_truth.jsonl)")
    p.add_argument("--runs-dir", default="runs", help="Directorio base de corridas")
    p.add_argument("--dry-run", action="store_true",
                   help="Valida seguridad y lista escenarios sin enviar")
    return p.parse_args()


def main() -> int:
    args = parse_args()

    if not args.scenario and not args.all:
        logger.error("Especifica --scenario AXX o --all")
        return 2

    # Desarrollo local (p. ej. Windows): la ruta por defecto /LAB_ONLY.marker
    # no es escribible en la raíz del disco. Si falta, cargar la configuración
    # apuntando al marcador del repo (mismo criterio que run_experiment).
    cfg_path = Path(args.config)
    if cfg_path.exists() and not Path("/LAB_ONLY.marker").exists():
        local_marker = Path(__file__).parent / "LAB_ONLY.marker"
        text = cfg_path.read_text(encoding="utf-8")
        if local_marker.exists() and 'lab_marker_path: "/LAB_ONLY.marker"' in text:
            import tempfile
            text = text.replace('lab_marker_path: "/LAB_ONLY.marker"',
                                f'lab_marker_path: "{local_marker.as_posix()}"')
            with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False,
                                             encoding="utf-8") as tf:
                tf.write(text)
            args.config = tf.name
            logger.info(f"Config con marcador del repo: {args.config}")

    try:
        settings = load_settings(args.config)
    except RuntimeError as e:
        logger.error(f"Configuración rechazada: {e}")
        return 3

    guard = SafetyGuard(settings)
    if not guard.check(args.host, args.port):
        logger.error("Generador BLOQUEADO por validación de seguridad.")
        logger.error("Para entorno de laboratorio autorizado:")
        logger.error("  export LAB_AUTHORIZED=YES")
        logger.error("  touch LAB_ONLY.marker")
        return 3

    exclude = {s.strip() for s in args.exclude.split(",") if s.strip()}
    if args.all:
        selected = select_scenarios(exclude, args.seed)
    else:
        selected = [SCENARIOS[args.scenario]]

    if args.seed is not None:
        logger.info(f"SEED={args.seed} ORDER={' '.join(s.id for s in selected)}")

    if args.dry_run:
        logger.info("DRY-RUN: seguridad OK, no se envía nada")
        for s in selected:
            logger.info(f"  {s.id} {s.name} -> regla {s.expected_rule} "
                        f"(límite {s.safety_limit}, MITRE {s.mitre_ics})")
        return 0

    ts_dir = datetime.now().strftime("%Y%m%d_%H%M%S")
    gt_path = (Path(args.ground_truth) if args.ground_truth
               else Path(args.runs_dir) / ts_dir / "ground_truth.jsonl")

    if args.seed is not None:
        gt_path.parent.mkdir(parents=True, exist_ok=True)
        (gt_path.parent / "scenario_order.txt").write_text(
            f"seed={args.seed}\n" +
            "".join(f"{i + 1:02d} {s.id} {s.name}\n"
                    for i, s in enumerate(selected)),
            encoding="utf-8")

    logger.info("=" * 60)
    logger.info("GENERADOR DE ANOMALÍAS - LABORATORIO AISLADO")
    logger.info(f"Destino: {args.host}:{args.port}")
    logger.info(f"Escenarios: {', '.join(s.id for s in selected)}")
    logger.info(f"Ground truth: {gt_path}")
    logger.info("=" * 60)

    gen = AnomalyGenerator(settings, args.host, args.port, gt_path,
                           session_label=ts_dir)

    def _sig(signum, frame):
        logger.info("Señal recibida, deteniendo...")
        gen.running = False
    signal.signal(signal.SIGINT, _sig)
    signal.signal(signal.SIGTERM, _sig)

    total = 0
    try:
        for s in selected:
            if not gen.running:
                break
            total += gen.run_scenario(s, args.count)
    finally:
        summary = gen.summary()
        gen.close()

    logger.info("=" * 60)
    logger.info(f"COMPLETADO: {total} inyecciones exitosas")
    for sid, n in summary.items():
        logger.info(f"  {sid}: {n}")
    logger.info(f"Ground truth: {gt_path}")
    logger.info("=" * 60)
    return 0 if total > 0 else 1


if __name__ == "__main__":
    sys.exit(main())
