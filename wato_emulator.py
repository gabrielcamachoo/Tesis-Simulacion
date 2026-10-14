#!/usr/bin/env python3
"""
wato_emulator.py - Emulador sintético HL7/MLLP para Mindray WATO EX-35
Genera tráfico benigno que reproduce la estructura y periodicidad observadas.
Solo se conecta al receptor fijo del laboratorio (nombre de servicio o localhost).
"""

import argparse
import socket
import time
import logging
import signal
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field
from enum import Enum

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# Importar componentes del proyecto
sys.path.insert(0, str(Path(__file__).parent / 'src'))
from src.mllp.framing import SB, EOM, frame_hl7_message, deframe_hl7_message
from src.mllp.ack import parse_ack, validate_ack
from src.hl7.parser import parse_hl7_message
from src.config.settings import load_settings


class EmulatorState(Enum):
    """Estados del emulador basados en evidencia observada."""
    STANDBY = "STANDBY"
    RUNNING = "RUNNING"
    ALARM_SIMULATED = "ALARM_SIMULATED"
    SESSION_END = "SESSION_END"
    DISCONNECTED = "DISCONNECTED"


@dataclass
class EmulatorConfig:
    """Configuración del emulador."""
    receiver_host: str = "mllp-receiver"
    receiver_port: int = 1550
    bind_host: str = "0.0.0.0"
    bind_port: int = 0  # Puerto efímero automático
    state: EmulatorState = EmulatorState.STANDBY
    interval_seconds: float = 10.0
    message_count: int = 0
    max_messages: int = 0  # 0 = infinito
    synthetic_prefix: str = "SYNTHETIC-NOT-FOR-CLINICAL-USE"
    require_ack: bool = True
    ack_timeout: float = 5.0
    reconnect_delay: float = 2.0
    max_reconnects: int = 3


class WATOEmulator:
    """
    Emulador de máquina de anestesia Mindray WATO EX-35.
    Genera mensajes HL7 ORU^R01 sintéticos con framing MLLP.
    """
    
    # Plantillas HL7 sintéticas basadas en evidencia observada
    TEMPLATES = {
        EmulatorState.STANDBY: {
            'msh': (
                "MSH|^~\\&|MINDRAY_WATOPRO-SERIES^000F14002D3586ec^EUI-64||||"
                "{timestamp}||ORU^R01^ORU_R01|{ctrl_id}|P|2.6|||NE|AL||UNICODE UTF-8|||"
                "IHE_PCD_001^IHE PCD^1.3.6.1.4.1.19376.1.6.1.1.1^ISO"
            ),
            'pid': "PID|||^^^^PI||^^^^^^L|||",
            'pv1': "PV1||I|^^^",
            'obr': (
                "OBR|1|1^MINDRAY_WATOPRO-SERIES^...|1^...|"
                "70040^MDC_DEV_SYS_ANESTH^MDC|||{timestamp}|"
            ),
            'obx': [
                "OBX|1|CWE|202886^MDC_EVT_STAT_DEV^MDC|1.1.1.202886|202836^MDC_EVT_STAT_STANDBY^MDC",
                "OBX|2|CWE|30002^MNDRY_EVT_STAT_MODE_DEV|1.1.1.30002|30003^MNDRY_EVT_STAT_MODE_NORMAL",
                "OBX|3|CWE|30005^MNDRY_EVT_PATIENT_TYPE|1.1.1.30005|202890^MDC_EVT_STAT_DEV_MODE_ADULT",
                "OBX|4|CWE|30007^MNDRY_EVT_STAT_WARMER_ON_BOOL|1.3.1.30007|30000^MDC_TRUE",
            ]
        },
        EmulatorState.RUNNING: {
            'msh': (
                "MSH|^~\\&|MINDRAY_WATOPRO-SERIES^000F14002D3586ec^EUI-64||||"
                "{timestamp}||ORU^R01^ORU_R01|{ctrl_id}|P|2.6|||NE|AL||UNICODE UTF-8|||"
                "IHE_PCD_001^IHE PCD^1.3.6.1.4.1.19376.1.6.1.1.1^ISO"
            ),
            'pid': "PID|||12345^5^M11^ADT^MR||DOE^JOHN^^^^^L||19800101|M",
            'pv1': "PV1||I|ICU^101^A^^^HOSP^A",
            'obr': (
                "OBR|1|1^MINDRAY_WATOPRO-SERIES^...|1^...|"
                "70040^MDC_DEV_SYS_ANESTH^MDC|||{timestamp}|"
            ),
            'obx': [
                "OBX|1|NM|150020^MDC_VOL_RESP_TIDAL^MDC||{tv}|mL",
                "OBX|2|NM|150021^MDC_VOL_RESP_MINUTE^MDC||{mv}|L/min",
                "OBX|3|NM|150022^MDC_RATE_RESP^MDC||{rr}|/min",
                "OBX|4|NM|150005^MDC_PRESS_AWAY_PEAK^MDC||{pip}|cmH2O",
                "OBX|5|NM|150007^MDC_PRESS_AWAY_MEAN^MDC||{map}|cmH2O",
                "OBX|6|NM|150009^MDC_PRESS_AWAY_PEEP^MDC||{peep}|cmH2O",
                "OBX|7|NM|150456^MDC_CONC_GAS_O2_INSP^MDC||{fio2}|%",
                "OBX|8|NM|150457^MDC_CONC_GAS_CO2_ET^MDC||{etco2}|mmHg",
                "OBX|9|CWE|202886^MDC_EVT_STAT_DEV^MDC||202837^MDC_EVT_STAT_RUNNING^MDC",
                "OBX|10|CWE|184352^MDC_VENT_MODE^MDC|1.3.1.184352|50005^MNDRY_VENT_MODE_VCV^99MNDRY",
            ]
        },
        EmulatorState.ALARM_SIMULATED: {
            'msh': (
                "MSH|^~\\&|MINDRAY_WATOPRO-SERIES^000F14002D3586ec^EUI-64||||"
                "{timestamp}||ORU^R01^ORU_R01|{ctrl_id}|P|2.6|||NE|AL||UNICODE UTF-8|||"
                "IHE_PCD_001^IHE PCD^1.3.6.1.4.1.19376.1.6.1.1.1^ISO"
            ),
            'pid': "PID|||12345^5^M11^ADT^MR||DOE^JOHN^^^^^L||19800101|M",
            'pv1': "PV1||I|ICU^101^A^^^HOSP^A",
            'obr': (
                "OBR|1|1^MINDRAY_WATOPRO-SERIES^...|1^...|"
                "70040^MDC_DEV_SYS_ANESTH^MDC|||{timestamp}|"
            ),
            'obx': [
                "OBX|1|NM|150020^MDC_VOL_RESP_TIDAL^MDC||{tv}|mL",
                "OBX|2|NM|150021^MDC_VOL_RESP_MINUTE^MDC||{mv}|L/min",
                "OBX|3|CWE|202886^MDC_EVT_STAT_DEV^MDC||202838^MDC_EVT_STAT_ALARM^MDC",
                "OBX|4|CWE|30001^MNDRY_EVT_ALARM^MDC||{alarm_code}|MDC",
                "OBX|5|ST|30002^MNDRY_EVT_ALARM_TEXT^MDC||{alarm_text}",
            ]
        }
    }
    
    # Valores fisiológicos simulados para modo RUNNING
    PHYSIOLOGICAL_RANGES = {
        'tv': (450, 550),      # mL
        'mv': (7.0, 9.0),      # L/min
        'rr': (14, 18),        # /min
        'pip': (18, 25),       # cmH2O
        'map': (10, 15),       # cmH2O
        'peep': (4, 6),        # cmH2O
        'fio2': (30, 50),      # %
        'etco2': (35, 45),     # mmHg
    }
    
    ALARM_CODES = [
        ("30001^MNDRY_ALARM_HIGH_PIP", "HIGH PIP ALARM"),
        ("30002^MNDRY_ALARM_LOW_MV", "LOW MINUTE VOLUME"),
        ("30003^MNDRY_ALARM_APNEA", "APNEA DETECTED"),
        ("30004^MNDRY_ALARM_O2_SUPPLY", "O2 SUPPLY FAILURE"),
        ("30005^MNDRY_ALARM_DISCONNECT", "CIRCUIT DISCONNECT"),
    ]

    def __init__(self, config: EmulatorConfig):
        self.config = config
        self.sock: Optional[socket.socket] = None
        # Control ID inicial aleatorio: evita colisiones si el emulador se
        # reinicia (fase 1 y fase 2 del experimento) y con semillas del
        # generador de anomalías (MCID duplicado).
        import random
        self.ctrl_id = random.randint(100000, 999999)
        self.running = False
        self.reconnect_count = 0
        self.last_message_time = 0
        self._lock = threading.Lock()
        self.stats = {
            'messages_sent': 0,
            'acks_received': 0,
            'ack_timeouts': 0,
            'reconnects': 0,
            'errors': 0
        }

    def _generate_timestamp(self) -> str:
        """Genera timestamp HL7 en formato YYYYMMDDHHMMSS±ZZZZ."""
        now = datetime.now(timezone.utc)
        return now.strftime("%Y%m%d%H%M%S%z")[:-2] + ":" + now.strftime("%z")[-2:]

    def _build_message(self) -> str:
        """Construye mensaje HL7 completo según estado actual."""
        template = self.TEMPLATES.get(self.config.state, self.TEMPLATES[EmulatorState.STANDBY])
        timestamp = self._generate_timestamp()
        
        # Valores fisiológicos aleatorios para RUNNING/ALARM
        import random
        physio = {}
        for key, (min_v, max_v) in self.PHYSIOLOGICAL_RANGES.items():
            if isinstance(min_v, int):
                physio[key] = str(random.randint(min_v, max_v))
            else:
                physio[key] = f"{random.uniform(min_v, max_v):.1f}"
        
        # Alarm code/text para ALARM_SIMULATED
        alarm_code, alarm_text = random.choice(self.ALARM_CODES)
        
        # Construir segmentos
        segments = []
        
        # MSH
        msh = template['msh'].format(timestamp=timestamp, ctrl_id=self.ctrl_id)
        segments.append(msh)
        
        # PID, PV1, OBR
        for seg_key in ['pid', 'pv1', 'obr']:
            seg = template[seg_key].format(timestamp=timestamp, **physio)
            segments.append(seg)
        
        # OBX segments
        for obx_template in template['obx']:
            obx = obx_template.format(
                timestamp=timestamp,
                ctrl_id=self.ctrl_id,
                tv=physio.get('tv', '500'),
                mv=physio.get('mv', '8.0'),
                rr=physio.get('rr', '16'),
                pip=physio.get('pip', '22'),
                map=physio.get('map', '12'),
                peep=physio.get('peep', '5'),
                fio2=physio.get('fio2', '40'),
                etco2=physio.get('etco2', '40'),
                alarm_code=alarm_code,
                alarm_text=alarm_text
            )
            segments.append(obx)
        
        # Unir con \r y terminar con \r
        hl7_message = '\r'.join(segments) + '\r'
        
        # Añadir prefijo sintético en comentario (no parte del HL7 estándar)
        # Lo añadimos como NTE segment opcional
        nte = f"NTE|1|{self.config.synthetic_prefix} - State: {self.config.state.value} - Msg: {self.ctrl_id}"
        hl7_message = hl7_message.rstrip('\r') + '\r' + nte + '\r'
        
        return hl7_message

    def _send_message(self, hl7_message: str) -> bool:
        """Envía mensaje HL7 con framing MLLP y espera ACK si configurado."""
        try:
            mllp_frame = frame_hl7_message(hl7_message.encode('utf-8'))
            self.sock.sendall(mllp_frame)
            self.stats['messages_sent'] += 1
            logger.info(f"SENT MLLP frame: {len(mllp_frame)} bytes, state={self.config.state.value}, ctrl_id={self.ctrl_id}")
            
            if self.config.require_ack:
                return self._wait_for_ack()
            return True
            
        except (socket.timeout, ConnectionResetError, BrokenPipeError, OSError) as e:
            logger.error(f"Send error: {e}")
            self.stats['errors'] += 1
            return False

    def _wait_for_ack(self) -> bool:
        """Espera y valida ACK del receptor."""
        try:
            self.sock.settimeout(self.config.ack_timeout)
            data = self.sock.recv(8192)
            if not data:
                logger.warning("ACK timeout: no data received")
                self.stats['ack_timeouts'] += 1
                return False
            
            # Desenmarcar MLLP
            hl7_content = deframe_hl7_message(data)
            if not hl7_content:
                logger.warning("ACK received but invalid MLLP framing")
                self.stats['ack_timeouts'] += 1
                return False
            
            ack_text = hl7_content.decode('utf-8', errors='replace')
            parsed_ack = parse_ack(ack_text)
            
            if not parsed_ack:
                logger.warning(f"ACK received but not parsable: {ack_text[:100]}")
                self.stats['ack_timeouts'] += 1
                return False
            
            valid, reason = validate_ack(parsed_ack, str(self.ctrl_id))
            if not valid:
                logger.warning(f"ACK validation failed: {reason}")
                self.stats['ack_timeouts'] += 1
                return False
            
            logger.info(f"ACK received and validated: code={parsed_ack.ack_code}, ctrl_id={parsed_ack.message_control_id}")
            self.stats['acks_received'] += 1
            return True
            
        except socket.timeout:
            logger.warning("ACK timeout")
            self.stats['ack_timeouts'] += 1
            return False
        except Exception as e:
            logger.error(f"ACK error: {e}")
            self.stats['ack_timeouts'] += 1
            return False

    def _connect(self) -> bool:
        """Establece conexión TCP con el receptor."""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(10)
            
            # Bind a puerto local si se especifica
            if self.config.bind_port > 0:
                self.sock.bind((self.config.bind_host, self.config.bind_port))
            
            logger.info(f"Connecting to {self.config.receiver_host}:{self.config.receiver_port}")
            self.sock.connect((self.config.receiver_host, self.config.receiver_port))
            
            local_addr = self.sock.getsockname()
            logger.info(f"Connected from {local_addr[0]}:{local_addr[1]}")
            return True
            
        except Exception as e:
            logger.error(f"Connection failed: {e}")
            if self.sock:
                self.sock.close()
                self.sock = None
            return False

    def _disconnect(self):
        """Cierra conexión limpiamente."""
        if self.sock:
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except:
                pass
            self.sock.close()
            self.sock = None

    def run(self):
        """Bucle principal del emulador."""
        self.running = True
        logger.info(f"Starting WATO Emulator - State: {self.config.state.value}")
        logger.info(f"Target: {self.config.receiver_host}:{self.config.receiver_port}")
        
        # Manejo de señales
        def signal_handler(signum, frame):
            logger.info(f"Signal {signum} received, shutting down...")
            self.running = False
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        while self.running:
            # Conectar si no hay conexión
            if not self.sock:
                if not self._connect():
                    self.reconnect_count += 1
                    self.stats['reconnects'] += 1
                    if self.reconnect_count >= self.config.max_reconnects:
                        logger.error(f"Max reconnects ({self.config.max_reconnects}) reached, stopping")
                        break
                    time.sleep(self.config.reconnect_delay)
                    continue
                self.reconnect_count = 0
            
            # Verificar límite de mensajes
            if self.config.max_messages > 0 and self.stats['messages_sent'] >= self.config.max_messages:
                logger.info(f"Max messages ({self.config.max_messages}) reached")
                break
            
            # Control de frecuencia
            now = time.time()
            if self.last_message_time > 0:
                elapsed = now - self.last_message_time
                if elapsed < self.config.interval_seconds:
                    time.sleep(self.config.interval_seconds - elapsed)
            
            # Generar y enviar mensaje
            hl7_message = self._build_message()
            success = self._send_message(hl7_message)
            
            if not success:
                logger.warning("Message send failed, will reconnect")
                self._disconnect()
                continue
            
            self.ctrl_id += 1
            self.last_message_time = time.time()
        
        self._disconnect()
        self._print_stats()

    def _print_stats(self):
        logger.info("=== EMULATOR STATISTICS ===")
        for k, v in self.stats.items():
            logger.info(f"  {k}: {v}")

    def set_state(self, state: EmulatorState):
        """Cambia el estado del emulador (thread-safe)."""
        with self._lock:
            old_state = self.config.state
            self.config.state = state
            # Ajustar intervalo según estado
            if state == EmulatorState.STANDBY:
                self.config.interval_seconds = 10.0
            elif state == EmulatorState.RUNNING:
                self.config.interval_seconds = 10.0
            elif state == EmulatorState.ALARM_SIMULATED:
                self.config.interval_seconds = 1.0
            logger.info(f"State changed: {old_state.value} -> {state.value}")


def parse_args() -> EmulatorConfig:
    parser = argparse.ArgumentParser(
        description="Emulador HL7/MLLP sintético para Mindray WATO EX-35",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Estados soportados:
  STANDBY          - Telemetría de estado (4 OBX CWE), intervalo 10s
  RUNNING          - Parámetros ventilatorios numéricos (10 OBX NM/CWE), intervalo 10s
  ALARM_SIMULATED  - Alarmas simuladas (5 OBX + alarma), intervalo 1s
  SESSION_END      - Cierra conexión tras enviar último mensaje

Ejemplos:
  python wato_emulator.py --state STANDBY --count 43
  python wato_emulator.py --state RUNNING --host mllp-receiver --port 1550
  python wato_emulator.py --state ALARM_SIMULATED --count 10 --interval 1
        """
    )
    parser.add_argument("--host", default="mllp-receiver", help="Host del receptor (default: mllp-receiver)")
    parser.add_argument("--port", type=int, default=1550, help="Puerto del receptor (default: 1550)")
    parser.add_argument("--bind-host", default="0.0.0.0", help="IP local para bind (default: 0.0.0.0)")
    parser.add_argument("--bind-port", type=int, default=0, help="Puerto local (0=automático)")
    parser.add_argument("--state", choices=[s.value for s in EmulatorState], 
                        default="STANDBY", help="Estado inicial (default: STANDBY)")
    parser.add_argument("--interval", type=float, default=10.0, help="Intervalo entre mensajes en segundos (default: 10.0)")
    parser.add_argument("--count", type=int, default=0, help="Número de mensajes a enviar (0=infinito)")
    parser.add_argument("--no-ack", action="store_true", help="No esperar ACK (modo fire-and-forget)")
    parser.add_argument("--ack-timeout", type=float, default=5.0, help="Timeout ACK en segundos")
    parser.add_argument("--reconnect-delay", type=float, default=2.0, help="Delay entre reconexiones")
    parser.add_argument("--max-reconnects", type=int, default=3, help="Máximo reintentos de conexión")
    parser.add_argument("--verbose", "-v", action="store_true", help="Logging detallado")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    return EmulatorConfig(
        receiver_host=args.host,
        receiver_port=args.port,
        bind_host=args.bind_host,
        bind_port=args.bind_port,
        state=EmulatorState(args.state),
        interval_seconds=args.interval,
        max_messages=args.count,
        require_ack=not args.no_ack,
        ack_timeout=args.ack_timeout,
        reconnect_delay=args.reconnect_delay,
        max_reconnects=args.max_reconnects
    )


def main():
    config = parse_args()
    emulator = WATOEmulator(config)
    try:
        emulator.run()
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    except Exception as e:
        logger.exception(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()