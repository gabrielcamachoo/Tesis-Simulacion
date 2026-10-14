#!/usr/bin/env python3
"""
mllp_receiver.py - Receptor MLLP/HL7 modular para WATO EX-35
Punto de entrada principal que integra todos los componentes.

Uso:
    python mllp_receiver.py                    # 127.0.0.1:1550, con ACK
    python mllp_receiver.py --host 0.0.0.0     # Solo con red Docker/lab aislada
    python mllp_receiver.py --no-ack           # Modo observador pasivo
    python mllp_receiver.py --config config.yaml
    python mllp_receiver.py --outdir evidence_output
"""

import argparse
import logging
import signal
import sys
import threading
import time
from pathlib import Path

# Configurar logging temprano
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# Importar componentes modulares
from src.config.settings import load_settings, Settings
from src.evidence.writer import EvidenceWriter
from src.detection.baseline import load_baseline
from src.detection.rules import RuleSet
from src.detection.engine import DetectionEngine
from src.alerting.json_logger import AlertLogger
from src.mllp.server import run_server


def setup_logging(verbose: bool = False):
    """Configura logging."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.getLogger().setLevel(level)
    
    # Reducir verbosidad de librerías
    logging.getLogger('socketserver').setLevel(logging.WARNING)


def create_lab_marker(marker_path: str = "/LAB_ONLY.marker"):
    """Crea archivo marcador de laboratorio si no existe (solo para desarrollo)."""
    try:
        Path(marker_path).touch(exist_ok=True)
        logger.info(f"LAB marker creado/verificado: {marker_path}")
    except PermissionError:
        logger.warning(f"No se pudo crear LAB marker en {marker_path} (requiere root)")


def main():
    parser = argparse.ArgumentParser(
        description="Receptor MLLP/HL7 modular para detección de anomalías WATO EX-35",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  python mllp_receiver.py                          # Puerto 1550, con ACK
  python mllp_receiver.py --port 1550 --no-ack     # Solo observación
  python mllp_receiver.py --config config.yaml     # Configuración personalizada
  python mllp_receiver.py --outdir ./mis_capturas  # Directorio de salida
        """
    )
    parser.add_argument("--host", default="127.0.0.1",
                        help="IP a escuchar (default: 127.0.0.1; usar 0.0.0.0 solo en red Docker del lab)")
    parser.add_argument("--port", type=int, default=1550, help="Puerto TCP (default: 1550)")
    parser.add_argument("--config", default="src/config/settings.yaml", help="Archivo YAML de configuración")
    parser.add_argument("--baseline", default="baseline.yaml", help="Archivo baseline YAML")
    parser.add_argument("--rules", default="config/rules.yaml", help="Archivo reglas YAML")
    parser.add_argument("--outdir", default="evidence_output", help="Directorio de evidencia")
    parser.add_argument("--no-ack", action="store_true", help="No responder ACK (modo pasivo)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Logging detallado")
    parser.add_argument("--create-marker", action="store_true", help="Crear LAB_ONLY.marker local")
    
    args = parser.parse_args()
    
    setup_logging(args.verbose)
    
    # Crear marker si se solicita (solo desarrollo)
    if args.create_marker:
        create_lab_marker("/LAB_ONLY.marker")
    
    logger.info("=" * 60)
    logger.info("INICIANDO RECEPTOR MLLP/HL7 MODULAR - WATO EX-35")
    logger.info("=" * 60)
    
    try:
        # 1. Cargar configuración (valida seguridad)
        logger.info(f"Cargando configuración: {args.config}")
        settings = load_settings(args.config)
        
        # Sobrescribir host/port si se pasan por CLI
        settings.network.bind_host = args.host
        settings.network.bind_port = args.port
        # Sincronizar directorio de evidencia (AlertLogger usa settings.evidence.output_dir)
        settings.evidence.output_dir = args.outdir
        
        logger.info(f"Configuración: bind={settings.network.bind_host}:{settings.network.bind_port}")
        logger.info(f"Servidor HL7 esperado: {settings.network.server_ip}:{settings.network.server_port}")
        logger.info(f"ACK: {'DESACTIVADO' if args.no_ack else 'ACTIVADO'}")
        logger.info(f"Evidencia en: {args.outdir}")
        
        # 2. Cargar baseline
        logger.info(f"Cargando baseline: {args.baseline}")
        baseline = load_baseline(args.baseline)
        
        # 3. Cargar reglas
        logger.info(f"Cargando reglas: {args.rules}")
        rules = RuleSet(args.rules)
        logger.info(f"Reglas habilitadas: {rules.list_enabled()}")
        
        # 4. Inicializar componentes
        evidence_writer = EvidenceWriter(args.outdir, settings)
        detection_engine = DetectionEngine(settings, baseline, rules)
        alert_logger = AlertLogger(settings, evidence_writer)
        
        # 5. Crear y arrancar servidor
        server = run_server(
            settings=settings,
            evidence_writer=evidence_writer,
            detection_engine=detection_engine,
            alert_logger=alert_logger,
            send_ack=not args.no_ack
        )
        
        # Manejo de señales para cierre limpio
        shutdown_event = threading.Event()
        
        def signal_handler(signum, frame):
            logger.info(f"Señal {signum} recibida, cerrando...")
            shutdown_event.set()
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        # 6. Servidor en hilo
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        
        logger.info("Servidor MLLP ejecutándose. Ctrl+C para detener.")
        
        # Loop principal con estadísticas periódicas
        while not shutdown_event.is_set():
            shutdown_event.wait(30)  # Cada 30s
            if not shutdown_event.is_set():
                stats = server.get_session_stats()
                logger.info(f"ESTADO: sesiones_activas={stats['active_sessions']} "
                           f"total_mensajes={sum(s['messages'] for s in stats['sessions'].values())}")
        
        # 7. Cierre limpio
        logger.info("Cerrando servidor...")
        server.shutdown()
        server.server_close()
        server_thread.join(timeout=5)
        
        alert_logger.close()
        logger.info("Receptor detenido correctamente.")
        
    except RuntimeError as e:
        if "VALIDACIÓN DE SEGURIDAD" in str(e):
            logger.error("=" * 60)
            logger.error("BLOQUEO DE SEGURIDAD: El laboratorio no está autorizado")
            logger.error("Para ejecutar en entorno de desarrollo:")
            logger.error("  export LAB_AUTHORIZED=YES")
            logger.error("  touch /LAB_ONLY.marker")
            logger.error("  python mllp_receiver.py --create-marker")
            logger.error("=" * 60)
        raise
    except Exception as e:
        logger.exception(f"Error fatal: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()