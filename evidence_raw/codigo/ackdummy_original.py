#!/usr/bin/env python3
"""
Receptor MLLP / HL7 v2.x para el Mindray WATO EX-35
Proyecto de Grado G18 - Nodo de monitoreo de seguridad de red

Escucha en TCP/1550, desenmarca los mensajes MLLP, los guarda crudos y
parseados, y responde ACK para que el equipo mantenga la sesion abierta.

Uso:
    python mllp_receiver.py                          # 0.0.0.0:1550, con ACK
    python mllp_receiver.py --port 1550 --no-ack     # modo observador puro
    python mllp_receiver.py --outdir capturas/sesion01

Salidas (en --outdir):
    raw_<ip>_<puerto>.bin   todos los bytes recibidos, tal cual llegaron
    mensajes.hl7            mensajes desenmarcados, separados por MLLP
    sesion.log             bitacora con timestamps y eventos
"""

import argparse
import datetime
import os
import socket
import socketserver
import sys
import threading

# Delimitadores MLLP (HL7 Interface Standards)
SB = b"\x0b"          # Start Block   <VT>
EB = b"\x1c"          # End Block     <FS>
CR = b"\x0d"          # Carriage Return
EOM = EB + CR         # fin de mensaje

ARGS = None
LOCK = threading.Lock()


def ts():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def log(msg):
    linea = f"[{ts()}] {msg}"
    with LOCK:
        print(linea, flush=True)
        with open(os.path.join(ARGS.outdir, "sesion.log"), "a",
                  encoding="utf-8") as f:
            f.write(linea + "\n")


def campos_msh(mensaje: str):
    """Extrae los campos utiles del segmento MSH para la bitacora."""
    lineas = mensaje.replace("\r\n", "\r").replace("\n", "\r").split("\r")
    msh = next((l for l in lineas if l.startswith("MSH")), None)
    if not msh:
        return None
    f = msh.split("|")

    def g(i):
        return f[i] if len(f) > i else ""

    return {
        "app_envia": g(2),
        "fac_envia": g(3),
        "app_recibe": g(4),
        "fac_recibe": g(5),
        "fecha": g(6),
        "tipo": g(8),
        "control_id": g(9),
        "version": g(11),
        "segmentos": [l[:3] for l in lineas if l.strip()],
    }


def construir_ack(mensaje: str) -> bytes:
    """ACK de aplicacion (MSA|AA) con el Message Control ID del original."""
    info = campos_msh(mensaje) or {}
    ctrl = info.get("control_id", "1")
    ahora = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
    # Se invierten emisor y receptor respecto al mensaje original
    msh = (
        f"MSH|^~\\&|{info.get('app_recibe','') or 'G18NODE'}|"
        f"{info.get('fac_recibe','') or 'JAVERIANA'}|"
        f"{info.get('app_envia','')}|{info.get('fac_envia','')}|"
        f"{ahora}||ACK|{ctrl}|P|{info.get('version','') or '2.3.1'}"
    )
    msa = f"MSA|AA|{ctrl}"
    cuerpo = msh + "\r" + msa + "\r"
    return SB + cuerpo.encode("iso-8859-1", errors="replace") + EOM


class ManejadorMLLP(socketserver.BaseRequestHandler):

    def setup(self):
        self.buffer = b""
        self.n_mensajes = 0
        ip, puerto = self.client_address
        self.raw_path = os.path.join(ARGS.outdir, f"raw_{ip}_{puerto}.bin")
        self.hl7_path = os.path.join(ARGS.outdir, "mensajes.hl7")
        log(f"CONEXION establecida desde {ip}:{puerto}")

    def handle(self):
        self.request.settimeout(ARGS.timeout)
        while True:
            try:
                datos = self.request.recv(8192)
            except socket.timeout:
                log(f"  sin datos por {ARGS.timeout}s (sesion sigue abierta)")
                continue
            except ConnectionResetError:
                log("  el equipo cerro la conexion de forma abrupta (RST)")
                return
            if not datos:
                return

            # Guardar todo lo crudo, incluso lo que no sea MLLP valido
            with open(self.raw_path, "ab") as f:
                f.write(datos)

            self.buffer += datos
            self.procesar_buffer()

    def procesar_buffer(self):
        while True:
            ini = self.buffer.find(SB)
            if ini == -1:
                # Nada de MLLP a la vista: puede ser basura o un protocolo
                # propietario. Se reporta pero no se descarta el archivo raw.
                if self.buffer:
                    log(f"  [!] {len(self.buffer)} bytes sin delimitador SB: "
                        f"{self.buffer[:40]!r}")
                    self.buffer = b""
                return
            if ini > 0:
                log(f"  [!] {ini} bytes descartados antes del SB")
                self.buffer = self.buffer[ini:]

            fin = self.buffer.find(EOM)
            if fin == -1:
                return          # mensaje incompleto, esperar mas TCP
            crudo = self.buffer[1:fin]
            self.buffer = self.buffer[fin + len(EOM):]
            self.entregar(crudo)

    def entregar(self, crudo: bytes):
        self.n_mensajes += 1
        # Mindray PDS usa ISO8859-1 por defecto (no soporta Unicode)
        mensaje = crudo.decode("iso-8859-1", errors="replace")

        info = campos_msh(mensaje)
        if info:
            log(f"  MSG #{self.n_mensajes}  tipo={info['tipo']}  "
                f"ctrl={info['control_id']}  v{info['version']}  "
                f"de={info['app_envia']}  segmentos={info['segmentos']}")
        else:
            log(f"  MSG #{self.n_mensajes}  sin segmento MSH reconocible "
                f"({len(crudo)} bytes)")

        with open(self.hl7_path, "a", encoding="utf-8") as f:
            f.write(f"### {ts()} | {self.client_address[0]} | "
                    f"msg {self.n_mensajes} | {len(crudo)} bytes\n")
            f.write(mensaje.replace("\r", "\n").rstrip() + "\n\n")

        if ARGS.verbose:
            for linea in mensaje.replace("\r\n", "\r").split("\r"):
                if linea.strip():
                    print("      " + linea)

        if not ARGS.no_ack:
            ack = construir_ack(mensaje)
            try:
                self.request.sendall(ack)
                log(f"  ACK enviado ({len(ack)} bytes)")
            except OSError as e:
                log(f"  [!] no se pudo enviar ACK: {e}")

    def finish(self):
        ip, puerto = self.client_address
        log(f"CONEXION cerrada {ip}:{puerto} — "
            f"{self.n_mensajes} mensajes en esta sesion")


class Servidor(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    global ARGS
    p = argparse.ArgumentParser(description="Receptor MLLP/HL7 para WATO EX-35")
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=1550)
    p.add_argument("--outdir", default="captura_hl7")
    p.add_argument("--no-ack", action="store_true",
                   help="no responder ACK (observacion pasiva)")
    p.add_argument("--verbose", action="store_true",
                   help="imprimir cada segmento en consola")
    p.add_argument("--timeout", type=int, default=60,
                   help="segundos de inactividad antes de avisar")
    ARGS = p.parse_args()

    os.makedirs(ARGS.outdir, exist_ok=True)

    log(f"Escuchando en {ARGS.host}:{ARGS.port}  "
        f"(ACK {'DESACTIVADO' if ARGS.no_ack else 'activado'})")
    log(f"Salidas en: {os.path.abspath(ARGS.outdir)}")
    log("Ctrl+C para terminar.")

    try:
        with Servidor((ARGS.host, ARGS.port), ManejadorMLLP) as srv:
            srv.serve_forever()
    except PermissionError:
        print("Permiso denegado al enlazar el puerto. Ejecuta como admin.",
              file=sys.stderr)
        sys.exit(1)
    except OSError as e:
        print(f"No se pudo enlazar {ARGS.host}:{ARGS.port} -> {e}",
              file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        log("Detenido por el usuario.")


if __name__ == "__main__":
    main()