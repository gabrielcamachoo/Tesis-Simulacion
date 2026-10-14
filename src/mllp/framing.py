#!/usr/bin/env python3
"""
framing.py - MLLP (Minimal Lower Layer Protocol) framing para HL7 v2.x
Según HL7 Standard y evidencia observada en WATO EX-35 (captura STANDBY 25-08-2026).

MLLP delimitadores estándar:
- SB (Start Block): 0x0B (VT - Vertical Tab)
- EB (End Block): 0x1C (FS - File Separator)
- CR (Carriage Return): 0x0D

Estructura: SB + HL7_MESSAGE + EB + CR
"""

from typing import List, Tuple, Optional, Iterator
from dataclasses import dataclass
from enum import Enum
import logging

logger = logging.getLogger(__name__)

# Delimitadores MLLP (bytes)
SB = b'\x0b'      # Start Block <VT>
EB = b'\x1c'      # End Block <FS>
CR = b'\x0d'      # Carriage Return
EOM = EB + CR     # End of Message completo

# Configuración por defecto (basada en evidencia WATO)
DEFAULT_ENCODING = 'utf-8'      # OBSERVADO: MSH-18 = "UNICODE UTF-8"
MAX_MESSAGE_SIZE = 65535        # Límite seguro
MAX_BUFFER_SIZE = 1024 * 1024   # 1MB buffer máximo

class FrameState(Enum):
    WAITING_SB = "waiting_sb"
    READING_MESSAGE = "reading_message"
    WAITING_EOM = "waiting_eom"

@dataclass
class MLLPFrame:
    """Mensaje MLLP completo parseado."""
    raw_bytes: bytes           # Bytes completos incluyendo delimitadores
    content: bytes             # Solo contenido HL7 (sin SB/EB/CR)
    start_pos: int             # Posición del SB en stream original
    end_pos: int               # Posición después de CR
    encoding: str = DEFAULT_ENCODING
    
    def decode(self, encoding: Optional[str] = None) -> str:
        """Decodifica contenido HL7 a string."""
        enc = encoding or self.encoding
        return self.content.decode(enc, errors='replace')
    
    def __len__(self) -> int:
        return len(self.content)
    
    def __bytes__(self) -> bytes:
        return self.raw_bytes

@dataclass
class FrameResult:
    """Resultado de intento de framing."""
    frames: List[MLLPFrame]
    remaining_buffer: bytes
    errors: List[str]
    bytes_consumed: int

class MLLPFramer:
    """
    Framer MLLP stateful para manejar streams TCP fragmentados.
    Maneja: mensajes fragmentados entre recv(), múltiples mensajes en un recv(),
    mensajes incompletos, bytes basura antes de SB.
    """
    
    def __init__(self, 
                 encoding: str = DEFAULT_ENCODING,
                 max_message_size: int = MAX_MESSAGE_SIZE,
                 max_buffer_size: int = MAX_BUFFER_SIZE,
                 strict: bool = True):
        self.encoding = encoding
        self.max_message_size = max_message_size
        self.max_buffer_size = max_buffer_size
        self.strict = strict
        self.buffer = b''
        self.state = FrameState.WAITING_SB
        self.message_start = 0
        self.frames_extracted = 0
        self.bytes_discarded = 0
        self.errors = []
    
    def feed(self, data: bytes) -> FrameResult:
        """
        Alimenta datos al framer y extrae frames completos.
        Retorna FrameResult con frames listos y buffer restante.
        """
        if not data:
            return FrameResult([], self.buffer, [], 0)
        
        # Límite de buffer para evitar DoS
        if len(self.buffer) + len(data) > self.max_buffer_size:
            # Descartar datos antiguos manteniendo posible mensaje parcial
            discard = len(self.buffer) + len(data) - self.max_buffer_size
            if discard < len(self.buffer):
                self.buffer = self.buffer[discard:]
                self.bytes_discarded += discard
                logger.warning(f"Buffer overflow: descartados {discard} bytes")
            else:
                self.buffer = b''
                self.bytes_discarded += len(self.buffer)
        
        self.buffer += data
        initial_len = len(self.buffer)
        frames = []
        errors = []
        
        while True:
            frame, consumed = self._try_extract_frame()
            if frame is None:
                break
            frames.append(frame)
            self.frames_extracted += 1
        
        # Copiar errores acumulados durante esta alimentación
        errors = self.errors.copy()
        self.errors.clear()
        
        remaining = self.buffer
        self.buffer = remaining
        bytes_consumed = initial_len - len(remaining)
        
        return FrameResult(frames, remaining, errors, bytes_consumed)
    
    def _try_extract_frame(self) -> Tuple[Optional[MLLPFrame], int]:
        """Intenta extraer un frame completo del buffer actual."""
        if self.state == FrameState.WAITING_SB:
            sb_pos = self.buffer.find(SB)
            if sb_pos == -1:
                # No hay SB - todo es basura o protocolo distinto
                if self.strict and self.buffer:
                    self.errors.append(f"no_sb_found:{len(self.buffer)}_bytes")
                    logger.debug(f"MLLP: {len(self.buffer)} bytes sin SB, descartando")
                self.bytes_discarded += len(self.buffer)
                self.buffer = b''
                return None, len(self.buffer)
            
            if sb_pos > 0:
                # Bytes basura antes de SB
                self.errors.append(f"garbage_before_sb:{sb_pos}_bytes")
                logger.warning(f"MLLP: {sb_pos} bytes descartados antes de SB")
                self.bytes_discarded += sb_pos
                self.buffer = self.buffer[sb_pos:]
            
            # Encontrado SB, empezar a leer mensaje
            self.message_start = 0  # Relativo al buffer actual (ya recortado)
            self.state = FrameState.READING_MESSAGE
            return self._try_extract_frame()
        
        elif self.state == FrameState.READING_MESSAGE:
            # Buscar EOM (EB + CR) primero
            eom_pos = self.buffer.find(EOM, 1)  # Empezar después de SB
            if eom_pos != -1:
                # EOM encontrado - buscar el último SB antes de este EOM
                # (para manejar múltiples SB: solo el último antes de EOM inicia el frame válido)
                last_sb_pos = self.buffer.rfind(SB, 0, eom_pos)
                if last_sb_pos > 0:
                    # Hay un SB antes del EOM que no es el primero - reiniciar desde ese SB
                    self.errors.append(f"late_sb_restart:{last_sb_pos}_bytes")
                    logger.warning(f"MLLP: SB tardío en pos {last_sb_pos}, reiniciando")
                    self.bytes_discarded += last_sb_pos
                    self.buffer = self.buffer[last_sb_pos:]
                    self.state = FrameState.WAITING_SB
                    return self._try_extract_frame()
                
                # Frame completo encontrado desde el primer SB
                content = self.buffer[1:eom_pos]  # Sin SB ni EOM
                
                # Validar longitud del contenido
                if len(content) == 0:
                    self.errors.append("empty_content")
                    logger.warning("MLLP: frame con contenido vacío rechazado")
                    self.buffer = self.buffer[eom_pos + 2:]
                    self.state = FrameState.WAITING_SB
                    return self._try_extract_frame()
                
                if len(content) > self.max_message_size:
                    self.errors.append("message_too_large")
                    logger.error(f"MLLP: mensaje excede {self.max_message_size} bytes")
                    self.buffer = self.buffer[eom_pos + 2:]
                    self.state = FrameState.WAITING_SB
                    return self._try_extract_frame()
                
                raw_frame = self.buffer[:eom_pos + 2]  # Con SB + EOM
                
                frame = MLLPFrame(
                    raw_bytes=raw_frame,
                    content=content,
                    start_pos=self.message_start,
                    end_pos=eom_pos + 2,
                    encoding=self.encoding
                )
                
                # Avanzar buffer
                consumed = eom_pos + 2
                self.buffer = self.buffer[consumed:]
                self.state = FrameState.WAITING_SB
                
                return frame, consumed
            
            # EOM no encontrado - buscar si hay un nuevo SB (reinicio)
            next_sb_pos = self.buffer.find(SB, 1)
            if next_sb_pos != -1:
                # Nuevo SB encontrado antes de EOM - reiniciar desde el nuevo SB
                self.errors.append(f"restart_at_sb:{next_sb_pos}_bytes")
                logger.warning(f"MLLP: nuevo SB en pos {next_sb_pos}, reiniciando mensaje parcial")
                self.bytes_discarded += next_sb_pos
                self.buffer = self.buffer[next_sb_pos:]
                self.state = FrameState.WAITING_SB
                return self._try_extract_frame()
            
            # Mensaje incompleto - esperar más datos
            if len(self.buffer) > self.max_message_size + 3:
                self.errors.append("message_too_large")
                logger.error(f"MLLP: mensaje excede {self.max_message_size} bytes")
                # Descartar buffer y resetear
                self.bytes_discarded += len(self.buffer)
                self.buffer = b''
                self.state = FrameState.WAITING_SB
            return None, 0
            
            frame = MLLPFrame(
                raw_bytes=raw_frame,
                content=content,
                start_pos=self.message_start,
                end_pos=eom_pos + 2,
                encoding=self.encoding
            )
            
            # Avanzar buffer
            consumed = eom_pos + 2
            self.buffer = self.buffer[consumed:]
            self.state = FrameState.WAITING_SB
            
            return frame, consumed
        
        # Si hay un SB mientras estamos en READING_MESSAGE, reiniciar
        # (Este caso se maneja en el loop principal de feed)
        return None, 0
    
    def reset(self):
        """Reinicia estado del framer."""
        self.buffer = b''
        self.state = FrameState.WAITING_SB
        self.message_start = 0
        self.bytes_discarded = 0
        self.frames_extracted = 0
        self.errors.clear()
    
    def get_stats(self) -> dict:
        return {
            'frames_extracted': self.frames_extracted,
            'bytes_discarded': self.bytes_discarded,
            'buffer_size': len(self.buffer),
            'errors': self.errors.copy(),
            'state': self.state.value
        }

def frame_hl7_message(hl7_content: bytes, encoding: str = DEFAULT_ENCODING) -> bytes:
    """
    Enmarca contenido HL7 en MLLP para envío.
    hl7_content: bytes del mensaje HL7 (sin delimitadores MLLP)
    """
    if isinstance(hl7_content, str):
        hl7_content = hl7_content.encode(encoding, errors='replace')
    return SB + hl7_content + EOM

def deframe_hl7_message(mllp_bytes: bytes, encoding: str = DEFAULT_ENCODING) -> Optional[bytes]:
    """
    Desenmarca un mensaje MLLP único (para casos simples).
    Retorna contenido HL7 o None si inválido.
    """
    if not mllp_bytes.startswith(SB):
        return None
    if not mllp_bytes.endswith(EOM):
        return None
    return mllp_bytes[1:-2]

def validate_mllp_frame(frame_bytes: bytes, max_size: int = MAX_MESSAGE_SIZE) -> Tuple[bool, str]:
    """
    Valida estructura básica de frame MLLP.
    Retorna (es_valido, mensaje_error).
    """
    if not frame_bytes:
        return False, "empty_frame"
    if not frame_bytes.startswith(SB):
        return False, "missing_start_block"
    if not frame_bytes.endswith(EOM):
        return False, "missing_end_block"
    if len(frame_bytes) < 4:  # SB + al menos 1 byte + EB + CR
        return False, "frame_too_short"
    content = frame_bytes[1:-2]
    if len(content) == 0:
        return False, "empty_content"
    if len(content) > max_size:
        return False, "message_too_large"
    return True, "ok"

class MLLPIterator:
    """
    Iterador sobre stream de bytes para extraer frames MLLP uno a uno.
    Útil para procesar archivos .bin o streams completos.
    """
    
    def __init__(self, data: bytes, encoding: str = DEFAULT_ENCODING):
        self.data = data
        self.encoding = encoding
        self.pos = 0
    
    def __iter__(self) -> Iterator[MLLPFrame]:
        return self
    
    def __next__(self) -> MLLPFrame:
        while self.pos < len(self.data):
            sb_pos = self.data.find(SB, self.pos)
            if sb_pos == -1:
                self.pos = len(self.data)
                raise StopIteration
            
            if sb_pos > self.pos:
                logger.debug(f"MLLP: {sb_pos - self.pos} bytes descartados en pos {self.pos}")
            
            eom_pos = self.data.find(EOM, sb_pos + 1)
            if eom_pos == -1:
                self.pos = len(self.data)
                raise StopIteration
            
            content = self.data[sb_pos + 1:eom_pos]
            raw = self.data[sb_pos:eom_pos + 2]
            
            frame = MLLPFrame(
                raw_bytes=raw,
                content=content,
                start_pos=sb_pos,
                end_pos=eom_pos + 2,
                encoding=self.encoding
            )
            
            self.pos = eom_pos + 2
            return frame
        
        raise StopIteration

# Funciones de conveniencia para testing
def extract_frames_simple(data: bytes) -> List[MLLPFrame]:
    """Extrae todos los frames de un buffer (no stateful)."""
    return list(MLLPIterator(data))

def count_frames(data: bytes) -> int:
    """Cuenta frames MLLP en datos (rápido, sin crear objetos)."""
    count = 0
    pos = 0
    while True:
        sb = data.find(SB, pos)
        if sb == -1:
            break
        eom = data.find(EOM, sb + 1)
        if eom == -1:
            break
        count += 1
        pos = eom + 2
    return count