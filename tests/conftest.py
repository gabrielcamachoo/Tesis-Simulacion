#!/usr/bin/env python3
"""
tests/conftest.py - Configuración compartida para pytest
"""

import pytest
import sys
import os

# Añadir src al path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))


@pytest.fixture
def sample_standby_hl7():
    """Mensaje HL7 STANDBY observado en captura real."""
    return """MSH|^~\\&|MINDRAY_WATOPRO-SERIES^000F14002D3586ec^EUI-64||||20260825141442-0500||ORU^R01^ORU_R01|1|P|2.6|||NE|AL|||UNICODE UTF-8|||IHE_PCD_001^IHE PCD^1.3.6.1.4.1.19376.1.6.1.1.1^ISO
PID|||^^^^PI||^^^^^^L|||
PV1||I|^^^
OBR|1|1^MINDRAY_WATOPRO-SERIES^...|1^...|70040^MDC_DEV_SYS_ANESTH^MDC|||20260825141442-0500|
OBX|1|CWE|202886^MDC_EVT_STAT_DEV^MDC|1.1.1.202886|202836^MDC_EVT_STAT_STANDBY^MDC
OBX|2|CWE|30002^MNDRY_EVT_STAT_MODE_DEV|1.1.1.30002|30003^MNDRY_EVT_STAT_MODE_NORMAL
OBX|3|CWE|30005^MNDRY_EVT_PATIENT_TYPE|1.1.1.30005|202890^MDC_EVT_STAT_DEV_MODE_ADULT
OBX|4|CWE|30007^MNDRY_EVT_STAT_WARMER_ON_BOOL|1.3.1.30007|30000^MDC_TRUE"""


@pytest.fixture
def sample_running_hl7():
    """Mensaje HL7 RUNNING con OBX numéricos."""
    return """MSH|^~\\&|MINDRAY_WATOPRO-SERIES^000F14002D3586ec^EUI-64||||20260827094815||ORU^R01^ORU_R01|48|P|2.6|||NE|AL|||UNICODE UTF-8|||IHE_PCD_001^IHE PCD^1.3.6.1.4.1.19376.1.6.1.1.1^ISO
PID|||12345^5^M11^ADT^MR||DOE^JOHN^^^^^L||19800101|M
PV1||I|ICU^101^A^^^HOSP^A
OBR|1|1^MINDRAY^...|1^...|70040^MDC_DEV_SYS_ANESTH^MDC|||20260827094815|
OBX|1|NM|150020^MDC_VOL_RESP_TIDAL^MDC||500|mL
OBX|2|SN|150021^MDC_VOL_RESP_MINUTE^MDC||8.5|L/min
OBX|3|CWE|202886^MDC_EVT_STAT_DEV^MDC||202837^MDC_EVT_STAT_RUNNING^MDC"""


@pytest.fixture
def sample_ack():
    """ACK válido."""
    return """MSH|^~\\&|G18NODE|JAVERIANA|MINDRAY_WATOPRO-SERIES^000F14002D3586ec^EUI-64||20260827094815||ACK|48|P|2.6
MSA|AA|48"""


@pytest.fixture
def mllp_framed_message(sample_standby_hl7):
    """Mensaje HL7 enmarcado en MLLP."""
    from src.mllp.framing import SB, EOM, frame_hl7_message
    return frame_hl7_message(sample_standby_hl7.encode('utf-8'))


# Configuración de pytest
def pytest_configure(config):
    config.addinivalue_line("markers", "unit: marca pruebas unitarias")
    config.addinivalue_line("markers", "integration: marca pruebas de integración")
    config.addinivalue_line("markers", "slow: marca pruebas lentas")