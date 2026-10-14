# Escenarios de Ataque del Laboratorio (A01–A16)

**Fuente de verdad operativa:** `anomaly_generator.py` → `SCENARIOS` (el bloque
`settings.yaml` → `anomaly_generator.scenarios` es espejo documental; debe mantenerse igual)
**Mapeo MITRE:** verificado contra ATT&CK ICS v20 el 2026-10-13 (`THREAT_MODEL.md` §4–§5)
**Carácter:** generación sintética **dentro del lab**, con techo por escenario
(`safety_limit`) y los límites globales de `ETHICS_AND_SAFETY.md` §3. No hay explotación,
persistencia ni objetivo externo.

Criterio de asignación (resumen): mensaje de reporte (ORU) no autorizado/malformado/falsificado
→ **T1692.002**; efecto de recursos (ráfaga, sobredimensión, reconexiones, ACK degradado) →
**T0814**; comando (CMD) → T1692.001 (reservado, el lab no genera comandos); control físico →
T0831 (no aplica, queda NO_VERIFICADO).

## Tabla de escenarios

| ID | Nombre | Qué genera | Amenaza STRIDE | Técnica (v20) | Techo | Regla que lo detecta |
|----|--------|------------|----------------|---------------|-------|----------------------|
| A01 | unknown_logical_source | MSH-3/MSH-4 fuera del baseline | Spoofing | T1692.002 | 10 | R-ID-001 |
| A02 | duplicate_control_id | MSH-10 repetido en sesión | Repudiation/Replay | T1692.002 | 10 | R-SEQ-001 |
| A03 | replay_synthetic_message | Reenvío de contenido previo con MCID nuevo | Replay | T1692.002 | 10 | R-SEQ-002 |
| A04 | regressive_timestamp | MSH-7 menor al anterior | Tampering temporal | T1692.002 | 10 | R-TIME-001 |
| A05 | missing_final_delimiter | Trama sin EOM (0x1C 0x0D) | Tampering/framing | T1692.002 | 5 | R-MLLP-001 |
| A06 | unexpected_bytes_before_start | Basura antes de SB (0x0B) | Evasión de parser | T1692.002 | 5 | R-MLLP-001 |
| A07 | missing_msh_segment | Mensaje sin MSH | Tampering estructural | T1692.002 | 5 | R-HL7-001 |
| A08 | invalid_segment_order | OBX antes de MSH (etc.) | Tampering estructural | T1692.002 | 5 | R-HL7-003 |
| A09 | unknown_message_type | ADT^A01/ORM^O01 fuera de baseline | Spoofing de tipo | T1692.002 | 10 | R-HL7-002 |
| A10 | synthetic_obx_unexpected_datatype | NM donde baseline dice CWE | Tampering de telemetría | T1692.002 | 10 | R-OBX-003 |
| A11 | synthetic_obx_unauthorized_unit | Unidad OBX-6 no permitida | Tampering de telemetría | T1692.002 | 10 | R-OBX-002 |
| A12 | frequency_out_of_baseline | Ráfaga ≤20 msg / 5 s | DoS | **T0814** | 20 | R-TIME-002 |
| A13 | repeated_reconnections | ≤5 reconexiones, 0.5 s entre intentos | DoS de recursos | **T0814** | 5 | R-TIME-002 (FSM/estado: secundaria) |
| A14 | periodic_silence | Hueco de 45 s (> baseline 15 s) y luego mensaje | Degradación de canal | **T0814** | 3 | R-TIME-002 |
| A15 | oversized_message | Mensaje ~32 KiB (excede framer de 4 KiB) | DoS de parser | **T0814** | 5 | R-MLLP-001 |
| A16 | logical_identity_change_mid_session | MSH-3/4 cambia dentro de la sesión | Spoofing/hijack lógico | T1692.002 | 5 | R-ID-001 |

## Notas de ejecución

- **Aleatoriedad acotada:** los escenarios usan semilla registrada en la corrida; sin semilla no
  hay repetibilidad de métricas.
- **Presupuesto total:** ≤ `max_anomalies_per_run` (70) por ejecución. Fórmula de cobertura
  completa: 20 (ráfaga A12) + 5 (reconexiones A13) + 14 escenarios × `count` = 25 + 14·count
  (con `count` = 3 → 67 ≤ 70). `run_experiment.py` valida esto antes de inyectar (fail-fast);
  un mismo escenario no puede superar su `safety_limit` aunque se reinicie el proceso sin
  cambiar settings.
- **Coherencia con evidencia:** A12/A15 respetan los límites observados en `baseline.yaml`
  (intervalos 9–10 s; tamaños ORU 968/971 B) — la anomalía es la desviación, no el volumen.
- **Detección esperada (hipótesis, a verificar en Fase 9):** ADR ≥ 90 % por escenario;
  falsos positivos estimados solo en RUNNING por códigos OBX NM/SN NO_VERIFICADOS
  (`LIMITATIONS.md`, pendiente).
- **Excluido por diseño:** cualquier escenario que requiera explotación, escalada, firmware,
  ransomware o tráfico fuera del lab (ver `ETHICS_AND_SAFETY.md` §3).

## Trazabilidad

Cada escenario se declara en `anomaly_generator.SCENARIOS` (con `enabled`, `safety_limit` y
parámetros propios; espejo en `settings.yaml`); la matriz de trazabilidad
requisito→escenario→regla→métrica queda en `TRACEABILITY_MATRIX.csv`.
