# Ética y Seguridad — Banco de Pruebas HL7/MLLP (Tesis G18 SIDRE)

**Fecha:** 2026-10-13 · **Estado:** vigente · **Revisión:** obligada antes de cada fase de ejecución

Este documento fija los límites aceptables del laboratorio. Cualquier ejecución que lo contradiga
se detiene. Los límites operativos citados están en `src/config/settings.yaml` (`laboratory.safety`).

## 1. Principios

1. **No maleficencia:** el laboratorio no daña equipos, pacientes, redes ni sistemas ajenos.
2. **Mínimo necesario:** solo se genera la anomalía mínima requerida por el escenario, con los
   límites cuantitativos de §3; nada se deja corriendo sin techo.
3. **Datos mínimos y anonimizados:** ningún dato clínico identificable sale del laboratorio en
   claro (§5).
4. **Defensiva por diseño:** todo artefacto (detector, emulador, generador) existe para medir
   detección, nunca para atacar sistemas productivos (§6, doble uso).
5. **Trazabilidad:** toda ejecución deja registro (config efectiva, semilla, hashes) para
   auditoría posterior.

## 2. Autorización y aislamiento

- Ejecutar **solo** en el host del laboratorio (Raspberry Pi u host del investigador) con
  `LAB_AUTHORIZED=YES` en el entorno y el marcador `LAB_ONLY.marker` presente; ambos exigidos
  por configuración (`require_lab_authorized`, `require_lab_marker`).
- Tráfico **exclusivamente** en `127.0.0.1`/`::1` o red Docker internal. **Prohibido** todo
  destino fuera de la máquina salvo descargas públicas documentadas.
- Ninguna IP pública, ningún escaneo, ningún objetivo que no sea el pipeline propio
  (emulador → receptor → detector).
- El dispositivo WATO real solo en modo externo con protocolo público, con conocimiento del
  personal autorizado; **nunca** se modifica su firmware ni su configuración.

## 3. Límites cuantitativos del generador de anomalías

| Control | Valor (settings.yaml `laboratory.safety`) |
|---------|-------------------------------|
| Anomalías por ejecución | ≤ 70 (`max_anomalies_per_run`; cobertura 14×3 + A12 20 + A13 5 = 67) |
| Tasa global | ≤ 5 msg/s (`max_rate_per_second`) |
| Tamaño máximo de mensaje | ≤ 32 768 bytes (`max_message_size_bytes`) |
| Enfriamiento entre ejecuciones | ≥ 30 s (`cooldown_seconds`) |
| Límite por escenario (A01–A16) | `safety_limit` 5–20 por escenario |
| Burst (A12) | ≤ 20 msg en 5 s |
| Reconexiones (A13) | ≤ 5, 0.5 s entre intentos |
| Silencio (A14) | hueco 45 s por inyección (techo 3) |

**Prohibiciones absolutas:** ransomware/wiper, malware o persistencia de cualquier clase,
exploits o búsqueda de vulnerabilidades en software de terceros, fuerza brute, DoS sin techo,
denegación a servicios ajenos, exfiltración de datos, suplantación hacia sistemas no laborales.
Todo intento de ampliar estos límites requiere enmienda explícita del plan aprobado.

## 4. Trazabilidad de ejecuciones

- Cada corrida registra: hash de `settings.yaml`/`rules.yaml`/`baseline.yaml`, versión del
  código (commit), escenarios habilitados, semilla aleatoria y los límites de §3.
- Evidencia en `evidence_raw/` sellada con SHA-256 e inmutable tras el cierre de la sesión
  (solo lectura).
- Alertas y logs en `analysis_output/`; los logs crudos se conservan sin editar.

## 5. Privacidad y datos clínicos

- **Anonimización por defecto** en toda salida derivada de evidencia: identificadores de
  paciente mediante token SHA-256 truncado a 8 hex (determinístico para re-identificación
  controlada interna), nunca en claro.
- IP/MAC de la red del hospital y **dispositivo** se conservan (necesarios para atribución del
  incidente), pero no se publican sin revisión.
- Los PCAP originales se tratan como material sensible: compartir solo por canales acordados
  con la institución.
- Marco de protección de datos aplicable por institución (Colombia: Ley 1581/2012 y
  Decreto 1377/2013) — **verificar con la facultad antes de cualquier publicación**
  (NO_VERIFICADO).
- **Gate clínico:** ninguna regla de umbrales clínicos (p. ej. valores críticos de laboratorio)
  se implementa ni evalúa sin aprobación escrita de un revisor clínico (SRS §requisito de
  validación clínica).

## 6. Doble uso y publicación

- El emulador/generador de anomalías reproduce **solo** comportamientos decaídos o sintéticos
  dentro del lab; no incorpora explotación, evasión de defensas reales ni objetivos externos.
- Publicación y divulgación: resultados agregados y métricas; PCAP crudos y payload identificable
  solo si la institución lo autoriza.
- Si durante la investigación se halla una vulnerabilidad real en producto comercial, aplica
  **divulgación responsable coordinada** (reporte al fabricante/CSIRT antes que publicación).

## 7. Puntos NO_VERIFICADOS de este documento

- Cumplimiento formal del marco de datos personales por revisión institucional.
- Aprobación escrita del revisor clínico (bloqueante de la Fase de reglas clínicas).
- Revisión de ética/asesoría de tesis sobre este documento (pendiente de firma).
