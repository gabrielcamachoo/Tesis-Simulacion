# Especificación de Evaluación Externa a Caja Negra (1 Página)

> **Para el evaluador externo (tercero independiente):** Este documento describe **únicamente el canal de red y el formato del protocolo** de la máquina de anestesia en el banco de pruebas aislado del proyecto 2026-03-G18 (PUJ / SIDRE). **No contiene las reglas ni los umbrales del detector** para garantizar una evaluación ciega (*black-box*) sin sesgo de diseño.

---

## 1. Objetivo de la prueba

Diseñar y ejecutar entre **5 y 10 escenarios de ataque o perturbación de red** contra un receptor HL7/MLLP de laboratorio que simula el canal de telemetría de una máquina de anestesia **Mindray WATO EX-35**. Al finalizar, se cruzarán tus marcas de tiempo (`ground_truth.jsonl`) con las alertas registradas por el detector para construir una matriz honesta de **detectado / evadido / causa**.

## 2. Especificación del canal y formato esperado

- **Transporte:** TCP, puerto **`1550`**, tráfico en texto plano (sin TLS ni autenticación).
- **Entramado (MLLP):** cada mensaje va envuelto entre `0x0B` (inicio, `<VT>`) y `0x1C 0x0D` (fin, `<FS><CR>`).
- **Protocolo de aplicación:** **HL7 v2.6**, tipo **`ORU^R01`** (observaciones periódicas), separadores `|^~\&`, fin de segmento `\r` (`0x0D`), codificación UTF-8.
- **Cadencia nominal observada:** `1` mensaje cada **`10 s`** mientras la máquina está encendida (en *Standby* o en ventilación activa *Running*). El receptor responde un `ACK^R01` (`AA`) por cada mensaje recibido.
- **Ejemplo anonimizado de mensaje `ORU^R01` (estado *Standby*):**

```hl7
MSH|^~\&|Mindray||Host||20261124120000+0000||ORU^R01|1001|P|2.6||||||UNICODE UTF-8
PID|||ANON-0001||ANON^PATIENT
PV1||I
OBR|1|||182777000^monitoring of patient^SCT|||20261124120000+0000
OBX|1|CWE|68282^MDC_DEV_SYS_ANESTH_STATE^MDC|1.1.1.1|68283^MDC_DEV_SYS_ANESTH_STATE_STANDBY^MDC||||||R
```

## 3. Entorno de ejecución y reglas de seguridad obligatorias

- **Destino de laboratorio:** dirección local (`127.0.0.1:1550`) o IP de red aislada asignada por el equipo (`192.168.5.134:1550`). **Prohibido** dirigir tráfico a redes hospitalarias o IPs externas.
- **Restricciones éticas y de seguridad:** sin malware real, sin exploits contra el sistema operativo, sin inundaciones destructivas (máximo `≤ 50` mensajes por escenario; duración total sugerida `5–10 min`).
- **Sincronización de reloj:** sincronizar tu máquina por NTP con el receptor antes de iniciar.

## 4. Qué debes entregar (sin mostrar tu código antes de la corrida)

Un archivo `ground_truth_tercero.jsonl` (una línea JSON por cada inyección enviada) y una tabla breve con la hipótesis de cada ataque:

```json
{"timestamp_utc": "2026-11-24T15:02:10.125000+00:00", "scenario": "T01", "description": "Breve descripción del vector"}
```

## 5. Familias de ataque sugeridas (libre elección del evaluador)

Puedes diseñar cualquier vector sobre TCP, MLLP o HL7 v2.6 — por ejemplo: manipulación de tiempos o entrega lenta byte a byte (*Slowloris* MLLP), fragmentación/reordenamiento TCP, inyección de `RST`/`FIN`, campos de longitud extrema, tipos de mensaje HL7 alternativos (`ADT`, `ORM`, `QRY`), suplantación de remitente, repetición diferida (*replay*) o alteración sutil de valores clínicos en `OBX-5`.

---

*Proyecto de Grado 2026-03-G18 — Grupo SIDRE, Ingeniería de Sistemas, Pontificia Universidad Javeriana.*
