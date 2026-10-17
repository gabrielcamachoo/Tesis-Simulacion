# Simulación de ransomware y de topología Raspberry Pi — detección en tiempo real

**Proyecto:** Detector determinista de anomalías HL7/MLLP para el monitor anestésico
WATO EX-35 (Tesis G18 SIDRE)
**Fecha:** 2026-10-14 · **Estado:** ✅ completada (observacional, laboratorio aislado)
**Corridas selladas:** `analysis_output/validation/ransomware_sim_20261014_175952/` (local)
y `analysis_output/validation/pi_sim_20261014_175742/` (docker, topología Pi)

> **ADVERTENCIA DE ALCANCE.** No se ejecutó, creó ni distribuyó malware real. La
> "simulación de ransomware" es una **composición de comportamientos de ataque
> modelados** con el generador de anomalías del propio laboratorio
> (`anomaly_generator.py`, escenarios A01–A16), dentro de la red aislada y con los
> interlocks de siempre (`LAB_AUTHORIZED=YES`, `LAB_ONLY.marker`, SafetyGuard).
> El "WATO EX-35" del laboratorio es el emulador `wato_emulator.py`; no hay equipo
> clínico real en el camino (`README.md` §Reglas, `docs/ETHICS_AND_SAFETY.md`).

---

## 1. Modelo de amenaza (ransomware IoT/OT sobre la telemetría del monitor)

Un ransomware que comprometa el monitor o su ruta de red hacia el HIS no cifra
archivos del PC: **secuestra el canal de telemetría**. En un dispositivo HL7/MLLP
periódico como el WATO, los efectos observables black-box son:

| Efecto del atacante | Comportamiento observable en el canal | Escenario del lab | Regla determinista | MITRE ATT&CK for ICS |
|---|---|---|---|---|
| Bloqueo de la salida (hostage del proceso de envío) | Silencio periódico: desaparece el latido ORU cada ~10 s | **A14** `periodic_silence` | `R-TIME-002` (hueco de periodicidad) | T0814 — Denial of Service |
| Corrupción / cifrado del stream | Bytes basura antes del SB, delimitador final ausente (stream ilegible para el HIS) | **A06**, **A05** | `R-MLLP-001` | T0885 — man-in-the-middle / corrupción de canal |
| Reintentos / inestabilidad del canal | Reconexiones repetidas a alta frecuencia | **A13** `repeated_reconnections` | `R-TIME-002` | T0814 |
| Suplantación para "mantener viva" la sesión | Cambio de identidad lógica a mitad de sesión y MSH con origen desconocido | **A16**, **A01** | `R-ID-001` | T1692.002 — Spoofing |

El detector **no necesita saber que es "ransomware"**: las 15 reglas deterministas
(`src/detection/rules.py`) operan sobre el comportamiento del stream, y la
composición anterior lo cubre por completo.

## 2. Metodología de la campaña ransomware

- **Modo:** `run_experiment.py --mode local` (receptor + motor de detección en el
  mismo host, **tiempo real**, alertas emitidas al recibir cada trama).
- **Escenarios incluidos:** A01, A05, A06, A13, A14, A16 (el resto excluido con
  `--exclude`). Total **20 inyecciones** (3 por escenario, 5 en A13; A14 con 3
  ventanas de silencio de 45 s = 135 s de la duración total).
- **Fases benignas:** STANDBY sintético 6 msg/6 s × 2 fases (protocolo §2).
- **Semilla fija:** `2026101401` (registrada en `seed.txt` y `manifest.json`).
- **Sin cambios de código:** se reutilizan los componentes congelados de Fase 5;
  la campaña es observacional (igual que A14/H3), no modifica el protocolo H1.

```powershell
$env:LAB_AUTHORIZED = "YES"
.\.venv\Scripts\python.exe run_experiment.py --mode local `
  --exclude "A02,A03,A04,A07,A08,A09,A10,A11,A12,A15" --seed 2026101401
```

## 3. Resultados — ransomware detectado en tiempo real

Corrida `runs/20261014_175952` (sellada en `analysis_output/validation/ransomware_sim_20261014_175952/`):

| Métrica | Valor |
|---|---|
| **TP / FP / FN** | **20 / 0 / 0** |
| Recall, Precision, F1 | **1.0000 / 1.0000 / 1.0000** |
| Detección por escenario | A01 3/3 · A05 3/3 · A06 3/3 · A13 5/5 · A14 3/3 · A16 3/3 (100 % cada uno) |
| Latencia inyección→alerta | p50 = **2.0 ms**, p95 = **8.8 ms**, max = 9.0 ms |
| Duración | 201 s (135 s de ellos: ventanas de silencio A14) |
| Pérdida de mensajes | 3/32 (9.4 %) — benignos no recibidos; las 20 inyecciones llegaron (FN=0) |

Evidencia cualitativa en el log del receptor (misma corrida):

- `FRAMING_ERROR ... error=garbage_before_sb:9_bytes` ×3 → **A06** (payload corrompido).
- Sesión de 136.8 s con 9 mensajes → ventana **A14** (silencio forzado entre tramas).
- 5 sesiones cortas de reconexión → **A13**.

**Interpretación:** las tres fases del ataque (bloqueo, corrupción, suplantación)
fueron detectadas al vuelo por reglas distintas, con latencia sub-10 ms y cero
falsos positivos en la campaña. El detector es indiferente a la "etiqueta"
ransomware: detecta las violaciones de comportamiento que el ataque produce.

## 4. Simulación de la topología Raspberry Pi (docker)

La Pi física no está disponible; se simuló **la topología de despliegue** (la que
usará la Pi, ver `docs/RASPBERRY_PI_SETUP.md` §6.3): mismo `docker-compose.yml`,
red internal `172.30.0.0/24`, IPs fijas, contenedor con el código congelado.

- **Campaña completa A01–A16** (sin A14 por duración): `--mode docker --exclude A14 --seed 20261014`.
- Corrida `runs/20261014_175742`, sellada en `analysis_output/validation/pi_sim_20261014_175742/`.

| Métrica | Valor |
|---|---|
| TP / FP / FN | 64 / **1** / 0 |
| Recall | **1.0000** (15/15 escenarios al 100 %) |
| Precision / F1 | 0.9846 / 0.9922 |
| Latencia | p50 = 0.95 ms, p95 = 1.78 ms |
| FP | 1 × `R-TIME-002` en fase benigna (jitter de red; comportamiento ya documentado en Fase 9) |

### Qué simula y qué NO simula esta corrida

| Simulado (idéntico a la Pi) | NO simulado (requiere hardware) |
|---|---|
| Código del receptor y del motor (mismo repo, misma imagen) | CPU ARM Cortex-A72 de la Pi 4 |
| Topología de red docker internal + IPs fijas | Consumo eléctrico y térmico real |
| Protocolo MLLP completo + ACK | **H2 (p95 ≤ 500 µs) — sigue NO VERIFICADO** |
| SafetyGuard, allowlist, anonimización | Latencia del stack de red ARM |

> H2 en este host da p95 = 248 µs (bench `latency_bench.py`, PC x86). **No
> extrapolar a la Pi**: solo la medición en la placa real cierra H2
> (`docs/VALIDATION_PROTOCOL.md` §3.3).

## 5. Cómo repetir en la Raspberry Pi física

```bash
# En la Pi (tras seguir docs/RASPBERRY_PI_SETUP.md §4–§5):
export LAB_AUTHORIZED=YES

# Topología idéntica a la simulada (§6.3 del setup):
.venv/bin/python run_experiment.py --mode local --exclude A14 --seed 20261014

# Campaña ransomware (idéntica a §2 de este documento):
.venv/bin/python run_experiment.py --mode local \
  --exclude "A02,A03,A04,A07,A08,A09,A10,A11,A12,A15" --seed 2026101401

# H2 (obligatorio en la Pi):
.venv/bin/python latency_bench.py --messages 1000 --runs 5
```

Criterio de equivalencia: misma semilla ⇒ mismo orden de escenarios
(`scenario_order.txt`); recall debe ser 1.0 en ambas; las latencias y la pérdida
pueden variar (se declaran por host).

## 6. Limitaciones (declaración de honestidad)

1. **No hay malware real.** Es una composición de escenarios del catálogo A01–A16
   con fines de validación del detector, dentro del laboratorio aislado.
2. **No hay equipo clínico real.** El emisor es `wato_emulator.py`; el WATO
   EX-35 real no participa (`evidence_raw/` solo se usa como corpus de replay).
3. **La Pi no se ejecutó.** Solo su topología docker. H2 en Pi pendiente.
4. **A14 modela el efecto, no el mecanismo.** El "silencio" es un hueco en la
   periodicidad; un ransomware real podría causarlo de muchas formas (todas
   caen en la misma señal observable).
5. **Un solo FP benigno** en la corrida docker (R-TIME-002 por jitter), dentro
   del rango ya reportado en Fase 9 (7 FP / 60 corridas).

## 7. Trazabilidad

| Artefacto | Ruta |
|---|---|
| Corrida ransomware (completa) | `runs/20261014_175952/` (gitignored) |
| Evidencia sellada ransomware | `analysis_output/validation/ransomware_sim_20261014_175952/` |
| Corrida topología Pi (completa) | `runs/20261014_175742/` (gitignored) |
| Evidencia sellada Pi | `analysis_output/validation/pi_sim_20261014_175742/` |
| Escenarios y reglas | `docs/ATTACK_SCENARIOS.md`, `src/detection/rules.py` |
| Guía de la Pi | `docs/RASPBERRY_PI_SETUP.md` |
| Resultados Fase 9 (contexto) | `docs/RESULTS_20261014.md`, `docs/LIMITATIONS.md` |
