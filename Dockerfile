# Dockerfile - Laboratorio HL7/MLLP de detección de anomalías (WATO EX-35)
# Una sola imagen para los tres servicios: mllp-receiver, wato-emulator,
# anomaly-generator. pip install se hace EN BUILD porque la red compose
# es internal: true (sin egress en runtime).
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Marcador de laboratorio (Settings._validate_safety lo exige en /)
RUN touch /LAB_ONLY.marker

# Por defecto corre el receptor; compose sobreescribe el comando
CMD ["python", "mllp_receiver.py", "--host", "0.0.0.0", "--port", "1550"]
