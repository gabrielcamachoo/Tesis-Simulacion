FROM python:3.11-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends tcpdump iproute2 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN touch /LAB_ONLY.marker

CMD ["/app/deploy/docker/raspberry/capture_and_detect.sh"]
