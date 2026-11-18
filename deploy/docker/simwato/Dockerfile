FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN touch /LAB_ONLY.marker

CMD ["python", "mllp_receiver.py", "--host", "0.0.0.0", "--port", "1550"]
