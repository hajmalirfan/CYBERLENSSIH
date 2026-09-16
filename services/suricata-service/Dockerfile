FROM python:3.12-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends suricata \
    && rm -rf /var/lib/apt/lists/*
COPY services/suricata-service/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY shared /app/shared
COPY services/suricata-service /app/service
EXPOSE 8005
ENV SURICATA_CONFIG=/etc/suricata/suricata.yaml
ENV SURICATA_LOG_DIR=/tmp/suricata
CMD ["uvicorn", "service.main:app", "--host", "0.0.0.0", "--port", "8005"]
