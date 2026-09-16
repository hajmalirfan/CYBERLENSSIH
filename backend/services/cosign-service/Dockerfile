FROM python:3.12-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && curl -sSL -o /usr/local/bin/cosign https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64 \
    && chmod +x /usr/local/bin/cosign
COPY services/cosign-service/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY shared /app/shared
COPY services/cosign-service /app/service
EXPOSE 8003
CMD ["uvicorn", "service.main:app", "--host", "0.0.0.0", "--port", "8003"]
