# Falco needs kernel/driver access at runtime: run with --privileged.
FROM python:3.12-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates gnupg \
    && rm -rf /var/lib/apt/lists/* \
    && curl -s https://falco.org/repo/falcosecurity-packages.asc | apt-key add - \
    && echo "deb https://download.falco.org/packages/deb stable main" > /etc/apt/sources.list.d/falcosecurity.list \
    && apt-get update && apt-get install -y --no-install-recommends falco || echo "falco install deferred to runtime" \
    && rm -rf /var/lib/apt/lists/* || true
COPY services/falco-service/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY shared /app/shared
COPY services/falco-service /app/service
EXPOSE 8004
CMD ["uvicorn", "service.main:app", "--host", "0.0.0.0", "--port", "8004"]
