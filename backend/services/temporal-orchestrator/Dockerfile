FROM python:3.12-slim
WORKDIR /app
COPY services/temporal-orchestrator/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY shared /app/shared
COPY services/temporal-orchestrator /app/service
EXPOSE 8011
CMD ["uvicorn", "service.main:app", "--host", "0.0.0.0", "--port", "8011"]
