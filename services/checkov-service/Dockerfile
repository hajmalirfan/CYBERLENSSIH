FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir checkov
COPY services/checkov-service/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY shared /app/shared
COPY services/checkov-service /app/service
EXPOSE 8002
CMD ["uvicorn", "service.main:app", "--host", "0.0.0.0", "--port", "8002"]
