FROM python:3.12-slim
WORKDIR /app
COPY services/graph-service/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY shared /app/shared
COPY services/graph-service /app/service
EXPOSE 8010
CMD ["uvicorn", "service.main:app", "--host", "0.0.0.0", "--port", "8010"]
