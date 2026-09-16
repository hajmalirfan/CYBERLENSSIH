FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir semgrep
COPY services/semgrep-service/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY shared /app/shared
COPY services/semgrep-service /app/service
EXPOSE 8001
CMD ["uvicorn", "service.main:app", "--host", "0.0.0.0", "--port", "8001"]
