FROM python:3.12-slim
WORKDIR /app
COPY services/auth-service/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY services/auth-service /app/service
EXPOSE 8019
CMD ["uvicorn", "service.main:app", "--host", "0.0.0.0", "--port", "8019"]
